/**
 * Loads and validates a graph.json document against the exact shape
 * sentinel_zero/graph_export.py produces (export_graph()'s return value).
 * This file is the one place in the viewer that knows that schema -- if
 * graph_export.py's shape ever changes, this is the only file that needs
 * to change with it.
 *
 * Deliberately NOT a silent best-effort parse: a malformed or unexpected
 * file throws a GraphValidationError with a specific reason, rather than
 * rendering a half-built scene from partial data. This mirrors the
 * engine's own "no silent tool failure" invariant (see docs/ARCHITECTURE.md
 * S2) -- a viewer that silently drops bad nodes and shows an
 * incomplete-looking-but-not-obviously-wrong graph would be worse than
 * one that refuses to render at all.
 */

export class GraphValidationError extends Error {}

const REQUIRED_NODE_FIELDS = ["id", "kind"];
const REQUIRED_EDGE_FIELDS = ["source", "kind"];
const KNOWN_NODE_KINDS = new Set(["module", "function"]);
const KNOWN_DISPOSITIONS = new Set([
  "VERIFIED_TRUE",
  "VERIFIED_FALSE",
  "UNRESOLVED_INCONCLUSIVE",
  "TOOL_FAILURE",
  null,
  undefined,
]);

/**
 * @param {unknown} raw - parsed JSON, not yet trusted
 * @returns {{targetRepository: string, nodes: object[], edges: object[]}}
 */
export function validateGraphDocument(raw) {
  if (typeof raw !== "object" || raw === null) {
    throw new GraphValidationError("top-level document is not a JSON object");
  }
  const { target_repository, nodes, edges, node_count, edge_count } = raw;

  if (!Array.isArray(nodes)) {
    throw new GraphValidationError("'nodes' is missing or not an array -- is this really a graph.json export?");
  }
  if (!Array.isArray(edges)) {
    throw new GraphValidationError("'edges' is missing or not an array -- is this really a graph.json export?");
  }

  nodes.forEach((node, i) => {
    if (!node || typeof node !== 'object' || Array.isArray(node) || typeof node.id !== 'string' || !node.id) {
      throw new GraphValidationError(`node[${i}] must have a nonempty string identity`);
    }
    for (const field of REQUIRED_NODE_FIELDS) {
      if (!(field in node)) {
        throw new GraphValidationError(`node[${i}] is missing required field '${field}'`);
      }
    }
    if (!KNOWN_NODE_KINDS.has(node.kind)) {
      throw new GraphValidationError(
        `node[${i}] ('${node.id}') has unknown kind '${node.kind}' -- expected 'module' or 'function'. ` +
          "This viewer refuses to guess a rendering for a node kind it doesn't recognize."
      );
    }
    if (!KNOWN_DISPOSITIONS.has(node.worst_disposition)) {
      throw new GraphValidationError(
        `node[${i}] ('${node.id}') has unrecognized worst_disposition '${node.worst_disposition}'.`
      );
    }
  });

  const byId = new Map(nodes.map(n => [n.id, n]));
  const validationWarnings = [];
  if (byId.size !== nodes.length) throw new GraphValidationError('duplicate node identities; refusing conflicting graph');
  edges.forEach((edge, i) => {
    if (!edge || typeof edge !== 'object' || Array.isArray(edge)) throw new GraphValidationError(`edge[${i}] is not an object`);
    for (const field of REQUIRED_EDGE_FIELDS) {
      if (!(field in edge)) {
        throw new GraphValidationError(`edge[${i}] is missing required field '${field}'`);
      }
    }
    if (!byId.has(edge.source)) throw new GraphValidationError(`edge[${i}] has missing source '${edge.source}'`);
    if (!['calls', 'contains'].includes(edge.kind)) throw new GraphValidationError(`edge[${i}] has unsupported kind '${edge.kind}'`);
    if (edge.kind === 'calls' && typeof edge.resolved !== 'boolean') throw new GraphValidationError(`edge[${i}] needs a boolean resolved flag`);
    if (edge.target != null && typeof edge.target !== 'string') throw new GraphValidationError(`edge[${i}] target must be string or null`);
    if (edge.kind === 'contains' && (byId.get(edge.source)?.kind !== 'module' || (byId.has(edge.target) && byId.get(edge.target)?.kind !== 'function'))) {
      throw new GraphValidationError(`edge[${i}] has invalid containment endpoints`);
    }
    if (edge.kind === 'contains' && !byId.has(edge.target)) validationWarnings.push(`edge #${i}: containment target '${edge.target}' is absent from this selection; shown as a missing-endpoint stub`);
    if (!KNOWN_DISPOSITIONS.has(edge.worst_disposition)) {
      throw new GraphValidationError(
        `edge[${i}] (${edge.source} -> ${edge.target}) has unrecognized worst_disposition '${edge.worst_disposition}'.`
      );
    }
  });

  const parents = new Map();
  for (const e of edges.filter(e => e.kind === 'contains')) {
    if (parents.has(e.target) && parents.get(e.target) !== e.source) throw new GraphValidationError(`conflicting parents for '${e.target}'`);
    parents.set(e.target, e.source);
  }
  const coverage = raw.coverage ?? null;
  if (coverage !== null && (typeof coverage !== 'object' || Array.isArray(coverage))) throw new GraphValidationError('coverage must be an object');
  if (coverage?.warnings !== undefined && (!Array.isArray(coverage.warnings) || coverage.warnings.some(w => !w || typeof w !== 'object' || typeof w.kind !== 'string'))) {
    throw new GraphValidationError('coverage warnings must be objects with a kind');
  }
  for (const key of ['collected_files', 'parsed_files']) {
    if (coverage?.[key] !== undefined && (!Number.isInteger(coverage[key]) || coverage[key] < 0)) throw new GraphValidationError(`invalid coverage ${key}`);
  }
  if (typeof node_count === "number" && node_count !== nodes.length) {
    throw new GraphValidationError(
      `document's own node_count (${node_count}) does not match nodes.length (${nodes.length}) -- ` +
        "this file may be truncated or hand-edited."
    );
  }
  if (typeof edge_count === "number" && edge_count !== edges.length) {
    throw new GraphValidationError(
      `document's own edge_count (${edge_count}) does not match edges.length (${edges.length}) -- ` +
        "this file may be truncated or hand-edited."
    );
  }

  return {
    targetRepository: typeof target_repository === "string" ? target_repository : "(unknown)",
    nodes,
    edges,
    coverage,
    validationWarnings,
  };
}

/**
 * Reads a File (from an <input type=file>) as text and parses+validates it.
 * Never touches the network -- the file never leaves the browser.
 */
export async function loadGraphFromFile(file) {
  const text = await file.text();
  let raw;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    throw new GraphValidationError(`'${file.name}' is not valid JSON: ${e.message}`);
  }
  return validateGraphDocument(raw);
}

/** Fetches a same-origin JSON file (used only for the bundled sample graph). */
export async function loadGraphFromUrl(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new GraphValidationError(`could not fetch '${url}': HTTP ${res.status}`);
  }
  return validateGraphDocument(await res.json());
}

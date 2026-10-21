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

  edges.forEach((edge, i) => {
    for (const field of REQUIRED_EDGE_FIELDS) {
      if (!(field in edge)) {
        throw new GraphValidationError(`edge[${i}] is missing required field '${field}'`);
      }
    }
    if (!KNOWN_DISPOSITIONS.has(edge.worst_disposition)) {
      throw new GraphValidationError(
        `edge[${i}] (${edge.source} -> ${edge.target}) has unrecognized worst_disposition '${edge.worst_disposition}'.`
      );
    }
  });

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

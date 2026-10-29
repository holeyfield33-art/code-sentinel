/** Validate graph exports before layout, inspection, filtering or comparison.
 * Version 2 separates module/function/external identities. Historical version 1
 * exports remain readable when their identities are unambiguous.
 */
export class GraphValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "GraphValidationError";
  }
}

const NODE_KINDS = new Set(["module", "function"]);
const EDGE_KINDS = new Set(["contains", "calls"]);
const DISPOSITIONS = new Set([
  "VERIFIED_TRUE", "VERIFIED_FALSE", "UNRESOLVED_INCONCLUSIVE", "TOOL_FAILURE", null, undefined,
]);

function requireRecord(value, label) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GraphValidationError(`${label} must be a JSON object`);
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || !value.trim()) {
    throw new GraphValidationError(`${label} must be a nonempty string`);
  }
}

function optionalString(value, label) {
  if (value !== undefined && value !== null && typeof value !== "string") {
    throw new GraphValidationError(`${label} must be a string or null`);
  }
}

function optionalBoolean(value, label) {
  if (value !== undefined && typeof value !== "boolean") {
    throw new GraphValidationError(`${label} must be a boolean`);
  }
}

function optionalLine(value, label) {
  if (value !== undefined && value !== null && (!Number.isSafeInteger(value) || value < 1)) {
    throw new GraphValidationError(`${label} must be a positive integer or null`);
  }
}

function annotationFields(value, label) {
  if (!DISPOSITIONS.has(value.worst_disposition)) {
    throw new GraphValidationError(`${label}.worst_disposition is unrecognized`);
  }
  for (const field of ["finding_plan_ids", "finding_uids"]) {
    if (value[field] === undefined) continue;
    if (!Array.isArray(value[field])) {
      throw new GraphValidationError(`${label}.${field} must be an array of strings`);
    }
    value[field].forEach((id, i) => requireString(id, `${label}.${field}[${i}]`));
  }
}

function checkCount(count, actual, field) {
  if (count === undefined) return; // early historical exports omitted counts
  if (!Number.isSafeInteger(count) || count < 0 || count !== actual) {
    throw new GraphValidationError(`${field} must be a nonnegative integer matching the array length (${actual})`);
  }
}

function readErrorMessage(error) {
  return error instanceof Error ? error.message : "unknown read failure";
}

/** @param {unknown} raw - parsed JSON, not yet trusted */
export function validateGraphDocument(raw) {
  requireRecord(raw, "top-level document");
  const version = raw.schema_version === undefined ? 1 : raw.schema_version;
  if (version !== 1 && version !== 2) {
    throw new GraphValidationError("unsupported schema_version; expected 1 or 2");
  }
  const { target_repository, nodes, edges, node_count, edge_count } = raw;
  if (!Array.isArray(nodes)) throw new GraphValidationError("'nodes' is missing or not an array");
  if (!Array.isArray(edges)) throw new GraphValidationError("'edges' is missing or not an array");
  if (target_repository !== undefined) requireString(target_repository, "target_repository");
  checkCount(node_count, nodes.length, "node_count");
  checkCount(edge_count, edges.length, "edge_count");

  const nodesById = new Map();
  const symbolIdentities = new Set();
  nodes.forEach((node, i) => {
    const label = `node[${i}]`;
    requireRecord(node, label);
    requireString(node.id, `${label}.id`);
    if (!NODE_KINDS.has(node.kind)) throw new GraphValidationError(`${label}.kind must be 'module' or 'function'`);
    if (nodesById.has(node.id)) {
      throw new GraphValidationError(`${label}.id is duplicated; re-export ambiguous historical graphs with the current scanner`);
    }
    optionalString(node.file_path, `${label}.file_path`);
    optionalLine(node.lineno, `${label}.lineno`);
    optionalBoolean(node.is_guard_shaped, `${label}.is_guard_shaped`);
    optionalBoolean(node.raises_on_guard, `${label}.raises_on_guard`);
    annotationFields(node, label);
    if (version === 2 || node.qualified_name !== undefined) {
      requireString(node.qualified_name, `${label}.qualified_name`);
    }
    if (version === 2 && node.id !== `${node.kind}:${node.qualified_name}`) {
      throw new GraphValidationError(`${label}.id does not match its kind and qualified_name`);
    }
    // Comparison uses this identity across old and new graph schemas. It must
    // be unique too, rather than allowing one upload to alias two diff nodes.
    const identity = JSON.stringify([node.kind, node.qualified_name ?? node.id]);
    if (symbolIdentities.has(identity)) throw new GraphValidationError(`${label} duplicates a qualified symbol identity`);
    symbolIdentities.add(identity);
    nodesById.set(node.id, node);
  });

  edges.forEach((edge, i) => {
    const label = `edge[${i}]`;
    requireRecord(edge, label);
    requireString(edge.source, `${label}.source`);
    if (!nodesById.has(edge.source)) throw new GraphValidationError(`${label}.source does not reference a node`);
    if (!EDGE_KINDS.has(edge.kind)) throw new GraphValidationError(`${label}.kind must be 'contains' or 'calls'`);
    annotationFields(edge, label);
    optionalLine(edge.lineno, `${label}.lineno`);
    optionalString(edge.unresolved_reason, `${label}.unresolved_reason`);
    if (edge.kind === "contains") {
      requireString(edge.target, `${label}.target`);
      if (nodesById.get(edge.source).kind !== "module" || nodesById.get(edge.target)?.kind !== "function") {
        throw new GraphValidationError(`${label} must connect an existing module to an existing function`);
      }
      return;
    }
    if (typeof edge.resolved !== "boolean") throw new GraphValidationError(`${label}.resolved must be a boolean`);
    if (!edge.resolved) {
      if (edge.target !== null) throw new GraphValidationError(`${label}.target must be null for an unresolved call`);
      requireString(edge.unresolved_reason, `${label}.unresolved_reason`);
      if (version === 2 && (edge.target_kind !== null || edge.target_symbol !== null)) {
        throw new GraphValidationError(`${label} cannot give an unresolved call a resolved symbol`);
      }
      return;
    }
    requireString(edge.target, `${label}.target`);
    if (edge.unresolved_reason !== undefined && edge.unresolved_reason !== null) {
      throw new GraphValidationError(`${label} cannot give a resolved call an unresolved reason`);
    }
    if (version === 2) {
      requireString(edge.target_symbol, `${label}.target_symbol`);
      if (!["module", "function", "external"].includes(edge.target_kind)) {
        throw new GraphValidationError(`${label}.target_kind must identify a module, function or external symbol`);
      }
      if (edge.target !== `${edge.target_kind}:${edge.target_symbol}`) {
        throw new GraphValidationError(`${label}.target does not match its symbol identity`);
      }
      if (edge.target_kind !== "external" && nodesById.get(edge.target)?.kind !== edge.target_kind) {
        throw new GraphValidationError(`${label}.target does not reference the declared internal node`);
      }
    }
    // Legacy resolved calls may name external stdlib/package APIs that have no
    // rendered node. Version 2 marks those references explicitly as external.
  });

  return {
    schemaVersion: version,
    targetRepository: target_repository ?? "(unknown)",
    nodes,
    edges,
  };
}

/** Read locally; uploaded graph files never leave the browser. */
export async function loadGraphFromFile(file) {
  try {
    return validateGraphDocument(JSON.parse(await file.text()));
  } catch (error) {
    if (error instanceof GraphValidationError) throw error;
    throw new GraphValidationError(`could not read a graph JSON file: ${readErrorMessage(error)}`);
  }
}

/** Fetch a same-origin JSON file, used for the bundled historical sample. */
export async function loadGraphFromUrl(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new GraphValidationError(`could not fetch '${url}': HTTP ${res.status}`);
    return validateGraphDocument(await res.json());
  } catch (error) {
    if (error instanceof GraphValidationError) throw error;
    throw new GraphValidationError(`could not read graph JSON from '${url}': ${readErrorMessage(error)}`);
  }
}

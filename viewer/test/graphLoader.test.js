import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { validateGraphDocument, GraphValidationError, loadGraphFromFile, loadGraphFromUrl } from "../src/graphLoader.js";

function validDoc(overrides = {}) {
  return {
    target_repository: "repo",
    node_count: 1,
    edge_count: 0,
    nodes: [{ id: "a", kind: "module", file_path: "a.py" }],
    edges: [],
    ...overrides,
  };
}

test("accepts a well-formed document", () => {
  const result = validateGraphDocument(validDoc());
  assert.equal(result.targetRepository, "repo");
  assert.equal(result.nodes.length, 1);
});

test("rejects a document missing 'nodes'", () => {
  const doc = validDoc();
  delete doc.nodes;
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
});

test("rejects a document missing 'edges'", () => {
  const doc = validDoc();
  delete doc.edges;
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
});

test("rejects a node with an unknown kind", () => {
  const doc = validDoc({ nodes: [{ id: "a", kind: "spooky-unknown-kind" }] });
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
});

test("rejects a node with an unrecognized worst_disposition", () => {
  const doc = validDoc({ nodes: [{ id: "a", kind: "module", worst_disposition: "TOTALLY_FINE" }] });
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
});

test("rejects a document whose own node_count disagrees with nodes.length", () => {
  const doc = validDoc({ node_count: 99 });
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
});

test("rejects an edge missing a required field", () => {
  const doc = validDoc({ edges: [{ kind: "calls" }] }); // missing 'source'
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
});

test("accepts a node with no worst_disposition at all (never-found-a-finding case)", () => {
  const doc = validDoc({ nodes: [{ id: "a", kind: "function" }] });
  const result = validateGraphDocument(doc);
  assert.equal(result.nodes.length, 1);
});

test("null and primitive node/edge records always produce a validation error", () => {
  for (const value of [null, 1, "node", [], false]) {
    assert.throws(() => validateGraphDocument(validDoc({ nodes: [value] })), GraphValidationError);
    assert.throws(() => validateGraphDocument(validDoc({ edges: [value], edge_count: 1 })), GraphValidationError);
  }
  for (const value of [null, [], "graph", false]) {
    assert.throws(() => validateGraphDocument(value), GraphValidationError);
  }
});

test("node IDs must be nonempty unique strings before entering the layout Map", () => {
  for (const id of [null, 0, {}, [], "", "   "]) {
    assert.throws(() => validateGraphDocument(validDoc({ nodes: [{ id, kind: "function" }] })), GraphValidationError);
  }
  const nodes = [{ id: "pkg.foo", kind: "module" }, { id: "pkg.foo", kind: "function" }];
  assert.throws(() => validateGraphDocument(validDoc({ nodes, node_count: 2 })), /duplicated/);
});

test("fields used by inspection, filtering and diffing are type checked", () => {
  const invalid = [
    { file_path: {} }, { lineno: "2" }, { lineno: -1 }, { lineno: 1.2 },
    { is_guard_shaped: "false" }, { raises_on_guard: null },
    { finding_plan_ids: "fp_1" }, { finding_plan_ids: [null] },
    { finding_uids: {} }, { finding_uids: [1] }, { finding_uids: [""] },
    { qualified_name: {} },
  ];
  for (const fields of invalid) {
    const node = { id: "a", kind: "function", ...fields };
    assert.throws(() => validateGraphDocument(validDoc({ nodes: [node] })), GraphValidationError);
  }
});

test("document counts, repository and schema version cannot use coercible values", () => {
  for (const fields of [
    { node_count: "1" }, { edge_count: null }, { node_count: -1 },
    { target_repository: {} }, { schema_version: "2" }, { schema_version: null }, { schema_version: 99 },
  ]) {
    assert.throws(() => validateGraphDocument(validDoc(fields)), GraphValidationError);
  }
});

function callDoc(overrides = {}) {
  return validDoc({ edges: [{ source: "a", kind: "calls", resolved: true, target: "os.system", ...overrides }], edge_count: 1 });
}

test("call edges require real sources and well-typed resolution metadata", () => {
  for (const fields of [
    { source: null }, { source: {} }, { source: "missing" }, { kind: "unknown" },
    { target: {} }, { target: null }, { target: "" }, { resolved: "true" },
    { finding_plan_ids: "fp_1" }, { finding_uids: [null] }, { lineno: [] },
    { unresolved_reason: {} }, { unresolved_reason: "cannot be resolved and unresolved" },
    { resolved: false, target: "os.system" }, { resolved: false, target: null },
  ]) {
    assert.throws(() => validateGraphDocument(callDoc(fields)), GraphValidationError);
  }
  assert.equal(validateGraphDocument(callDoc()).edges.length, 1); // external legacy symbol
  assert.equal(validateGraphDocument(callDoc({ resolved: false, target: null, unresolved_reason: "dynamic dispatch" })).edges.length, 1);
});

test("containment cannot refer to absent nodes or reverse module/function roles", () => {
  const nodes = [{ id: "a", kind: "module" }, { id: "a.fn", kind: "function" }];
  for (const edge of [
    { source: "a", target: "missing", kind: "contains" },
    { source: "a.fn", target: "a", kind: "contains" },
    { source: "a", target: null, kind: "contains" },
  ]) {
    assert.throws(() => validateGraphDocument(validDoc({ nodes, node_count: 2, edges: [edge], edge_count: 1 })), GraphValidationError);
  }
});

function version2Doc() {
  return {
    schema_version: 2, target_repository: "collision", node_count: 2, edge_count: 4,
    nodes: [
      { id: "module:pkg.foo", kind: "module", qualified_name: "pkg.foo" },
      { id: "function:pkg.foo", kind: "function", qualified_name: "pkg.foo", finding_plan_ids: ["fp_1"] },
    ],
    edges: [
      { source: "module:pkg.foo", target: "function:pkg.foo", kind: "contains" },
      { source: "function:pkg.foo", target: "function:pkg.foo", target_kind: "function", target_symbol: "pkg.foo", kind: "calls", resolved: true },
      { source: "function:pkg.foo", target: "external:os.system", target_kind: "external", target_symbol: "os.system", kind: "calls", resolved: true },
      { source: "function:pkg.foo", target: null, target_kind: null, target_symbol: null, kind: "calls", resolved: false, unresolved_reason: "dynamic dispatch" },
    ],
  };
}

test("version 2 separates module, function and external identities", () => {
  const result = validateGraphDocument(version2Doc());
  assert.equal(result.schemaVersion, 2);
  assert.equal(new Set(result.nodes.map(node => node.id)).size, 2);
  assert.equal(result.edges[2].target, "external:os.system");
});

test("version 2 rejects mismatched namespaces and dangling internal targets", () => {
  for (const fields of [
    { target: "function:missing", target_symbol: "missing" },
    { target_kind: "external" }, { target_symbol: null }, { target_kind: "unknown" },
  ]) {
    const doc = version2Doc();
    Object.assign(doc.edges[1], fields);
    assert.throws(() => validateGraphDocument(doc), GraphValidationError);
  }
  const doc = version2Doc();
  doc.nodes[1].id = "pkg.foo";
  assert.throws(() => validateGraphDocument(doc), GraphValidationError);
  const unresolved = version2Doc();
  unresolved.edges[3].target_symbol = "pretend-resolved";
  assert.throws(() => validateGraphDocument(unresolved), GraphValidationError);
});

test("historical bundled graph exports remain readable without rewriting their IDs", () => {
  for (const filename of ["sample-graph.json", "sample-graph-baseline.json"]) {
    const raw = JSON.parse(readFileSync(new URL(`../public/${filename}`, import.meta.url), "utf8"));
    const result = validateGraphDocument(raw);
    assert.equal(result.schemaVersion, 1);
    assert.equal(result.nodes.length, raw.node_count);
    assert.deepEqual(result.nodes.map(node => node.id), raw.nodes.map(node => node.id));
  }
});

test("file read and JSON failures use the same validation error contract", async () => {
  for (const text of ["not JSON", JSON.stringify(validDoc({ nodes: [null] }))]) {
    await assert.rejects(loadGraphFromFile({ text: async () => text }), GraphValidationError);
  }
  await assert.rejects(loadGraphFromFile({ text: async () => { throw null; } }), GraphValidationError);
});

test("URL parse and fetch failures use the same validation error contract", async (t) => {
  t.mock.method(globalThis, "fetch", async () => ({ ok: true, json: async () => { throw new SyntaxError("invalid JSON"); } }));
  await assert.rejects(loadGraphFromUrl("/broken.json"), GraphValidationError);
});

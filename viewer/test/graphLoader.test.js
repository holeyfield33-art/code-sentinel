import { test } from "node:test";
import assert from "node:assert/strict";
import { validateGraphDocument, GraphValidationError } from "../src/graphLoader.js";

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

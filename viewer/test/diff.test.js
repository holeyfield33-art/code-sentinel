import { test } from "node:test";
import assert from "node:assert/strict";
import { diffGraphs } from "../src/diff.js";

function node(id, worst_disposition, finding_uids = []) {
  return { id, kind: "function", worst_disposition, finding_uids };
}

test("a node absent from the baseline is classified 'new'", () => {
  const oldGraph = { nodes: [node("a", null)] };
  const newGraph = { nodes: [node("a", null), node("b", "VERIFIED_TRUE", ["uid1"])] };
  const { diffByNodeId, newCount } = diffGraphs(newGraph, oldGraph);
  assert.equal(diffByNodeId.get("b").classification, "new");
  assert.equal(newCount, 1);
});

test("same node, same finding_uids, same disposition -> unchanged", () => {
  const oldGraph = { nodes: [node("a", "UNRESOLVED_INCONCLUSIVE", ["uid1"])] };
  const newGraph = { nodes: [node("a", "UNRESOLVED_INCONCLUSIVE", ["uid1"])] };
  const { diffByNodeId, unchangedCount } = diffGraphs(newGraph, oldGraph);
  assert.equal(diffByNodeId.get("a").classification, "unchanged");
  assert.equal(unchangedCount, 1);
});

test("same node, disposition improved -> changed, even with the same finding_uids", () => {
  const oldGraph = { nodes: [node("a", "UNRESOLVED_INCONCLUSIVE", ["uid1"])] };
  const newGraph = { nodes: [node("a", "VERIFIED_TRUE", ["uid1"])] };
  const { diffByNodeId, changedCount } = diffGraphs(newGraph, oldGraph);
  const d = diffByNodeId.get("a");
  assert.equal(d.classification, "changed");
  assert.equal(d.oldStatus, "UNRESOLVED_INCONCLUSIVE");
  assert.equal(d.newStatus, "VERIFIED_TRUE");
  assert.equal(changedCount, 1);
});

test("same node, same worst_disposition STRING, but the underlying finding set changed -> changed", () => {
  // The precise case this module exists to catch: worst_disposition alone
  // would read as "unchanged" here (both UNRESOLVED_INCONCLUSIVE), but the
  // actual set of findings attached to this node is different -- one
  // resolved, a different one appeared. finding_uids is what notices.
  const oldGraph = { nodes: [node("a", "UNRESOLVED_INCONCLUSIVE", ["uid-old"])] };
  const newGraph = { nodes: [node("a", "UNRESOLVED_INCONCLUSIVE", ["uid-new"])] };
  const { diffByNodeId } = diffGraphs(newGraph, oldGraph);
  assert.equal(diffByNodeId.get("a").classification, "changed");
});

test("a node present in the baseline but absent from the new graph is reported as removed, not silently dropped", () => {
  const oldGraph = { nodes: [node("a", "VERIFIED_TRUE"), node("gone", "UNRESOLVED_INCONCLUSIVE")] };
  const newGraph = { nodes: [node("a", "VERIFIED_TRUE")] };
  const { removedNodes } = diffGraphs(newGraph, oldGraph);
  assert.equal(removedNodes.length, 1);
  assert.equal(removedNodes[0].id, "gone");
});

test("identical graphs produce zero new/changed/removed", () => {
  const graph = { nodes: [node("a", "VERIFIED_TRUE", ["u1"]), node("b", null, [])] };
  const { newCount, changedCount, removedNodes, unchangedCount } = diffGraphs(graph, graph);
  assert.equal(newCount, 0);
  assert.equal(changedCount, 0);
  assert.equal(removedNodes.length, 0);
  assert.equal(unchangedCount, 2);
});

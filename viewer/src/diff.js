/**
 * Milestone 22: node-level diff between two loaded graph.json documents,
 * for the viewer's "compare to another scan" feature -- the client-side
 * half of the scan-diffing concept in docs/SECURITY_MONITORING.md and
 * sentinel_zero/scan_diff.py.
 *
 * This is DELIBERATELY a node-level diff, not the finding-level diff
 * scan_diff.py does -- the viewer renders nodes, so node-level is the
 * right granularity for what gets colored in the scene. It still uses
 * each node's `finding_uids` (Milestone 21's stable per-finding identity,
 * threaded through graph_export.py) rather than just comparing
 * `worst_disposition` strings, so a node whose SET of findings changed
 * (one resolved, a different one appeared) but whose worst status
 * happens to read the same in both scans is still correctly classified
 * as "changed," not silently folded into "unchanged."
 */

/**
 * @param {{nodes: object[]}} newGraph - the currently-loaded (baseline-relative "after") graph
 * @param {{nodes: object[]}} oldGraph - the comparison ("before") graph
 * @returns {{
 *   diffByNodeId: Map<string, {classification: "new"|"changed"|"unchanged", oldStatus: string|null, newStatus: string|null}>,
 *   removedNodes: object[],   // present in oldGraph, absent from newGraph entirely
 *   newCount: number,
 *   changedCount: number,
 *   unchangedCount: number,
 * }}
 */
export function diffGraphs(newGraph, oldGraph) {
  const oldById = new Map(oldGraph.nodes.map((n) => [n.id, n]));
  const newIds = new Set(newGraph.nodes.map((n) => n.id));
  const diffByNodeId = new Map();

  let newCount = 0;
  let changedCount = 0;
  let unchangedCount = 0;

  for (const node of newGraph.nodes) {
    const oldNode = oldById.get(node.id);
    if (!oldNode) {
      diffByNodeId.set(node.id, { classification: "new", oldStatus: null, newStatus: node.worst_disposition ?? null });
      newCount++;
      continue;
    }
    const oldUids = new Set(oldNode.finding_uids ?? []);
    const newUids = new Set(node.finding_uids ?? []);
    const sameUids = oldUids.size === newUids.size && [...oldUids].every((u) => newUids.has(u));
    const sameStatus = (oldNode.worst_disposition ?? null) === (node.worst_disposition ?? null);
    const classification = sameUids && sameStatus ? "unchanged" : "changed";
    diffByNodeId.set(node.id, {
      classification,
      oldStatus: oldNode.worst_disposition ?? null,
      newStatus: node.worst_disposition ?? null,
    });
    if (classification === "changed") changedCount++;
    else unchangedCount++;
  }

  const removedNodes = oldGraph.nodes.filter((n) => !newIds.has(n.id));

  const identityWarnings = [...(newGraph.coverage?.warnings ?? []), ...(oldGraph.coverage?.warnings ?? [])]
    .filter(w => w.kind === 'module_identity_disambiguated');
  return { diffByNodeId, removedNodes, newCount, changedCount, unchangedCount, identityWarnings };
}

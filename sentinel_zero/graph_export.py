"""Exports the in-memory ISBG (graph.py's ProjectGraph) as a nodes+edges
JSON file, annotated with the finding plans that touch each node/edge.

Why this exists: dogfood_scan.run() builds a full ProjectGraph -- every
module, every function, every resolved/unresolved call -- and then threw
all of it away once the flat finding-plan ledger was written. That graph
is exactly what any future 3D rendering or Code Atlas adapter work needs,
and re-deriving it from the ledger alone is not possible (the ledger only
keeps calls that reached a known sink; most of the graph isn't in there
at all). This module adds no new analysis -- it is a pure, lossless
serialization of data the resolvers already computed.

Node/edge identity is exactly graph.py's own qualified names -- the same
Symbol strings callgraph.py and dogfood_scan.py already treat as the
single source of truth for "is this the same callee." Nothing here
re-derives or guesses an identity.
"""
from __future__ import annotations

from typing import Any

from sentinel_zero.graph import ProjectGraph, Symbol

# A plan's disposition.status that should take priority when a node is
# touched by more than one finding, ordered most- to least-notable for a
# reader scanning a visualization. TOOL_FAILURE is listed even though it
# should never appear inside a ledger's `plans` (dogfood_scan.run() halts
# the whole scan on a tool failure instead of reporting one as a finding)
# -- if it ever did show up here, it must outrank everything else, never
# be silently sorted below a clean-looking status.
_STATUS_PRIORITY = {
    "TOOL_FAILURE": 0,
    "VERIFIED_TRUE": 1,
    "UNRESOLVED_INCONCLUSIVE": 2,
    "VERIFIED_FALSE": 3,
}


def _worst_status(statuses: list[str]) -> str | None:
    if not statuses:
        return None
    return min(statuses, key=lambda s: _STATUS_PRIORITY.get(s, -1))


def export_graph(graph: ProjectGraph, plans: list[dict[str, Any]], repo_name: str) -> dict[str, Any]:
    """Builds the exportable nodes+edges document. `plans` is the same
    list of Finding Plan dicts (FindingPlan.as_dict()) the verification
    ledger writes -- this function reads them, never recomputes a
    disposition itself, so a node's annotation can never disagree with
    what the ledger says for the same finding."""

    # One lookup from (file_path, lineno, sink qualified_name) -> the
    # plan(s) whose hypothesis names that exact call site. This is the
    # same triple find_finding_plans() had in hand when it built each
    # plan's hypothesis -- file_path/lineno from the CallSite, sink
    # identity from the resolved Symbol -- so the match is exact, not a
    # heuristic re-guess.
    plans_by_call_site: dict[tuple[str, int, str], list[dict]] = {}
    plans_by_caller: dict[str, list[dict]] = {}
    for plan in plans:
        hyp = plan["hypothesis"]
        source_node = hyp["source_node"]  # "file_path:lineno"
        file_path, _, lineno_str = source_node.rpartition(":")
        key = (file_path, int(lineno_str), hyp["sink_node"])
        plans_by_call_site.setdefault(key, []).append(plan)
        caller = hyp["symbol_binding"]
        if caller and caller != "<module scope>":
            plans_by_caller.setdefault(caller, []).append(plan)

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for module in graph.modules.values():
        nodes.append(
            {
                "id": module.module_qualname,
                "kind": "module",
                "file_path": module.file_path,
            }
        )

    for qualname, fn in graph.functions.items():
        caller_plans = plans_by_caller.get(qualname, [])
        nodes.append(
            {
                "id": qualname,
                "kind": "function",
                "file_path": fn.file_path,
                "lineno": fn.lineno,
                "is_guard_shaped": fn.is_guard_shaped,
                "raises_on_guard": fn.raises_on_guard,
                "worst_disposition": _worst_status([p["disposition"]["status"] for p in caller_plans]),
                "finding_plan_ids": [p["plan_id"] for p in caller_plans],
            }
        )
        module_qualname = qualname.rsplit(".", 1)[0] if "." in qualname else qualname
        if module_qualname in graph.modules:
            edges.append({"source": module_qualname, "target": qualname, "kind": "contains"})

    for module in graph.modules.values():
        for call in module.calls:
            resolved = isinstance(call.target, Symbol)
            target_name = call.target.qualified_name if resolved else None
            matching_plans = (
                plans_by_call_site.get((module.file_path, call.lineno, target_name), [])
                if resolved
                else []
            )
            edges.append(
                {
                    "source": call.caller or module.module_qualname,
                    "target": target_name,
                    "kind": "calls",
                    "resolved": resolved,
                    "unresolved_reason": None if resolved else call.target.reason,
                    "lineno": call.lineno,
                    "finding_plan_ids": [p["plan_id"] for p in matching_plans],
                    "worst_disposition": _worst_status([p["disposition"]["status"] for p in matching_plans]),
                }
            )

    return {
        "target_repository": repo_name,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
    }

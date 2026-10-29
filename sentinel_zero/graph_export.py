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

Schema version 2 gives module, function and external-symbol references
separate namespaces. The original qualified name stays on each node and
resolved call, so exporting a module and a function with the same symbol
cannot merge their identities in a viewer. Analysis still uses graph.py's
Symbol strings; this module does not re-resolve source code.
"""
from __future__ import annotations

from typing import Any

from sentinel_zero.graph import ProjectGraph, Symbol

GRAPH_SCHEMA_VERSION = 2


def _node_id(kind: str, qualified_name: str) -> str:
    return f"{kind}:{qualified_name}"

# A plan's disposition.status that should take priority when a node is
# touched by more than one finding, ordered most- to least-notable for a
# reader scanning a visualization. TOOL_FAILURE is listed even though it
# should never appear inside a ledger's `plans` (dogfood_scan.run() halts
# the whole scan on a tool failure instead of reporting one as a finding)
# -- if it ever did show up here, it must outrank everything else, never
# be silently sorted below a clean-looking status.
#
# Deliberately NOT including "PENDING": disposition.set_disposition()
# allows it as a transient state on a freshly-built FindingPlan, but every
# plan dogfood_scan.find_finding_plans() appends to its result list has
# already had set_disposition() called on it (see that function's two
# set_disposition call sites, both unconditionally reached before
# plans.append) -- a plan reaching this module still PENDING, or bearing
# any other string outside the four above, means that invariant broke
# upstream, and _worst_status below treats that as the hard error it is
# rather than silently ranking an unrecognized status by some made-up
# priority.
_STATUS_PRIORITY = {
    "TOOL_FAILURE": 0,
    "VERIFIED_TRUE": 1,
    "UNRESOLVED_INCONCLUSIVE": 2,
    "VERIFIED_FALSE": 3,
}


def _worst_status(statuses: list[str]) -> str | None:
    if not statuses:
        return None
    unknown = sorted({s for s in statuses if s not in _STATUS_PRIORITY})
    if unknown:
        raise ValueError(
            f"export_graph found disposition status(es) {unknown!r} that are not one of "
            f"{sorted(_STATUS_PRIORITY)} -- every Finding Plan must be disposed (set_disposition) "
            "before it reaches graph export. Refusing to silently rank an unrecognized status "
            "instead of surfacing this as the bug it is."
        )
    return min(statuses, key=lambda s: _STATUS_PRIORITY[s])


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
    modules_by_path: dict[str, str] = {}
    module_ids: dict[str, str] = {}
    function_ids = {name: _node_id("function", name) for name in graph.functions}

    for module in graph.modules.values():
        if module.module_qualname in module_ids or module.file_path in modules_by_path:
            raise ValueError("export_graph found duplicate module identities or file ownership")
        module_ids[module.module_qualname] = _node_id("module", module.module_qualname)
        modules_by_path[module.file_path] = module_ids[module.module_qualname]
        nodes.append(
            {
                "id": module_ids[module.module_qualname],
                "qualified_name": module.module_qualname,
                "kind": "module",
                "file_path": module.file_path,
            }
        )

    for qualname, fn in graph.functions.items():
        if fn.qualified_name != qualname:
            raise ValueError(f"export_graph found inconsistent function identity {qualname!r}")
        if fn.file_path not in modules_by_path:
            raise ValueError(f"export_graph cannot locate the owning module for {qualname!r}")
        caller_plans = plans_by_caller.get(qualname, [])
        nodes.append(
            {
                "id": function_ids[qualname],
                "qualified_name": qualname,
                "kind": "function",
                "file_path": fn.file_path,
                "lineno": fn.lineno,
                "is_guard_shaped": fn.is_guard_shaped,
                "raises_on_guard": fn.raises_on_guard,
                "worst_disposition": _worst_status([p["disposition"]["status"] for p in caller_plans]),
                "finding_plan_ids": [p["plan_id"] for p in caller_plans],
                # Milestone 21: finding_uid (disposition.py's
                # _compute_finding_uid) is the STABLE identity across
                # two separate scans -- finding_plan_ids above is not,
                # since plan_id is only sequential within one run. A
                # plan built before Milestone 21 has no finding_uid; .get
                # keeps this export working against an older ledger
                # rather than crashing a feature (graph export) that
                # doesn't itself need the diff capability to function.
                "finding_uids": [p.get("finding_uid") for p in caller_plans if p.get("finding_uid")],
            }
        )
        # Lexical parents such as Class.method and outer.<locals>.inner are
        # not module names. Physical ownership keeps every function attached
        # to its actual module, even when another module shares its name.
        edges.append({"source": modules_by_path[fn.file_path], "target": function_ids[qualname], "kind": "contains"})

    for module in graph.modules.values():
        for call in module.calls:
            target_name: str | None
            target_id: str | None
            target_kind: str | None
            unresolved_reason: str | None
            if isinstance(call.target, Symbol):
                target_name = call.target.qualified_name
                if target_name in function_ids:
                    target_id, target_kind = function_ids[target_name], "function"
                elif target_name in module_ids:
                    target_id, target_kind = module_ids[target_name], "module"
                else:
                    target_id, target_kind = _node_id("external", target_name), "external"
                unresolved_reason = None
                matching_plans = plans_by_call_site.get((module.file_path, call.lineno, target_name), [])
            else:
                target_name = None
                target_id, target_kind = None, None
                unresolved_reason = call.target.reason
                matching_plans = []
            if call.caller:
                if call.caller not in function_ids:
                    raise ValueError(f"export_graph found a call from unknown function {call.caller!r}")
                source_id = function_ids[call.caller]
            else:
                source_id = module_ids[module.module_qualname]
            edges.append(
                {
                    "source": source_id,
                    "target": target_id,
                    "target_symbol": target_name,
                    "target_kind": target_kind,
                    "kind": "calls",
                    "resolved": isinstance(call.target, Symbol),
                    "unresolved_reason": unresolved_reason,
                    "lineno": call.lineno,
                    "finding_plan_ids": [p["plan_id"] for p in matching_plans],
                    "finding_uids": [p.get("finding_uid") for p in matching_plans if p.get("finding_uid")],
                    "worst_disposition": _worst_status([p["disposition"]["status"] for p in matching_plans]),
                }
            )

    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "target_repository": repo_name,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": nodes,
        "edges": edges,
        "coverage": graph.coverage,
    }

"""Cross-function guard propagation over the ISBG.

Language-agnostic by construction: this module only touches the generic
shapes in sentinel_zero.graph (ProjectGraph, Symbol, CallSite), never AST
nodes. Any language resolver that populates those shapes gets this for
free, same split as graph.py itself.

What this adds over same-function guard detection (Milestone 2): a thin
delegating wrapper --

    def require_admin(user):
        require_role(user, allowed=["admin"])

-- has no `if ...: raise ...` of its own, so Milestone 2's structural
check would call it NOT guard-shaped, even though it functions as a guard.
This module asks the question one hop further: does `name` either look
like a guard itself, or unconditionally call something that does, through
a bounded chain? That chain crosses files for free, because the call
graph it walks is already project-wide (built in the resolver's pass 1).

Explicit bound, stated plainly: depth-capped (MAX_DEPTH) and cycle-safe (a
function already on the current path is treated as not-a-guard, not
re-entered). This is not full interprocedural dataflow -- it does not know
whether a delegating wrapper's call is reachable, only that it exists in
the source. A wrapper that calls the guard inside a dead branch would
still read as "guard-shaped" by this check alone; same-function
branch-exclusivity (callgraph has no branch_path of its own, that lives on
the CallSite that invoked `name`) still applies at the call site that uses
this result.
"""
from __future__ import annotations

from sentinel_zero.graph import ProjectGraph, Symbol, WrapConstruction

MAX_DEPTH = 6


def find_wrap_constructions(graph: ProjectGraph) -> list[WrapConstruction]:
    """Anywhere a known WrapperClass is instantiated, record what it
    wrapped. This is what lets a middleware-style guard (one that never
    appears in any handler's own call graph, because it wraps the app at
    construction time instead) surface as a structural fact at all.

    Moved here from python_resolver.py's build_project_graph (Milestone 9,
    while adding JS wrapper-middleware detection) because this logic only
    ever touched graph.py's generic shapes -- Symbol, CallSite, WrapperClass,
    WrapConstruction -- never anything Python-specific. Both resolvers now
    call this one implementation instead of each carrying their own copy."""
    constructions: list[WrapConstruction] = []
    for module in graph.modules.values():
        for call in module.calls:
            if not isinstance(call.target, Symbol):
                continue
            wrapper = graph.wrapper_classes.get(call.target.qualified_name)
            if wrapper is None:
                continue
            wrapped_expr = (
                call.args[wrapper.wrapped_param_index]
                if wrapper.wrapped_param_index < len(call.args)
                else "<could not resolve positional argument -- possibly passed by keyword>"
            )
            constructions.append(
                WrapConstruction(
                    wrapper_qualified_name=wrapper.qualified_name,
                    wrapped_expr=wrapped_expr,
                    file_path=module.file_path,
                    lineno=call.lineno,
                )
            )
    return constructions


def build_direct_external_index(graph: ProjectGraph) -> dict[str, set[str]]:
    """qualified function name -> the set of external package names it
    reaches DIRECTLY (not through another project function)."""
    index: dict[str, set[str]] = {}
    for ref in graph.external_references:
        if not ref.caller:
            continue
        index.setdefault(ref.caller, set()).add(ref.package)
    return index


def external_packages_reached(
    name: str,
    graph: ProjectGraph,
    callee_index: dict[str, set[str]],
    direct_external_index: dict[str, set[str]],
    _visited: frozenset[str] = frozenset(),
    _depth: int = 0,
) -> frozenset[str]:
    """The dual of transitively_guard_shaped: instead of 'does this resolve
    to a guard', 'what third-party packages does this function reach,
    directly or through delegation to other project functions.' Same
    bound (depth, cycle-safety) and same reasoning for why: a route/
    function's exposure to a dependency should survive the function being
    refactored into a helper two calls deeper, the same way a guard
    should."""
    if _depth >= MAX_DEPTH or name in _visited:
        return frozenset()
    reached = set(direct_external_index.get(name, ()))
    next_visited = _visited | {name}
    for callee in callee_index.get(name, ()):
        reached |= external_packages_reached(callee, graph, callee_index, direct_external_index, next_visited, _depth + 1)
    return frozenset(reached)


def build_direct_callee_index(graph: ProjectGraph) -> dict[str, set[str]]:
    """qualified function name -> the set of project-defined functions it
    directly calls (anywhere in its body, any branch -- intentionally
    branch-blind here; branch exclusivity is checked at the original call
    site, not inside this delegation walk)."""
    index: dict[str, set[str]] = {}
    for call in graph.all_calls():
        if not call.caller or not isinstance(call.target, Symbol):
            continue
        if call.target.qualified_name not in graph.functions:
            continue  # stdlib / unindexed calls are leaves, not delegation hops
        index.setdefault(call.caller, set()).add(call.target.qualified_name)
    return index


def transitively_guard_shaped(
    name: str,
    graph: ProjectGraph,
    callee_index: dict[str, set[str]],
    _visited: frozenset[str] = frozenset(),
    _depth: int = 0,
) -> bool:
    fn = graph.functions.get(name)
    if fn is None:
        return False
    if fn.is_guard_shaped:
        return True
    if _depth >= MAX_DEPTH or name in _visited:
        return False
    next_visited = _visited | {name}
    return any(
        transitively_guard_shaped(callee, graph, callee_index, next_visited, _depth + 1)
        for callee in callee_index.get(name, ())
    )

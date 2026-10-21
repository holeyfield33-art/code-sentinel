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
    """Milestone 12: checks FunctionInfo.raises_on_guard, NOT the broader
    is_guard_shaped. This function answers "if I call `name` as a
    delegate and discard whatever it returns, can `name` still stop MY
    next statement from running?" Only a `raise` can do that (it
    propagates as an exception into the caller); a plain `return` only
    ends `name`'s own body and has zero effect on the caller's control
    flow unless the caller checks a returned value, which this resolver
    does not model. Confirmed as a real false-positive category before
    this field existed: a return-shaped delegate was read as "protecting"
    a sink in a caller that never actually checked its return value. See
    graph.py's FunctionInfo.raises_on_guard for the full reasoning, and
    is_guard_shaped's own docstring for why that broader, raise-OR-return
    check is still the right one for a DIFFERENT use (a wrapper's own
    dispatch method checking itself before forwarding, same function)."""
    fn = graph.functions.get(name)
    if fn is None:
        return False
    if fn.raises_on_guard:
        return True
    if _depth >= MAX_DEPTH or name in _visited:
        return False
    next_visited = _visited | {name}
    return any(
        transitively_guard_shaped(callee, graph, callee_index, next_visited, _depth + 1)
        for callee in callee_index.get(name, ())
    )


def build_direct_sink_call_counts(graph: ProjectGraph, sink_table: dict[str, str]) -> dict[str, dict[str, int]]:
    """qualified function name -> {sink_symbol: direct call-site count},
    counting only calls made directly in that function's own body (not
    through another project function) that resolve to a symbol present in
    `sink_table`. The dual of build_direct_external_index above, scoped to
    sink symbols instead of external packages."""
    counts: dict[str, dict[str, int]] = {}
    for call in graph.all_calls():
        if not call.caller or not isinstance(call.target, Symbol):
            continue
        symbol = call.target.qualified_name
        if symbol not in sink_table:
            continue
        per_fn = counts.setdefault(call.caller, {})
        per_fn[symbol] = per_fn.get(symbol, 0) + 1
    return counts


def transitive_sink_symbol_counts(
    name: str,
    callee_index: dict[str, set[str]],
    direct_sink_counts: dict[str, dict[str, int]],
    _visited: frozenset[str] = frozenset(),
    _depth: int = 0,
) -> dict[str, int]:
    """VERIFICATION_LEDGER.md sz-2026-10-21-18 (Codex review on PR #3,
    comment_id 4340617860 -- confirmed real by direct reproduction before
    this fix was written): docs/REMEDIATION_PLAN.md item 3's original fix
    only counted a sink symbol's call sites WITHIN the one function being
    probed. It missed that the probe calls `name` and lets it run
    completely normally -- including whatever `name` itself calls -- so a
    sink reached inside a helper `name` delegates to is just as real a
    source of the probe's reported symbol as a second direct call site in
    `name` itself. Concretely: `run_it()` calling `helper()` (which has
    its own, genuinely-reachable `os.system` call), with a SECOND,
    actually-dead `os.system` call sitting after a `return` in `run_it`
    itself -- probing `run_it()` observes `os.system` fire (via helper)
    and the item-3-only fix had no way to know that evidence belongs to
    helper's call site, not run_it's own dead one, because it only ever
    counted call sites inside run_it's own body. This function closes that
    by summing direct sink-symbol counts across `name` and everything
    transitively reachable from it through the project's own call graph,
    so the same caller/gate code in dogfood_scan.py sees the TRUE number
    of places the probe's reported symbol could have come from, not just
    the count local to one function.

    Same bound and cycle-safety as transitively_guard_shaped and
    external_packages_reached above, and for the same reason: this is not
    a precise reachability proof (branch-blind, like build_direct_callee_index
    itself), only an answer to "how many distinct sources could the
    probe's report have come from" -- which is exactly what the gate it
    feeds needs, and no more."""
    if _depth >= MAX_DEPTH or name in _visited:
        return {}
    merged: dict[str, int] = dict(direct_sink_counts.get(name, {}))
    next_visited = _visited | {name}
    for callee in callee_index.get(name, ()):
        for symbol, count in transitive_sink_symbol_counts(
            callee, callee_index, direct_sink_counts, next_visited, _depth + 1
        ).items():
            merged[symbol] = merged.get(symbol, 0) + count
    return merged

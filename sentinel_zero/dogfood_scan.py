"""Milestone 3 dogfood run: cross-function guard propagation added on top
of the Milestone 2 ISBG resolver.

What changed vs. Milestone 2, and why: a guard used to have to contain its
own `if ...: raise ...` to count. A thin delegating wrapper --

    def require_admin(user):
        require_role(user, allowed=["admin"])

-- has no raise of its own, so it read as NOT a guard even though it
functions as one, and even though require_role (the thing it delegates
to) might live in a different file entirely. sentinel_zero.callgraph walks
the project-wide call graph, bounded and cycle-safe, to answer "does this
resolve to a guard, directly or through delegation" instead of "does this
one function's own body look like a guard."

Carried forward from Milestone 2, unchanged:
  - sink matching by resolved identity, not name/token.
  - guard matching by resolved identity + structural shape, not name.
  - same-function branch-exclusivity (an elif sibling can't "precede" a
    sink it can never run alongside) -- subsumed by Milestone 19's real
    dominance check below, which catches this case too, plus the one the
    old mutually_exclusive-based check missed.

Milestone 19 replaced the "guard precedes sink" approximation (same-
function call ORDER plus a branch-exclusivity check that only caught two
paths diverging at a SHARED ancestor node) with real CFG dominance for
If/Try nesting (python_resolver.dominates): a guard call now only counts
if it executes on EVERY control-flow path that can reach the sink, not
just "comes earlier in source and isn't on a mutually-exclusive sibling
branch." That distinction is not academic -- the old check had a real,
confirmed false positive: a guard call sitting inside a bare `if`, with
no `else`, used to be wrongly credited with protecting a sink at an
outer, unconditional level, even though the sink runs regardless of
whether that `if`'s condition was ever true. See dominates()'s own
docstring for the worked example and the exact fix.

Still bounded, still stated plainly:
  - "guard precedes sink" is still same-function dominance at the
    ORIGINAL call site -- delegation crosses functions/files for the
    *guard's own identity*, but the call that invokes it still has to be
    in the sink's function, dominating the sink. A guard called three
    functions up the stack, never passed down, is not yet traced -- that
    is real interprocedural dataflow, not delegation propagation, and is
    not claimed here.
  - Dominance proves the guard CALL runs before the sink on every path --
    it does not, and cannot from static structure alone, prove the
    guard's own internal condition corresponds to attacker-controlled
    input. This is why a confirmed dominance hit still only promotes to
    UNRESOLVED_INCONCLUSIVE, never VERIFIED_FALSE -- real CFG dominance
    was necessary, but was never claimed to be sufficient, for that
    promotion.
  - Loop bodies still get one undifferentiated branch tag regardless of
    how many times (zero or many) the loop actually runs -- not given
    their own dominance treatment per iteration.

Milestone 7 added a second resolver (JS/TS, via resolvers/js_resolver.py)
selected with the `language` parameter/CLI arg -- the proof that graph.py's
IR holds for more than one language without changing any of the generic
machinery above. The JS resolver is deliberately NOT at parity with
Python's five milestones yet (see js_resolver.py/extract_graph.js for the
current, stated bounds -- wrapper-class detection and class-method
call-walking were added in Milestones 9 and 12 respectively, so this is
no longer "top-level functions only").
Milestone 8 added external-dependency mapping for JS too, via the same
_dependency_summary()/ExternalReference machinery below -- no new logic
needed here, only a JS-populated graph.external_references. Milestone 6's
dynamic sandbox probe is Python-specific (drives importlib) and is gated
to `language == "python"` accordingly -- never attempted against a JS
finding. Milestone 16 widened that probe past its original PROCESS_EXEC-
only scope to also cover FILE_IO and DESERIALIZATION sink kinds (see
probes/sink_reachability_probe.py, renamed from process_exec_probe.py),
and fixed a real correctness bug found while widening it: the probe
patches every known sink simultaneously and reports whichever one fired
first, so a disposition must check that the reported symbol actually
matches THIS finding's own sink before promoting to VERIFIED_TRUE -- a
check that was missing before, and would have gotten worse as more sink
kinds were added to the same probe run. Milestone 17 widened the probe's
eligible CALL SHAPE, not just its sink coverage: a function requiring
arguments is no longer automatically out of scope -- if a real call site
elsewhere in the project passes it only literal-constant arguments
(Milestone 15's taint classifier says so), those exact values are
harvested and used to make the probe call, instead of calling with zero
arguments. See _literal_argument_values/_probe_invocation_for below.

Milestone 18 ported the dynamic probe to JS/TS (probes/js_sink_reachability_probe.py
+ probes/js/_sink_reachability_harness.js), closing the "Python-specific"
bound stated two paragraphs up for the one call shape this probe already
knows how to handle (exported, zero-argument). Same safety model as
Python's (an isolated `node` subprocess, hard timeout, patch sinks before
require()-ing the target, raise-not-return to short-circuit before the
real sink runs), same Milestone 16 symbol-match correctness rule (shared
now via _promote_if_sink_reached, used by both the Python and JS probing
blocks below) -- but the specific function that is unsafe to patch is
different per language: Python's is builtins.eval/exec (patching exec
breaks CPython's own import machinery); JS's is fs.readFileSync (patching
it breaks Node's own require()). Eligibility is also decided differently:
Python checks call shape statically from the AST before invoking the
probe; JS decides it at RUNTIME inside the harness itself, via the real
exported function's own `fn.length === 0`, because JS silently fills a
missing argument with `undefined` rather than raising the way Python
raises TypeError, so a static "requires no arguments" check on the JS
side would not actually guarantee a safe, nothing-synthesized call.

Honest dogfooding result, not oversold: across two real JS/TS repos
(runtime-firewall-mvp, vercel-cli), this produced zero actual VERIFIED_TRUE
promotions, despite the mechanism itself being correct (proven via the
synthetic tests in tests/test_js_sink_probe.py). Diagnosed causes, both
pre-existing, expected bounds rather than bugs in this milestone: (1) a
matched finding inside a self-executing test file (one that runs its own
assertions at require()-time) can make the whole harness process exit
nonzero before ours reports cleanly -- this project's directory-skip list
does not exclude __tests__/test directories, so such files are not
filtered out of the finding set to begin with; (2) a .ts finding generally
fails to require() at all under plain Node, either because the file
exercises ESM/TS-only syntax, or because it imports a dependency that is
not installed in sentinel-zero's own environment (the probe always runs
under sentinel-zero's interpreter, never the target's own node_modules --
the same category of bound already true of Python's own venv isolation).
Neither is a flaw in the probe's correctness; both are documented in
README.md's Known Bounds section rather than silently worked around.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

from sentinel_zero.disposition import (
    ToolFailure,
    build_finding_plan,
    load_catalog,
    set_disposition,
)
from sentinel_zero.callgraph import (
    build_direct_callee_index,
    build_direct_external_index,
    external_packages_reached,
    transitively_guard_shaped,
)
from sentinel_zero.graph import ProjectGraph, Symbol
from sentinel_zero.graph_export import export_graph
from sentinel_zero.ledger_writer import safe_write_text
from sentinel_zero.probes.sink_reachability_probe import run_sink_reachability_probe
from sentinel_zero.probes.js_sink_reachability_probe import run_js_sink_reachability_probe
from sentinel_zero.resolvers.python_resolver import build_project_graph as build_python_project_graph
from sentinel_zero.resolvers.python_resolver import dominates
from sentinel_zero.resolvers.js_resolver import build_project_graph as build_js_project_graph

SINK_ATTACK_IDS = {
    "FILE_IO": "AAC-17",
    "DESERIALIZATION": "AAC-27",
    "PROCESS_EXEC": "AAC-11",
}

_SINK_KIND_BY_NAME = {
    "builtins.open": "FILE_IO",
    "json.load": "DESERIALIZATION",
    "json.loads": "DESERIALIZATION",
    # Milestone 15: widened past the Milestone 2 starting set. pickle's
    # load/loads can execute arbitrary code during unpickling (the classic
    # __reduce__ gadget), and PyYAML's yaml.load (without a Safe/FullLoader)
    # can do the same via its default Loader -- both are DESERIALIZATION,
    # same category as json.load, not a new SinkKind. Still not claimed
    # exhaustive -- this is a wider starting set, not a closed list.
    "pickle.load": "DESERIALIZATION",
    "pickle.loads": "DESERIALIZATION",
    "yaml.load": "DESERIALIZATION",
    "os.system": "PROCESS_EXEC",
    "subprocess.run": "PROCESS_EXEC",
    "subprocess.call": "PROCESS_EXEC",
    "subprocess.check_call": "PROCESS_EXEC",
    "subprocess.check_output": "PROCESS_EXEC",
    "subprocess.Popen": "PROCESS_EXEC",
    # Milestone 15: builtins.eval/exec now actually reachable -- see
    # python_resolver.py's _BUILTIN_SINK_NAMES, which fixes the bare-name
    # resolution gap that made "builtins.open" dead data in this table
    # since the day it was added (a bare `open(...)` call resolved to the
    # Symbol "open", which can never match a key in this dict spelled
    # "builtins.open" -- confirmed by grepping tests/ for "builtins.open"
    # before this milestone: zero hits, nothing ever exercised this path).
    "builtins.eval": "PROCESS_EXEC",
    "builtins.exec": "PROCESS_EXEC",
}

# Milestone 7: the JS/TS equivalent of _SINK_KIND_BY_NAME, keyed by the same
# kind of resolved dotted identity js_resolver.py produces via require()/
# import bindings. Node's child_process family + eval/Function cover
# PROCESS_EXEC; fs's sync+callback read/write cover FILE_IO; JSON.parse
# covers DESERIALIZATION. Milestone 15 widened both this table (vm module)
# and the Python one (pickle, yaml.load, builtins.eval/exec) -- still not
# claimed exhaustive, this is a wider starting set, not a closed list.
_JS_SINK_KIND_BY_NAME = {
    "child_process.exec": "PROCESS_EXEC",
    "child_process.execSync": "PROCESS_EXEC",
    "child_process.execFile": "PROCESS_EXEC",
    "child_process.execFileSync": "PROCESS_EXEC",
    "child_process.spawn": "PROCESS_EXEC",
    "child_process.spawnSync": "PROCESS_EXEC",
    "child_process.fork": "PROCESS_EXEC",
    "eval": "PROCESS_EXEC",
    "Function": "PROCESS_EXEC",
    "fs.readFile": "FILE_IO",
    "fs.readFileSync": "FILE_IO",
    "fs.writeFile": "FILE_IO",
    "fs.writeFileSync": "FILE_IO",
    "JSON.parse": "DESERIALIZATION",
    # Milestone 15: Node's vm module -- runs a string of code (or a
    # precompiled vm.Script) in a new/existing V8 context. Functionally
    # the same category as eval/Function above (PROCESS_EXEC), just a
    # different, less-obvious API surface for the same capability. Still
    # not claimed exhaustive.
    "vm.runInThisContext": "PROCESS_EXEC",
    "vm.runInNewContext": "PROCESS_EXEC",
    "vm.runInContext": "PROCESS_EXEC",
    "vm.Script": "PROCESS_EXEC",
}

_RESOLVERS = {
    "python": build_python_project_graph,
    "javascript": build_js_project_graph,
}

_SINK_TABLES = {
    "python": _SINK_KIND_BY_NAME,
    "javascript": _JS_SINK_KIND_BY_NAME,
}


def _zero_arg_top_level_function(file_path: str, module_qualname: str, caller_qualname: str) -> str | None:
    """Returns the bare function name if `caller_qualname` names a plain
    module-level function (not a class method, not nested) in this module
    taking no required arguments -- the only shape Milestone 6's dynamic
    probe is allowed to call with no inputs. Returns None for anything else
    (a class method, a function needing real arguments, an unparseable
    file) -- the probe is simply not attempted for those, never guessed at."""
    fn_node = _top_level_function_node(file_path, module_qualname, caller_qualname)
    if fn_node is None:
        return None
    args = fn_node.args
    required_positional = len(args.posonlyargs) + len(args.args) - len(args.defaults)
    required_kwonly = sum(1 for default in args.kw_defaults if default is None)
    if required_positional > 0 or required_kwonly > 0:
        return None
    return fn_node.name


def _top_level_function_node(
    file_path: str, module_qualname: str, caller_qualname: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """Shared AST lookup behind both _zero_arg_top_level_function and
    Milestone 17's literal-argument harvesting: finds caller_qualname's own
    function definition, but only when it's a plain top-level function in
    this module (not a class method, not nested) -- the shape every probe
    invocation path requires regardless of its arity."""
    prefix = module_qualname + "."
    if not caller_qualname.startswith(prefix):
        return None
    name = caller_qualname[len(prefix):]
    if "." in name:
        return None  # "Class.method" -- out of scope for this probe
    try:
        tree = ast.parse(Path(file_path).read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, OSError):
        return None
    for node in tree.body:  # top-level only -- a nested def is a different scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _literal_argument_values(graph: ProjectGraph, module_qualname: str, function_name: str) -> list | None:
    """Milestone 17: looks for a real call site ANYWHERE in the project
    graph that calls <module_qualname>.<function_name> with one or more
    positional arguments Milestone 15's taint classifier confirmed are
    "literal" for every one of them -- built entirely from constants in
    the AST, never from a parameter, a global, or another call's result.
    When found, harvests the concrete Python values via ast.literal_eval
    on the call site's own captured source text (CallSite.args) -- never
    synthesized, never guessed, always a value that genuinely gets passed
    to this function somewhere in the real codebase today.

    Zero-arg call sites are irrelevant here (the simpler, pre-existing
    zero-arg path already covers those) -- only call sites that actually
    pass arguments are considered. If several qualifying call sites exist,
    the first by (caller, lineno, order) is used, for determinism; any one
    of them is equally valid evidence, since each is a real invocation
    that genuinely occurs in this codebase. Returns None if no call site
    qualifies, or if ast.literal_eval unexpectedly fails on a value the
    taint classifier called "literal" (defensive only -- should not
    happen; never silently falls back to guessing a value instead)."""
    target_qualname = f"{module_qualname}.{function_name}"
    candidates = [
        call
        for call in graph.all_calls()
        if isinstance(call.target, Symbol)
        and call.target.qualified_name == target_qualname
        and call.args
        and len(call.arg_taint) == len(call.args)
        and all(t == "literal" for t in call.arg_taint)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda c: (c.caller, c.lineno, c.order))
    try:
        return [ast.literal_eval(text) for text in candidates[0].args]
    except (ValueError, SyntaxError):
        return None


def _probe_invocation_for(
    file_path: str, module_qualname: str, caller_qualname: str, graph: ProjectGraph
) -> tuple[str, list | None] | None:
    """Decides whether, and how, the dynamic probe may safely call this
    caller: returns (function_name, None) for the original zero-required-
    argument case, (function_name, values) when Milestone 17's harvesting
    found real literal values for every required positional parameter, or
    None when neither applies -- the probe is simply not attempted, never
    guessed at. Keyword-only parameters are never modeled (no harvesting
    attempted for them) -- a function requiring one is always ineligible."""
    fn_node = _top_level_function_node(file_path, module_qualname, caller_qualname)
    if fn_node is None:
        return None
    args = fn_node.args
    required_positional = len(args.posonlyargs) + len(args.args) - len(args.defaults)
    required_kwonly = sum(1 for default in args.kw_defaults if default is None)
    if required_kwonly > 0:
        return None
    if required_positional == 0:
        return (fn_node.name, None)
    harvested = _literal_argument_values(graph, module_qualname, fn_node.name)
    if harvested is None or len(harvested) < required_positional:
        return None  # too few literal values to satisfy required params -- would be a TypeError
    total_positional_slots = len(args.posonlyargs) + len(args.args)
    if not args.vararg and len(harvested) > total_positional_slots:
        return None  # more values than this function accepts positionally
    return (fn_node.name, harvested)


def _js_top_level_function_name(module_qualname: str, caller_qualname: str) -> str | None:
    """Milestone 18: the JS/TS equivalent of _top_level_function_node's
    shape check, done purely from the qualname string -- no JS parsing
    needed here, because js_sink_reachability_probe.py's harness decides
    real eligibility (is it exported? is its arity zero?) at runtime
    against the actually-required module (see that harness's module
    docstring for why this is more accurate than static analysis would
    be). This function only rules out what graph.py's own naming
    convention already rules out structurally: a class method's qualname
    is "module.ClassName.methodName" (extract_graph.js builds it that
    way -- confirmed in its indexClass), so anything with more than one
    segment past the module prefix is a method, never a plain top-level
    function, and module scope itself (caller_qualname == "") never
    matches the prefix at all."""
    prefix = module_qualname + "."
    if not caller_qualname.startswith(prefix):
        return None
    name = caller_qualname[len(prefix):]
    if "." in name:
        return None  # "ClassName.methodName" -- out of scope for this probe
    return name


def _promote_if_sink_reached(plan, probe_result: dict, call, guard_hit: str | None, caller: str, call_desc: str) -> None:
    """Shared by both the Python and JS/TS probing paths (Milestone 18
    factored this out so neither language's block could silently drift
    from the other's correctness rule): promotes `plan` to VERIFIED_TRUE
    only when the harness reported "sink_reached" AND the reported symbol
    is THIS finding's own sink -- the Milestone 16 fix, now applied
    uniformly. `call_desc` is the language-specific clause describing how
    the probe actually invoked the function ("with zero arguments", or
    Python's harvested-literal-argument variant) -- written into the
    reason text so a human reading a finding never has to guess what was
    actually run."""
    if probe_result.get("status") != "sink_reached" or probe_result.get("symbol") != call.target.qualified_name:
        return
    guard_note = (
        f" A guard-shaped call ({guard_hit}) was detected statically on this path, "
        "but the dynamic probe still reached the sink -- this does not mean the guard "
        "is bypassable by attacker-controlled input, only that it did not block this "
        "specific call."
        if guard_hit else ""
    )
    set_disposition(
        plan,
        "VERIFIED_TRUE",
        reason=(
            f"a bounded dynamic probe called {caller}() {call_desc} in an "
            f"isolated subprocess and observed {probe_result.get('symbol')} invoked "
            f"(args={probe_result.get('args')}) before the real sink could execute "
            "(monkeypatched, never actually run). This confirms the call path is live "
            "and reachable under at least one real invocation." + guard_note
        ),
        residual_uncertainty="Low: dynamic reachability confirmed under one benign "
        "call; no adversarial inputs were attempted (explicitly out of scope for this probe).",
    )


def _taint_note(arg_taint: tuple) -> str:
    """One sentence summarizing a sink call's per-argument taint
    classification (see graph.py's CallSite.arg_taint), appended to a
    plan's reason text so the triage signal is visible without having to
    dig into hypothesis.argument_taint. Never changes what the sentence
    before it claims -- purely additional evidence."""
    if not arg_taint:
        return " This sink call takes no positional arguments."
    if "parameter" in arg_taint:
        return (
            " At least one argument to this sink traces to this function's own parameter "
            "-- worth checking whether that parameter can be influenced by whatever calls this function "
            "(this is a same-function trace, not interprocedural taint tracking -- see CallSite.arg_taint)."
        )
    if "unknown" in arg_taint:
        return (
            " At least one argument to this sink could not be classified as either a literal constant or "
            "parameter-derived (e.g. it's the result of another call) -- taint is simply unknown here, not ruled out."
        )
    return " Every argument to this sink is a literal constant in this call -- lower priority to review by hand."


def find_finding_plans(
    graph: ProjectGraph,
    repo_name: str,
    catalog,
    plan_counter: list[int],
    repo_root: Path,
    language: str = "python",
) -> list:
    sink_table = _SINK_TABLES[language]
    plans = []
    callee_index = build_direct_callee_index(graph)
    external_index = build_direct_external_index(graph)
    for module in graph.modules.values():
        calls_by_caller: dict[str, list] = {}
        for call in module.calls:
            calls_by_caller.setdefault(call.caller, []).append(call)

        for caller, calls in calls_by_caller.items():
            for call in calls:
                if not isinstance(call.target, Symbol) or call.target.qualified_name not in sink_table:
                    continue
                sink_kind = sink_table[call.target.qualified_name]
                attack_id = SINK_ATTACK_IDS[sink_kind]

                # guard precedes sink, same function, by resolved identity + shape,
                # never by name string. Milestone 19: real CFG dominance
                # (python_resolver.dominates) in place of the old
                # order+mutually_exclusive heuristic -- see that function's
                # docstring for the exact false positive this replaces (a
                # guard call sitting inside a bare `if`, with no `else`,
                # used to be wrongly credited with protecting a sink that
                # sits at an outer, unconditional level and so can run
                # without the guard ever executing).
                guard_hit = None
                for earlier in calls:
                    if earlier.order >= call.order:
                        continue
                    if not isinstance(earlier.target, Symbol):
                        continue
                    if not dominates(earlier.branch_path, call.branch_path):
                        continue  # guard is not on EVERY path that reaches this sink
                    if transitively_guard_shaped(earlier.target.qualified_name, graph, callee_index):
                        guard_hit = earlier.target.qualified_name

                reached_packages = sorted(external_packages_reached(caller, graph, callee_index, external_index)) if caller else []

                plan_counter[0] += 1
                plan = build_finding_plan(
                    plan_id=f"fp_sz_{plan_counter[0]:04d}",
                    target_repository=repo_name,
                    attack_id=attack_id,
                    catalog=catalog,
                    hypothesis={
                        "source_node": f"{module.file_path}:{call.lineno}",
                        "sink_node": call.target.qualified_name,
                        "symbol_binding": caller or "<module scope>",
                        "description": f"resolved call to {call.target.qualified_name} ({sink_kind}).",
                        "external_dependencies_reached": reached_packages,
                        # Milestone 15: per-argument taint classification (see
                        # graph.py's CallSite.arg_taint for the full contract
                        # and stated bound). Pure additive evidence -- it
                        # narrows which UNRESOLVED_INCONCLUSIVE findings are
                        # worth a human's time first, it never changes a
                        # disposition status on its own.
                        "argument_taint": list(call.arg_taint),
                    },
                    verification_method={
                        "checker_type": f"isbg_{language}_resolver_v0",
                        "required_evidence_tier": "CONFIRMED_REACHABLE",
                        "sandbox_validation_required": True,
                    },
                    execution_gate={
                        "tool_identifier": "sentinel-zero-dogfood-scan",
                        "expected_exit_code": 0,
                        "timeout_seconds": 15,
                    },
                )
                if guard_hit:
                    set_disposition(
                        plan,
                        "UNRESOLVED_INCONCLUSIVE",
                        reason=f"a resolved call to {guard_hit} genuinely dominates this sink in the same "
                               f"function -- Milestone 19's real CFG dominance check (python_resolver.dominates) "
                               f"confirms {guard_hit} executes on EVERY control-flow path that can reach this "
                               f"sink, not just an approximation of call order, and {guard_hit} raises (directly, "
                               "or through a bounded delegation chain) on an early-exit condition -- Milestone 12 "
                               "tightened this to require an actual `raise`, not a plain `return`, specifically "
                               "because a return-shaped delegate's early exit only ends ITS OWN body and does "
                               "nothing to stop this function's next statement. Still bounded, still stated "
                               "plainly: dominance proves the guard CALL runs before the sink on every path -- it "
                               "does not, and cannot from static structure alone, prove the guard's own internal "
                               "condition corresponds to attacker-controlled input, so this is still never "
                               "promoted to VERIFIED_FALSE." + _taint_note(call.arg_taint),
                        residual_uncertainty="Medium: a raise-shaped guard call is now CONFIRMED to dominate the "
                        "sink (every path to the sink passes through it), but the triggering condition's "
                        "relationship to attacker-controlled input is still not verified.",
                    )
                else:
                    set_disposition(
                        plan,
                        "UNRESOLVED_INCONCLUSIVE",
                        reason="no resolved, guard-shaped call precedes this sink in the same function. "
                               "No sandbox probe has run yet for this finding." + _taint_note(call.arg_taint),
                        residual_uncertainty="Medium: no in-function guard resolved, no dynamic check run.",
                    )

                # Milestone 6, widened in Milestone 16 (FILE_IO/DESERIALIZATION
                # sink kinds) and Milestone 17 (harvested-literal-argument
                # calls, not just zero-argument ones -- see
                # _probe_invocation_for/_literal_argument_values above): a
                # bounded dynamic reachability probe, never attempting
                # adversarial inputs, that patches every known sink kind
                # simultaneously (see probes/_sink_reachability_harness.py
                # for the full scope statement). It can only ever argue FOR
                # VERIFIED_TRUE ("this path is live, confirmed by a real
                # call") -- a sink not reached on this one run proves nothing
                # about other inputs, so "not_reached" and "call_failed"
                # leave the disposition exactly as the static analysis above
                # already set it.
                #
                # builtins.eval/builtins.exec findings are deliberately
                # excluded from probing entirely, not just from promotion:
                # the harness cannot safely patch them (see its own
                # docstring -- CPython's import machinery itself runs on
                # the builtin exec()), so probing a function BECAUSE it
                # contains an eval/exec call would mean actually calling
                # that real eval/exec in the subprocess -- the one thing
                # this probe's own safety claim ("no real process is ever
                # executed by this probe") promises never happens. Static
                # evidence only for these two, same as before this probe
                # existed.
                if (
                    language == "python"
                    and sink_kind in ("PROCESS_EXEC", "FILE_IO", "DESERIALIZATION")
                    and call.target.qualified_name not in ("builtins.eval", "builtins.exec")
                    and caller
                ):
                    invocation = _probe_invocation_for(module.file_path, module.module_qualname, caller, graph)
                    if invocation:
                        fn_name, harvested_args = invocation
                        args_repr = repr(tuple(harvested_args)) if harvested_args is not None else None
                        probe_result = run_sink_reachability_probe(
                            repo_root, module.module_qualname, fn_name, args_repr
                        )
                        if harvested_args is not None:
                            call_desc = (
                                f"with harvested arguments {tuple(harvested_args)!r} -- values lifted "
                                "verbatim from a real call site elsewhere in this project that Milestone 15's "
                                "taint classifier confirmed are literal constants there, never synthesized"
                            )
                        else:
                            call_desc = "with zero arguments"
                        _promote_if_sink_reached(plan, probe_result, call, guard_hit, caller, call_desc)

                # Milestone 18: the JS/TS mirror of the probe above. Same
                # sink-kind gating, same "never attempt eval/exec-equivalent
                # sinks" caution -- but the specific sink that cannot be
                # safely patched before require() differs on Node
                # (fs.readFileSync, not eval/exec/vm -- confirmed directly;
                # see js/_sink_reachability_harness.js's module docstring
                # for the full comparison against Python's landmine).
                # Eligibility (is this caller a plain top-level function, is
                # it actually exported, does it take zero arguments) is
                # decided at runtime by the harness itself against the real,
                # already-required module -- see that file's docstring for
                # why that's more accurate here than static source parsing
                # would be. Milestone 17's literal-argument harvesting is
                # NOT mirrored here yet: dogfooding it on the Python side
                # found it never fires on real code (see Milestone 17's
                # commit message), so it wasn't worth the added complexity
                # for this first JS/TS port.
                if (
                    language == "javascript"
                    and sink_kind in ("PROCESS_EXEC", "FILE_IO", "DESERIALIZATION")
                    and call.target.qualified_name != "fs.readFileSync"
                    and caller
                ):
                    fn_name = _js_top_level_function_name(module.module_qualname, caller)
                    if fn_name:
                        probe_result = run_js_sink_reachability_probe(module.file_path, fn_name)
                        _promote_if_sink_reached(plan, probe_result, call, guard_hit, caller, "with zero arguments")
                plans.append(plan)
    return plans


def _dependency_summary(graph: ProjectGraph) -> dict:
    """Project-wide view of the queued dependency-mapping feature: which
    third-party packages does this codebase actually call into, and how
    many distinct call sites reach each one directly. This is the
    AAC-10-anchored ('Agentic Supply Chain Tampering') question -- 'if
    package X were compromised, how exposed is this codebase' -- answered
    from data the resolver already collects, not a new analysis pass.
    Does not yet cross-reference against aletheia-registry or any
    known-vulnerable-package list; that is the natural next hook, not
    done here."""
    by_package: dict[str, int] = {}
    for ref in graph.external_references:
        by_package[ref.package] = by_package.get(ref.package, 0) + 1
    return dict(sorted(by_package.items(), key=lambda kv: -kv[1]))


def run(
    repo_root: Path,
    catalog_path: str,
    out_dir: Path,
    language: str = "python",
    *,
    is_bundled_snapshot_catalog: bool = False,
) -> int:
    if language not in _RESOLVERS:
        raise ToolFailure(f"unknown language {language!r} -- expected one of {sorted(_RESOLVERS)}")
    catalog = load_catalog(catalog_path, is_bundled_snapshot=is_bundled_snapshot_catalog)
    if catalog.is_bundled_snapshot:
        # Never silent: a run checked against the catalog shipped inside
        # this package, not one the caller fetched fresh, must say so
        # loudly enough to notice before trusting the taxonomy labels.
        meta = catalog.meta
        print(
            "NOTICE: no --catalog given -- using the ASI catalog snapshot bundled with this "
            f"install (version {meta.get('version', 'unknown')}, generated {meta.get('generatedAt', 'unknown')}, "
            f"status={meta.get('status', 'unknown')}). Pass --catalog PATH for a freshly-fetched export.",
            file=sys.stderr,
        )
    try:
        graph = _RESOLVERS[language](repo_root)
    except Exception as exc:  # resolver-level failure halts, never silently returns partial
        raise ToolFailure(f"ISBG resolver failed on {repo_root}: {exc}") from exc

    plan_counter = [0]
    plans = find_finding_plans(graph, repo_root.name, catalog, plan_counter, repo_root, language)

    unresolved_calls = sum(
        1 for c in graph.all_calls() if not isinstance(c.target, Symbol)
    )

    ledger = {
        "target_repository": repo_root.name,
        "modules_scanned": len(graph.modules),
        "functions_indexed": len(graph.functions),
        "unresolved_call_sites": unresolved_calls,
        "plan_count": len(plans),
        "plans": [p.as_dict() for p in plans],
        "wrapper_middleware_detected": [
            {
                "class": w.qualified_name,
                "dispatch_is_guarded": w.dispatch_is_guarded,
            }
            for w in graph.wrapper_classes.values()
        ],
        "wrapper_construction_sites": [
            {
                "wrapper": wc.wrapper_qualified_name,
                "wraps": wc.wrapped_expr,
                "location": f"{wc.file_path}:{wc.lineno}",
            }
            for wc in graph.wrap_constructions
        ],
        "external_dependencies": _dependency_summary(graph),
        "parse_errors": graph.parse_errors,
        "catalog": {
            "path": catalog.source_path,
            "is_bundled_snapshot": catalog.is_bundled_snapshot,
            "metadata": catalog.meta,
        },
    }
    safe_write_text(str(out_dir), "verification_ledger.json", json.dumps(ledger, indent=2), 5_000_000)

    # Milestone 14: the full node/edge graph, not just the flat findings --
    # a pure re-serialization of data already in `graph`/`ledger["plans"]`,
    # so this can never disagree with the ledger for the same finding. See
    # graph_export.py for why this exists (nothing a future 3D view or a
    # Code Atlas adapter needs survives past this function otherwise).
    graph_doc = export_graph(graph, ledger["plans"], repo_root.name)
    safe_write_text(str(out_dir), "graph.json", json.dumps(graph_doc, indent=2), 20_000_000)

    print(
        f"{repo_root.name}: {len(graph.modules)} modules, {len(graph.functions)} functions indexed, "
        f"{unresolved_calls} unresolved call sites, {len(plans)} finding plans -> "
        f"{out_dir / 'verification_ledger.json'} (graph: {out_dir / 'graph.json'})"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4):
        print("usage: dogfood_scan.py REPO_ROOT ASI_CATALOG_JSON OUT_DIR [python|javascript]")
        return 2
    language = argv[3] if len(argv) == 4 else "python"
    try:
        return run(Path(argv[0]), argv[1], Path(argv[2]), language)
    except ToolFailure as exc:
        print(f"CRITICAL_TOOL_FAILURE: {exc}")
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

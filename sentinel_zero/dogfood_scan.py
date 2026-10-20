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
    sink it can never run alongside).

Still bounded, still stated plainly:
  - "guard precedes sink" is still same-function call order at the
    ORIGINAL call site -- delegation crosses functions/files for the
    *guard's own identity*, but the call that invokes it still has to be
    in the sink's function, in a non-exclusive branch, before the sink.
    A guard called three functions up the stack, never passed down, is
    not yet traced -- that is real interprocedural dataflow, not delegation
    propagation, and is not claimed here.

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
finding.
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
from sentinel_zero.ledger_writer import safe_write_text
from sentinel_zero.probes.process_exec_probe import run_process_exec_probe
from sentinel_zero.resolvers.python_resolver import build_project_graph as build_python_project_graph
from sentinel_zero.resolvers.python_resolver import mutually_exclusive
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
    "os.system": "PROCESS_EXEC",
    "subprocess.run": "PROCESS_EXEC",
    "subprocess.call": "PROCESS_EXEC",
    "subprocess.check_call": "PROCESS_EXEC",
    "subprocess.check_output": "PROCESS_EXEC",
    "subprocess.Popen": "PROCESS_EXEC",
}

# Milestone 7: the JS/TS equivalent of _SINK_KIND_BY_NAME, keyed by the same
# kind of resolved dotted identity js_resolver.py produces via require()/
# import bindings. Node's child_process family + eval/Function cover
# PROCESS_EXEC; fs's sync+callback read/write cover FILE_IO; JSON.parse
# covers DESERIALIZATION. Not claimed exhaustive -- the Python table isn't
# either (no yaml.load, pickle, etc.) -- this is Milestone 7's starting set.
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
            args = node.args
            required_positional = len(args.posonlyargs) + len(args.args) - len(args.defaults)
            required_kwonly = sum(1 for default in args.kw_defaults if default is None)
            if required_positional > 0 or required_kwonly > 0:
                return None
            return name
    return None


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
                # never by name string.
                guard_hit = None
                for earlier in calls:
                    if earlier.order >= call.order:
                        continue
                    if not isinstance(earlier.target, Symbol):
                        continue
                    if mutually_exclusive(earlier.branch_path, call.branch_path):
                        continue  # e.g. an elif sibling -- cannot have actually run
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
                        reason=f"a resolved call to {guard_hit} precedes this sink in the same function, in a "
                               f"non-exclusive branch, and {guard_hit} raises (directly, or through a bounded "
                               "delegation chain) on an early-exit condition -- Milestone 12 tightened this check "
                               "to require an actual `raise`, not a plain `return`, specifically because a "
                               "return-shaped delegate's early exit only ends ITS OWN body and does nothing to "
                               "stop this function's next statement. Same-function call order is still only an "
                               "approximation of control dependency, not full CFG dominance, and this resolver "
                               "still does not know whether the condition that triggers the raise corresponds to "
                               "attacker-controlled input -- never promoted to VERIFIED_FALSE.",
                        residual_uncertainty="Medium: a raise-shaped guard call precedes the sink, but neither "
                        "full CFG dominance nor the triggering condition's relationship to attacker input is "
                        "verified.",
                    )
                else:
                    set_disposition(
                        plan,
                        "UNRESOLVED_INCONCLUSIVE",
                        reason="no resolved, guard-shaped call precedes this sink in the same function. "
                               "No sandbox probe has run yet for this finding.",
                        residual_uncertainty="Medium: no in-function guard resolved, no dynamic check run.",
                    )

                # Milestone 6: a bounded dynamic reachability probe, PROCESS_EXEC
                # only, zero-argument top-level functions only, never attempting
                # adversarial inputs. It can only ever argue FOR VERIFIED_TRUE
                # ("this path is live, confirmed by a real call") -- a sink not
                # reached on this one run proves nothing about other inputs, so
                # "not_reached" and "call_failed" leave the disposition exactly
                # as the static analysis above already set it. See
                # probes/_process_exec_harness.py for the full scope statement.
                if language == "python" and sink_kind == "PROCESS_EXEC" and caller:
                    fn_name = _zero_arg_top_level_function(module.file_path, module.module_qualname, caller)
                    if fn_name:
                        probe_result = run_process_exec_probe(repo_root, module.module_qualname, fn_name)
                        if probe_result.get("status") == "sink_reached":
                            guard_note = (
                                f" A guard-shaped call ({guard_hit}) was detected statically on this path, "
                                "but the dynamic probe still reached the sink -- this does not mean the guard "
                                "is bypassable by attacker-controlled input, only that it did not block this "
                                "specific zero-argument call."
                                if guard_hit else ""
                            )
                            set_disposition(
                                plan,
                                "VERIFIED_TRUE",
                                reason=(
                                    f"a bounded dynamic probe called {caller}() with zero arguments in an "
                                    f"isolated subprocess and observed {probe_result.get('symbol')} invoked "
                                    f"(args={probe_result.get('args')}) before the real sink could execute "
                                    "(monkeypatched, never actually run). This confirms the call path is live "
                                    "and reachable under at least one real invocation." + guard_note
                                ),
                                residual_uncertainty="Low: dynamic reachability confirmed under one benign "
                                "call; no adversarial inputs were attempted (explicitly out of scope for this probe).",
                            )
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
    print(
        f"{repo_root.name}: {len(graph.modules)} modules, {len(graph.functions)} functions indexed, "
        f"{unresolved_calls} unresolved call sites, {len(plans)} finding plans -> "
        f"{out_dir / 'verification_ledger.json'}"
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

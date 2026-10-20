"""Milestone 2 dogfood run: the ISBG resolver replaces the raw AST-token
scan from Milestone 1.

What actually changed vs. Milestone 1, and why it matters:
  - a call site's callee is now a resolved Symbol (qualified identity) or an
    explicit Unresolved, never a bare name string. Sink matching happens
    against that resolved identity (sentinel_zero.graph.STDLIB_SINKS, keyed
    by dotted path), not a literal token like "open" or "json.load" --
    so `from os import system as run_shell; run_shell(cmd)` is now caught,
    which plain token matching would miss.
  - guard detection is by resolved call identity + a structural shape check
    on the guard's own body (an early `if ...: raise ...`), never by
    matching the guard's *name*. This is what keeps the class of bug where
    a `check*` wildcard matched an unrelated `.checkbox()` call from being
    reproducible here: there is no name-wildcard step anywhere in this path.
  - the guard can now live in a different file than the sink call, because
    the project-wide function index (built in pass 1 of the resolver) is
    looked up by qualified name, not by "is this guard mentioned in the
    same file's text."

Still bounded, still stated plainly:
  - "guard precedes sink" is same-function call order, not CFG dominance.
  - only Python is resolved. A second run against vibe-explainer (a
    completely unrelated repo, not Block-Wise) is included below runners
    so sink/guard detection is checked against more than one codebase --
    see run_dogfood.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from sentinel_zero.disposition import (
    ToolFailure,
    build_finding_plan,
    load_catalog,
    set_disposition,
)
from sentinel_zero.graph import ProjectGraph, Symbol
from sentinel_zero.ledger_writer import safe_write_text
from sentinel_zero.resolvers.python_resolver import build_project_graph, mutually_exclusive

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


def find_finding_plans(graph: ProjectGraph, repo_name: str, catalog, plan_counter: list[int]) -> list:
    plans = []
    for module in graph.modules.values():
        calls_by_caller: dict[str, list] = {}
        for call in module.calls:
            calls_by_caller.setdefault(call.caller, []).append(call)

        for caller, calls in calls_by_caller.items():
            for call in calls:
                if not isinstance(call.target, Symbol) or call.target.qualified_name not in _SINK_KIND_BY_NAME:
                    continue
                sink_kind = _SINK_KIND_BY_NAME[call.target.qualified_name]
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
                    fn_info = graph.functions.get(earlier.target.qualified_name)
                    if fn_info and fn_info.is_guard_shaped:
                        guard_hit = earlier.target.qualified_name

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
                    },
                    verification_method={
                        "checker_type": "isbg_python_resolver_v0",
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
                        reason=f"a resolved, structurally guard-shaped call to {guard_hit} precedes this "
                               "sink in the same function. Same-function call order is an approximation of "
                               "control dependency, not full CFG dominance -- never promoted to VERIFIED_FALSE.",
                        residual_uncertainty="Low-medium: guard resolved by identity and shape, coverage not proven.",
                    )
                else:
                    set_disposition(
                        plan,
                        "UNRESOLVED_INCONCLUSIVE",
                        reason="no resolved, guard-shaped call precedes this sink in the same function. "
                               "No sandbox probe has run in v0.",
                        residual_uncertainty="Medium: no in-function guard resolved, no dynamic check run.",
                    )
                plans.append(plan)
    return plans


def run(repo_root: Path, catalog_path: str, out_dir: Path) -> int:
    catalog = load_catalog(catalog_path)
    try:
        graph = build_project_graph(repo_root)
    except Exception as exc:  # resolver-level failure halts, never silently returns partial
        raise ToolFailure(f"ISBG resolver failed on {repo_root}: {exc}") from exc

    plan_counter = [0]
    plans = find_finding_plans(graph, repo_root.name, catalog, plan_counter)

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
    }
    safe_write_text(str(out_dir), "verification_ledger.json", json.dumps(ledger, indent=2), 5_000_000)
    print(
        f"{repo_root.name}: {len(graph.modules)} modules, {len(graph.functions)} functions indexed, "
        f"{unresolved_calls} unresolved call sites, {len(plans)} finding plans -> "
        f"{out_dir / 'verification_ledger.json'}"
    )
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: dogfood_scan.py REPO_ROOT ASI_CATALOG_JSON OUT_DIR")
        return 2
    try:
        return run(Path(argv[0]), argv[1], Path(argv[2]))
    except ToolFailure as exc:
        print(f"CRITICAL_TOOL_FAILURE: {exc}")
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

"""Milestone 1 dogfood run: point Sentinel-Zero at Block-Wise's own repo.

v0 scope is deliberately small -- this is NOT the interprocedural symbol/
binding graph the locked spec calls for later. It is a literal AST walk that
finds two boundary shapes (file I/O, JSON deserialization of file contents)
and proves the three success criteria for real:

  1. a file that fails to parse halts the run with TOOL_FAILURE, it is never
     silently skipped;
  2. every hypothesis resolves against the live ASI catalog -- an unknown
     attack id is a hard crash, not a guess;
  3. nothing is marked VERIFIED/clean by this pass -- v0 has no dynamic
     sandbox step yet, so every real hit is explicitly UNRESOLVED_INCONCLUSIVE,
     which is the honest answer, not a false reassurance.
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
from sentinel_zero.ledger_writer import safe_write_text

FILE_IO_ATTACK_ID = "AAC-17"  # Filesystem Escape / Path Traversal
DESERIALIZATION_ATTACK_ID = "AAC-27"  # Serialization Injection

# Names that, if present anywhere in the same function, we treat as a
# declared (not verified) guard -- v0 cannot trace whether the guard
# actually covers the call, so a guard only softens residual_uncertainty,
# it never flips disposition to VERIFIED_*.
KNOWN_GUARD_NAMES = {"resolve_inside", "safe_write_text", "safe_read_text"}


def _function_source_calls(tree: ast.Module) -> dict[str, set[str]]:
    """Map each top-level function name to the set of names it calls, by
    walking its body. Good enough for a v0 same-function guard hint."""
    calls_by_fn: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            calls: set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    calls.add(sub.func.id)
                elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    calls.add(sub.func.attr)
            calls_by_fn[node.name] = calls
    return calls_by_fn


def _enclosing_function(tree: ast.Module, target: ast.AST) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(child is target for child in ast.walk(node)):
                return node.name
    return None


def scan_file(py_path: Path, repo_root: Path, catalog, plan_counter: list[int]) -> list:
    try:
        source = py_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_path))
    except (SyntaxError, UnicodeDecodeError) as exc:
        # This is exactly failure mode #2 from the prior pipeline, closed:
        # a file this engine cannot parse halts the run instead of being
        # silently dropped from the finding count.
        raise ToolFailure(f"could not parse {py_path} as Python: {exc}") from exc

    calls_by_fn = _function_source_calls(tree)
    rel_path = py_path.relative_to(repo_root)
    plans = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        attack_id = None
        description = None
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            attack_id = FILE_IO_ATTACK_ID
            description = "File opened; path origin not traced in v0."
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("load", "loads") \
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "json":
            attack_id = DESERIALIZATION_ATTACK_ID
            description = "JSON deserialized; source trust not traced in v0."

        if attack_id is None:
            continue

        fn_name = _enclosing_function(tree, node)
        guards_present = calls_by_fn.get(fn_name, set()) & KNOWN_GUARD_NAMES if fn_name else set()

        plan_counter[0] += 1
        plan = build_finding_plan(
            plan_id=f"fp_sz_{plan_counter[0]:04d}",
            target_repository=str(repo_root.name),
            attack_id=attack_id,
            catalog=catalog,
            hypothesis={
                "source_node": f"{rel_path}:{node.lineno}",
                "sink_node": f"{rel_path}:{node.lineno}",
                "symbol_binding": fn_name or "<module scope>",
                "description": description,
            },
            verification_method={
                "checker_type": "ast_literal_scan_v0",
                "required_evidence_tier": "CONFIRMED_REACHABLE",
                "sandbox_validation_required": True,
            },
            execution_gate={
                "tool_identifier": "sentinel-zero-dogfood-scan",
                "expected_exit_code": 0,
                "timeout_seconds": 15,
            },
        )
        if guards_present:
            set_disposition(
                plan,
                "UNRESOLVED_INCONCLUSIVE",
                reason=f"a declared guard ({', '.join(sorted(guards_present))}) is present in "
                       "the same function, but v0 has no dataflow trace to confirm it covers "
                       "this call -- never promoted to VERIFIED_FALSE on a guard's presence alone.",
                residual_uncertainty="Low-medium: guard declared, coverage unverified.",
            )
        else:
            set_disposition(
                plan,
                "UNRESOLVED_INCONCLUSIVE",
                reason="no sandbox probe has run yet in v0; same-function AST scan cannot "
                       "confirm reachability or taint. Never defaulted to clean.",
                residual_uncertainty="Medium: no guard found in the same function, no dynamic check run.",
            )
        plans.append(plan)
    return plans


def run(repo_root: Path, catalog_path: str, out_dir: Path) -> int:
    catalog = load_catalog(catalog_path)
    plan_counter = [0]
    all_plans = []
    for py_path in sorted(repo_root.rglob("*.py")):
        if "/.venv/" in str(py_path) or "/tests/mutants/" in str(py_path):
            continue
        all_plans.extend(scan_file(py_path, repo_root, catalog, plan_counter))

    ledger = {
        "target_repository": repo_root.name,
        "catalog_version": catalog.classes_by_id.get("AAC-11", {}).get("family", "unknown"),
        "plan_count": len(all_plans),
        "plans": [p.as_dict() for p in all_plans],
    }
    safe_write_text(str(out_dir), "verification_ledger.json", json.dumps(ledger, indent=2), 5_000_000)
    print(f"wrote {len(all_plans)} finding plans to {out_dir / 'verification_ledger.json'}")
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

"""The `sentinel-zero` command -- the install-and-run-without-reading-the-
source entry point this package is built around. Everything here is a
thin wrapper over dogfood_scan.run(); it adds nothing to the analysis
itself, only to making that analysis reachable by a stranger on a fresh
machine with one command.

Three invariants this CLI must never weaken (see tests/test_invariants.py):

  1. No silent tool failure. Every path that can fail -- a bad repo path,
     a missing/invalid catalog, a resolver crash, Node.js missing for a
     JS/TS target -- surfaces as a nonzero exit and a printed message.
     Nothing is caught and turned into an empty/clean-looking ledger.
  2. Live ASI catalog only. There is no hardcoded attack-class name/label
     table anywhere in this file or in dogfood_scan.py -- only ever an
     attack_id key into whatever Catalog disposition.load_catalog()
     returns. The bundled snapshot catalog (used only when the caller
     passes no --catalog) goes through that exact same load_catalog()
     path, so an unknown ID is still a hard UnknownAttackClass, and the
     ledger always records which catalog (and version) a run actually
     checked against -- see run()'s "catalog" block.
  3. Finding Plan required. Every reported hypothesis is a FindingPlan
     built by disposition.build_finding_plan(), never a bare dict this
     file assembles itself -- that object is what forces the attack_id
     resolution and the required-field check to happen before anything
     can be reported as a finding.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.disposition import ToolFailure, UnknownAttackClass
from sentinel_zero.dogfood_scan import run as run_scan
from sentinel_zero.dogfood_scan import write_or_fail_cleanly
from sentinel_zero.repo_detect import detect_language, js_deps_installed


def _install_js_deps() -> int:
    js_dir = Path(__file__).parent / "resolvers" / "js"
    # shutil.which (not a bare "npm" argv[0]) is required here: on Windows,
    # npm is actually npm.cmd, a shim script, not an .exe. subprocess.run
    # without shell=True resolves argv[0] via CreateProcess directly and
    # does not apply PATHEXT the way cmd.exe does, so ["npm", "install"]
    # raises FileNotFoundError even when npm is genuinely installed and on
    # PATH. shutil.which performs the correct PATHEXT-aware lookup on
    # Windows (and is a harmless, equivalent which-based lookup on
    # Linux/macOS), so this is the fix for all three platforms, not a
    # Windows-only special case.
    npm_path = shutil.which("npm")
    if npm_path is None:
        print("CRITICAL_TOOL_FAILURE: `npm` executable not found -- install Node.js/npm first.", file=sys.stderr)
        return 3
    print(f"running `npm install` in {js_dir} ...")
    try:
        completed = subprocess.run([npm_path, "install"], cwd=str(js_dir))
    except FileNotFoundError:
        print("CRITICAL_TOOL_FAILURE: `npm` executable not found -- install Node.js/npm first.", file=sys.stderr)
        return 3
    if completed.returncode != 0:
        print(f"CRITICAL_TOOL_FAILURE: npm install exited {completed.returncode}", file=sys.stderr)
        return 3
    print("JS/TS resolver dependencies installed.")
    return 0


def _render_markdown(ledger: dict) -> str:
    """Renders the same ledger dict dogfood_scan.run() writes as JSON into
    a human-skimmable Markdown report. Purely a presentation transform --
    no field here is computed independently of the ledger, so there is no
    way for the Markdown view to say something the JSON ledger doesn't."""
    lines = []
    lines.append(f"# Sentinel-Zero report: {ledger['target_repository']}")
    lines.append("")
    cat = ledger.get("catalog", {})
    lines.append(f"Probe mode: **{ledger.get('probe_mode', 'legacy/unspecified')}**. "
                 "Current probe reports are untrusted diagnostics, not independent verification.")
    lines.append("")
    snapshot_note = " (bundled snapshot -- pass --catalog for a fresh export)" if cat.get("is_bundled_snapshot") else ""
    meta = cat.get("metadata", {}) or {}
    lines.append(
        f"Checked against ASI catalog version **{meta.get('version', 'unknown')}** "
        f"(generated {meta.get('generatedAt', 'unknown')}, status={meta.get('status', 'unknown')}){snapshot_note}."
    )
    lines.append("")
    lines.append(
        f"- Modules scanned: **{ledger['modules_scanned']}**\n"
        f"- Functions indexed: **{ledger['functions_indexed']}**\n"
        f"- Unresolved call sites: **{ledger['unresolved_call_sites']}**\n"
        f"- Finding plans: **{ledger['plan_count']}**\n"
        f"- Parse errors: **{len(ledger['parse_errors'])}**"
    )
    lines.append("")

    if ledger.get("coverage"):
        coverage = ledger["coverage"]
        lines.extend([
            "## Coverage", "",
            f"Collected: {coverage.get('collected_files', 'unknown')}; "
            f"parsed: {coverage.get('parsed_files', 'unknown')}.", "",
        ])
        for warning in coverage.get("warnings", []):
            lines.append(f"- **{warning.get('kind')}**: {warning.get('detail', '')}")
        lines.append("")

    by_status: dict[str, list[dict]] = {}
    for plan in ledger["plans"]:
        by_status.setdefault(plan["disposition"]["status"], []).append(plan)

    status_order = ["VERIFIED_TRUE", "VERIFIED_FALSE", "UNRESOLVED_INCONCLUSIVE", "TOOL_FAILURE"]
    for status in status_order:
        plans = by_status.get(status, [])
        if not plans:
            continue
        lines.append(f"## {status} ({len(plans)})")
        lines.append("")
        for plan in plans:
            hyp = plan["hypothesis"]
            lines.append(
                f"- `{plan['plan_id']}` — **{plan['asi_classification']['category']}** "
                f"({plan['asi_classification']['attack_id']}) at `{hyp['source_node']}`\n"
                f"  - sink: `{hyp['sink_node']}` via `{hyp['symbol_binding']}`\n"
                f"  - {plan['disposition']['reason']}\n"
                f"  - residual uncertainty: {plan['disposition']['residual_uncertainty']}"
            )
        lines.append("")

    if ledger["wrapper_middleware_detected"]:
        lines.append(f"## Wrapper middleware detected ({len(ledger['wrapper_middleware_detected'])})")
        lines.append("")
        for w in ledger["wrapper_middleware_detected"]:
            lines.append(f"- `{w['class']}` (dispatch guarded: {w['dispatch_is_guarded']})")
        lines.append("")

    if ledger["external_dependencies"]:
        lines.append("## External dependencies reached (by call-site count)")
        lines.append("")
        for pkg, count in list(ledger["external_dependencies"].items())[:25]:
            lines.append(f"- `{pkg}`: {count}")
        lines.append("")

    if ledger["parse_errors"]:
        lines.append(f"## Parse errors ({len(ledger['parse_errors'])})")
        lines.append("")
        for err in ledger["parse_errors"]:
            lines.append(f"- `{err['file_path']}`: {err.get('error', err)}")
        lines.append("")

    return "\n".join(lines)


def cmd_analyze(args: argparse.Namespace) -> int:
    repo_root = Path(args.path).resolve()
    if not repo_root.is_dir():
        print(f"CRITICAL_TOOL_FAILURE: {repo_root} is not a directory", file=sys.stderr)
        return 3

    is_bundled = args.catalog is None
    catalog_path = args.catalog or str(bundled_snapshot_path())
    out_dir = Path(args.out).resolve() if args.out else repo_root.parent / f"{repo_root.name}.sentinel-zero"

    try:
        language = args.language or detect_language(repo_root)
        if language == "javascript" and not js_deps_installed():
            raise ToolFailure(
                "the JS/TS resolver's dependencies are not installed. "
                "Run `sentinel-zero install-js-deps` once, then re-run this scan."
            )
        run_scan(repo_root, catalog_path, out_dir, language,
                 is_bundled_snapshot_catalog=is_bundled, probe_mode=getattr(args, "probe_mode", "static"))

        ledger = json.loads((out_dir / "verification_ledger.json").read_text(encoding="utf-8"))

        if args.format == "md":
            # VERIFICATION_LEDGER.md sz-2026-10-22-01/-03 / REMEDIATION_PLAN.md
            # item 7: this write has the exact same "refuses before writing,
            # raises a bare ValueError over the byte cap" shape
            # dogfood_scan.run()'s own writes have, and used to sit entirely
            # outside this try/except -- a report.md over 5MB crashed with an
            # uncaught traceback instead of this same CRITICAL_TOOL_FAILURE
            # message. Moved inside so the existing
            # (ToolFailure, UnknownAttackClass) handler also catches it, and
            # reuses dogfood_scan.write_or_fail_cleanly() rather than a second,
            # separately-maintained copy of the same ValueError-handling
            # logic (an earlier version of this duplicated it, which is
            # exactly how Codex's PR #9 P2 finding -- the duplicate wrongly
            # claiming "too large" for any ValueError, not just an oversize
            # one -- would have had to be fixed twice).
            write_or_fail_cleanly(
                str(out_dir), "report.md", _render_markdown(ledger), 5_000_000,
                what="the markdown report",
            )
            print(f"markdown report -> {out_dir / 'report.md'}")
        else:
            print(f"ledger -> {out_dir / 'verification_ledger.json'} (graph: {out_dir / 'graph.json'})")
    except (ToolFailure, UnknownAttackClass) as exc:
        print(f"CRITICAL_TOOL_FAILURE: {exc}", file=sys.stderr)
        return 3

    return 0


def cmd_install_js_deps(_args: argparse.Namespace) -> int:
    return _install_js_deps()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel-zero",
        description="Source-code security triage for Python, JavaScript, and TypeScript.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="scan a target repository and produce a verification ledger")
    analyze.add_argument("path", help="path to the target repository (not this one)")
    analyze.add_argument(
        "--probe-mode", choices=["static", "diagnostic"], default="static",
        help="static (default): never execute target code. diagnostic: execute target code in Docker "
             "and record untrusted reports; no existing probe can authorize VERIFIED_TRUE.",
    )
    analyze.add_argument(
        "--format", choices=["json", "md"], default="json",
        help="json (default): just the ledger. md: also render a human-readable report.md alongside it.",
    )
    analyze.add_argument(
        "--language", choices=["python", "javascript"], default=None,
        help="defaults to auto-detect by counting source files under PATH.",
    )
    analyze.add_argument(
        "--catalog", default=None,
        help="path to a live asi-catalog.json export. If omitted, falls back to the snapshot bundled with "
             "this install (clearly marked as such in the ledger/report) -- never a hardcoded taxonomy.",
    )
    analyze.add_argument(
        "--out", default=None,
        help="output directory for the ledger. Defaults to <PATH>.sentinel-zero next to the target repo.",
    )
    analyze.set_defaults(func=cmd_analyze)

    install_js = sub.add_parser(
        "install-js-deps", help="run `npm install` for the JS/TS resolver's own subprocess dependencies"
    )
    install_js.set_defaults(func=cmd_install_js_deps)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

"""Score Sentinel-Zero's triage against labeled fixtures.

    python calibration/calibrate.py                    # score, compare with baseline
    python calibration/calibrate.py --update-baseline  # accept the current result
    python calibration/calibrate.py --update-manifest  # accept edited fixtures

Exit codes: 0 no regression, 1 a case or headline metric regressed against the
baseline, 2 the fixtures no longer match their pinned digests (re-pin with
--update-manifest after reviewing the change).

The score is about ranking, not detection: Sentinel-Zero always emits a plan
and never claims a verdict, so a near-miss is correct when its plan is NOT
priority, and a reachable sink is correct when its plan IS priority.
Headline (Youden): priority rate on reachable cases minus priority rate on
detected near-miss cases. 1.0 is perfect ranking, 0 is no better than chance.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from cases import CASES, UNCHECKED, Case  # noqa: E402

from sentinel_zero import cli  # noqa: E402

MANIFEST = HERE / "manifest.json"
BASELINE = HERE / "baseline.json"
EPSILON = 1e-9


def case_digest(case: Case) -> str:
    body = json.dumps({"files": case.files}, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def materialize(case: Case, root: Path) -> Path:
    target = root / case.id
    for rel, text in case.files.items():
        path = target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return target


def scan(repo: Path, out: Path) -> tuple[dict, dict]:
    # The CLI prints progress; keep the scorer's output readable.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
        code = cli.main(["analyze", str(repo), "--language", "python", "--format", "json", "--out", str(out)])
    if code != 0:
        raise RuntimeError(f"scan of {repo.name} exited {code}: {err.getvalue()[-800:]}")
    ledger = json.loads((out / "verification_ledger.json").read_text(encoding="utf-8"))
    graph_path = out / "graph.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8")) if graph_path.is_file() else {"edges": []}
    return ledger, graph


def gap_outcome(case: Case, graph: dict) -> str:
    """How the scanner saw a sink it does not report, read from the call graph.

    resolved-not-sink: the call resolved to the expected name, but that name is
                       not in the sink registry (cheapest gap: a table entry).
    unresolved:        a call on a line mentioning the sink could not be
                       resolved -- honest uncertainty.
    silent:            neither; the call left no trace.
    """
    calls = [e for e in graph.get("edges", []) if e.get("kind") == "calls"]
    if any(e.get("resolved") and e.get("target") == case.sink for e in calls):
        return "resolved-not-sink"
    attribute = case.sink.rsplit(".", 1)[-1]
    lines = {rel: text.splitlines() for rel, text in case.files.items()}
    for edge in calls:
        if edge.get("resolved") or not edge.get("lineno"):
            continue
        for text in lines.values():
            if 0 < edge["lineno"] <= len(text) and attribute in text[edge["lineno"] - 1]:
                return "unresolved"
    return "silent"


def evaluate(case: Case, ledger: dict, graph: dict) -> dict:
    plans = [p for p in ledger["plans"] if p["hypothesis"]["sink_node"] == case.sink]
    tags = [p.get("triage", {}) for p in plans]
    priority = any(t.get("priority") for t in tags)
    row: dict = {
        "id": case.id, "family": case.family, "dimension": case.dimension, "sink": case.sink,
        "plans": len(plans), "priority": priority, "unresolved": ledger["unresolved_call_sites"],
        "guarded_by": sorted({t.get("guarded_by") or "" for t in tags} - {""}),
        "constant": [t.get("constant_arguments") for t in tags],
    }
    if case.family == "reachable":
        row["outcome"] = "correct" if priority else ("missed" if not plans else "under-ranked")
    elif case.family == "near_miss":
        row["outcome"] = "missed" if not plans else ("over-ranked" if priority else "correct")
    else:
        row["outcome"] = "detected" if priority else gap_outcome(case, graph)

    checks: dict[str, bool] = {}
    if case.expect_guard != UNCHECKED and plans:
        found = row["guarded_by"]
        checks["guard"] = (found == []) if case.expect_guard is None else (found == [case.expect_guard])
    if case.expect_constant is not None and plans:
        checks["constant"] = all(c is case.expect_constant for c in row["constant"])
    row["checks"] = checks
    row["correct"] = row["outcome"] in ("correct", "detected") and all(checks.values())
    return row


def summarize(rows: list[dict]) -> dict:
    def rate(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    reach = [r for r in rows if r["family"] == "reachable"]
    near = [r for r in rows if r["family"] == "near_miss"]
    near_detected = [r for r in near if r["plans"]]
    gaps = [r for r in rows if r["family"] == "coverage_gap"]
    tpr = rate(sum(r["priority"] for r in reach), len(reach))
    fpr = rate(sum(r["priority"] for r in near_detected), len(near_detected))
    flagged = sum(r["priority"] for r in reach) + sum(r["priority"] for r in near_detected)
    guard_checks = [r["checks"]["guard"] for r in rows if "guard" in r["checks"]]
    const_checks = [r["checks"]["constant"] for r in rows if "constant" in r["checks"]]
    by_dimension: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for r in rows:
        by_dimension[r["dimension"]][0] += r["correct"]
        by_dimension[r["dimension"]][1] += 1
    return {
        "cases": len(rows),
        "correct": sum(r["correct"] for r in rows),
        "reachable_priority_rate": tpr,
        "near_miss_priority_rate": fpr,
        "near_miss_downgrade_rate": None if fpr is None else round(1 - fpr, 4),
        "youden": None if tpr is None or fpr is None else round(tpr - fpr, 4),
        "priority_precision": rate(sum(r["priority"] for r in reach), flagged),
        "near_miss_not_detected": [r["id"] for r in near if not r["plans"]],
        "guard_evidence_accuracy": rate(sum(guard_checks), len(guard_checks)),
        "constant_accuracy": rate(sum(const_checks), len(const_checks)),
        "coverage_gaps": {k: [r["id"] for r in gaps if r["outcome"] == k]
                          for k in ("detected", "resolved-not-sink", "unresolved", "silent")},
        "by_dimension": {k: f"{v[0]}/{v[1]}" for k, v in sorted(by_dimension.items())},
    }


def report(rows: list[dict], summary: dict) -> str:
    lines = ["| case | family | dimension | outcome | checks |", "|---|---|---|---|---|"]
    for r in rows:
        mark = "" if r["correct"] else " **x**"
        checks = ", ".join(f"{k}:{'ok' if v else 'FAIL'}" for k, v in r["checks"].items()) or "-"
        lines.append(f"| {r['id']}{mark} | {r['family']} | {r['dimension']} | {r['outcome']} | {checks} |")
    lines += ["", "```json", json.dumps(summary, indent=2), "```"]
    return "\n".join(lines)


def regressions(summary: dict, rows: list[dict], baseline: dict) -> list[str]:
    problems = []
    was_correct = {r["id"] for r in baseline.get("rows", []) if r["correct"]}
    for r in rows:
        if r["id"] in was_correct and not r["correct"]:
            problems.append(f"{r['id']} was correct in the baseline and now is {r['outcome']} {r['checks']}")
    for metric in ("youden", "near_miss_downgrade_rate", "reachable_priority_rate"):
        old, new = baseline.get("summary", {}).get(metric), summary.get(metric)
        if old is not None and new is not None and new < old - EPSILON:
            problems.append(f"{metric} fell from {old} to {new}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update-baseline", action="store_true")
    parser.add_argument("--update-manifest", action="store_true")
    parser.add_argument("--report", type=Path, help="also write the markdown report here")
    args = parser.parse_args(argv)

    ids = [c.id for c in CASES]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate case ids")
    unknown_pairs = [c.id for c in CASES if c.pair and c.pair not in ids]
    if unknown_pairs:
        raise SystemExit(f"cases name unknown pairs: {unknown_pairs}")

    digests = {c.id: case_digest(c) for c in CASES}
    if args.update_manifest:
        MANIFEST.write_text(json.dumps(digests, indent=2, sort_keys=True) + "\n")
        print(f"pinned {len(digests)} fixtures in {MANIFEST.name}")
    pinned = json.loads(MANIFEST.read_text()) if MANIFEST.is_file() else {}
    if pinned != digests:
        changed = sorted(k for k in set(pinned) | set(digests) if pinned.get(k) != digests.get(k))
        print(f"fixtures differ from {MANIFEST.name}: {changed}. Review, then --update-manifest.", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory(prefix="sz_calibration_") as tmp:
        root = Path(tmp)
        rows = [evaluate(c, *scan(materialize(c, root / "fixtures"), root / "out" / c.id)) for c in CASES]
    summary = summarize(rows)
    text = report(rows, summary)
    print(text)
    if args.report:
        args.report.write_text(text + "\n")

    if args.update_baseline:
        BASELINE.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2) + "\n")
        print(f"\nbaseline updated ({summary['correct']}/{summary['cases']} correct)")
        return 0
    if not BASELINE.is_file():
        print("\nno baseline yet; run with --update-baseline to record one")
        return 0
    problems = regressions(summary, rows, json.loads(BASELINE.read_text()))
    if problems:
        print("\nREGRESSIONS:\n- " + "\n- ".join(problems))
        return 1
    print(f"\nno regressions against the baseline ({summary['correct']}/{summary['cases']} correct)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

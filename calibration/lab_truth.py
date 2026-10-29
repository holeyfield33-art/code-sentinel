"""Score Sentinel-Zero against an independently built vulnerable-lab answer key
(schema sentinel-lab-groundtruth-v1).

    python calibration/lab_truth.py MANIFEST.json [--cache DIR] [--out FILE]

The answer key is built by a separate agent that never runs the scanner. This
script only applies the key's own handoff rules:

  * score entries that are located, expected vulnerable, a documented
    vulnerability, in an eligible server language, and in Sentinel's scope;
  * count a shared sink site once (several challenges may hit one line);
  * keep weak entries (low-signal JSON parsers, constant commands) apart
    from direct cases;
  * never score unlocated entries as misses.

Every quoted sink line is re-checked against the pinned source before scoring.
A site is matched to a plan by file, exact line and sink identity.
Outcomes per site: detected (a priority plan), under-ranked (plans, none
priority), missed (no plan on that line). Like cve_pairs.py, it clones public
repositories, so it is not part of pytest.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from cve_pairs import checkout, scan, scan_identity, validate_scored_files  # noqa: E402
from sentinel_zero.source_inputs import read_source_text  # noqa: E402

SCHEMA = "sentinel-lab-groundtruth-v1"
# The key spells sinks as written in source; Sentinel resolves Python builtins as builtins.X.
PY_BUILTINS = {"eval", "exec", "open"}
LOW_SIGNAL = {"json.load", "json.loads", "JSON.parse"}


def resolver_language(language: str) -> str:
    return "python" if language == "python" else "javascript"


def sentinel_sink(identity: str, language: str) -> str:
    return f"builtins.{identity}" if language == "python" and identity in PY_BUILTINS else identity


def scoreable(v: dict) -> bool:
    return (v.get("located") is True and v.get("expected") == "vulnerable"
            and v.get("documented_vulnerability") is not False
            and v.get("eligible_server_language") is not False and v.get("sentinel_scope") == "in_scope")


def weak_reason(v: dict) -> str | None:
    if v["sink_identity"] in LOW_SIGNAL:
        return "low-signal parser"
    if "constant" in (v.get("notes") or "").lower() and "command" in (v.get("notes") or "").lower():
        return "constant command"
    return None


def restrict_to_subdirectory(ledger: dict, root: str, sub: str) -> dict:
    """Keep only plans under `sub` (repository-relative); an empty `sub` keeps everything."""
    if not sub:
        return ledger
    prefix = f"{root}{sub}/"
    return {**ledger, "plans": [p for p in ledger["plans"] if p["hypothesis"]["source_node"].startswith(prefix)]}


def score_lab(lab: dict, cache: Path) -> dict:
    tree = checkout(cache, lab["repo"], lab["commit"])
    language = lab["language"]
    sites: dict[tuple, dict] = {}
    for v in lab["vulnerabilities"]:
        if not scoreable(v):
            continue
        lines = read_source_text(tree / v["file"], tree).splitlines()
        if not (1 <= v["line"] <= len(lines) and lines[v["line"] - 1].rstrip() == v["sink_line_quote"].rstrip()):
            raise RuntimeError(f"{v['vid']}: quoted line does not match {v['file']}:{v['line']} at {lab['commit']}")
        key = (v["file"], v["line"], sentinel_sink(v["sink_identity"], language))
        site = sites.setdefault(key, {"file": v["file"], "line": v["line"], "sink": key[2], "vids": [], "weak": None})
        site["vids"].append(v["vid"])
        site["weak"] = site["weak"] or weak_reason(v)
    ledger = scan(tree, resolver_language(language))
    validate_scored_files(ledger, tree, [s["file"] for s in sites.values()])
    root = str(tree).rstrip("/") + "/"
    # A lab that lives in one folder of a monorepo declares it; plans elsewhere belong to other
    # applications and must not enter this lab's statistics. Paths stay repository-relative.
    sub = (lab.get("subdirectory") or "").strip("/")
    ledger = restrict_to_subdirectory(ledger, root, sub)
    by_site: dict[tuple, list] = {}
    for plan in ledger["plans"]:
        path, _, lineno = plan["hypothesis"]["source_node"].rpartition(":")
        rel = path[len(root):] if path.startswith(root) else path
        by_site.setdefault((rel, int(lineno), plan["hypothesis"]["sink_node"]), []).append(plan)
    rows = []
    for key, site in sites.items():
        plans = by_site.get(key, [])
        priority = any((p.get("triage") or {}).get("priority") for p in plans)
        site["outcome"] = "detected" if priority else ("under-ranked" if plans else "missed")
        site["triage"] = [{k: (p.get("triage") or {}).get(k) for k in
                           ("priority", "signal", "code_context", "guarded_by", "constant_arguments")} for p in plans]
        # For a miss, what the scanner did see on that line, if anything.
        site["other_plans_on_line"] = sorted({k[2] for k in by_site if k[0] == key[0] and k[1] == key[1]} - {key[2]})
        rows.append(site)
    total = len(ledger["plans"])
    prio = sum(1 for p in ledger["plans"] if (p.get("triage") or {}).get("priority"))
    same_sink = {}
    for site in rows:
        same = [p for p in ledger["plans"] if p["hypothesis"]["sink_node"] == site["sink"]]
        same_sink[site["sink"]] = round(sum(bool((p.get("triage") or {}).get("priority")) for p in same) / len(same), 4) if same else None
    return {"id": lab["id"], "language": language, "commit": lab["commit"], "subdirectory": sub or None, "sites": rows,
            "plans": total, "priority": prio, "same_sink_priority_share": same_sink,
            "scan_evidence": {**scan_identity(ledger, tree), "parse_errors": ledger.get("parse_errors", []),
                              "coverage_warnings": ledger.get("coverage", {}).get("warnings", [])}}


def summarize(labs: list[dict]) -> dict:
    def block(sites):
        n = len(sites)
        return {"sites": n, **{k: sum(s["outcome"] == k for s in sites) for k in ("detected", "under-ranked", "missed")},
                "recall": round(sum(s["outcome"] == "detected" for s in sites) / n, 4) if n else None}
    all_sites = [s for lab in labs for s in lab["sites"]]
    plans = sum(lab["plans"] for lab in labs)
    prio = sum(lab["priority"] for lab in labs)
    shares = [lab["same_sink_priority_share"][s["sink"]] for lab in labs for s in lab["sites"]
              if not s["weak"] and lab["same_sink_priority_share"].get(s["sink"]) is not None]
    return {"direct": block([s for s in all_sites if not s["weak"]]),
            "weak": block([s for s in all_sites if s["weak"]]),
            "base_rate": {"plans": plans, "priority": prio, "priority_share": round(prio / plans, 4) if plans else None,
                          "same_sink_priority_share_mean_direct": round(statistics.mean(shares), 4) if shares else None}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "sentinel-zero-labs")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    data = json.loads(args.manifest.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise SystemExit(f"expected schema {SCHEMA}, got {data.get('schema')!r}")
    labs = [score_lab(lab, args.cache) for lab in data["labs"]]
    for lab in labs:
        for s in lab["sites"]:
            print(f"{lab['id']}: {s['sink']} {s['file']}:{s['line']} {'(weak: ' + s['weak'] + ') ' if s['weak'] else ''}"
                  f"-> {s['outcome']} {s['vids']}")
    result = {"summary": summarize(labs), "labs": labs}
    print(json.dumps(result["summary"], indent=2))
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Score Sentinel-Zero on real vulnerabilities: known CVEs, scanned at the
vulnerable commit and at the fix commit.

    python calibration/cve_pairs.py                 # score every pair in cve_pairs.json
    python calibration/cve_pairs.py --only ID ...   # score some pairs
    python calibration/cve_pairs.py --cache DIR     # where clones live (default ~/.cache/sentinel-zero-cve)
    python calibration/cve_pairs.py --out FILE      # write the results JSON (default: stdout only)

This is NOT part of the pytest gate: it clones public repositories over the
network. The synthetic harness (calibrate.py) stays the offline regression
gate; this script measures what the synthetic set cannot: recall on real bugs.

Each pair names the vulnerable calls the fix changed: (file, function, sink,
line_at_vulnerable). Scoring is per GROUP, one group per (file, function,
sink), because a function may contain several calls to the same sink.

At the vulnerable commit each call is matched by its exact line, so one
detected call cannot hide a missed call in the same function:
    detected      every call in the group has a priority plan
    under-ranked  every call has a plan, but at least one is not priority
    missed        at least one call has no plan at all
At the fixed commit lines move and calls cannot be mapped one to one, so the
group is judged as a whole (any plan on that sink in that function):
    gone          no plan remains
    downgraded    plans remain, none is priority
    still-flagged a priority plan remains (the fix is invisible to triage)

Headline: recall = detected / groups, and quiet-on-fix = (gone + downgraded) /
groups. Per-call recall is reported too. All are reported whatever they are;
the pair list must not be tuned to them.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from sentinel_zero import cli  # noqa: E402

MANIFEST = HERE / "cve_pairs.json"


def git(repo_dir: Path, *args: str, timeout: int = 600) -> str:
    result = subprocess.run(["git", "-C", str(repo_dir), *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed in {repo_dir}: {result.stderr.strip()[-400:]}")
    return result.stdout.strip()


def checkout(cache: Path, repo_url: str, commit: str) -> Path:
    """A clean worktree of `commit`, shallow-fetched once and reused."""
    name = repo_url.rstrip("/").removesuffix(".git").split("github.com/")[-1].replace("/", "__")
    base = cache / name
    if not (base / ".git").exists():
        base.mkdir(parents=True, exist_ok=True)
        git(base, "init", "-q")
        git(base, "remote", "add", "origin", repo_url)
    tree = cache / f"{name}@{commit[:12]}"
    if not tree.exists():
        git(base, "fetch", "-q", "--depth=1", "origin", commit)
        git(base, "worktree", "add", "-q", "--detach", str(tree), commit)
    if git(tree, "rev-parse", "HEAD") != commit:
        raise RuntimeError(f"{tree} is not at {commit}")
    return tree


def scan(tree: Path, language: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="sz_cve_") as out:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(["analyze", str(tree), "--language", language, "--format", "json", "--out", out])
        if code != 0:
            raise RuntimeError(f"scan of {tree.name} exited {code}: {err.getvalue()[-600:]}")
        return json.loads((Path(out) / "verification_ledger.json").read_text(encoding="utf-8"))


def site_plans(ledger: dict, tree: Path, site: dict, line: int | None = None) -> list[dict]:
    """Plans on `site`'s sink in its file and function; with `line`, only the call on that line."""
    root = str(tree).rstrip("/") + "/"
    hits = []
    for plan in ledger["plans"]:
        hyp = plan["hypothesis"]
        path, _, lineno = hyp["source_node"].rpartition(":")
        rel = path[len(root):] if path.startswith(root) else path
        func = hyp.get("symbol_binding") or ""
        if (hyp["sink_node"] == site["sink"] and rel == site["file"]
                and (func == site["function"] or func.endswith("." + site["function"]))
                and (line is None or lineno == str(line))):
            hits.append(plan)
    return hits


def group_sites(sites: list[dict]) -> list[dict]:
    """One group per (file, function, sink), keeping each vulnerable call's line."""
    groups: dict[tuple, dict] = {}
    for site in sites:
        key = (site["file"], site["function"], site["sink"])
        group = groups.setdefault(key, {"file": site["file"], "function": site["function"],
                                        "sink": site["sink"], "lines": []})
        if site["line_at_vulnerable"] not in group["lines"]:
            group["lines"].append(site["line_at_vulnerable"])
    return list(groups.values())


def classify_vulnerable(per_call: list[list[dict]]) -> str:
    """per_call: the plans matched at each vulnerable call's exact line."""
    if any(not plans for plans in per_call):
        return "missed"
    if all(any(p.get("triage", {}).get("priority") for p in plans) for plans in per_call):
        return "detected"
    return "under-ranked"


def classify(plans: list[dict], vulnerable: bool) -> str:
    priority = any(p.get("triage", {}).get("priority") for p in plans)
    if vulnerable:
        return "detected" if priority else ("under-ranked" if plans else "missed")
    return "still-flagged" if priority else ("downgraded" if plans else "gone")


def score_pair(pair: dict, cache: Path) -> dict:
    row = {"id": pair["id"], "repo": pair["repo"], "kind": pair["kind"], "sites": []}
    try:
        trees = {k: checkout(cache, pair["repo"], pair[k]) for k in ("vulnerable", "fixed")}
        ledgers = {k: scan(t, pair.get("language", "python")) for k, t in trees.items()}
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        row["error"] = str(exc)[-600:]
        return row
    for group in group_sites(pair["sites"]):
        per_call = [site_plans(ledgers["vulnerable"], trees["vulnerable"], group, line) for line in group["lines"]]
        after = site_plans(ledgers["fixed"], trees["fixed"], group)
        row["sites"].append({
            **group,
            "vulnerable": classify_vulnerable(per_call),
            "calls_detected": sum(any(p.get("triage", {}).get("priority") for p in plans) for plans in per_call),
            "fixed": classify(after, False),
            "guard_after_fix": sorted({(p.get("triage") or {}).get("guarded_by") or "" for p in after} - {""}),
            # Why each vulnerable call was or was not priority, so every miss is explainable.
            "vulnerable_triage": [{k: (p.get("triage") or {}).get(k) for k in
                                   ("priority", "signal", "code_context", "guarded_by", "constant_arguments")}
                                  for plans in per_call for p in plans],
        })
    row["plans"] = {k: len(v["plans"]) for k, v in ledgers.items()}
    return row


def summarize(rows: list[dict]) -> dict:
    sites = [s for r in rows if "error" not in r for s in r["sites"]]
    count = len(sites)

    def rate(n: int) -> float | None:
        return round(n / count, 4) if count else None

    calls = sum(len(s.get("lines", [])) for s in sites)
    return {
        "pairs": len(rows),
        "pairs_errored": [r["id"] for r in rows if "error" in r],
        "groups": count,
        "calls": calls,
        "call_recall": round(sum(s.get("calls_detected", 0) for s in sites) / calls, 4) if calls else None,
        "recall": rate(sum(s["vulnerable"] == "detected" for s in sites)),
        "quiet_on_fix": rate(sum(s["fixed"] in ("gone", "downgraded") for s in sites)),
        "vulnerable_outcomes": {k: sum(s["vulnerable"] == k for s in sites) for k in ("detected", "under-ranked", "missed")},
        "fixed_outcomes": {k: sum(s["fixed"] == k for s in sites) for k in ("gone", "downgraded", "still-flagged")},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", nargs="+")
    parser.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "sentinel-zero-cve")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    pairs = json.loads(MANIFEST.read_text(encoding="utf-8"))["pairs"]
    if args.only:
        pairs = [p for p in pairs if p["id"] in set(args.only)]
    rows = []
    for pair in pairs:
        row = score_pair(pair, args.cache)
        rows.append(row)
        if "error" in row:
            print(f"{row['id']}: ERROR {row['error'][-200:]}", flush=True)
        for s in row.get("sites", []):
            print(f"{row['id']}: {s['sink']} in {s['file']}:{s['function']} lines={s['lines']} -> "
                  f"vulnerable={s['vulnerable']} fixed={s['fixed']}", flush=True)
    result = {"summary": summarize(rows), "rows": rows}
    print(json.dumps(result["summary"], indent=2))
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

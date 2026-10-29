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
import hashlib
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
    # Git status intentionally trusts these index flags and can hide changed
    # tracked bytes. A calibration cache must not use that optimization.
    flagged = [entry[2:] for entry in git(tree, "ls-files", "-v", "-z").split("\0")
               if entry and (entry[0].islower() or entry[0] == "S")]
    if flagged:
        raise RuntimeError(f"{tree} has assume-unchanged or skip-worktree index flags: {flagged[:8]}; "
                           "use a fresh frozen checkout; nothing was reset.")
    # A matching HEAD is not evidence of matching scanned bytes. Include
    # ignored files too: a project's .gitignore can hide source that the
    # static resolver still collects. Preserve changes instead of resetting.
    dirty = git(tree, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching")
    if dirty:
        raise RuntimeError(
            f"{tree} is not a clean frozen checkout (modified, untracked or ignored files): "
            f"{dirty[:400]}. Preserve the changes and use a fresh cache; nothing was reset."
        )
    return tree


def scan(tree: Path, language: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="sz_cve_") as out:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
            code = cli.main(["analyze", str(tree), "--language", language, "--format", "json", "--out", out])
        if code != 0:
            raise RuntimeError(f"scan of {tree.name} exited {code}: {err.getvalue()[-600:]}")
        return json.loads((Path(out) / "verification_ledger.json").read_text(encoding="utf-8"))


def validate_scored_files(ledger: dict, tree: Path, files: list[str], *, allow_deleted: bool = False) -> None:
    """Require evidence that every scored source file was actually analyzed.

    A deleted fixed-side file can legitimately make the old site disappear.
    A present but excluded/unreadable/unparseable file cannot. Unrelated
    parse failures are retained in scan evidence and do not certify a site.
    """
    root = tree.resolve()
    analyzed = {Path(p).resolve() for p in ledger.get("analyzed_files", [])}
    failed = {Path(e["file_path"]).resolve(): e.get("error", "analysis failed")
              for e in ledger.get("parse_errors", [])}
    for relative in sorted(set(files)):
        path = root / relative
        resolved = path.resolve()
        if Path(relative).is_absolute() or root not in resolved.parents:
            raise RuntimeError(f"scored source escapes checkout: {relative!r}")
        if not path.exists() and not path.is_symlink() and allow_deleted:
            continue
        if resolved in failed:
            raise RuntimeError(f"analysis_failed for scored file {relative}: {failed[resolved]}")
        if not path.is_file() or resolved not in analyzed:
            raise RuntimeError(f"analysis_failed: scored file {relative} was not analyzed")


def scan_identity(ledger: dict, tree: Path) -> dict:
    """Bind retained metrics to source bytes and the scanner implementation."""
    source = hashlib.sha256()
    root = tree.resolve()
    files = sorted({Path(p).resolve() for p in ledger.get("analyzed_files", [])})
    for path in files:
        relative = path.relative_to(root).as_posix()
        source.update(relative.encode("utf-8") + b"\0")
        source.update(hashlib.sha256(path.read_bytes()).digest())
    scanner = hashlib.sha256()
    package = HERE.parent / "sentinel_zero"
    for path in sorted(package.rglob("*")):
        if not path.is_file() or any(part in {"node_modules", "__pycache__"} for part in path.parts):
            continue
        if path.suffix not in {".py", ".js", ".json"}:
            continue
        scanner.update(path.relative_to(package).as_posix().encode("utf-8") + b"\0")
        scanner.update(hashlib.sha256(path.read_bytes()).digest())
    return {"commit": git(tree, "rev-parse", "HEAD"), "analyzed_file_count": len(files),
            "analyzed_source_sha256": source.hexdigest(), "scanner_source_sha256": scanner.hexdigest()}


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
    expected = group_sites(pair["sites"])
    row = {"id": pair["id"], "repo": pair["repo"], "kind": pair["kind"], "sites": [],
           "groups_expected": len(expected), "calls_expected": sum(len(g["lines"]) for g in expected)}
    try:
        trees = {k: checkout(cache, pair["repo"], pair[k]) for k in ("vulnerable", "fixed")}
        ledgers = {k: scan(t, pair.get("language", "python")) for k, t in trees.items()}
        row["scan_diagnostics"] = {
            side: {"parse_errors": ledgers[side].get("parse_errors", []),
                   "coverage_warnings": ledgers[side].get("coverage", {}).get("warnings", [])}
            for side in ("vulnerable", "fixed")
        }
        files = [s["file"] for s in pair["sites"]]
        for side in ("vulnerable", "fixed"):
            validate_scored_files(ledgers[side], trees[side], files, allow_deleted=side == "fixed")
        row["scan_evidence"] = {
            side: {**scan_identity(ledgers[side], trees[side]),
                   "parse_errors": ledgers[side].get("parse_errors", []),
                   "coverage_warnings": ledgers[side].get("coverage", {}).get("warnings", [])}
            for side in ("vulnerable", "fixed")
        }
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        row["error"] = str(exc)[-600:]
        return row
    for group in expected:
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
    errors = [r for r in rows if "error" in r]
    scored_rates = {
        "call_recall": round(sum(s.get("calls_detected", 0) for s in sites) / calls, 4) if calls else None,
        "recall": rate(sum(s["vulnerable"] == "detected" for s in sites)),
        "quiet_on_fix": rate(sum(s["fixed"] in ("gone", "downgraded") for s in sites)),
    }
    return {
        "pairs": len(rows),
        "complete": not errors,
        "pairs_errored": [r["id"] for r in errors],
        "groups": count,
        "groups_unscored": sum(r.get("groups_expected", 0) for r in errors),
        "calls_unscored": sum(r.get("calls_expected", 0) for r in errors),
        "calls": calls,
        **{key: None if errors else value for key, value in scored_rates.items()},
        "scored_only_rates": scored_rates,
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
    result = {"schema": "sentinel-cve-calibration-v2", "summary": summarize(rows), "rows": rows}
    print(json.dumps(result["summary"], indent=2))
    if args.out:
        args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 1 if result["summary"]["pairs_errored"] else 0


if __name__ == "__main__":
    sys.exit(main())

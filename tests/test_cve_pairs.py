"""Offline checks for calibration/cve_pairs.py: site matching and outcome
classes. The script itself clones repositories and is not run here."""
import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("cve_pairs", ROOT / "calibration" / "cve_pairs.py")
if spec is None or spec.loader is None:
    raise ImportError("calibration/cve_pairs.py could not be loaded")
cve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cve)


def plan(path, line, sink, func, priority):
    return {"hypothesis": {"source_node": f"{path}:{line}", "sink_node": sink, "symbol_binding": func},
            "triage": {"priority": priority}}


def test_site_matches_by_file_function_and_sink_not_line():
    tree = Path("/work/repo")
    ledger = {"plans": [
        plan("/work/repo/pkg/a.py", 40, "yaml.load", "pkg.a.Loader.read", True),     # match (line moved)
        plan("/work/repo/pkg/a.py", 41, "builtins.open", "pkg.a.Loader.read", True),  # other sink
        plan("/work/repo/pkg/b.py", 40, "yaml.load", "pkg.b.Loader.read", True),      # other file
        plan("/work/repo/pkg/a.py", 90, "yaml.load", "pkg.a.other", True),            # other function
    ]}
    site = {"file": "pkg/a.py", "function": "Loader.read", "sink": "yaml.load"}
    hits = cve.site_plans(ledger, tree, site)
    assert [h["hypothesis"]["source_node"] for h in hits] == ["/work/repo/pkg/a.py:40"]


def test_function_suffix_must_be_a_whole_name():
    tree = Path("/r")
    ledger = {"plans": [plan("/r/m.py", 1, "builtins.eval", "m.myload", True)]}
    assert cve.site_plans(ledger, tree, {"file": "m.py", "function": "load", "sink": "builtins.eval"}) == []


def test_outcome_classes():
    p, n = {"triage": {"priority": True}}, {"triage": {"priority": False}}
    assert cve.classify([p, n], vulnerable=True) == "detected"
    assert cve.classify([n], vulnerable=True) == "under-ranked"
    assert cve.classify([], vulnerable=True) == "missed"
    assert cve.classify([p], vulnerable=False) == "still-flagged"
    assert cve.classify([n], vulnerable=False) == "downgraded"
    assert cve.classify([], vulnerable=False) == "gone"


def test_incomplete_summary_exposes_unscored_sites_and_withholds_headline_rates():
    rows = [{"id": "A", "sites": [
                {"vulnerable": "detected", "fixed": "gone", "lines": [3], "calls_detected": 1},
                {"vulnerable": "missed", "fixed": "still-flagged", "lines": [7, 9], "calls_detected": 1}]},
            {"id": "B", "error": "clone failed", "sites": [], "groups_expected": 1, "calls_expected": 2}]
    s = cve.summarize(rows)
    assert (s["groups"], s["calls"], s["groups_unscored"], s["calls_unscored"], s["pairs_errored"]) == \
        (2, 3, 1, 2, ["B"])
    assert s["complete"] is False
    assert s["recall"] is s["call_recall"] is s["quiet_on_fix"] is None
    assert s["scored_only_rates"] == {"recall": 0.5, "call_recall": 0.6667, "quiet_on_fix": 0.5}


def _git(tree, *args):
    return subprocess.run(["git", "-C", str(tree), *args], check=True,
                          text=True, capture_output=True).stdout.strip()


@pytest.fixture
def frozen_pair(tmp_path):
    """Real local commit/worktree behavior, with no remote fetches."""
    cache = tmp_path / "cache"
    base = cache / "example__fixture"
    base.mkdir(parents=True)
    _git(base, "init", "-q")
    _git(base, "config", "user.name", "Calibration test")
    _git(base, "config", "user.email", "calibration@example.invalid")
    app = base / "app.py"
    app.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n", encoding="utf-8")
    (base / ".gitignore").write_text("ignored.py\n", encoding="utf-8")
    _git(base, "add", ".")
    _git(base, "commit", "-qm", "source with supported sink")
    vulnerable = _git(base, "rev-parse", "HEAD")
    app.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n    this is (\n", encoding="utf-8")
    _git(base, "add", "app.py")
    _git(base, "commit", "-qm", "malformed fixed source")
    fixed = _git(base, "rev-parse", "HEAD")
    for sha in (vulnerable, fixed):
        _git(base, "worktree", "add", "-q", "--detach", str(cache / f"example__fixture@{sha[:12]}"), sha)
    pair = {"id": "LOCAL-PARSE-FAIL", "repo": "https://github.com/example/fixture", "kind": "PROCESS_EXEC",
            "language": "python", "vulnerable": vulnerable, "fixed": fixed,
            "sites": [{"file": "app.py", "function": "run", "sink": "os.system", "line_at_vulnerable": 3}]}
    return cache, pair


def test_parse_failed_fixed_file_cannot_earn_gone_or_quiet_on_fix(frozen_pair):
    cache, pair = frozen_pair
    row = cve.score_pair(pair, cache)
    assert "analysis_failed" in row["error"] and "app.py" in row["error"]
    assert "SyntaxError" in row["scan_diagnostics"]["fixed"]["parse_errors"][0]["error"]
    assert row["sites"] == []
    summary = cve.summarize([row])
    assert summary["quiet_on_fix"] is None
    assert summary["groups_unscored"] == 1 and summary["pairs_errored"] == [pair["id"]]


@pytest.mark.parametrize("change", ["tracked", "untracked", "ignored"])
def test_frozen_checkout_refuses_changed_bytes_without_resetting_them(frozen_pair, change):
    cache, pair = frozen_pair
    tree = cache / f"example__fixture@{pair['vulnerable'][:12]}"
    path = tree / {"tracked": "app.py", "untracked": "new.py", "ignored": "ignored.py"}[change]
    changed = "def run(cmd):\n    return cmd\n"
    path.write_text(changed, encoding="utf-8")
    assert _git(tree, "rev-parse", "HEAD") == pair["vulnerable"]
    with pytest.raises(RuntimeError, match="not a clean frozen checkout"):
        cve.checkout(cache, pair["repo"], pair["vulnerable"])
    assert path.read_text(encoding="utf-8") == changed


def test_present_but_unanalyzed_file_cannot_be_scored_as_absent(tmp_path):
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="was not analyzed"):
        cve.validate_scored_files({"analyzed_files": [], "parse_errors": []}, tmp_path, ["app.py"])


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_index_flags_cannot_conceal_changed_frozen_source(frozen_pair, flag):
    cache, pair = frozen_pair
    tree = cache / f"example__fixture@{pair['vulnerable'][:12]}"
    _git(tree, "update-index", flag, "app.py")
    (tree / "app.py").write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")
    assert _git(tree, "status", "--porcelain") == ""
    with pytest.raises(RuntimeError, match="index flags"):
        cve.checkout(cache, pair["repo"], pair["vulnerable"])


def test_legitimately_deleted_fixed_file_is_allowed_but_missing_vulnerable_file_is_not(tmp_path):
    ledger: dict = {"analyzed_files": [], "parse_errors": []}
    cve.validate_scored_files(ledger, tmp_path, ["removed.py"], allow_deleted=True)
    with pytest.raises(RuntimeError, match="was not analyzed"):
        cve.validate_scored_files(ledger, tmp_path, ["removed.py"])


def test_complete_pair_retains_source_and_scanner_digests(frozen_pair):
    cache, pair = frozen_pair
    # A separate clean fixed commit removes the dangerous call.
    base = cache / "example__fixture"
    (base / "app.py").write_text("def run(cmd):\n    return cmd\n", encoding="utf-8")
    _git(base, "add", "app.py")
    _git(base, "commit", "-qm", "safe fixed source")
    fixed = _git(base, "rev-parse", "HEAD")
    _git(base, "worktree", "add", "-q", "--detach", str(cache / f"example__fixture@{fixed[:12]}"), fixed)
    row = cve.score_pair({**pair, "fixed": fixed}, cache)
    assert "error" not in row, row
    assert row["sites"][0]["fixed"] == "gone"
    assert cve.summarize([row])["quiet_on_fix"] == 1.0
    evidence = row["scan_evidence"]
    assert evidence["fixed"]["commit"] == fixed
    assert evidence["fixed"]["analyzed_source_sha256"] != evidence["vulnerable"]["analyzed_source_sha256"]
    assert len(evidence["fixed"]["scanner_source_sha256"]) == 64


def test_calibration_cli_retains_failed_rows_and_returns_nonzero(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"pairs": [{"id": "failed"}]}), encoding="utf-8")
    monkeypatch.setattr(cve, "MANIFEST", manifest)
    monkeypatch.setattr(cve, "score_pair", lambda *args: {
        "id": "failed", "error": "analysis_failed", "sites": [], "groups_expected": 1, "calls_expected": 1
    })
    output = tmp_path / "result.json"
    assert cve.main(["--cache", str(tmp_path), "--out", str(output)]) == 1
    result = json.loads(output.read_text(encoding="utf-8"))
    assert result["summary"]["complete"] is False
    assert result["summary"]["quiet_on_fix"] is None
    assert result["rows"][0]["error"] == "analysis_failed"


# --- Codex review on #23: one detected call must not hide another ---------

def test_calls_are_matched_by_exact_line():
    tree = Path("/r")
    ledger = {"plans": [plan("/r/k.py", 125, "os.system", "k.R.kill_task", True),
                        plan("/r/k.py", 127, "os.system", "k.R.kill_task", False)]}
    group = {"file": "k.py", "function": "R.kill_task", "sink": "os.system"}
    assert len(cve.site_plans(ledger, tree, group, 125)) == 1
    assert len(cve.site_plans(ledger, tree, group, 129)) == 0
    assert len(cve.site_plans(ledger, tree, group)) == 2


def test_group_detected_only_if_every_call_is_priority():
    p, n = {"triage": {"priority": True}}, {"triage": {"priority": False}}
    assert cve.classify_vulnerable([[p], [p]]) == "detected"
    assert cve.classify_vulnerable([[p], [n]]) == "under-ranked"
    assert cve.classify_vulnerable([[p], []]) == "missed"


def test_sites_group_by_file_function_and_sink():
    sites = [{"file": "k.py", "function": "R.kill", "sink": "os.system", "line_at_vulnerable": l} for l in (125, 127)]
    sites.append({"file": "k.py", "function": "R.kill", "sink": "builtins.eval", "line_at_vulnerable": 130})
    groups = cve.group_sites(sites)
    assert [(g["sink"], g["lines"]) for g in groups] == [("os.system", [125, 127]), ("builtins.eval", [130])]


def test_manifest_is_well_formed():
    data = json.loads((ROOT / "calibration" / "cve_pairs.json").read_text())
    assert data["schema"] == "sentinel-cve-pairs-v1"
    ids = [p["id"] for p in data["pairs"]]
    assert len(ids) == len(set(ids)) and ids
    for p in data["pairs"]:
        assert len(p["vulnerable"]) == 40 and len(p["fixed"]) == 40 and p["vulnerable"] != p["fixed"]
        assert p["repo"].startswith("https://github.com/") and p["sites"]
        for s in p["sites"]:
            assert {"file", "function", "sink", "line_at_vulnerable"} <= set(s)

"""Offline checks for calibration/cve_pairs.py: site matching and outcome
classes. The script itself clones repositories and is not run here."""
import importlib.util
import json
from pathlib import Path

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


def test_summary_excludes_errored_pairs():
    rows = [{"id": "A", "sites": [
                {"vulnerable": "detected", "fixed": "gone", "lines": [3], "calls_detected": 1},
                {"vulnerable": "missed", "fixed": "still-flagged", "lines": [7, 9], "calls_detected": 1}]},
            {"id": "B", "error": "clone failed", "sites": []}]
    s = cve.summarize(rows)
    assert (s["groups"], s["calls"], s["recall"], s["call_recall"], s["quiet_on_fix"], s["pairs_errored"]) == \
        (2, 3, 0.5, 0.6667, 0.5, ["B"])


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

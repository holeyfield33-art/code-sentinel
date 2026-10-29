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
    rows = [{"id": "A", "sites": [{"vulnerable": "detected", "fixed": "gone"}, {"vulnerable": "missed", "fixed": "still-flagged"}]},
            {"id": "B", "error": "clone failed", "sites": []}]
    s = cve.summarize(rows)
    assert s["sites"] == 2 and s["recall"] == 0.5 and s["quiet_on_fix"] == 0.5 and s["pairs_errored"] == ["B"]


def test_manifest_is_well_formed():
    data = json.loads((ROOT / "calibration" / "cve_pairs.json").read_text())
    assert data["schema"] == "sentinel-cve-pairs-v1"
    ids = [p["id"] for p in data["pairs"]]
    assert len(ids) == len(set(ids)) and ids
    for p in data["pairs"]:
        assert len(p["vulnerable"]) == 40 and len(p["fixed"]) == 40 and p["vulnerable"] != p["fixed"]
        assert p["repo"].startswith("https://github.com/") and p["sites"]
        for s in p["sites"]:
            assert {"file", "function", "sink"} <= set(s)

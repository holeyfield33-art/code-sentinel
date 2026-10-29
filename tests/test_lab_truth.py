"""Offline checks for calibration/lab_truth.py: which answer-key entries are
scored, how sink names are mapped, and which entries are kept apart as weak."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "calibration"))
spec = importlib.util.spec_from_file_location("lab_truth", ROOT / "calibration" / "lab_truth.py")
if spec is None or spec.loader is None:
    raise ImportError("calibration/lab_truth.py could not be loaded")
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

BASE = {"located": True, "expected": "vulnerable", "documented_vulnerability": True,
        "sentinel_scope": "in_scope", "sink_identity": "subprocess.run", "notes": ""}


def test_only_located_documented_in_scope_vulnerable_entries_are_scored():
    assert lab.scoreable(BASE)
    for change in ({"located": False}, {"expected": "not_vulnerable"}, {"documented_vulnerability": False},
                   {"eligible_server_language": False}, {"sentinel_scope": "planned"}):
        assert not lab.scoreable({**BASE, **change}), change


def test_python_builtins_map_to_sentinel_identities_and_js_names_do_not():
    assert lab.sentinel_sink("eval", "python") == "builtins.eval"
    assert lab.sentinel_sink("open", "python") == "builtins.open"
    assert lab.sentinel_sink("eval", "typescript") == "eval"
    assert lab.sentinel_sink("pickle.loads", "python") == "pickle.loads"


def test_weak_entries_are_kept_apart():
    assert lab.weak_reason({**BASE, "sink_identity": "JSON.parse"}) == "low-signal parser"
    assert lab.weak_reason({**BASE, "notes": "Command is constant and has no command-injection taint."}) == "constant command"
    assert lab.weak_reason(BASE) is None


def test_bundled_key_is_the_hashed_one():
    sums = (ROOT / "calibration" / "labs" / "SHA256SUMS").read_text().split()
    import hashlib
    data = (ROOT / "calibration" / "labs" / "vuln_labs_manifest.json").read_bytes()
    assert sums[0] == hashlib.sha256(data).hexdigest()
    assert json.loads(data)["schema"] == lab.SCHEMA

"""Current reports are diagnostic-only; the milestone notes below are historical.

Milestone 16: widens the Milestone 6 dynamic reachability probe past
its original PROCESS_EXEC-only scope to also cover FILE_IO and
DESERIALIZATION, and fixes a real correctness bug found in the process --
see probes/_sink_reachability_harness.py and dogfood_scan.py's comments
on the probing block for the full story. Three things to prove here:

1. The new sink kinds actually promote to VERIFIED_TRUE under a real
   zero-arg dynamic call, the same way PROCESS_EXEC already did.
2. The symbol-mismatch bug is fixed: two different sinks in the same
   zero-arg caller no longer both get promoted off one probe run when
   only the first was actually reached.
3. builtins.eval/builtins.exec are never probed at all (not just never
   promoted) -- probing them would mean actually executing the real
   eval/exec in the subprocess, since the harness cannot safely patch
   them without breaking Python's own import machinery.
"""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.resolvers.python_resolver import build_project_graph

_CATALOG_PATH = str(bundled_snapshot_path())


def _run(root: Path) -> list[dict]:
    graph = build_project_graph(root)
    catalog = load_catalog(_CATALOG_PATH, is_bundled_snapshot=True)
    plans = find_finding_plans(graph, root.name, catalog, [0], root, probe_mode="diagnostic")
    return [p.as_dict() for p in plans]


@pytest.mark.docker_integration
def test_file_io_sink_report_does_not_grant_verification():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "def read_it():\n    open('/dev/null')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        assert "builtins.open" in plans[0]["disposition"]["reason"]


@pytest.mark.docker_integration
def test_deserialization_sink_report_does_not_grant_verification():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import json\ndef load_it():\n    json.loads('{}')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        assert "json.loads" in plans[0]["disposition"]["reason"]


@pytest.mark.docker_integration
def test_reported_symbol_does_not_verify_either_sink():
    """The regression this milestone fixes: before the symbol-match check,
    both sinks in this caller were wrongly marked VERIFIED_TRUE off a
    single probe run, even though the second is never reached (the first
    _SinkReached exception aborts the call before that line executes)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "def run_it():\n"
            "    subprocess.run(['echo', 'first'])\n"
            "    subprocess.call(['echo', 'second'])\n"
        )
        plans = _run(root)
        by_sink = {p["hypothesis"]["sink_node"]: p["disposition"]["status"] for p in plans}
        assert by_sink["subprocess.run"] == "UNRESOLVED_INCONCLUSIVE"
        assert any(p["verification_method"].get("probe_observation", {}).get("report", {}).get("symbol") == "subprocess.run" for p in plans)
        assert by_sink["subprocess.call"] == "UNRESOLVED_INCONCLUSIVE"


def test_eval_sink_is_never_probed_and_stays_inconclusive():
    """A zero-arg function whose own finding IS an eval() call must never
    be dynamically probed -- the harness cannot patch builtins.eval
    without breaking import machinery, so probing would actually run the
    real eval() in the subprocess. Must stay exactly where static
    analysis left it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "def run_it():\n    eval('1 + 1')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "sandbox probe" in plans[0]["disposition"]["reason"] or "No sandbox probe" in plans[0]["disposition"]["reason"]


def test_exec_sink_does_not_actually_execute_during_probing():
    """End-to-end proof, not just a status check: an exec() call that
    would have a real, observable side effect if actually run must NOT
    produce that side effect when this finding is scanned."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        marker = root / "SHOULD_NOT_EXIST"
        (root / "runner.py").write_text(
            "MARKER = " + repr(str(marker)) + "\n"
            "def run_it():\n"
            "    exec(\"open(MARKER, 'w').close()\")\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert not marker.exists()

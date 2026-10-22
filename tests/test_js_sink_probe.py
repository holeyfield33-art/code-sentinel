"""Current reports are diagnostic-only; the milestone notes below are historical.

Milestone 18: JS/TS mirror of the dynamic reachability probe. Proves
the same three things the Python probe tests prove, through the Node
harness instead of the Python one -- plus the two things that are
genuinely different on this side (eligibility decided at runtime via the
real exported function's arity, not static source parsing; and the one
sink that cannot be safely patched before require() is fs.readFileSync,
not eval/exec)."""
import shutil
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.catalog_loader import bundled_snapshot_path

pytestmark = [pytest.mark.docker_integration,
              pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not available in this environment")]

_CATALOG_PATH = str(bundled_snapshot_path())


def _run(root: Path) -> list[dict]:
    from sentinel_zero.resolvers.js_resolver import build_project_graph

    graph = build_project_graph(root)
    catalog = load_catalog(_CATALOG_PATH, is_bundled_snapshot=True)
    plans = find_finding_plans(graph, root.name, catalog, [0], root, "javascript", probe_mode="diagnostic")
    return [p.as_dict() for p in plans]


def test_exported_zero_arg_sink_report_does_not_grant_verification():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function safe() {\n  exec('echo hi');\n}\n"
            "module.exports = { safe };\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        assert "child_process.exec" in plans[0]["disposition"]["reason"]


def test_unexported_function_stays_unresolved():
    """A top-level function this resolver's static analysis finds is not
    automatically callable -- CommonJS requires an explicit export. Must
    never be guessed at or synthetically force-exported."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function notExported() {\n  exec('echo hi');\n}\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_function_requiring_an_argument_stays_unresolved():
    """JS silently fills a missing argument with undefined rather than
    raising -- the harness refuses to call anything with fn.length !== 0,
    same safety bar as Python's zero-arg-only rule."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function needsArg(cmd) {\n  exec(cmd);\n}\n"
            "module.exports = { needsArg };\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_class_method_sink_is_not_probed_but_is_still_a_finding():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "class Runner {\n  run() {\n    exec('echo hi');\n  }\n}\n"
            "module.exports = { Runner };\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_reported_symbol_does_not_verify_either_sink():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec, execSync } = require('child_process');\n"
            "function multi() {\n  exec('first');\n  execSync('second');\n}\n"
            "module.exports = { multi };\n"
        )
        plans = _run(root)
        by_sink = {p["hypothesis"]["sink_node"]: p["disposition"]["status"] for p in plans}
        assert by_sink["child_process.exec"] == "UNRESOLVED_INCONCLUSIVE"
        assert any(p["verification_method"].get("probe_observation", {}).get("report", {}).get("symbol") == "child_process.exec" for p in plans)
        assert by_sink["child_process.execSync"] == "UNRESOLVED_INCONCLUSIVE"


def test_fs_read_file_sync_sink_is_never_probed_and_stays_inconclusive():
    """The JS equivalent of Python's eval/exec exclusion: fs.readFileSync
    cannot be safely patched before require() (Node's own CommonJS loader
    uses the real one to read the target's source), so a finding whose
    own sink is fs.readFileSync must never be probed at all."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const fs = require('fs');\n"
            "function readIt() {\n  fs.readFileSync('/dev/null');\n}\n"
            "module.exports = { readIt };\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "No sandbox probe" in plans[0]["disposition"]["reason"] or "sandbox probe" in plans[0]["disposition"]["reason"]


def test_eval_sink_is_safely_probed_unlike_python():
    """Unlike Python (where patching builtins.exec breaks import itself),
    Node's require() does not route through the redefinable global eval
    -- confirmed directly before this code was written. So, unlike
    Python's eval/exec, a JS eval() sink IS eligible for this probe."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "function safe() {\n  eval('1 + 1');\n}\n"
            "module.exports = { safe };\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        assert "eval" in plans[0]["disposition"]["reason"]

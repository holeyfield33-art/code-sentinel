"""Triage tags and the non-fatal graph cap, from the 2026-10-28 held-out
benchmark (stytch-node, django-DefectDojo, chia-blockchain; vercel/swr as
control). Triage ranks findings; it never removes one or changes a
disposition."""
import json
from pathlib import Path

import pytest

from sentinel_zero import cli
from sentinel_zero import dogfood_scan
from sentinel_zero.disposition import _compute_finding_uid
from sentinel_zero.triage import code_context, sink_signal, summarize, triage_for

ROOT = "/work/repo"


@pytest.mark.parametrize("rel, expected", [
    ("app/views.py", "production"),
    ("src/index.ts", "production"),
    ("dojo/tools/parser.py", "production"),  # nested tools/ is product code
    ("tools/release.py", "build_tooling"),
    ("pkg/scripts/run.py", "production"),
    ("chia/_tests/util/blockchain.py", "test"),
    ("unittests/test_api.py", "test"),
    ("pkg/test_utils.py", "test"),
    ("pkg/utils_test.py", "test"),
    ("pkg/conftest.py", "test"),
    ("lib/client.test.ts", "test"),
    ("lib/client.spec.mjs", "test"),
    ("packages/a/__tests__/x.js", "test"),
    ("examples/optimistic-ui/pages/api/data.js", "example"),
    ("docs/conf.py", "docs"),
    (".github/workflows/check.py", "build_tooling"),
    ("scripts/release.py", "build_tooling"),
    ("benchmarks/run.py", "build_tooling"),
    ("docker/install_deps.py", "build_tooling"),
])
def test_code_context(rel, expected):
    context, rule = code_context(f"{ROOT}/{rel}", ROOT)
    assert context == expected
    assert rule


def test_repo_root_segments_never_count():
    # A checkout that itself lives under a "tests" or "examples" directory
    # must not down-rank all of its own code.
    assert code_context("/home/u/tests/myrepo/app.py", "/home/u/tests/myrepo")[0] == "production"


def test_windows_separators():
    assert code_context("C:\\w\\repo\\tests\\a.py", "C:\\w\\repo")[0] == "test"


@pytest.mark.parametrize("sink", ["json.load", "json.loads", "JSON.parse"])
def test_json_parsing_is_low_signal(sink):
    signal, reason = sink_signal(sink)
    assert signal == "low" and "cannot execute code" in reason


@pytest.mark.parametrize("sink", ["pickle.loads", "yaml.load", "subprocess.run", "builtins.open", "eval"])
def test_dangerous_sinks_stay_high_signal(sink):
    assert sink_signal(sink)[0] == "high"


def test_priority_needs_high_signal_and_production():
    assert triage_for(f"{ROOT}/app.py:3", "subprocess.run", ROOT)["priority"] is True
    assert triage_for(f"{ROOT}/app.py:3", "json.loads", ROOT)["priority"] is False
    assert triage_for(f"{ROOT}/tests/a.py:3", "subprocess.run", ROOT)["priority"] is False


def test_summary_counts_untriaged_rather_than_guessing():
    plans = [{"triage": triage_for(f"{ROOT}/app.py:1", "os.system", ROOT)}, {}]
    s = summarize(plans)
    assert s["priority"] == 1 and s["untriaged"] == 1


def _scan(tmp_path: Path, files: dict[str, str], fmt: str = "md") -> tuple[dict, Path]:
    repo = tmp_path / "repo"
    for rel, text in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    out = tmp_path / "out"
    assert cli.main(["analyze", str(repo), "--language", "python", "--format", fmt, "--out", str(out)]) == 0
    return json.loads((out / "verification_ledger.json").read_text()), out


def test_scan_tags_every_plan_and_keeps_all_of_them(tmp_path):
    ledger, out = _scan(tmp_path, {
        "app.py": "import subprocess, json\ndef run(x):\n    subprocess.run(x)\n    json.loads(x)\n",
        "tests/test_app.py": "import os\ndef t(x):\n    os.system(x)\n",
    })
    assert ledger["plan_count"] == 3
    tags = {p["hypothesis"]["sink_node"]: p["triage"] for p in ledger["plans"]}
    assert tags["subprocess.run"]["priority"] is True
    assert tags["json.loads"]["signal"] == "low"
    assert tags["os.system"]["code_context"] == "test"
    assert ledger["triage_summary"]["priority"] == 1
    assert {p["disposition"]["status"] for p in ledger["plans"]} == {"UNRESOLVED_INCONCLUSIVE"}

    report = (out / "report.md").read_text()
    for plan in ledger["plans"]:
        assert plan["plan_id"] in report
    assert report.index("subprocess.run") < report.index("## Lower-priority findings")


def test_triage_does_not_change_finding_uid(tmp_path):
    ledger, _ = _scan(tmp_path, {"app.py": "import os\ndef run(x):\n    os.system(x)\n"}, fmt="json")
    plan = ledger["plans"][0]
    # The uid is hashed from the hypothesis only, so scan-to-scan diffs
    # against ledgers written before triage existed still line up.
    assert plan["finding_uid"] == _compute_finding_uid(plan["hypothesis"])
    assert "triage" not in plan["hypothesis"]


def test_oversize_graph_is_skipped_not_fatal(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(dogfood_scan, "GRAPH_MAX_BYTES", 10)
    out = tmp_path / "out"
    out.mkdir()
    (out / "graph.json").write_text('{"stale": true}')
    ledger, out = _scan(tmp_path, {"app.py": "import os\ndef run(x):\n    os.system(x)\n"})
    graph = ledger["artifacts"]["graph"]
    assert graph["written"] is False and graph["bytes"] > graph["max_bytes"] == 10
    assert not (out / "graph.json").exists(), "a stale graph from an earlier run must not survive"
    assert (out / "report.md").exists()
    assert "Call graph not written" in (out / "report.md").read_text()
    assert "graph_skipped" in capsys.readouterr().err


def test_graph_within_cap_is_written_compact(tmp_path):
    ledger, out = _scan(tmp_path, {"app.py": "import os\ndef run(x):\n    os.system(x)\n"}, fmt="json")
    assert ledger["artifacts"]["graph"]["written"] is True
    text = (out / "graph.json").read_text()
    assert "\n" not in text and json.loads(text)

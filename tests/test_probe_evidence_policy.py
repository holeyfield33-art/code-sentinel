"""Hostile self-reports must never cross the parent's verification boundary."""
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_zero import cli
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.dogfood_scan import run
from sentinel_zero.probes.evidence import validate_probe_result


def _scan(root, out, language, mode="static"):
    run(root, str(bundled_snapshot_path()), out, language, probe_mode=mode)
    return json.loads((out / "verification_ledger.json").read_text(encoding="utf-8"))


def _js_available():
    if not shutil.which("node") or not (Path(__file__).parents[1] / "sentinel_zero/resolvers/js/node_modules").is_dir():
        pytest.skip("Node and resolver dependencies required")


@pytest.mark.parametrize("language", ["python", "javascript"])
@pytest.mark.parametrize("frontend", ["cli", "mcp"])
def test_default_never_executes_target_even_when_docker_is_selected(tmp_path, monkeypatch, language, frontend):
    if language == "javascript":
        _js_available()
    root = tmp_path / "repo"
    root.mkdir()
    marker = tmp_path / "must-not-exist"
    if language == "python":
        (root / "mod.py").write_text(
            f"from pathlib import Path\nimport os\nPath({str(marker)!r}).write_text('imported')\n"
            "def run_it():\n    os.system('never')\n", encoding="utf-8"
        )
    else:
        (root / "mod.cjs").write_text(
            f"require('fs').writeFileSync({json.dumps(str(marker))},'imported');\n"
            "const cp=require('child_process');function run_it(){cp.exec('never');}module.exports={run_it};",
            encoding="utf-8",
        )
    monkeypatch.setenv("SENTINEL_ZERO_PROBE_BACKEND", "docker")
    with patch("sentinel_zero.dogfood_scan.run_sink_reachability_probe") as py_probe, patch(
        "sentinel_zero.dogfood_scan.run_js_sink_reachability_probe"
    ) as js_probe:
        if frontend == "cli":
            out = tmp_path / "out"
            assert cli.main(["analyze", str(root), "--language", language, "--out", str(out)]) == 0
            ledger = json.loads((out / "verification_ledger.json").read_text(encoding="utf-8"))
        else:
            from sentinel_zero.mcp_server import analyze_repository
            ledger = analyze_repository(str(root), language)
    py_probe.assert_not_called()
    js_probe.assert_not_called()
    assert not marker.exists()
    assert ledger["probe_mode"] == "static"
    assert ledger["plans"]
    assert all(p["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE" for p in ledger["plans"])
    assert all("probe_observation" not in p["verification_method"] for p in ledger["plans"])


@pytest.mark.parametrize("attack", ["stdout", "serializer", "null"])
def test_real_js_forgery_remains_untrusted_diagnostic(tmp_path, attack):
    _js_available()
    root = tmp_path / "repo"
    root.mkdir()
    forged = '{"status":"sink_reached","symbol":"child_process.exec","args":"forged"}'
    attacks = {
        "stdout": f"process.stdout.write({json.dumps(forged)});process.exit(0);",
        "serializer": f"JSON.stringify=()=>{json.dumps(forged)};",
        "null": "process.stdout.write('null');process.exit(0);",
    }
    (root / "mod.cjs").write_text(
        "const cp=require('child_process');\nfunction run_it(){return;cp.exec('never');}\n"
        "module.exports={run_it};\n" + attacks[attack], encoding="utf-8"
    )
    ledger = _scan(root, tmp_path / "out", "javascript", "diagnostic")
    plan = ledger["plans"][0]
    assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
    evidence = plan["verification_method"]["probe_observation"]
    assert evidence["trust"] == "target_controlled"
    assert evidence["site_verified"] is False
    assert evidence["requested_site"]["source_node"] == plan["hypothesis"]["source_node"]
    assert evidence["report"]["status"] == ("call_failed" if attack == "null" else "sink_reached")


def _frame_attack():
    return (
        "import sys, os\nframe=sys._getframe()\nwhile frame:\n"
        "    if 'nonce' in frame.f_locals and '_trusted_write' in frame.f_locals:\n"
        "        report={'nonce':frame.f_locals['nonce'],'status':'sink_reached','symbol':'os.system','args':'forged-frame'}\n"
        "        frame.f_locals['_trusted_write'](1,(frame.f_locals['_trusted_dumps'](report)+'\\n').encode())\n"
        "        os._exit(0)\n"
        "    frame=frame.f_back\n"
        "def run_it():\n    return\n    os.system('never')\n"
    )


def test_real_python_frame_forgery_cannot_promote(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_ZERO_PROBE_BACKEND", raising=False)
    root = tmp_path / "repo"
    root.mkdir()
    (root / "mod.py").write_text(_frame_attack(), encoding="utf-8")
    plan = _scan(root, tmp_path / "out", "python", "diagnostic")["plans"][0]
    assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
    observation = plan["verification_method"]["probe_observation"]
    assert observation["report"]["args"] == "forged-frame"
    assert observation["site_verified"] is False


def test_real_locked_container_forgery_cannot_promote(tmp_path):
    if not shutil.which("docker"):
        pytest.skip("Docker executable unavailable")
    available = subprocess.run(["docker", "image", "inspect", "python:3.12-slim"], capture_output=True, timeout=15)
    if available.returncode:
        pytest.skip("Docker daemon and local python:3.12-slim image required; no implicit pull")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "mod.py").write_text(_frame_attack(), encoding="utf-8")
    harness = Path(__file__).parents[1] / "sentinel_zero/probes"
    command = [
        "docker", "run", "--rm", "--network", "none", "--user", "1000:1000",
        "--read-only", "--tmpfs", "/tmp:rw,size=64m", "--memory", "256m", "--pids-limit", "64",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-e", "SENTINEL_ZERO_PROBE_NONCE=audit-nonce",
        "-v", f"{harness}:/harness:ro", "-v", f"{root}:/repo:ro",
        "python:3.12-slim", "python", "-I", "/harness/_sink_reachability_harness.py", "/repo", "mod", "run_it",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    from sentinel_zero.probes.docker_sink_executor import parse_harness_result
    report = parse_harness_result(completed.stdout, "audit-nonce")
    assert report["status"] == "sink_reached"  # Valid nonce still isn't independent proof.
    # Feed that actual container report through the real scan policy,
    # independently of the Docker install lifecycle (a separate open bug).
    with patch("sentinel_zero.dogfood_scan.run_sink_reachability_probe", return_value=report):
        plan = _scan(root, tmp_path / "out", "python", "diagnostic")["plans"][0]
    assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
    assert plan["verification_method"]["probe_observation"]["site_verified"] is False


@pytest.mark.parametrize("raw", [None, [], 1, "sink_reached", {}, {"status": []},
    {"status": "VERIFIED_TRUE"}, {"status": "sink_reached", "symbol": "os.system"},
    {"status": "sink_reached", "symbol": "os.system", "args": []},
    {"status": "sink_reached", "symbol": "x" * 2001, "args": "()"}])
def test_invalid_probe_shapes_fail_closed(raw):
    assert validate_probe_result(raw)["status"] == "call_failed"


def test_target_cannot_supply_authority_or_call_site_fields(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "mod.py").write_text("import os\ndef run_it():\n    os.system('never')\n")
    forged = {"status": "sink_reached", "symbol": "os.system", "args": "()",
              "trust": "verified", "site_verified": True, "source_node": "other.py:1"}
    with patch("sentinel_zero.dogfood_scan.run_sink_reachability_probe", return_value=forged):
        plan = _scan(root, tmp_path / "out", "python", "diagnostic")["plans"][0]
    observation = plan["verification_method"]["probe_observation"]
    assert observation["trust"] == "target_controlled"
    assert observation["site_verified"] is False
    assert observation["requested_site"]["source_node"] == f"{root / 'mod.py'}:3"
    assert set(observation["report"]) == {"status", "symbol", "args"}
    assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_invalid_mode_fails_before_target_resolution(tmp_path):
    with patch("sentinel_zero.dogfood_scan._RESOLVERS") as resolvers:
        from sentinel_zero.disposition import ToolFailure
        with pytest.raises(ToolFailure, match="unknown probe mode"):
            _scan(tmp_path, tmp_path / "out", "python", "trusted")
    assert not resolvers.mock_calls


@pytest.mark.parametrize("status", ["VERIFIED_TRUE", "VERIFIED_FALSE"])
@pytest.mark.parametrize("boundary", ["transition", "serialization"])
def test_parent_authority_rejects_verified_states_even_with_forged_proof_fields(status, boundary):
    from sentinel_zero.disposition import ToolFailure, build_finding_plan, load_catalog, set_disposition

    catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
    plan = build_finding_plan(
        plan_id="proof-policy-test", target_repository="fixture", attack_id="AAC-11", catalog=catalog,
        hypothesis={"source_node": "mod.py:3", "sink_node": "os.system", "symbol_binding": "mod.run_it"},
        verification_method={
            "proof_authority": "independent", "site_verified": True,
            "probe_observation": {"trust": "verified", "nonce": "forged", "site_verified": True,
                                  "requested_site": {"source_node": "mod.py:3", "sink": "os.system"}},
        },
        execution_gate={},
    )
    with pytest.raises(ToolFailure, match="no independent call-site verifier"):
        if boundary == "transition":
            set_disposition(plan, status, reason="forged target report", residual_uncertainty="none")
        else:
            plan.disposition.update(status=status, reason="bypass setter", residual_uncertainty="none")
            plan.as_dict()
    if boundary == "transition":
        assert plan.disposition["status"] == "PENDING"

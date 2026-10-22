"""Lifecycle fault injection and real public-CLI Docker integration."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_zero.probes import container_runner as runner


@pytest.mark.parametrize("failure", [PermissionError("cleanup denied"), subprocess.TimeoutExpired("rm", 10),
                                     subprocess.CompletedProcess([], 1, "", "daemon refused cleanup")])
def test_cleanup_failure_preserves_execution_error(failure):
    real_popen = subprocess.Popen

    def failed_target(*args, **kwargs):
        return real_popen([sys.executable, "-I", "-c",
                           "import sys;sys.stderr.write('original execution error');sys.exit(7)"], **kwargs)

    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "Popen", side_effect=failed_target
    ), patch.object(runner.subprocess, "run", **(
        {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
    )) as cleanup:
        code, _, stderr, timed_out = runner._docker_run([])
    assert code == 7
    assert "original execution error" in stderr
    assert "cleanup failed" in stderr
    assert not timed_out
    assert cleanup.call_args.kwargs["timeout"] == 10


def test_launch_and_cleanup_permission_errors_are_structured():
    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "Popen", side_effect=PermissionError("launch denied")
    ), patch.object(runner.subprocess, "run", side_effect=PermissionError("cleanup denied")):
        code, _, stderr, _ = runner._docker_run([])
    assert code == -1
    assert "launch denied" in stderr and "cleanup denied" in stderr


def test_client_wait_failure_cannot_escape_cleanup():
    from unittest.mock import MagicMock
    process = MagicMock()
    process.poll.return_value = None
    process.stdout.read.return_value = b""
    process.stderr.read.return_value = b""
    process.wait.side_effect = subprocess.TimeoutExpired("docker run", 10)
    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "Popen", return_value=process
    ), patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
        code, _, stderr, timed_out = runner._docker_run([], timeout=0)
    assert code == -1 and timed_out
    assert "execution failed" in stderr and "client cleanup failed" in stderr


def test_cleanup_failure_invalidates_otherwise_successful_report():
    real_popen = subprocess.Popen

    def successful_target(*args, **kwargs):
        return real_popen([sys.executable, "-I", "-c", "print('{}')"], **kwargs)

    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "Popen", side_effect=successful_target
    ), patch.object(runner.subprocess, "run", side_effect=PermissionError("cleanup denied")):
        code, _, stderr, timed_out = runner._docker_run([])
    assert code == -1 and not timed_out
    assert "cleanup denied" in stderr


def test_timeout_keeps_execution_and_cleanup_diagnostics(tmp_path):
    with patch.object(runner, "docker_available", return_value=(True, "available")), patch.object(
        runner, "_docker_run", return_value=(-1, "", "original error; cleanup failed", True)
    ):
        result = runner.run_container_probe("javascript", tmp_path, [])
    assert result["status"] == "call_failed"
    assert "timeout" in result["detail"]
    assert "original error; cleanup failed" in result["detail"]


@pytest.mark.parametrize("language", ["python", "javascript"])
@pytest.mark.docker_integration
def test_public_cli_docker_outcome(tmp_path, language):
    """Runs on either host OS; a Linux worker alone is not Linux-host coverage."""
    available, detail = runner.docker_available()
    if not available:
        pytest.skip(detail)
    image = subprocess.run([runner._docker_executable(), "image", "inspect", runner.IMAGES[language]],
                           capture_output=True, timeout=15)
    if image.returncode:
        pytest.skip("pinned runtime image must already be installed")
    repo = Path(__file__).parents[1]
    if language == "javascript" and (not shutil.which("node") or not (
        repo / "sentinel_zero/resolvers/js/node_modules"
    ).is_dir()):
        pytest.skip("JS resolver dependencies required")
    source = tmp_path / "source"
    source.mkdir()
    # A root-run Linux test must explicitly make this synthetic fixture
    # readable by the non-root worker. Host ancestors are not mounted.
    if os.name != "nt":
        source.chmod(0o755)
    if language == "python":
        (source / "mod.py").write_text("import os\ndef run_it():\n    os.system('positive-control')\n")
    else:
        (source / "mod.cjs").write_text(
            "const cp=require('child_process');function run_it(){cp.exec('never');}"
            "module.exports={run_it};process.stdout.write('null');process.exit(0);"
        )
    env = dict(os.environ, SENTINEL_ZERO_PROBE_BACKEND="docker", PYTHONPATH=str(repo))
    out = tmp_path / "out"
    completed = subprocess.run([sys.executable, "-m", "sentinel_zero.cli", "analyze", str(source),
                                "--probe-mode", "diagnostic", "--language", language, "--out", str(out)],
                               capture_output=True, text=True, timeout=90, cwd=repo, env=env)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Traceback" not in completed.stderr
    ledger = json.loads((out / "verification_ledger.json").read_text(encoding="utf-8"))
    assert ledger["plans"]
    report = ledger["plans"][0]["verification_method"]["probe_observation"]["report"]
    assert report["status"] == ("sink_reached" if language == "python" else "call_failed")
    if language == "javascript":
        assert "expected an object" in report["detail"]
    assert ledger["plans"][0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"

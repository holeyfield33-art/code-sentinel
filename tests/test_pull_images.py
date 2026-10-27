"""F6: pinned runtime images are never pulled by a scan, so a missing image
must fail closed with the exact remedy, and the remedy must be one command."""
import subprocess
from unittest.mock import patch

import pytest

from sentinel_zero import cli
from sentinel_zero.probes import container_runner as runner


def _completed(code, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_missing_image_names_digest_and_remedy(language):
    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "run", return_value=_completed(1, stderr="No such image")
    ) as run:
        ok, detail = runner.image_available(language)
    assert not ok
    assert runner.IMAGES[language] in detail
    assert f"sentinel-zero pull-images --language {language}" in detail
    assert run.call_args.args[0][1:3] == ["image", "inspect"]


def test_present_image_is_reported_available():
    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "run", return_value=_completed(0, stdout="sha256:abc\n")
    ):
        assert runner.image_available("python") == (True, "sha256:abc")


def test_image_check_error_fails_closed():
    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "run", side_effect=subprocess.TimeoutExpired("docker", 15)
    ):
        ok, detail = runner.image_available("javascript")
    assert not ok and "could not check" in detail


def test_probe_stops_before_docker_run_when_image_missing(tmp_path):
    with patch.object(runner, "docker_available", return_value=(True, "available")), patch.object(
        runner, "image_available", return_value=(False, "pinned python runtime image is not installed")
    ), patch.object(runner, "_docker_run") as docker_run:
        result = runner.run_container_probe("python", tmp_path, [])
    assert result == {"status": "call_failed", "detail": "pinned python runtime image is not installed"}
    docker_run.assert_not_called()


def test_container_args_still_never_pull(tmp_path):
    args = runner.build_container_args("python", tmp_path, [])
    assert args[args.index("--pull") + 1] == "never"


def test_cli_pulls_both_pinned_digests_by_default(capsys):
    with patch.object(cli, "docker_available", return_value=(True, "27.0")), patch.object(
        cli, "pull_image", return_value=(True, "img")
    ) as pull:
        assert cli.main(["pull-images"]) == 0
    assert [c.args[0] for c in pull.call_args_list] == list(runner.IMAGES)
    assert "can now run" in capsys.readouterr().out


def test_cli_pulls_one_language(capsys):
    with patch.object(cli, "docker_available", return_value=(True, "27.0")), patch.object(
        cli, "pull_image", return_value=(True, "img")
    ) as pull:
        assert cli.main(["pull-images", "--language", "javascript"]) == 0
    assert [c.args[0] for c in pull.call_args_list] == ["javascript"]


def test_cli_without_daemon_is_tool_failure(capsys):
    with patch.object(cli, "docker_available", return_value=(False, "no socket")), patch.object(
        cli, "pull_image"
    ) as pull:
        assert cli.main(["pull-images"]) == 3
    pull.assert_not_called()
    assert "CRITICAL_TOOL_FAILURE" in capsys.readouterr().err


def test_cli_pull_failure_is_tool_failure(capsys):
    with patch.object(cli, "docker_available", return_value=(True, "27.0")), patch.object(
        cli, "pull_image", return_value=(False, "docker pull x exited 1")
    ):
        assert cli.main(["pull-images"]) == 3
    assert "docker pull x exited 1" in capsys.readouterr().err


def test_pull_image_uses_exact_pinned_digest():
    with patch.object(runner, "_docker_executable", return_value="docker"), patch.object(
        runner.subprocess, "run", return_value=_completed(0)
    ) as run:
        assert runner.pull_image("python") == (True, runner.IMAGES["python"])
    assert run.call_args.args[0] == ["docker", "pull", runner.IMAGES["python"]]

"""F1: --mount values must round-trip through Docker's CSV + first-"=" parser.

Docker splits each --mount field on its FIRST "=" (docker/cli opts/mount.go,
strings.Cut), so "=" inside a path is carried intact and is accepted here.
Characters that change how the CSV record parses are rejected up front."""
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_zero.probes import container_runner as runner


def _mounts(args):
    return [args[i + 1] for i, a in enumerate(args) if a == "--mount"]


@pytest.mark.skipif(os.name == "nt", reason="'\"' and newlines are not valid in Windows paths")
@pytest.mark.parametrize("name", ["a,dst=evil", 'a"b', "a\nb", "a\rb", "trailing "])
def test_unsafe_source_paths_rejected(tmp_path, name):
    target = tmp_path / name
    target.mkdir()
    with pytest.raises(ValueError, match="probe source path"):
        runner.build_container_args("python", target, [])


@pytest.mark.parametrize("name", ["a=b", "key=value=more", "plain"])
def test_equals_in_source_path_is_carried_intact(tmp_path, name):
    target = tmp_path / name
    target.mkdir()
    source_mount = _mounts(runner.build_container_args("python", target, []))[0]
    assert source_mount == f"type=bind,src={target.resolve()},dst=/repo,readonly"
    # Mirror Docker's per-field parse: split on the first "=" only.
    fields = dict(f.split("=", 1) for f in source_mount.split(",") if "=" in f)
    assert fields["src"] == str(target.resolve())
    assert fields["dst"] == "/repo"


def test_unsafe_harness_install_path_rejected(tmp_path):
    bad = tmp_path / "site,dst=evil"
    bad.mkdir()
    with patch.object(runner, "_HARNESS_DIR", bad):
        with pytest.raises(ValueError, match="harness install path"):
            runner.build_container_args("python", tmp_path, [])


def test_source_must_be_directory(tmp_path):
    with pytest.raises(ValueError, match="must be a directory"):
        runner.build_container_args("python", tmp_path / "missing", [])


def test_rejected_path_fails_closed_before_docker(tmp_path):
    bad = tmp_path / "x,y"
    bad.mkdir()
    with patch.object(runner, "docker_available", return_value=(True, "ok")), patch.object(
        runner, "image_available", return_value=(True, "id")
    ), patch.object(runner, "_docker_run") as docker_run:
        result = runner.run_container_probe("python", bad, [])
    assert result["status"] == "call_failed" and "Docker --mount" in result["detail"]
    docker_run.assert_not_called()


def test_unsafe_chars_match_docs():
    assert set(runner._MOUNT_UNSAFE_CHARS) == {",", '"', "\n", "\r"}
    assert "=" not in runner._MOUNT_UNSAFE_CHARS

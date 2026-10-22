"""Actual public Python/JS adapters must enforce host isolation, not just flags."""
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_zero.probes.container_runner import IMAGES, build_container_args, docker_available
from sentinel_zero.probes.js_sink_reachability_probe import run_js_sink_reachability_probe
from sentinel_zero.probes.sink_reachability_probe import run_sink_reachability_probe


@pytest.fixture(params=["python", "javascript"])
def runtime(request):
    language = request.param
    available, detail = docker_available()
    if not available:
        pytest.skip(f"real Docker integration unavailable: {detail}")
    p = subprocess.run(["docker", "image", "inspect", IMAGES[language]], capture_output=True, timeout=15)
    if p.returncode:
        pytest.skip(f"pinned {language} runtime image not present; pull it explicitly")
    return language


def _probe(root, language, source):
    name = "mod.py" if language == "python" else "mod.cjs"
    path = root / name
    path.write_text(source, encoding="utf-8")
    return (run_sink_reachability_probe(root, "mod", "run_it") if language == "python"
            else run_js_sink_reachability_probe(str(path), "run_it", repo_root=root))


@pytest.mark.docker_integration
def test_real_container_hides_parent_env_and_cwd(tmp_path, monkeypatch, runtime):
    monkeypatch.setenv("SENTINEL_ISOLATION_FAKE_SECRET", "synthetic-parent-secret")
    # HOME is asserted to be a fixed container value below. Host Docker
    # still needs its own normal configuration to contact the daemon.
    marker = tmp_path / "host-cwd-marker"
    marker.write_text("private-parent-cwd")
    monkeypatch.chdir(tmp_path)
    root = tmp_path / "repo"
    root.mkdir()
    if runtime == "python":
        source = (
            "import os, _io\ndef run_it():\n"
            "    assert os.environ.get('SENTINEL_ISOLATION_FAKE_SECRET') is None\n"
            "    assert os.environ.get('HOME') == '/scratch'\n"
            "    assert os.getcwd() == '/scratch'\n"
            "    assert not os.path.exists('host-cwd-marker')\n"
            "    assert os.getuid() == 1000\n"
            "    status=_io.FileIO('/proc/self/status').read().decode()\n"
            "    assert 'CapEff:\\t0000000000000000' in status\n"
            "    assert 'NoNewPrivs:\\t1' in status\n"
            "    assert len(_io.FileIO('/proc/net/route').read().decode().splitlines()) == 1\n"
            "    os.system('positive-control')\n"
        )
    else:
        source = (
            "const cp=require('child_process'); const fs=require('fs');\n"
            "exports.run_it=function(){\n"
            "if(process.env.SENTINEL_ISOLATION_FAKE_SECRET!==undefined)throw Error('secret leak');\n"
            "if(process.env.HOME!=='/scratch'||process.cwd()!=='/scratch')throw Error('host cwd/home leaked');\n"
            "if(fs.existsSync('host-cwd-marker'))throw Error('host cwd exposed');\n"
            "if(process.getuid()!==1000)throw Error('root user');\n"
            "let status=fs.readFileSync('/proc/self/status','utf8');\n"
            "if(!status.includes('CapEff:\\t0000000000000000')||!status.includes('NoNewPrivs:\\t1'))throw Error('privileges');\n"
            "if(fs.readFileSync('/proc/net/route','utf8').trim().split('\\n').length!==1)throw Error('network route');\n"
            "cp.exec('positive-control');};\n"
        )
    result = _probe(root, runtime, source)
    assert result["status"] == "sink_reached", result
    assert result["symbol"] == ("os.system" if runtime == "python" else "child_process.exec")


@pytest.mark.docker_integration
def test_real_unpatched_file_writes_stay_in_private_scratch(tmp_path, runtime):
    root = tmp_path / "repo"
    root.mkdir()
    if runtime == "python":
        source = (
            "import _io, os\ndef run_it():\n"
            "    _io.FileIO('scratch-marker','w').write(b'private')\n"
            "    try:\n        _io.FileIO('/repo/host-marker','w').write(b'escape')\n"
            "    except OSError:\n        pass\n"
            "    else:\n        raise RuntimeError('source was writable')\n"
            "    os.system('positive-control')\n"
        )
    else:
        source = (
            "const fs=require('fs'),cp=require('child_process');\nexports.run_it=function(){\n"
            "let fd=fs.openSync('scratch-marker','w');fs.writeSync(fd,'private');fs.closeSync(fd);\n"
            "let refused=false;try{fd=fs.openSync('/repo/host-marker','w');fs.writeSync(fd,'escape');}catch(e){refused=true;}\n"
            "if(!refused)throw Error('source was writable');cp.exec('positive-control');};\n"
        )
    result = _probe(root, runtime, source)
    assert result["status"] == "sink_reached", result
    assert not (root / "host-marker").exists()
    assert not (root / "scratch-marker").exists()
    assert not (tmp_path / "scratch-marker").exists()


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_no_daemon_never_falls_back_to_host(tmp_path, language):
    marker = tmp_path / "not-executed"
    source = (f"from pathlib import Path\nPath({str(marker)!r}).write_text('escape')\ndef run_it():\n    pass\n"
              if language == "python" else
              f"require('fs').writeFileSync({json.dumps(str(marker))},'escape');exports.run_it=()=>{{}};")
    with patch("sentinel_zero.probes.container_runner.docker_available", return_value=(False, "mock no daemon")), patch(
        "sentinel_zero.probes.container_runner._docker_run"
    ) as runner:
        result = _probe(tmp_path, language, source)
    assert result["status"] == "call_failed"
    assert "no host fallback" in result["detail"]
    runner.assert_not_called()
    assert not marker.exists()


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_explicit_subprocess_backend_is_rejected(tmp_path, monkeypatch, language):
    monkeypatch.setenv("SENTINEL_ZERO_PROBE_BACKEND", "subprocess")
    with patch("sentinel_zero.probes.container_runner._docker_run") as runner:
        result = _probe(tmp_path, language, "def run_it(): pass" if language == "python" else "exports.run_it=()=>{};")
    assert result["status"] == "call_failed"
    assert "disabled" in result["detail"]
    runner.assert_not_called()


def test_js_source_cannot_escape_declared_repository(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.cjs"
    outside.write_text("exports.run_it=()=>{};")
    with patch("sentinel_zero.probes.js_sink_reachability_probe.run_container_probe") as runner:
        result = run_js_sink_reachability_probe(str(outside), "run_it", repo_root=root)
    assert result["status"] == "call_failed"
    runner.assert_not_called()


@pytest.mark.parametrize("language", ["python", "javascript"])
def test_container_args_do_not_inherit_host_environment(tmp_path, monkeypatch, language):
    monkeypatch.setenv("HOME", "fake-home-secret")
    monkeypatch.setenv("NODE_OPTIONS", "--require=host-code")
    args = build_container_args(language, tmp_path, [])
    assert args[args.index("--pull") + 1] == "never"
    assert "@sha256:" in IMAGES[language]
    assert "fake-home-secret" not in " ".join(args)
    assert "--require=host-code" not in " ".join(args)
    for flag in ("--read-only", "--network", "none", "--cap-drop", "ALL", "--user", "1000:1000"):
        assert flag in args


def test_container_output_is_bounded_and_overflow_fails_closed(tmp_path):
    # Exercise the real parent output-draining path with a local synthetic
    # emitter in place of the Docker CLI, not target execution as a fallback.
    import sys
    from sentinel_zero.probes import container_runner
    real_popen = subprocess.Popen
    emitted = []

    def emitter(*args, **kwargs):
        emitted.append(args[0])
        return real_popen([sys.executable, "-I", "-c", "import os;os.write(1,b'x'*300000)"], **kwargs)

    with patch.object(container_runner.subprocess, "Popen", side_effect=emitter), patch.object(
        container_runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")
    ) as remove:
        code, stdout, stderr, timed_out = container_runner._docker_run([], timeout=5)
    assert code != 0
    assert not stdout
    assert "byte limit" in stderr
    assert not timed_out
    assert Path(emitted[0][0]).stem == "docker"
    assert emitted[0][1] == "run"
    remove.assert_called()


def test_timeout_removes_named_container_and_never_retries_on_host():
    import sys
    from sentinel_zero.probes import container_runner
    real_popen = subprocess.Popen

    def sleepy(*args, **kwargs):
        return real_popen([sys.executable, "-I", "-c", "import time;time.sleep(60)"], **kwargs)

    with patch.object(container_runner.subprocess, "Popen", side_effect=sleepy), patch.object(
        container_runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")
    ) as cleanup:
        code, stdout, stderr, timed_out = container_runner._docker_run([], timeout=0)
    assert timed_out
    assert code != 0
    assert any(c.args[0][1:3] == ["rm", "-f"] for c in cleanup.call_args_list)


def test_external_source_symlink_is_refused_before_launch(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "parent-private"
    outside.mkdir()
    (outside / "secret").write_text("synthetic-host-secret")
    link = root / "escape"
    junction = False
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        if os.name != "nt":
            pytest.skip("host does not permit creation of a directory symlink")
        # A Windows directory junction exercises the reparse-point path
        # without requiring the symlink-creation privilege.
        quoted_link = str(link).replace("'", "''")
        quoted_target = str(outside).replace("'", "''")
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"New-Item -ItemType Junction -Path '{quoted_link}' -Target '{quoted_target}' | Out-Null"],
            check=True, capture_output=True, timeout=15,
        )
        junction = True
    try:
        with pytest.raises(ValueError, match="escaping or unreadable link"):
            build_container_args("python", root, [])
    finally:
        if junction:
            os.rmdir(link)  # Remove only our junction entry, never recurse into its target.
        else:
            link.unlink()


def test_hostile_cwd_cannot_supply_docker_executable(tmp_path, monkeypatch):
    from sentinel_zero.probes import container_runner
    name = "docker.exe" if os.name == "nt" else "docker"
    tools = tmp_path / "trusted-tools"
    tools.mkdir()
    trusted = tools / name
    trusted.write_text("test executable placeholder; subprocess is mocked")
    trusted.chmod(0o755)
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    (hostile / name).write_text("must not be selected")
    monkeypatch.chdir(hostile)
    monkeypatch.setenv("PATH", os.pathsep.join(["", ".", str(tools)]))
    with patch.object(container_runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "test", "")) as run:
        assert container_runner.docker_available()[0]
    assert run.call_args.args[0][0] == str(trusted.resolve())
    assert run.call_args.kwargs["cwd"] == container_runner._HARNESS_DIR

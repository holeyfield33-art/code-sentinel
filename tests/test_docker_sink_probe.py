"""VERIFICATION_LEDGER.md sz-2026-10-21-19: the Docker-backed probe
backend (sentinel_zero/probes/docker_sink_executor.py) and its dispatch
from sink_reachability_probe.py.

No Docker daemon is reachable in this session (confirmed via
docker_available() itself, exercised below as a real, unmocked call --
not assumed), so these tests cover exactly what can honestly be checked
without one: argument/flag construction for the execute phase, the
nonce-authenticated result parser, and the dispatcher's behavior when the
docker backend is requested but unavailable. They do NOT exercise a real
container run -- that still needs a smoke test wherever Docker actually
runs, per the module's own docstring.
"""
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from sentinel_zero.probes import docker_sink_executor
from sentinel_zero.probes.docker_sink_executor import (
    _INSTALL_SCRIPT,
    _install_user,
    build_docker_run_args,
    docker_available,
    parse_harness_result,
)
from sentinel_zero.probes.sink_reachability_probe import run_sink_reachability_probe


def test_docker_availability_in_this_environment_is_recorded_not_assumed_elsewhere():
    """Not a mock -- a real call, confirming (rather than assuming) the
    actual state of this session's environment. Codex review, PR #5: the
    original version of this test unconditionally asserted `available is
    False`, which would fail outright on any developer or CI machine
    with a reachable Docker daemon -- exactly the environment this
    backend is meant to be smoke-tested in. Rather than assert a
    machine-specific fact, this self-skips when Docker IS reachable: the
    "not verified end-to-end" caveat in the module docstring is about
    THIS session specifically, not a portable property of every
    environment this suite might run in. Deterministic coverage of the
    dispatcher's own behavior in each case lives in the mocked tests
    below, which don't depend on what this one finds."""
    available, detail = docker_available()
    if available:
        pytest.skip(f"Docker IS reachable here ({detail}) -- unavailability is not a fact this suite can assume.")
    assert available is False


def test_execute_phase_args_carry_every_lock_down_flag():
    """The security model readme-tester's executor proved out and this
    file ported by hand: network segmentation, no capabilities, no
    privilege escalation, a read-only root, and resource caps. If any of
    these silently drop out of the argument list, the "real OS-level
    isolation" claim in the module docstring stops being true -- so this
    test pins the whole list, not just one flag."""
    with tempfile.TemporaryDirectory() as env_dir:
        args = build_docker_run_args(
            env_path=Path(env_dir),
            module_qualname="pkg.mod",
            function_name="run_it",
            args_repr=None,
            nonce="deadbeef",
        )
        for flag in (
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            "--pids-limit", "128",
            "--cpus", "1",
            "--memory", "1g",
            "--user", "1000:1000",
        ):
            assert flag in args, f"missing lock-down flag {flag!r} in execute-phase args"
        # The harness is invoked through the mounted venv's own
        # interpreter against the mounted, install-phase-populated
        # source copy -- never the bare /repo mount (which the execute
        # phase doesn't even receive -- see module docstring on why).
        assert "/env/venv/bin/python" in args
        assert "/harness/_sink_reachability_harness.py" in args
        assert "/env/src" in args
        assert "pkg.mod" in args
        assert "run_it" in args


def test_execute_phase_args_pass_the_nonce_and_never_the_target_args_by_accident():
    with tempfile.TemporaryDirectory() as env_dir:
        args = build_docker_run_args(
            env_path=Path(env_dir),
            module_qualname="pkg.mod",
            function_name="run_it",
            args_repr="(1, 'x')",
            nonce="cafef00d",
        )
        assert "SENTINEL_ZERO_PROBE_NONCE=cafef00d" in args
        assert "(1, 'x')" in args


def test_execute_phase_args_only_pass_allowlisted_env_names():
    """Same allowlist discipline as the subprocess backend: a real
    secret sitting in the scan process's own environment under a name
    not on the allowlist must never show up as a `-e NAME=value` pair."""
    with tempfile.TemporaryDirectory() as env_dir:
        os.environ["SENTINEL_ZERO_TEST_NOT_ALLOWLISTED"] = "sz-real-secret-4f9c"
        try:
            args = build_docker_run_args(
                env_path=Path(env_dir),
                module_qualname="pkg.mod",
                function_name="run_it",
                args_repr=None,
                nonce="abc123",
            )
            assert not any("sz-real-secret-4f9c" in a for a in args)
        finally:
            del os.environ["SENTINEL_ZERO_TEST_NOT_ALLOWLISTED"]


def test_parse_harness_result_accepts_a_correctly_nonced_line():
    stdout = json.dumps({"status": "sink_reached", "symbol": "os.system", "args": "()", "nonce": "n1"}) + "\n"
    result = parse_harness_result(stdout, nonce="n1")
    assert result["status"] == "sink_reached"
    assert "nonce" not in result


def test_parse_harness_result_rejects_a_mismatched_or_forged_nonce():
    stdout = json.dumps({"status": "sink_reached", "symbol": "os.system", "args": "()", "nonce": "wrong"}) + "\n"
    result = parse_harness_result(stdout, nonce="n1")
    assert result["status"] == "call_failed"
    assert "nonce" in result["detail"]


def test_parse_harness_result_handles_empty_output():
    assert parse_harness_result("", nonce="n1")["status"] == "call_failed"


def test_dispatcher_reports_a_clear_failure_rather_than_silently_falling_back():
    """VERIFICATION_LEDGER.md sz-2026-10-21-19: requesting the docker
    backend without a reachable daemon must be a visible call_failed,
    never a silent switch back to the subprocess backend -- the two
    backends make different isolation claims, and conflating them on
    failure would make the stronger claim unverifiable from the
    caller's side. Relies on the real environment genuinely having no
    Docker daemon (confirmed by the test above); the mocked version
    right below covers the identical path deterministically, regardless
    of what this host actually has."""
    if docker_available()[0]:
        pytest.skip("Docker IS reachable here -- this exact path is covered deterministically by the mocked test below.")
    os.environ["SENTINEL_ZERO_PROBE_BACKEND"] = "docker"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mod.py").write_text("def run_it():\n    pass\n")
            result = run_sink_reachability_probe(root, "mod", "run_it")
            assert result["status"] == "call_failed"
            assert "docker" in result["detail"].lower()
            assert "daemon" in result["detail"].lower()
    finally:
        del os.environ["SENTINEL_ZERO_PROBE_BACKEND"]


def test_dispatcher_reports_a_clear_failure_when_docker_is_unavailable_mocked():
    """Codex review, PR #5: deterministic coverage for the dispatcher's
    unavailable-docker path, independent of whether THIS host actually
    has Docker -- mocks docker_available() to return False regardless of
    the real environment, so this test (unlike the one above) passes the
    same way on every machine, including one with a reachable daemon."""
    with mock.patch(
        "sentinel_zero.probes.docker_sink_executor.docker_available",
        return_value=(False, "mocked: no daemon reachable"),
    ):
        os.environ["SENTINEL_ZERO_PROBE_BACKEND"] = "docker"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "mod.py").write_text("def run_it():\n    pass\n")
                result = run_sink_reachability_probe(root, "mod", "run_it")
                assert result["status"] == "call_failed"
                assert "docker" in result["detail"].lower()
                assert "daemon" in result["detail"].lower()
        finally:
            del os.environ["SENTINEL_ZERO_PROBE_BACKEND"]


def test_dispatcher_rejects_an_unknown_backend_name_rather_than_guessing():
    os.environ["SENTINEL_ZERO_PROBE_BACKEND"] = "not-a-real-backend"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "mod.py").write_text("def run_it():\n    pass\n")
            result = run_sink_reachability_probe(root, "mod", "run_it")
            assert result["status"] == "call_failed"
            assert "unknown" in result["detail"].lower()
    finally:
        del os.environ["SENTINEL_ZERO_PROBE_BACKEND"]


def test_default_backend_is_unchanged_subprocess_behavior():
    """No SENTINEL_ZERO_PROBE_BACKEND set at all -- every existing
    caller, unmodified -- must still get the original subprocess
    backend's real, working behavior, not a call_failed stub."""
    assert "SENTINEL_ZERO_PROBE_BACKEND" not in os.environ
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "good.py").write_text("import subprocess\ndef run_it():\n    subprocess.run(['echo', 'hi'])\n")
        result = run_sink_reachability_probe(root, "good", "run_it")
        assert result["status"] == "sink_reached"
        assert result["symbol"] == "subprocess.run"


def test_install_script_never_swallows_a_real_pip_failure():
    """Codex review, PR #5: `|| true` on either pip install line defeated
    `set -e` for the one case that actually matters -- a manifest DOES
    exist and pip genuinely fails -- making the install container
    report success regardless, so `_install` believed a broken/partial
    environment was fine to probe. Pinned directly against the script
    text rather than a real docker run, since no daemon is reachable
    here to exercise it end to end."""
    assert "|| true" not in _INSTALL_SCRIPT
    assert "pip install --no-cache-dir --quiet -e .\n" in _INSTALL_SCRIPT
    assert "pip install --no-cache-dir --quiet -r requirements.txt\n" in _INSTALL_SCRIPT


def test_install_user_matches_the_host_uid_so_cleanup_can_remove_its_files():
    """Codex review, PR #5: the install container used to run as a
    hardcoded 1000:1000, creating /env/src and the venv inside the
    bind-mounted temp dir as that UID. On a host whose own process isn't
    UID 1000, tempfile.TemporaryDirectory's cleanup can't remove files
    it doesn't own, turning an otherwise-successful probe into a
    PermissionError. _install_user() must report the HOST's actual
    UID/GID (when os.getuid/getgid exist), not a hardcoded value."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        pytest.skip("os.getuid/getgid not available on this platform (not Linux/macOS)")
    assert _install_user() == f"{getuid()}:{getgid()}"


def test_install_user_falls_back_to_a_fixed_uid_without_getuid():
    """The non-Linux/macOS fallback path, exercised deterministically by
    removing os.getuid/getgid regardless of what this host actually
    has."""
    with mock.patch.object(docker_sink_executor.os, "getuid", None, create=True), mock.patch.object(
        docker_sink_executor.os, "getgid", None, create=True
    ):
        assert _install_user() == "1000:1000"

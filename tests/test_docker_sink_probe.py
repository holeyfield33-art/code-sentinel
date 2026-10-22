"""Container flags, report parsing, and fail-closed backend selection.

Public-adapter OS isolation is exercised separately in
test_container_isolation.py against a real daemon and pinned images.
"""
import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from sentinel_zero.probes.docker_sink_executor import (
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
            "--pids-limit", "64",
            "--cpus", "1",
            "--memory", "512m",
            "--user", "1000:1000",
        ):
            assert flag in args, f"missing lock-down flag {flag!r} in execute-phase args"
        # Use the image interpreter and read-only source directly.
        # No host virtualenv or install-phase writable bind exists.
        assert "/usr/local/bin/python" in args
        assert "/harness/_sink_reachability_harness.py" in args
        assert "/repo" in args
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
        "sentinel_zero.probes.container_runner.docker_available",
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


def test_default_backend_retains_positive_sink_report_inside_docker():
    """The default retains benign reports, but only inside Docker."""
    assert "SENTINEL_ZERO_PROBE_BACKEND" not in os.environ
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "good.py").write_text("import subprocess\ndef run_it():\n    subprocess.run(['echo', 'hi'])\n")
        result = run_sink_reachability_probe(root, "good", "run_it")
        assert result["status"] == "sink_reached"
        assert result["symbol"] == "subprocess.run"


def test_probe_never_installs_untrusted_manifests():
    with tempfile.TemporaryDirectory() as tmp:
        args = build_docker_run_args(env_path=Path(tmp), module_qualname="mod", function_name="run_it", args_repr=None, nonce="n")
        assert not any("pip" in arg or "npm" in arg for arg in args)
        assert "/usr/local/bin/python" in args



def test_source_mount_is_readonly_and_no_host_virtualenv_is_created():
    with tempfile.TemporaryDirectory() as tmp:
        args = build_docker_run_args(env_path=Path(tmp), module_qualname="mod", function_name="run_it", args_repr=None, nonce="n")
        mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
        assert len(mounts) == 2
        assert all(m.endswith(",readonly") for m in mounts)
        assert not (Path(tmp) / "venv").exists()



def test_container_user_is_nonroot_regardless_of_host_uid():
    with tempfile.TemporaryDirectory() as tmp:
        args = build_docker_run_args(env_path=Path(tmp), module_qualname="mod", function_name="run_it", args_repr=None, nonce="n")
        assert args[args.index("--user") + 1] == "1000:1000"

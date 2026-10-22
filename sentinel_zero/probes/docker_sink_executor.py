"""Docker-backed diagnostic execution; target output is not trusted proof.

The scan parent never grants VERIFIED_TRUE from this backend's reports.
Container isolation does not separate the target from the harness that
produces those reports. The historical design notes below still describe
the execution boundary and its limitations.

Ported logic (NOT a dependency) from Ashura's own readme-tester project
(`liedetector/executor.py`): the same two-phase install/execute split and
the same container lock-down flags (network segmentation, cap-drop,
read-only root, pids/cpu/mem limits, non-root user, no-new-privileges).
This file is entirely self-contained -- sentinel-zero does not import or
depend on the readme-tester package, and never will just to get this;
the security-flag *pattern* was copied and adapted by hand, not reused as
a library.

Why this exists: VERIFICATION_LEDGER.md sz-2026-10-21-14 recorded, after
two independent Verifier rounds each broke the subprocess-based probe's
in-process monkeypatch "sandbox" via a different unpatched primitive
(`os.open`+`/proc/self/environ`, then `io.FileIO`), that a genuine fix
needs real OS-level isolation -- a container, seccomp, a real
separate-privilege process -- not another name added to the patch table.
This module is that fix, offered as an OPT-IN alternate backend (see
`SENTINEL_ZERO_PROBE_BACKEND` in `sink_reachability_probe.py`): the
existing subprocess backend remains the default and is completely
unchanged by this file's existence.

STATED PLAINLY, NOT GLOSSED OVER: this module's claims are NOT verified
end-to-end as of the session that wrote it. No Docker daemon was
reachable in that environment (`docker_available()` below genuinely
returns `False` there -- confirmed, not assumed). Everything here was
checked at the level this session COULD check it: argument/flag
construction, stdout parsing, and the backend-selection fallback, all
exercised with a mocked `subprocess.run` (see
`tests/test_docker_sink_probe.py`). It has never actually launched a
real container. It needs a real smoke test wherever Docker actually
runs -- a dev machine, CI -- before anyone trusts a `sink_reached`
result that came out of it, let alone before it becomes the default.

Design, two phases per probe call (today: one fresh install per call, not
cached/reused across calls within a scan -- see the module-level TODO
below for why that's a deliberate, disclosed limitation rather than an
oversight):

  1. install (network ON): copies the target repo into a fresh,
     per-call writable Docker volume, creates a venv there, and
     best-effort installs it -- `pip install -e .` if a pyproject.toml
     or setup.py exists, else `pip install -r requirements.txt` if one
     exists, else nothing. This is the SAME honest limitation the
     existing subprocess backend already discloses in its own docstring:
     a target with real third-party dependencies and no manifest at all
     only gets the stdlib. The install phase never hard-fails the probe
     just because there was nothing to install -- only a genuine
     install-command failure (pip exiting non-zero on a manifest that
     DOES exist) is reported as call_failed.
  2. execute (network NONE, read-only root filesystem, non-root user,
     all Linux capabilities dropped, no-new-privileges, cpu/mem/pids
     capped, hard timeout): runs the EXACT SAME, already-hardened
     `_sink_reachability_harness.py` from this project (mounted
     read-only), against the venv's own python interpreter. This file
     does not reimplement the harness or its nonce protocol -- every
     bit of this evening's hardening (the nonce, the trusted
     json.dumps/os.write capture) carries over unchanged. All this file
     changes is how that harness gets launched.

Explicit, disclosed gap versus readme-tester's own executor: no pinned
image digest yet (uses a floating tag, `python:3.12-slim`) -- a real
difference from the stronger claim readme-tester makes for itself,
called out here rather than silently matched to it.

Explicit, disclosed gap in this module's OWN isolation claim (Codex
review, PR #5, VERIFICATION_LEDGER.md sz-2026-10-21-24, flagged to the
user rather than fixed unilaterally): containerizing the process does
nothing for the harness/target boundary WITHIN that one process. The
nonce still travels through the target's own environment (the same
`_io.FileIO('/proc/self/environ')` bypass already documented for the
subprocess backend works just as well inside this container), so this
backend's container-isolation claim and its nonce-authentication claim
are independent -- today it only delivers the first. A real fix needs
the harness and the target to run in genuinely separate processes with
the nonce confined to one the target never touches, which is an
architecture change to `_sink_reachability_harness.py` itself (shared
with the subprocess backend), not a local patch to this file.

TODO (deliberately not done here, same "pick the bounded fix first"
principle as every item in docs/REMEDIATION_PLAN.md): installing fresh
per probe call is wasteful when a scan probes many findings in the same
repo. Caching the install phase's volume across probe calls for one scan
run needs a lifecycle hook in dogfood_scan.py's own scan entrypoint
(construct once, reuse, clean up at the end) that does not exist yet --
a real design decision, not a drop-in optimization, so it's left as a
named follow-up rather than guessed at here.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import uuid
from pathlib import Path

from sentinel_zero.probes.evidence import validate_probe_result

DOCKER_IMAGE = "python:3.12-slim"
INSTALL_TIMEOUT_SECONDS = 180
EXECUTE_TIMEOUT_SECONDS = 15

_HARNESS_PATH = Path(__file__).parent / "_sink_reachability_harness.py"
_NONCE_ENV_VAR = "SENTINEL_ZERO_PROBE_NONCE"
# Same allowlist as sink_reachability_probe.py's subprocess backend --
# kept identical and not imported from there, so this file has no import
# dependency on the backend it's an alternative to.
_ENV_PASSTHROUGH_NAMES = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "HOME")

_INSTALL_SCRIPT = (
    "set -e\n"
    "cp -r /repo /env/src\n"
    "cd /env/src\n"
    "python -m venv /env/venv\n"
    # Codex review, PR #5: `|| true` here defeated `set -e` for the one
    # case that actually matters -- a manifest DOES exist and pip
    # genuinely fails (bad pin, unreachable index, broken editable
    # build). That made the install container exit 0 regardless, so
    # `_install` reported success and the harness went on to probe a
    # partial environment, which can produce misleading reachability
    # evidence (e.g. exercising an ImportError fallback branch as if it
    # were the real code path) instead of the promised call_failed. The
    # "never hard-fail just because there's nothing to install" bound
    # this module's docstring states is still intact -- these `if`
    # branches are skipped entirely, not reached, when no manifest
    # exists at all.
    "if [ -f pyproject.toml ] || [ -f setup.py ]; then\n"
    "    /env/venv/bin/pip install --no-cache-dir --quiet -e .\n"
    "elif [ -f requirements.txt ]; then\n"
    "    /env/venv/bin/pip install --no-cache-dir --quiet -r requirements.txt\n"
    "fi\n"
)


def docker_available() -> tuple[bool, str]:
    """Whether a Docker daemon is actually reachable right now. Ported
    from readme-tester's own doctor check, same shape and same reasoning:
    the `docker` CLI binary being on PATH proves nothing about whether a
    daemon is actually running and reachable -- check both, trust
    neither alone."""
    try:
        proc = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if proc.returncode != 0:
        return False, proc.stderr.strip()
    return True, proc.stdout.strip()


def build_docker_run_args(
    *,
    env_path: Path,
    module_qualname: str,
    function_name: str,
    args_repr: str | None,
    nonce: str,
) -> list[str]:
    """Pure argument construction for the execute phase, split out from
    the actual docker invocation so it can be tested (flags present, in
    the right shape) without a live daemon. Mirrors _docker_run's own
    `docker run` argument convention: this returns everything after
    `docker run --name <generated>`."""
    env_args: list[str] = []
    for name in _ENV_PASSTHROUGH_NAMES:
        value = os.environ.get(name)
        if value:
            env_args += ["-e", f"{name}={value}"]
    env_args += ["-e", f"{_NONCE_ENV_VAR}={nonce}"]

    argv = [
        "/env/venv/bin/python",
        "-I",
        "/harness/_sink_reachability_harness.py",
        "/env/src",
        module_qualname,
        function_name,
    ]
    if args_repr is not None:
        argv.append(args_repr)

    return [
        "--rm",
        "--network", "none",
        "--user", "1000:1000",
        *env_args,
        "--read-only",
        "--tmpfs", "/tmp:rw,size=256m",
        "--cpus", "1",
        "--memory", "1g",
        "--pids-limit", "128",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "-v", f"{env_path}:/env:ro",
        "-v", f"{_HARNESS_PATH.parent}:/harness:ro",
        "-w", "/tmp",
        DOCKER_IMAGE,
        *argv,
    ]


def _docker_run(args: list[str], timeout: int) -> tuple[int, str, str, bool]:
    name = f"sentinel-zero-probe-{uuid.uuid4().hex[:12]}"
    cmd = ["docker", "run", "--name", name, *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr, False
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "kill", name], capture_output=True)
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return -1, stdout, stderr, True
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _install_user() -> str:
    """Codex review, PR #5: the install container used to run as a
    hardcoded `1000:1000`, but `cp -r`/`pip install` create `/env/src` and
    the venv INSIDE the bind-mounted `env_path` as that UID, at the
    directory's normal (0755) mode. On a host where the process running
    Sentinel is not UID 1000, `tempfile.TemporaryDirectory`'s own cleanup
    then can't remove those nested files/dirs it doesn't own, and an
    otherwise-successful probe raises PermissionError instead of
    returning its result. Running the install container as the HOST's
    own UID/GID instead makes every file it creates removable by the
    same process that will later clean it up -- on platforms without
    os.getuid (not Linux/macOS), falls back to the previous `1000:1000`,
    since Docker itself is Linux-container-only here regardless."""
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if getuid is None or getgid is None:
        return "1000:1000"
    return f"{getuid()}:{getgid()}"


def _install(repo_root: Path, env_path: Path) -> tuple[bool, str]:
    env_path.chmod(0o777)
    code, stdout, stderr, timed_out = _docker_run(
        [
            "--rm",
            "--user", _install_user(),
            "-e", "HOME=/tmp",
            "--tmpfs", "/tmp:rw,size=512m",
            "-v", f"{repo_root}:/repo:ro",
            "-v", f"{env_path}:/env:rw",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "256",
            DOCKER_IMAGE,
            "sh", "-c", _INSTALL_SCRIPT,
        ],
        timeout=INSTALL_TIMEOUT_SECONDS,
    )
    ok = code == 0 and not timed_out
    return ok, f"install exit={code} timed_out={timed_out}\n{stdout}\n{stderr}"


def parse_harness_result(stdout: str, nonce: str) -> dict:
    """Same nonce-authenticated last-line parsing as
    sink_reachability_probe.py's subprocess backend -- duplicated rather
    than imported, so this file stays genuinely standalone, but kept
    behaviorally identical on purpose: a forged or stale line is
    discarded as untrusted, never read as real probe evidence."""
    lines = [line for line in stdout.strip().splitlines() if line.strip()]
    if not lines:
        return {"status": "call_failed", "detail": "harness produced no output"}
    try:
        result = json.loads(lines[-1])
    except ValueError as exc:
        return {"status": "call_failed", "detail": f"could not parse harness output: {exc}"}
    if not isinstance(result, dict) or result.get("nonce") != nonce:
        return {
            "status": "call_failed",
            "detail": "harness result missing or mismatched nonce -- discarding as untrusted "
            "(this is the expected outcome for a forged or stale result line, not a crash)",
        }
    result.pop("nonce", None)
    return validate_probe_result(result)


def run_sink_reachability_probe_docker(
    repo_root: Path, module_qualname: str, function_name: str, args_repr: str | None = None
) -> dict:
    """Docker-backed equivalent of
    sink_reachability_probe.run_sink_reachability_probe -- identical
    return contract ({"status": "sink_reached"|"not_reached"|"call_failed",
    ...}), so callers (dogfood_scan.py) need no changes to use either
    backend. Runs the project's own, already-hardened harness file
    completely unchanged, just inside a locked-down container instead of
    a bare subprocess. See module docstring for the full design and the
    explicit "not verified end-to-end" caveat."""
    if not _HARNESS_PATH.is_file():
        raise FileNotFoundError(f"sandbox probe harness missing at {_HARNESS_PATH}")

    with tempfile.TemporaryDirectory(prefix="sentinel-zero-docker-env-") as env_dir:
        env_path = Path(env_dir)
        ok, install_log = _install(repo_root, env_path)
        if not ok:
            return {"status": "call_failed", "detail": f"docker install phase failed: {install_log[-500:]}"}

        nonce = secrets.token_hex(16)
        run_args = build_docker_run_args(
            env_path=env_path,
            module_qualname=module_qualname,
            function_name=function_name,
            args_repr=args_repr,
            nonce=nonce,
        )
        code, stdout, stderr, timed_out = _docker_run(run_args, timeout=EXECUTE_TIMEOUT_SECONDS)

        if timed_out:
            return {"status": "call_failed", "detail": f"docker probe exceeded {EXECUTE_TIMEOUT_SECONDS}s timeout"}
        if code != 0:
            return {"status": "call_failed", "detail": f"harness container exited {code}: {stderr.strip()[-500:]}"}

        return parse_harness_result(stdout, nonce)

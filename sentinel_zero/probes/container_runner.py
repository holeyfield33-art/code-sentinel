"""Mandatory OS boundary for diagnostic target execution in both languages.

Only the source tree and shipped harnesses are mounted, read-only. Target
code runs as a non-root container user with no network, a read-only root,
and a private scratch tmpfs. There is no host-process fallback or automatic
installation of target manifests. Output remains untrusted diagnostics.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
from pathlib import Path

from sentinel_zero.probes.evidence import validate_probe_result

IMAGES = {
    "python": "python@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2",
    "javascript": "node@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d",
}
PROBE_TIMEOUT_SECONDS = 10
MAX_OUTPUT_BYTES = 128_000
_HARNESS_DIR = Path(__file__).parent
# Fixed container values only: no host PATH, HOME, TEMP, NODE_OPTIONS,
# PYTHONPATH, tokens, or application environment are forwarded.
CONTAINER_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/scratch", "TMPDIR": "/scratch", "TEMP": "/scratch", "TMP": "/scratch",
    "LANG": "C.UTF-8", "NODE_OPTIONS": "",
}


def _docker_executable() -> str | None:
    """Do not let an untrusted cwd supply docker.exe on Windows."""
    name = "docker.exe" if os.name == "nt" else "docker"
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        directory = Path(os.path.expandvars(entry.strip().strip('"')))
        if not directory.is_absolute():
            continue
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate.resolve())
    return None


def _validate_source_links(root: Path) -> None:
    """Do not expose external content through host symlinks/junctions.

    This checks a caller-controlled source tree before mounting it. As
    with analysis itself, the host filesystem must not be adversarially
    mutated while the scan is running; this is not a filesystem snapshot.
    """
    def unreadable(exc):
        raise ValueError(f"cannot inspect diagnostic source tree: {exc}") from exc

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=unreadable):
        linked_dirs = set()
        for name in dirs + files:
            path = Path(directory) / name
            try:
                linked = path.is_symlink() or bool(getattr(path.lstat(), "st_file_attributes", 0) & 0x400)
                if linked:
                    path.resolve(strict=True).relative_to(root)
                    linked_dirs.add(name)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ValueError(f"diagnostic source has an escaping or unreadable link: {path}") from exc
        # Windows junctions may be traversed by os.walk even when ordinary
        # symlink following is disabled. Their real in-tree target is
        # visited through its canonical path instead.
        dirs[:] = [name for name in dirs if name not in linked_dirs]


def docker_available() -> tuple[bool, str]:
    executable = _docker_executable()
    if executable is None:
        return False, "Docker executable not found in absolute PATH directories"
    try:
        p = subprocess.run([executable, "info", "--format", "{{.ServerVersion}}"],
                           capture_output=True, text=True, timeout=10, cwd=_HARNESS_DIR)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    return p.returncode == 0, (p.stdout if p.returncode == 0 else p.stderr).strip()


def build_container_args(language: str, repo_root: Path, harness_args: list[str], nonce: str | None = None) -> list[str]:
    if language not in IMAGES:
        raise ValueError(f"unsupported probe language {language!r}")
    root = repo_root.resolve()
    if not root.is_dir() or "," in str(root):
        raise ValueError("probe source must be a directory with a Docker-compatible mount path")
    _validate_source_links(root)
    env = dict(CONTAINER_ENV)
    if nonce is not None:
        env["SENTINEL_ZERO_PROBE_NONCE"] = nonce
    env_args = [arg for key, value in env.items() for arg in ("-e", f"{key}={value}")]
    executable = "/usr/local/bin/python" if language == "python" else "/usr/local/bin/node"
    harness = "/harness/_sink_reachability_harness.py" if language == "python" else "/harness/js/_sink_reachability_harness.js"
    return [
        "--rm", "--pull", "never", "--network", "none", "--user", "1000:1000",
        "--read-only", "--tmpfs", "/scratch:rw,nosuid,nodev,noexec,size=64m,mode=1777",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--cpus", "1", "--memory", "512m", "--pids-limit", "64",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--mount", f"type=bind,src={root},dst=/repo,readonly",
        "--mount", f"type=bind,src={_HARNESS_DIR.resolve()},dst=/harness,readonly",
        "--workdir", "/scratch", *env_args, IMAGES[language], executable,
        *(["-I"] if language == "python" else []), harness, *harness_args,
    ]


def _docker_run(args: list[str], timeout: int = PROBE_TIMEOUT_SECONDS) -> tuple[int, str, str, bool]:
    """Bound target output in the host too, and remove timed-out containers."""
    executable = _docker_executable()
    if executable is None:
        return -1, "", "Docker executable not found in absolute PATH directories", False
    name = f"sentinel-zero-probe-{uuid.uuid4().hex}"
    chunks: list[bytearray] = [bytearray(), bytearray()]
    exceeded = threading.Event()
    process = None
    readers = []
    timed_out = False
    errors: list[str] = []
    code = -1

    def remove_container():
        try:
            removed = subprocess.run([executable, "rm", "-f", name], capture_output=True,
                                     text=True, timeout=10, cwd=_HARNESS_DIR)
            # --rm may already have removed a normally completed container.
            if removed.returncode != 0 and "no such container" not in removed.stderr.lower():
                errors.append(f"container cleanup failed: {removed.stderr[:500]}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"container cleanup failed: {exc}")

    def drain(stream, dest):
        try:
            while True:
                block = stream.read(4096)
                if not block:
                    break
                remaining = MAX_OUTPUT_BYTES - len(dest)
                dest.extend(block[:remaining])
                if len(block) > remaining:
                    exceeded.set()
        finally:
            stream.close()

    try:
        process = subprocess.Popen([executable, "run", "--name", name, *args], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=_HARNESS_DIR)
        for stream, dest in zip((process.stdout, process.stderr), chunks):
            thread = threading.Thread(target=drain, args=(stream, dest), daemon=True)
            thread.start()
            readers.append(thread)
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if exceeded.wait(0.05) or time.monotonic() >= deadline:
                timed_out = not exceeded.is_set()
                break
        if process.poll() is None:
            # Removing the named container stops target code, rather than
            # only terminating the local Docker client process.
            remove_container()
            process.kill()
        process.wait(timeout=10)
        for reader in readers:
            reader.join(timeout=2)
        code = process.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.insert(0, f"container execution failed: {exc}")
        timed_out = timed_out or isinstance(exc, subprocess.TimeoutExpired)
    finally:
        try:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"Docker client cleanup failed: {exc}")
        remove_container()
        for reader in readers:
            reader.join(timeout=2)
    stdout, stderr = (bytes(part).decode("utf-8", "replace") for part in chunks)
    if exceeded.is_set():
        errors.insert(0, "container diagnostic output exceeded its byte limit")
        code, stdout = -1, ""
    if errors:
        stderr = "\n".join([stderr, *errors]).strip()
        if code == 0:
            code = -1
    return code, stdout, stderr, timed_out


def parse_result(stdout: str, nonce: str | None = None) -> dict:
    lines = stdout.strip().splitlines()
    if not lines:
        return {"status": "call_failed", "detail": "harness produced no output"}
    try:
        raw = json.loads(lines[-1])
    except ValueError as exc:
        return {"status": "call_failed", "detail": f"invalid harness JSON: {exc}"}
    if nonce is not None and (not isinstance(raw, dict) or raw.get("nonce") != nonce):
        return {"status": "call_failed", "detail": "harness result missing or mismatched nonce"}
    return validate_probe_result(raw)


def run_container_probe(language: str, repo_root: Path, harness_args: list[str], nonce: str | None = None) -> dict:
    backend = os.environ.get("SENTINEL_ZERO_PROBE_BACKEND", "docker")
    if backend != "docker":
        return {"status": "call_failed", "detail": f"unknown or disabled probe backend {backend!r}; Docker isolation is required"}
    available, detail = docker_available()
    if not available:
        return {"status": "call_failed", "detail": f"Docker daemon required; no host fallback: {detail}"}
    try:
        args = build_container_args(language, repo_root, harness_args, nonce)
    except ValueError as exc:
        return {"status": "call_failed", "detail": str(exc)}
    code, stdout, stderr, timed_out = _docker_run(args)
    if timed_out:
        return {"status": "call_failed", "detail": f"container probe exceeded {PROBE_TIMEOUT_SECONDS}s timeout: {stderr[:1500]}"}
    if code != 0:
        return {"status": "call_failed", "detail": f"container probe exited {code}: {stderr[:1500]}"}
    return parse_result(stdout, nonce)

"""Real paired local effect test. Does not promote scanner findings or run arbitrary repos."""
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from sentinel_zero.graph import Symbol
from sentinel_zero.probes.container_runner import IMAGES, CONTAINER_ENV, _docker_executable
from sentinel_zero.resolvers.js_resolver import build_project_graph

FIXTURE = Path(__file__).parent / "fixtures" / "path_traversal"


@pytest.mark.docker_integration
def test_equivalent_vulnerable_and_patched_http_effects(tmp_path: Path) -> None:
    docker = _docker_executable()
    if docker is None:
        pytest.skip("Docker executable required for actual paired control")
    deadline = time.time() + 60
    owned: list[str] = []
    observations: dict = {}
    token = secrets.token_hex(32)
    paths: dict = {}
    sources: dict = {}
    started = time.time()

    def command(args: list[str], *, cleanup: bool = False) -> subprocess.CompletedProcess[str]:
        budget = 8 if cleanup else min(8, deadline - time.time())
        assert budget > 0, "paired experiment exceeded its overall deadline"
        completed = subprocess.run([docker, *args], capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=budget, cwd=FIXTURE)
        assert len(completed.stdout) + len(completed.stderr) < 16384
        if not cleanup:
            assert time.time() <= deadline, "deadline exceeded, including host suspension"
            assert completed.returncode == 0, completed.stderr
        return completed

    snapshot = tmp_path / "snapshot"
    shutil.copytree(FIXTURE, snapshot)
    try:
        for variant in ("vulnerable", "patched"):
            root = snapshot / variant
            graph = build_project_graph(root)
            edges = [(c.caller, c.target.qualified_name, c.lineno) for c in graph.all_calls() if isinstance(c.target, Symbol)]
            required = [("src.server.onRequest", "src.files.readPublicFile", 6),
                        ("src.files.readPublicFile", "fs.readFileSync", 4 if variant == "vulnerable" else 7)]
            assert all(edge in edges for edge in required), edges
            paths[variant] = required
            for file in root.rglob("*.mjs"):
                text = file.read_text(encoding="utf-8")
                sources[f"{variant}/{file.relative_to(root).as_posix()}"] = {
                    "sha256": hashlib.sha256(file.read_bytes()).hexdigest(), "source": text,
                }
            private = root / "private"
            private.mkdir()
            (private / "canary.txt").write_text(token, encoding="utf-8")
            name = "sentinel-paired-" + secrets.token_hex(12)
            owned.append(name)
            env = [a for k, v in CONTAINER_ENV.items() for a in ("--env", f"{k}={v}")]
            command(["create", "--name", name, "--label", "sentinel.test=paired-traversal",
                     "--pull", "never", "--network", "none", "--user", "1000:1000",
                     "--read-only", "--log-driver", "none", "--cap-drop", "ALL",
                     "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1",
                     "--pids-limit", "32", "--tmpfs", "/scratch:rw,nosuid,nodev,noexec,size=8m,mode=1777",
                     "--workdir", "/scratch", *env,
                     "--mount", f"type=bind,src={root},dst=/fixture,readonly",
                     "--mount", f"type=bind,src={snapshot / 'observer.cjs'},dst=/witness/observer.cjs,readonly",
                     IMAGES["javascript"], "/usr/local/bin/node", "/fixture/src/server.mjs"])
            command(["start", name])
            observations[variant] = {}
            for label, request in (("benign", "/?file=index.txt"), ("traversal", "/?file=../private/canary.txt")):
                raw = command(["exec", "--user", "1001:1001", name, "/usr/local/bin/node", "/witness/observer.cjs", request]).stdout
                value = json.loads(raw)
                assert isinstance(value, dict) and set(value) == {"status", "body"}
                assert type(value["status"]) is int and isinstance(value["body"], str)
                observations[variant][label] = value
            # Different UID/process and stdout channel from the running target.
            assert observations[variant]["benign"]["status"] == 200
            assert observations[variant]["benign"]["body"].strip() == "public positive control"
        assert observations["vulnerable"]["traversal"] == {"status": 200, "body": token}
        assert observations["patched"]["traversal"] == {"status": 403, "body": "forbidden"}
    finally:
        errors = []
        for name in owned:
            try:
                command(["rm", "-f", name], cleanup=True)
                check = command(["container", "ls", "-a", "--filter", f"name=^/{name}$", "--format", "{{.Names}}"], cleanup=True)
                if check.returncode or check.stdout.strip():
                    errors.append(name)
            except (OSError, subprocess.TimeoutExpired, AssertionError):
                errors.append(name)
        assert not errors, f"bounded cleanup not confirmed: {errors}"
    observations["vulnerable"]["traversal"]["body"] = "<exact host canary match>"
    report = {"disposition": "CONFIRMED_LOCAL_IMPACT", "scope": "Maintained synthetic fixture only; not Next.js",
              "cwe": "CWE-22", "source_to_sink": paths, "sources": sources, "observations": observations,
              "canary_sha256": hashlib.sha256(token.encode()).hexdigest(), "image": IMAGES["javascript"],
              "observer": "Separate interpreter and UID 1001; target UID 1000; target stdout ignored",
              "cleanup": "all owned names confirmed absent", "elapsed_seconds": time.time() - started,
              "review": "Source/path and paired effect assertions passed; external human review pending"}
    if os.environ.get("SENTINEL_PAIRED_REPORT"):
        Path(os.environ["SENTINEL_PAIRED_REPORT"]).write_text(json.dumps(report, indent=2), encoding="utf-8")

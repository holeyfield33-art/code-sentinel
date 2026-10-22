"""Python diagnostics always execute within Docker, never as the host user.

These remain target-controlled reports and cannot authorize VERIFIED_TRUE.
The old subprocess backend is disabled; unavailable isolation fails closed.
"""
from __future__ import annotations

from pathlib import Path

from sentinel_zero.probes.docker_sink_executor import run_sink_reachability_probe_docker

_HARNESS_PATH = Path(__file__).parent / "_sink_reachability_harness.py"


def run_sink_reachability_probe(
    repo_root: Path, module_qualname: str, function_name: str, args_repr: str | None = None,
) -> dict:
    if not _HARNESS_PATH.is_file():
        raise FileNotFoundError(f"Python diagnostic harness missing at {_HARNESS_PATH}")
    return run_sink_reachability_probe_docker(repo_root, module_qualname, function_name, args_repr)

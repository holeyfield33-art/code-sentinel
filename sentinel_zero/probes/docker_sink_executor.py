"""Python adapter for the mandatory, shared container diagnostic runner.

Source and harnesses are mounted read-only; scratch lives only inside the
container. No target manifests are installed and no host bind directory
is used as a writable virtualenv. Missing dependencies report call_failed.
"""
from __future__ import annotations

import secrets
from pathlib import Path

from sentinel_zero.probes.container_runner import (
    build_container_args, docker_available, parse_result, run_container_probe,
)


def build_docker_run_args(
    *, env_path: Path, module_qualname: str, function_name: str,
    args_repr: str | None, nonce: str,
) -> list[str]:
    """Compatibility API: env_path now names the read-only source tree."""
    argv = ["/repo", module_qualname, function_name]
    if args_repr is not None:
        argv.append(args_repr)
    return build_container_args("python", env_path, argv, nonce)


def parse_harness_result(stdout: str, nonce: str) -> dict:
    return parse_result(stdout, nonce)


def run_sink_reachability_probe_docker(
    repo_root: Path, module_qualname: str, function_name: str, args_repr: str | None = None,
) -> dict:
    argv = ["/repo", module_qualname, function_name]
    if args_repr is not None:
        argv.append(args_repr)
    return run_container_probe("python", repo_root, argv, secrets.token_hex(16))

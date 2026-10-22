"""JS diagnostics execute inside Docker with a fixed env and private cwd.

No host Node invocation or weaker fallback is permitted. Even a confined
target can forge its shared-process harness's output, so reports remain
untrusted and never grant verification.
"""
from __future__ import annotations

from pathlib import Path

from sentinel_zero.probes.container_runner import run_container_probe

_HARNESS_PATH = Path(__file__).parent / "js" / "_sink_reachability_harness.js"


def run_js_sink_reachability_probe(
    file_path: str, function_name: str, *, repo_root: Path | None = None,
) -> dict:
    if not _HARNESS_PATH.is_file():
        raise FileNotFoundError(f"JS diagnostic harness missing at {_HARNESS_PATH}")
    source = Path(file_path).resolve()
    root = repo_root.resolve() if repo_root is not None else source.parent
    try:
        relative = source.relative_to(root)
    except ValueError:
        return {"status": "call_failed", "detail": "JS probe source escapes its repository root"}
    if not source.is_file():
        return {"status": "call_failed", "detail": "JS probe source does not exist"}
    return run_container_probe("javascript", root, ["/repo/" + relative.as_posix(), function_name])

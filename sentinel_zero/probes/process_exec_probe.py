"""Parent-side driver for the bounded PROCESS_EXEC reachability probe
(Milestone 6, see _process_exec_harness.py for the actual isolation
boundary and full scope statement).

This module never executes target code itself -- it only launches the
harness as an isolated subprocess with a hard timeout and turns whatever
comes back into a plain result dict. It never raises on the target's own
bad behavior (an uncooperative target is an expected, reportable outcome
here, not a defect in this code); it only raises if the harness file
itself is missing, which is this project's own bug, not the target's.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_HARNESS_PATH = Path(__file__).parent / "_process_exec_harness.py"
PROBE_TIMEOUT_SECONDS = 5


def run_process_exec_probe(repo_root: Path, module_qualname: str, function_name: str) -> dict:
    """Runs the harness in an isolated `python -I` subprocess and returns
    one of:
      {"status": "sink_reached", "symbol": ..., "args": ...}
      {"status": "not_reached", "detail": ...}
      {"status": "call_failed", "detail": ...}
    Never raises for any outcome of probing the target; see module docstring.
    """
    if not _HARNESS_PATH.is_file():
        raise FileNotFoundError(f"sandbox probe harness missing at {_HARNESS_PATH}")

    try:
        completed = subprocess.run(
            [sys.executable, "-I", str(_HARNESS_PATH), str(repo_root), module_qualname, function_name],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return {"status": "call_failed", "detail": f"probe exceeded {PROBE_TIMEOUT_SECONDS}s timeout"}

    if completed.returncode != 0:
        return {
            "status": "call_failed",
            "detail": f"harness process exited {completed.returncode}: {completed.stderr.strip()[-500:]}",
        }

    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    if not lines:
        return {"status": "call_failed", "detail": "harness produced no output"}
    try:
        return json.loads(lines[-1])
    except ValueError as exc:
        return {"status": "call_failed", "detail": f"could not parse harness output: {exc}"}

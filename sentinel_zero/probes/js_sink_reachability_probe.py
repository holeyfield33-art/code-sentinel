"""Milestone 18: JS/TS mirror of sink_reachability_probe.py (Python's
Milestone 6/16 dynamic reachability probe). Same safety model, same
parent-side responsibility split: this module never executes target
code itself, only launches probes/js/_sink_reachability_harness.js as an
isolated `node` subprocess with a hard timeout, and turns whatever comes
back into a plain result dict. It never raises on the target's own bad
behavior; it only raises if the harness file or the `node` executable
itself is missing, which is this project's own problem, not the target's.

Takes a file path directly, not a module-qualified name the way the
Python driver does -- Node's `require()` resolves by path, so there is
no dotted-name-plus-sys.path indirection to mirror here.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

_HARNESS_PATH = Path(__file__).parent / "js" / "_sink_reachability_harness.js"
PROBE_TIMEOUT_SECONDS = 5


def run_js_sink_reachability_probe(file_path: str, function_name: str) -> dict:
    """Runs the Node harness in an isolated subprocess and returns one of:
      {"status": "sink_reached", "symbol": ..., "args": ...}
      {"status": "not_reached", "detail": ...}
      {"status": "call_failed", "detail": ...}
    Never raises for any outcome of probing the target; see module
    docstring. `symbol` must be compared against the specific finding's
    own sink identity before promoting to VERIFIED_TRUE, exactly the same
    correctness rule Milestone 16 enforces on the Python side (this
    harness also patches every known sink at once and reports whichever
    fires first).
    """
    if shutil.which("node") is None:
        return {"status": "call_failed", "detail": "`node` executable not found -- JS/TS probe requires Node.js"}
    if not _HARNESS_PATH.is_file():
        raise FileNotFoundError(f"JS sandbox probe harness missing at {_HARNESS_PATH}")

    try:
        completed = subprocess.run(
            ["node", str(_HARNESS_PATH), str(file_path), function_name],
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

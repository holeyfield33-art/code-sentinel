"""Parent-side driver for the bounded dynamic sink-reachability probe
(Milestone 6, widened in Milestone 16 past its original PROCESS_EXEC-only
scope to also cover FILE_IO and DESERIALIZATION -- see
_sink_reachability_harness.py for the actual isolation boundary and full
scope statement). Renamed from process_exec_probe.py/run_process_exec_probe
to reflect that widening -- this file was never specific to PROCESS_EXEC
internally, only in name.

This module never executes target code itself -- it only launches the
harness as an isolated subprocess with a hard timeout and turns whatever
comes back into a plain result dict. It never raises on the target's own
bad behavior (an uncooperative target is an expected, reportable outcome
here, not a defect in this code); it only raises if the harness file
itself is missing, which is this project's own bug, not the target's.

VERIFICATION_LEDGER.md sz-2026-10-21-02/03: an independent audit confirmed
the previous version of this file (a) trusted the *last line of stdout*
as probe evidence with no check on which process wrote it -- target code
that printed a matching JSON line and exited before the real call could
force a false VERIFIED_TRUE -- and (b) ran the harness with the scan's own
cwd and the real inherited environment, so a target's import-time code
could write real files outside any sandbox and read real environment
values. Both are addressed below:

  - a per-call random nonce (never placed in the child's argv or left in
    its environment past the harness's own startup -- see the harness's
    docstring for exactly how) must appear in the harness's own result
    line for that line to be trusted at all. A target that doesn't know
    the nonce cannot forge a line that passes this check by ordinary
    means (printing a plausible-looking line, reading os.environ, or
    replaying a previous run's output). This is NOT a claim that no
    target code could ever recover the nonce -- a sufficiently
    sophisticated target with stack-frame introspection (sys._getframe
    walking up into the harness's own locals) is a different, harder
    problem this does not claim to solve; see the harness docstring.
  - the subprocess runs with `cwd` pinned to a fresh, per-call scratch
    directory (created here, torn down after) and `env` built from an
    explicit small allowlist, never the scan process's own inherited
    environment.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

_HARNESS_PATH = Path(__file__).parent / "_sink_reachability_harness.py"
PROBE_TIMEOUT_SECONDS = 5

# Environment variables a target module's own import-time code might
# legitimately need the interpreter itself to start up correctly on a given
# platform -- NOT a general allowlist of "things that look safe". Deliberately
# small: every name added here is a name whose real value a probed target
# gets to see. PATH is required for the interpreter and any stdlib module
# that shells out to a system tool; the rest are platform startup plumbing,
# not application secrets.
_ENV_PASSTHROUGH_NAMES = ("PATH", "SYSTEMROOT", "SYSTEMDRIVE", "TEMP", "TMP", "HOME")
_NONCE_ENV_VAR = "SENTINEL_ZERO_PROBE_NONCE"


def run_sink_reachability_probe(
    repo_root: Path, module_qualname: str, function_name: str, args_repr: str | None = None
) -> dict:
    """Runs the harness in an isolated `python -I` subprocess and returns
    one of:
      {"status": "sink_reached", "symbol": ..., "args": ...}
      {"status": "not_reached", "detail": ...}
      {"status": "call_failed", "detail": ...}
    Never raises for any outcome of probing the target; see module docstring.

    `symbol` in a "sink_reached" result is whichever patched sink actually
    fired first -- it may or may not be the specific sink the caller is
    currently deciding a disposition for (the harness patches every known
    sink simultaneously; see its own docstring). The caller MUST compare
    `symbol` against the specific finding's own sink identity before
    promoting anything to VERIFIED_TRUE -- see dogfood_scan.py's comment
    on this, added in Milestone 16 to fix a real bug where a second,
    never-actually-reached sink in the same function was incorrectly
    promoted to VERIFIED_TRUE off the first sink's evidence. (A narrower,
    still-open gap -- two call sites resolving to the SAME sink symbol in
    one caller -- is tracked separately; see docs/REMEDIATION_PLAN.md item 3.)

    `args_repr` (Milestone 17), when given, is the repr() of a tuple of
    real Python values -- never raw/arbitrary text -- harvested by the
    caller from a genuine call site in the project (see dogfood_scan.py's
    _literal_argument_call_site). Passed straight through as one of the
    harness's argv entries; omitted entirely (zero-argument call) when None.
    """
    if not _HARNESS_PATH.is_file():
        raise FileNotFoundError(f"sandbox probe harness missing at {_HARNESS_PATH}")

    nonce = secrets.token_hex(16)
    env = {name: os.environ[name] for name in _ENV_PASSTHROUGH_NAMES if name in os.environ}
    env[_NONCE_ENV_VAR] = nonce

    with tempfile.TemporaryDirectory(prefix="sentinel-zero-probe-") as scratch_dir:
        argv = [sys.executable, "-I", str(_HARNESS_PATH), str(repo_root), module_qualname, function_name]
        if args_repr is not None:
            argv.append(args_repr)

        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                cwd=scratch_dir,
                env=env,
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
        result = json.loads(lines[-1])
    except ValueError as exc:
        return {"status": "call_failed", "detail": f"could not parse harness output: {exc}"}

    if not isinstance(result, dict) or result.get("nonce") != nonce:
        # Either genuinely malformed harness output, or a line this probe
        # call did not itself produce -- including, specifically, a line
        # printed by the TARGET module's own code attempting to forge a
        # result. Either way this is untrusted and must never be read as
        # real probe evidence.
        return {
            "status": "call_failed",
            "detail": "harness result missing or mismatched nonce -- discarding as untrusted "
            "(this is the expected outcome for a forged or stale result line, not a crash)",
        }
    result.pop("nonce", None)
    return result

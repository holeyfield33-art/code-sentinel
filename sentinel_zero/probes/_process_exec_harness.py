"""Bounded dynamic reachability probe for PROCESS_EXEC findings (Milestone 6).

Invoked ONLY as a subprocess (python -I, hard timeout) -- never imported by
the main scan process. That subprocess boundary is the actual isolation:
this file monkeypatches os.system and every subprocess entry point to a
recorder BEFORE importing the target module, calls exactly one named
zero-argument top-level function, and reports whether the recorder fired.
No real process is ever executed by this probe.

Scope, stated plainly and deliberately narrow:
  - Confirms REACHABILITY under one benign, zero-argument call. It never
    attempts adversarial/crafted inputs -- that is open-ended fuzzing work,
    explicitly out of scope for this milestone.
  - It can only ever argue FOR "this path is live" (-> VERIFIED_TRUE in the
    caller). A sink NOT reached on this one run proves nothing about other
    inputs, so this harness never produces evidence for VERIFIED_FALSE --
    the caller (dogfood_scan.py) enforces that by only ever checking for
    the "sink_reached" status, never treating "not_reached" as a pass.
  - Only a plain module-level function the caller has already confirmed
    takes zero required arguments is ever named here; that eligibility
    check lives in dogfood_scan.py, not here.

Every outcome -- including the target module's own import-time or call-time
exceptions -- is reported as one JSON line on stdout, never swallowed. The
two broad `except Exception` blocks below are not silent-failure shortcuts:
they bound a call into untrusted, unknown target code whose failure modes
cannot be enumerated in advance, and every one is reported with its real
exception type and message, not absorbed.
"""
import importlib
import json
import os
import subprocess
import sys


class _SinkReached(Exception):
    def __init__(self, symbol: str, args_repr: str) -> None:
        super().__init__(symbol)
        self.symbol = symbol
        self.args_repr = args_repr


def _recorder(symbol: str):
    def _fn(*args, **kwargs):
        raise _SinkReached(symbol, repr(args)[:200])

    return _fn


def main() -> None:
    if len(sys.argv) != 4:
        print(json.dumps({
            "status": "call_failed",
            "detail": "usage: _process_exec_harness.py REPO_ROOT MODULE_QUALNAME FUNCTION_NAME",
        }))
        return
    repo_root, module_qualname, function_name = sys.argv[1], sys.argv[2], sys.argv[3]

    sys.path.insert(0, repo_root)

    os.system = _recorder("os.system")
    subprocess.run = _recorder("subprocess.run")
    subprocess.call = _recorder("subprocess.call")
    subprocess.check_call = _recorder("subprocess.check_call")
    subprocess.check_output = _recorder("subprocess.check_output")
    subprocess.Popen = _recorder("subprocess.Popen")

    try:
        module = importlib.import_module(module_qualname)
    except Exception as exc:  # the target module's own import-time behavior
        # is unknown and untrusted -- any failure here is a reported
        # outcome of probing it, not a defect in this harness.
        print(json.dumps({
            "status": "call_failed",
            "detail": f"import failed: {type(exc).__name__}: {exc}",
        }))
        return

    fn = getattr(module, function_name, None)
    if fn is None or not callable(fn):
        print(json.dumps({
            "status": "call_failed",
            "detail": f"{function_name!r} not found or not callable on {module_qualname!r}",
        }))
        return

    try:
        fn()
    except _SinkReached as reached:
        print(json.dumps({
            "status": "sink_reached",
            "symbol": reached.symbol,
            "args": reached.args_repr,
        }))
        return
    except Exception as exc:  # same reasoning as the import try/except above:
        # the target function's own behavior under a zero-argument call is
        # unknown; reported explicitly, never absorbed.
        print(json.dumps({
            "status": "call_failed",
            "detail": f"call raised: {type(exc).__name__}: {exc}",
        }))
        return

    print(json.dumps({
        "status": "not_reached",
        "detail": "function returned without reaching a patched sink",
    }))


if __name__ == "__main__":
    main()

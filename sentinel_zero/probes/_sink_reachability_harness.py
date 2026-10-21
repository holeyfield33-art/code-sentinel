"""Bounded dynamic reachability probe (Milestone 6, widened in Milestone 16
to cover FILE_IO and DESERIALIZATION in addition to the original
PROCESS_EXEC-only scope, and in Milestone 17 to call a function with
harvested literal arguments instead of only zero-argument functions --
same mechanism both times, just a wider patch table / wider call shape).

Invoked ONLY as a subprocess (python -I, hard timeout) -- never imported by
the main scan process. That subprocess boundary is the actual isolation:
this file monkeypatches every known sink entry point to a recorder BEFORE
importing the target module, calls exactly one named top-level function
(with zero arguments, or with a tuple of real values harvested from a
genuine literal-only call site -- see main()'s argv handling), and reports
whether the recorder fired. No real process is ever executed, no real file
is ever opened, no real payload is ever deserialized by this probe --
every one of those actions is replaced by a recorder that raises before
the real call underneath it runs.

Scope, stated plainly and deliberately narrow:
  - Confirms REACHABILITY under one benign call -- either zero arguments,
    or arguments that are themselves constants lifted verbatim from a real
    call site elsewhere in the project (Milestone 17). It never attempts
    adversarial/crafted inputs -- that is open-ended fuzzing work,
    explicitly out of scope here.
  - It can only ever argue FOR "this path is live" (-> VERIFIED_TRUE in the
    caller). A sink NOT reached on this one run proves nothing about other
    inputs, so this harness never produces evidence for VERIFIED_FALSE --
    the caller (dogfood_scan.py) enforces that by only ever checking for
    the "sink_reached" status, never treating "not_reached" as a pass.
  - Only a plain module-level function the caller has already confirmed
    is safe to call this way is ever named here; that eligibility check
    (arity, harvested-literal-argument lookup) lives in dogfood_scan.py,
    not here -- this file only ever does what it's told.
  - Every known sink across all three kinds is patched simultaneously
    (same approach the original PROCESS_EXEC-only version used for its own
    six entry points) -- the harness does not know or care which specific
    finding it was launched for; it reports whichever patched symbol
    actually fired first. It is dogfood_scan.py's job, not this file's, to
    check that the reported `symbol` actually matches the specific
    finding being decided before promoting anything to VERIFIED_TRUE --
    see its own comment for the real bug that check fixes.
  - This probe runs under the SAME interpreter/environment that launched
    sentinel-zero, never the target repo's own virtualenv. A target module
    that imports a third-party package not installed in sentinel-zero's
    own environment (PyYAML, say) will fail at import time inside this
    harness regardless of this probe's own patch table -- reported
    honestly as "call_failed: import failed", never silently skipped.
    This is a pre-existing bound of the dynamic-probe approach generally,
    not something this widening introduced.

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


def _patch_sinks() -> None:
    """Monkeypatches every known sink entry point this probe is able to
    patch safely (see dogfood_scan.py's _SINK_KIND_BY_NAME for the
    canonical sink list -- this covers a subset of it, see below) to a
    recorder, BEFORE the target module is imported, so the recorder is in
    place even for sink calls made at the target's own import time.

    builtins.eval and builtins.exec are deliberately NOT patched here, and
    never will be by this mechanism: CPython's own import machinery runs
    every module's compiled bytecode via the builtin `exec()` function
    (confirmed directly: patching builtins.exec before calling
    importlib.import_module makes EVERY import fail, not just one that
    itself calls eval/exec). There is no "patch after import, before the
    call" workaround either that is fully safe -- a probed function that
    does its own lazy `import` internally would trip a patched exec via
    that nested import, not via a real eval/exec sink call, which would
    be a genuine false VERIFIED_TRUE. Given this tool's standing rule
    against overclaiming, builtins.eval/builtins.exec sinks are static-
    evidence-only (same as before this probe existed) -- never dynamically
    probed.

    builtins.open IS confirmed safe to patch this way: CPython's import
    machinery reads source/bytecode through its own internal io, never
    through the redefinable builtins.open (verified directly before this
    code was written -- a fresh module imports fine with builtins.open
    replaced). json.load/loads and pickle.load/loads are ordinary module
    attributes with no bootstrap role and are safe for the same reason.
    """
    import builtins
    import json as json_module
    import pickle

    os.system = _recorder("os.system")
    subprocess.run = _recorder("subprocess.run")
    subprocess.call = _recorder("subprocess.call")
    subprocess.check_call = _recorder("subprocess.check_call")
    subprocess.check_output = _recorder("subprocess.check_output")
    subprocess.Popen = _recorder("subprocess.Popen")

    builtins.open = _recorder("builtins.open")

    json_module.load = _recorder("json.load")
    json_module.loads = _recorder("json.loads")
    pickle.load = _recorder("pickle.load")
    pickle.loads = _recorder("pickle.loads")

    try:
        import yaml

        yaml.load = _recorder("yaml.load")
    except ImportError:
        # PyYAML isn't installed in THIS environment (the one running
        # sentinel-zero, not the target repo's own venv -- see module
        # docstring). A target module that itself does `import yaml` will
        # fail to import here regardless, and that failure is reported
        # honestly as call_failed below -- never silently treated as "no
        # yaml.load sink exists."
        pass


def main() -> None:
    # Milestone 17: an optional 5th argv, ARGS_REPR, is the repr() of a
    # tuple of real Python values harvested from a genuine call site
    # elsewhere in the project that calls this exact function with
    # arguments Milestone 15's taint classifier confirmed are built
    # entirely from literal constants (see dogfood_scan.py's
    # _literal_argument_call_site). repr() of a literal-eval'able value
    # round-trips cleanly through ast.literal_eval, the same mechanism
    # used to harvest it in the first place -- never raw source text
    # re-embedded as code, never eval()'d. If absent, the call is made
    # with zero arguments, same as Milestone 6's original behavior.
    if len(sys.argv) not in (4, 5):
        print(json.dumps({
            "status": "call_failed",
            "detail": "usage: _sink_reachability_harness.py REPO_ROOT MODULE_QUALNAME FUNCTION_NAME [ARGS_REPR]",
        }))
        return
    repo_root, module_qualname, function_name = sys.argv[1], sys.argv[2], sys.argv[3]

    call_args: tuple = ()
    if len(sys.argv) == 5:
        import ast as _ast

        try:
            call_args = tuple(_ast.literal_eval(sys.argv[4]))
        except (ValueError, SyntaxError) as exc:
            # This project's own harvesting step is supposed to only ever
            # produce a literal_eval-able repr -- a failure here is this
            # tool's own bug, not the target's, but it must still be
            # reported rather than silently falling back to a zero-arg
            # call (that would claim a DIFFERENT, unintended invocation
            # happened).
            print(json.dumps({
                "status": "call_failed",
                "detail": f"could not parse harvested arguments: {type(exc).__name__}: {exc}",
            }))
            return

    sys.path.insert(0, repo_root)

    _patch_sinks()

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
        fn(*call_args)
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

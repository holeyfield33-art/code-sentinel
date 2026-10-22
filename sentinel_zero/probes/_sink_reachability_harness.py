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

VERIFICATION_LEDGER.md sz-2026-10-21-02: every JSON line this harness emits
now carries a `nonce` the parent (sink_reachability_probe.py) generated
per-call and the parent checks on the way back. The nonce arrives via the
SENTINEL_ZERO_PROBE_NONCE environment variable and is popped out of
os.environ as the very first action in main() -- before _patch_sinks(),
before the target module is imported -- specifically so the target's own
code never finds it by reading os.environ normally. This closes the
realistic forgery case (target code prints a plausible-looking result line
and exits early) and the "reads the nonce out of its own environment" case.
It is not a claim that this defeats a target sophisticated enough to walk
the call stack with sys._getframe() and read this function's own local
`nonce` variable directly -- that remains possible in principle, because
the target executes in the same interpreter/process as this harness (there
is no OS-level process boundary between them), and is a genuinely different
and harder problem than the one this fixes. See docs/REMEDIATION_PLAN.md
item 1 and docs/IVP.md for why this bound is stated rather than left
implicit.

VERIFICATION_LEDGER.md sz-2026-10-21-16: the nonce above authenticates the
TARGET side of this channel (is this line really from this probe run) but
originally did nothing for the HARNESS's OWN side -- main()'s emit() used
to call json.dumps() and print() by looking them up fresh on the shared
json/sys module objects every target module shares, so a target that
reassigns json.dumps (or sys.stdout/builtins.print) at import time could
forge the harness's own later, legitimate result line, nonce included,
for a call that reached no sink at all. Found by Codex's automated review
on PR #2 (commit fec251c), independently reproduced by hand before being
acted on, per IVP discipline of never taking a bot's or a report's claim
on its word. Fixed categorically, not by patching one more name: main()
captures `json.dumps` and `os.write` as local variables immediately after
popping the nonce -- before `_patch_sinks()` or the target import ever
run -- and emit() writes the final line directly to fd 1 through the
captured os.write, never through print()/sys.stdout, which are equally
shared and equally hijackable by the same mechanism. See
test_probe_verification_hardening.py's
test_target_cannot_forge_output_by_hijacking_json_dumps_or_stdout for the
regression test, confirmed via `git stash` to fail before this fix.

A second Codex finding on the same commit (comment_id 4340475522) --
module-level aliases such as `_io.FileIO`/`posix.open` bypassing the
io.FileIO/os.open patches in _patch_sinks() -- was also independently
reproduced as real, but is NOT fixed here. It is the same open-ended
primitive-hunting pattern already decided against in sz-2026-10-21-14
(stop chasing individual I/O primitives; the real fix is OS-level
isolation or an honestly-narrowed claim, not one more alias in the patch
table). Logged as sz-2026-10-21-17, folded into item 1's existing
"claim downgraded, not closed" status rather than treated as a new item.
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

    VERIFICATION_LEDGER.md sz-2026-10-21-09/10: an independent Verifier
    broke the nonce-secrecy fix (sz-2026-10-21-02) and the scratch-dir
    write confinement (sz-2026-10-21-03) via the SAME unpatched gap --
    os.open/os.read let a target read /proc/self/environ directly (the
    kernel's frozen execve()-time snapshot, which os.environ.pop() never
    touches -- it only scrubs Python's own process-local copy), and
    os.open/os.write with an absolute path let it write anywhere, bypassing
    the pinned cwd entirely (cwd only ever governed *relative*-path writes).
    os.open is also confirmed safe to patch the same way builtins.open is:
    verified directly (see tests/test_probe_verification_hardening.py) that
    patching it before import does not break importlib.import_module on
    ordinary stdlib/project modules -- CPython's own import machinery does
    not route through the Python-level os.open symbol either.

    Stated honestly, not left implicit: patching os.open closes the two
    concrete breaks above. It does not, and cannot, close every conceivable
    native-level escape -- target code using ctypes/cffi to call the C
    library's open()/read()/write() directly bypasses any Python-level
    monkeypatch entirely, since there is no real OS-level sandbox boundary
    between this harness and the code it imports (same process, same
    privileges). That is a structurally different and harder problem --
    real isolation needs an OS-level mechanism (a container, seccomp, a
    genuinely separate restricted process), not more patching here. See
    docs/REMEDIATION_PLAN.md for this noted as an accepted, disclosed
    residual bound rather than something this pass claims to have closed.
    """
    import builtins
    import io
    import json as json_module
    import pickle

    os.system = _recorder("os.system")
    subprocess.run = _recorder("subprocess.run")
    subprocess.call = _recorder("subprocess.call")
    subprocess.check_call = _recorder("subprocess.check_call")
    subprocess.check_output = _recorder("subprocess.check_output")
    subprocess.Popen = _recorder("subprocess.Popen")

    builtins.open = _recorder("builtins.open")
    os.open = _recorder("os.open")

    # VERIFICATION_LEDGER.md sz-2026-10-21-12/13: a SECOND independent
    # Verifier round broke the os.open patch above the same way -- not by
    # finding a new environment-leak vector, but by finding yet another
    # unpatched file-opening primitive: io.FileIO (a C-implemented class
    # that issues its own open() syscall directly, never routing through
    # the Python-level os.open or builtins.open symbols this harness had
    # already patched) and io.open (a separate module attribute from
    # builtins.open -- rebinding builtins.open does NOT rebind io.open,
    # confirmed directly: they are the same underlying function object at
    # interpreter startup but are two independent, independently-patchable
    # names). Both are patched here too, confirmed safe the same way
    # (see tests/test_probe_verification_hardening.py).
    io.FileIO = _recorder("io.FileIO")
    io.open = _recorder("io.open")

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
    # Popped before anything else -- including before the argv shape is even
    # validated -- so this value is never in os.environ by the time any
    # target code could possibly run. See module docstring for the full
    # threat-model statement (sz-2026-10-21-02).
    nonce = os.environ.pop("SENTINEL_ZERO_PROBE_NONCE", "")

    # Confirmed real (Codex review on PR #2, commit fec251c -- verified by
    # hand before this fix, not taken on the bot's word): json.dumps and
    # os.environ are the SAME shared, mutable module objects the target
    # module's own import-time code executes inside. A target that does
    # `import json; json.dumps = <forges status/symbol, keeps the real
    # nonce>` at import time, then returns NORMALLY (the honest,
    # legitimate "not_reached" case), was hijacking the harness's OWN
    # later, trusted call to json.dumps() -- a different and more
    # fundamental gap than "one more unpatched read primitive": it is the
    # harness's own OUTPUT path being forgeable, not an input-reading
    # bypass. The fix is categorical, not another name added to a patch
    # list: capture the real json.dumps AND the real os.write BEFORE
    # _patch_sinks() or the target import ever run, bind them only to
    # local variables (never read again from the shared json/os module
    # objects afterward), and write the final result directly to fd 1 via
    # the captured os.write -- bypassing print()/sys.stdout entirely, both
    # of which are equally shared, mutable, and equally hijackable the
    # same way (builtins.print, sys.stdout) if the output step still did a
    # late dynamic lookup of them.
    _trusted_dumps = json.dumps
    _trusted_write = os.write

    def emit(payload: dict) -> None:
        line = _trusted_dumps({**payload, "nonce": nonce}) + "\n"
        data = line.encode("utf-8")
        written = 0
        while written < len(data):
            written += _trusted_write(1, data[written:])

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
        emit({
            "status": "call_failed",
            "detail": "usage: _sink_reachability_harness.py REPO_ROOT MODULE_QUALNAME FUNCTION_NAME [ARGS_REPR]",
        })
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
            emit({
                "status": "call_failed",
                "detail": f"could not parse harvested arguments: {type(exc).__name__}: {exc}",
            })
            return

    sys.path.insert(0, repo_root)

    _patch_sinks()

    try:
        module = importlib.import_module(module_qualname)
    except Exception as exc:  # the target module's own import-time behavior
        # is unknown and untrusted -- any failure here is a reported
        # outcome of probing it, not a defect in this harness.
        emit({
            "status": "call_failed",
            "detail": f"import failed: {type(exc).__name__}: {exc}",
        })
        return

    fn = getattr(module, function_name, None)
    if fn is None or not callable(fn):
        emit({
            "status": "call_failed",
            "detail": f"{function_name!r} not found or not callable on {module_qualname!r}",
        })
        return

    try:
        fn(*call_args)
    except _SinkReached as reached:
        emit({
            "status": "sink_reached",
            "symbol": reached.symbol,
            "args": reached.args_repr,
        })
        return
    except Exception as exc:  # same reasoning as the import try/except above:
        # the target function's own behavior under a zero-argument call is
        # unknown; reported explicitly, never absorbed.
        emit({
            "status": "call_failed",
            "detail": f"call raised: {type(exc).__name__}: {exc}",
        })
        return

    emit({
        "status": "not_reached",
        "detail": "function returned without reaching a patched sink",
    })


if __name__ == "__main__":
    main()

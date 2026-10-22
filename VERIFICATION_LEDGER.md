# Sentinel-Zero — Verification Ledger

Per the Independent Verification Protocol (IVP): every claim of "done", "fixed",
"verified", or "ready" made about this project is logged here with who checked
it, how, and what they found — before the claim is repeated to anyone. See
`docs/IVP.md` for the full protocol. This file is append-only; a superseded
entry is not edited or deleted, a new entry supersedes it and says so.

---

### sz-2026-10-21-01
- **claim:** "Sentinel-Zero is a complete, demoable thing as it stands" (stated
  by the Builder session, prior to the independent audit below).
- **claimant:** Builder session (this conversation, prior turn)
- **verifier:** An independently-commissioned audit (external to this
  conversation, run against `main` @ `9762422`), re-checked in this same
  conversation by direct source reading (ad-hoc re-check, not a dedicated
  fresh Tier-1 session — see `docs/IVP.md` §8.2 for why that gap matters)
- **method:** Full audit: tests, independent probes, package build, MCP smoke
  test, 10,000-file synthetic fixture. Re-check: direct reading of
  `sink_reachability_probe.py`, `_sink_reachability_harness.py`,
  `dogfood_scan.py`, `python_resolver.py`, `extract_graph.js`.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** See entries 02–07 below for the itemized breakdown.
- **date:** 2026-10-21

### sz-2026-10-21-02
- **claim:** "The dynamic sink-reachability probe's VERIFIED_TRUE output
  cannot be forged by the code it is probing."
- **claimant:** Implicit in the probe's own design/docstrings
- **verifier:** This conversation, direct source read (ad-hoc, not Tier-1)
- **method:** Traced `run_sink_reachability_probe()` in
  `sentinel_zero/probes/sink_reachability_probe.py`.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `sink_reachability_probe.py`, `run_sink_reachability_probe()`:
  takes `completed.stdout.strip().splitlines()[-1]` and `json.loads()`s it
  with no check on which process emitted that line. Target code that prints a
  matching `{"status": "sink_reached", ...}` line and exits 0 before the real
  call satisfies this unmodified.
- **date:** 2026-10-21

### sz-2026-10-21-03
- **claim:** "The probe subprocess is sandboxed — it cannot cause real side
  effects outside the target repo or read real secrets."
- **claimant:** Implicit in the probe's "isolated subprocess" / "sandbox"
  language throughout `dogfood_scan.py` and `_sink_reachability_harness.py`.
- **verifier:** This conversation, direct source read (ad-hoc, not Tier-1)
- **method:** Read `run_sink_reachability_probe()`'s `subprocess.run()` call
  and `_patch_sinks()`'s patch table in full.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `subprocess.run(argv, capture_output=True, text=True,
  timeout=...)` passes no `cwd=` and no `env=` — the harness inherits the
  real environment and runs wherever the scan's own process cwd happens to
  be. `_patch_sinks()` only patches six symbol names (`os.system`,
  `subprocess.*`, `open`, `json`/`pickle.load*`, `yaml.load`); any other
  action a target module takes at import time (file writes via `pathlib`,
  `os.environ` reads, network calls) runs for real, unsandboxed.
- **date:** 2026-10-21

### sz-2026-10-21-04
- **claim:** "Milestone 16 fixed the wrong-call-promoted bug: a probe result
  can no longer be misattributed to a finding it didn't actually verify."
- **claimant:** `dogfood_scan.py` module docstring, describing the
  `_promote_if_sink_reached` symbol-match check.
- **verifier:** This conversation, direct source read (ad-hoc, not Tier-1)
- **method:** Read `_promote_if_sink_reached()` and its call sites in
  `find_finding_plans()`.
- **verdict:** CONFIRMED (claim is narrower than stated — true for
  cross-sink-kind mismatches, FALSE for same-sink/different-call-site)
- **evidence:** `dogfood_scan.py:357`, `_promote_if_sink_reached()` compares
  `probe_result["symbol"]` to `call.target.qualified_name` — a match by
  resolved *name*, not call-site identity. Two `os.system(...)` call sites in
  one function, only one reachable: the probe fires once on the reachable
  one, reports `"os.system"`, and that single result is reused to promote
  *every* finding in that caller whose sink resolves to the same name,
  including the unreachable one.
- **date:** 2026-10-21

### sz-2026-10-21-05
- **claim:** "Sink calls inside a nested (closure) Python function are
  indexed and can produce finding plans, same as a top-level function."
- **claimant:** Implicit — no stated bound in `python_resolver.py` excludes
  nested functions; `README.md`'s Known Bounds section does not list this.
- **verifier:** This conversation, direct source read (ad-hoc, not Tier-1)
- **method:** Read `walk_stmts()` and `build_project_graph()` in
  `python_resolver.py` end to end.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `python_resolver.py:665-666`, `walk_stmts()` explicitly skips
  nested `FunctionDef`/`AsyncFunctionDef`/`ClassDef` ("separate scope,
  indexed/walked on its own") — but the only scopes ever walked are
  top-level module functions and class methods (lines 717-752). No code path
  ever walks a function nested inside another function. A closure's sink
  calls are invisible to the resolver entirely, not even reported as
  unresolved.
- **date:** 2026-10-21

### sz-2026-10-21-06
- **claim:** "An anonymous function literal (arrow/function expression)
  passed inline as a call argument — e.g. an Express route handler — is
  walked for sink calls, same as a named function."
- **claimant:** Implicit — `README.md`'s Known Bounds section does not list
  this as excluded.
- **verifier:** This conversation, direct source read (ad-hoc, not Tier-1)
- **method:** Read `findCallsInExpr()` in `resolvers/js/extract_graph.js` and
  searched for any separate indexing pass over inline function literals.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `extract_graph.js:448-452`, `findCallsInExpr()` returns
  immediately on `FunctionExpression`/`ArrowFunctionExpression`/
  `FunctionDeclaration` nodes without descending, with the same "separate
  scope, walked on its own" rationale as the Python resolver — but no
  separate pass walks an anonymous function literal used as a call argument
  (only named declarations and `const x = () => {}`-style variable
  assignments are indexed, per lines 625/793). This is exactly the shape of
  `app.get('/x', (req, res) => { ...sink... })` — standard
  Express/Fastify/Next.js route-handler syntax.
- **date:** 2026-10-21

### sz-2026-10-21-07
- **claim:** "A VERIFIED_TRUE disposition from the harvested-literal-argument
  probe path means the attack class (e.g. Serialization Injection) is a
  genuinely confirmed, attacker-reachable vulnerability."
- **claimant:** Implicit — `set_disposition(plan, "VERIFIED_TRUE", ...)` in
  `_promote_if_sink_reached` carries no distinction between this path and a
  zero-argument probe call.
- **verifier:** This conversation, direct source read (ad-hoc, not Tier-1)
- **method:** Read `_literal_argument_values()`, `_probe_invocation_for()`,
  and the Milestone 17 probing block in `find_finding_plans()`.
- **verdict:** CONFIRMED (claim is FALSE — structurally backwards)
- **evidence:** `dogfood_scan.py:255-320,553-574` — this path specifically
  requires every harvested argument to be provably `"literal"` (constant,
  non-attacker-controlled) per the Milestone 15 taint classifier *before* it
  will even attempt the probe call. Success proves "this constant input
  reaches the sink," which is evidence the call is safe under at least the
  tested input — not evidence of an exploitable injection. The disposition
  label does not reflect this distinction anywhere in the reason text.
- **date:** 2026-10-21

### sz-2026-10-21-09
- **claim:** "A target Python module cannot force a false VERIFIED_TRUE by
  printing a forged result line and exiting first, and cannot recover the
  verification nonce by reading its own environment, after the
  nonce+env-allowlist fix (commit 7f39743)."
- **claimant:** Builder session (this conversation)
- **verifier:** A genuinely fresh, non-forked Tier-1 subagent, given only
  the claim and the artifact per `docs/IVP.md` Appendix B
- **method:** Read `sink_reachability_probe.py` and
  `_sink_reachability_harness.py` directly, then wrote and ran real
  adversarial fixture modules against the live code (not just re-running
  the Builder's own tests).
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `_patch_sinks()` patches `builtins.open` but not
  `os.open`/`os.read`. `os.environ.pop()` only scrubs Python's own
  process-local copy, not the kernel's frozen `/proc/self/environ`
  snapshot from `execve()`. A target doing
  `os.open('/proc/self/environ', os.O_RDONLY)` + `os.read(fd, 65536)`
  recovers the real nonce, prints a forged `sink_reached` line including it,
  and `sys.exit(0)`s before the real (no-op) function body runs. The
  Verifier confirmed `run_sink_reachability_probe()` on this exact fixture
  returns a false `sink_reached` result. The naive `builtins.open()`-based
  version of this attack is correctly blocked (confirming the existing
  regression tests weren't wrong, just not adversarial enough) — the break
  requires the unpatched `os` module functions specifically.
- **date:** 2026-10-21

### sz-2026-10-21-10
- **claim:** "After the scratch-dir/env-allowlist fix, a target module's
  import-time code cannot write a file outside the per-call scratch
  directory."
- **claimant:** Builder session (this conversation)
- **verifier:** Same fresh Tier-1 subagent as sz-2026-10-21-09
- **method:** Same as above.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** Same root cause as sz-2026-10-21-09 — `os.open` with
  `O_CREAT|O_WRONLY` and an absolute path, followed by `os.write`, is
  unpatched and bypasses the scratch-cwd confinement entirely (cwd only
  governs *relative*-path writes, which was never the full claim as
  originally stated). The Verifier confirmed a real file was created
  outside the scratch dir via this path, then deleted it.
- **date:** 2026-10-21

### sz-2026-10-21-11
- **claim:** "After the env-allowlist fix, a target module cannot read a
  real secret from the scan process's own original environment, regardless
  of which API it uses to read environment variables."
- **claimant:** Builder session (this conversation)
- **verifier:** Same fresh Tier-1 subagent as sz-2026-10-21-09/10
- **method:** Set a real sentinel value in the parent process's actual
  environment, then tried the same `/proc/self/environ`-via-`os.open`
  bypass used to break sz-2026-10-21-09, this time to recover that value
  instead of the nonce.
- **verdict:** REFUTED (genuinely tried to break it, could not)
- **evidence:** `subprocess.run(..., env=env)` *replaces* the child's
  `envp` at `execve()` time rather than merging it with the parent's, so
  the child's `/proc/self/environ` — inspected directly, not inferred —
  contained only the small explicit allowlist plus the nonce; no trace of
  the real secret set in the parent's environment. The env-scrubbing half
  of the original claim holds; only the nonce-secrecy and write-confinement
  halves (same root cause, both via unpatched `os.open`) were false.
- **date:** 2026-10-21

### sz-2026-10-21-12
- **claim:** "After patching os.open (commit c8eee3e), a target Python
  module cannot force a false VERIFIED_TRUE by reading the verification
  nonce, nor write outside the scratch directory."
- **claimant:** Builder session (this conversation)
- **verifier:** A SECOND, independently-fresh (non-forked, no shared
  context with the first) Tier-1 subagent, explicitly instructed not to
  just replay the first verifier's exact break
- **method:** Read the current source directly, then wrote and ran new
  adversarial fixtures against the live code.
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `io.FileIO` (a C-implemented class) opens files via its own
  direct syscall and routes through neither the patched `os.open` nor
  `builtins.open`. `io.open` is a separate module attribute from
  `builtins.open` -- the same underlying function object at interpreter
  startup, but rebinding one name does not rebind the other. A target using
  `io.FileIO('/proc/self/environ', 'r')` recovered the real nonce and
  forged a passing `sink_reached` result (reproduced; `sys.stdout.flush()`
  before `os._exit(0)` is required for the forged print to reliably reach
  the parent, since `os._exit()` skips the interpreter's normal buffer
  flush -- noted because the Builder's own first attempt at reproducing
  this test omitted the explicit flush and was briefly, incorrectly,
  non-failing as a result; corrected before this entry was logged).
- **date:** 2026-10-21

### sz-2026-10-21-13
- **claim:** same source, write-confinement half.
- **claimant/verifier/method:** same as sz-2026-10-21-12
- **verdict:** CONFIRMED (claim is FALSE)
- **evidence:** `io.FileIO(absolute_path, 'w')` writes a real file outside
  the pinned scratch cwd, same root cause as sz-2026-10-21-12.
- **date:** 2026-10-21

### sz-2026-10-21-14 — decision record, not a claim check
After `io.FileIO`/`io.open` were also patched (both confirmed empirically
not to break `importlib.import_module` on ordinary modules, same as
`os.open` before them) and all adversarial regression tests pass, this is
the SECOND distinct unpatched file-opening primitive two independent
Verifier rounds have found in two attempts. A real, enumerable but
non-exhaustive set of further primitives remains unverified (`os.posix_spawn`
with fd inheritance, `mmap`, `codecs.open`, `pathlib`'s internal open path
across Python versions, and, as already disclosed since the first round,
any `ctypes`/native-syscall access, which no Python-level monkeypatch can
ever close). Decision: stop chasing individual primitives with a third
Verifier round tonight. Monkeypatching cannot be honestly claimed to make
VERIFIED_TRUE forgery-proof against a determined, in-process adversary --
only "hardened against the specific unsophisticated-to-moderately-
sophisticated forgery vectors found and closed so far." This is now
recorded as the real, broader claim in `docs/REMEDIATION_PLAN.md` item 1,
replacing the original, too-strong acceptance claim. A genuine fix would
need OS-level isolation (a container, seccomp, a real separate-privilege
process), which is a materially different and larger piece of work than
this plan's scope, and is recorded there as a separate, larger decision for
Ashura to make, not something closed by further patching.

### sz-2026-10-21-16
- **claim:** "The dynamic sink-reachability probe harness's own result
  line (the trusted side of the nonce channel) cannot be forged by a
  target module that reassigns `json.dumps` or `sys.stdout`/`print` at
  import time."
- **claimant:** Codex automated review (chatgpt-codex-connector[bot]) on
  PR #2, commit `fec251c`, comment_id 4340475510, P1
- **verifier:** Builder session (this conversation) — independently
  reproduced by hand with a fixture (`/tmp/codex_verify/target/evil_dumps.py`:
  a module that reassigns `json.dumps` at import time to rewrite any dict
  containing a `nonce` key into a fake `sink_reached` payload, then defines
  a harmless no-op function) BEFORE accepting the finding as real or
  acting on it, per IVP's "never take a claim on its word" discipline —
  not a fresh/non-forked Tier-1 session, so this is a Builder-side
  reproduction, same tier as the Builder's own regression tests, not a
  substitute for an independent Verifier pass.
- **method:** Ran the fixture against the pre-fix harness: a function that
  does nothing produced `{"status": "sink_reached", "symbol": "os.system",
  ...}`. Fixed by capturing `json.dumps`/`os.write` as local variables in
  `main()` before `_patch_sinks()` or the target import run, and writing
  the final line directly to fd 1 via the captured `os.write`, bypassing
  `print()`/`sys.stdout` entirely. Added
  `tests/test_probe_verification_hardening.py::test_target_cannot_forge_output_by_hijacking_json_dumps_or_stdout`,
  confirmed via `git stash` to fail against the pre-fix harness and pass
  post-fix. Full suite re-run post-fix: 128 passed.
- **verdict:** CONFIRMED (claim was FALSE pre-fix; fix closes this specific
  vector) — still pending a fresh, non-forked Verifier pass before this is
  asserted to the PR thread as closed, per IVP (a Builder's own test for a
  bug the Builder found and fixed does not close an item on its own).
- **date:** 2026-10-21

### sz-2026-10-21-17 — decision record, not a claim check
- **claim under review:** "`_io.FileIO`/`posix.open` module-level aliases
  bypass the `io.FileIO`/`os.open` patches already in `_patch_sinks()`."
- **claimant:** Codex automated review on PR #2, commit `fec251c`,
  comment_id 4340475522, P1
- **check performed:** Builder session independently reproduced this as
  real by hand (a target importing `_io` directly and calling `_io.FileIO`
  bypasses the `io.FileIO` name patched in the `io` module, since they are
  the same underlying type reachable via two import paths).
- **decision:** NOT implemented as a new patch. This is the same open-ended
  primitive-hunting pattern already decided against in sz-2026-10-21-14 —
  a third instance of "one more unpatched alias/primitive" in the exact
  same category as `/proc/self/environ` via `os.open` and the `io.FileIO`
  bypass of `os.open` itself. Folded into item 1's existing "claim
  downgraded, not closed" status in `docs/REMEDIATION_PLAN.md` rather than
  treated as a new item or patched piecemeal. Flagged to the user as a
  judgment call rather than decided unilaterally to patch or to dismiss,
  per the standing PR-steward policy on borderline/architecturally-
  significant review findings.
- **date:** 2026-10-21

### sz-2026-10-21-08 (believed true, not independently verified to CONFIRMED/REFUTED rigor)
- **claims:**
  1. "A ledger over 5 MB crashes the scan with no partial output" —
     plausible from `dogfood_scan.py:687`'s hardcoded `5_000_000` cap passed
     to `safe_write_text`, combined with `cli.py`'s `except (ToolFailure,
     UnknownAttackClass)` not covering the `ValueError` that cap raises —
     but not reproduced with an actual oversized run in this session.
  2. "The distributed wheel omits the JS probe harness, so the installed
     probe raises FileNotFoundError" — not checked against an actual built
     wheel in this session.
- **claimant:** External audit
- **verifier:** UNABLE_TO_VERIFY (this session did not build the package or
  reproduce an oversized run)
- **date:** 2026-10-21

### sz-2026-10-21-21
- **claim:** "A nested Python function (a `def` inside another `def`) is
  invisible to the static resolver: it is never indexed into
  `project_functions` and its own body is never walked for `CallSite`s, so a
  sink call inside one produces zero finding plans — not even
  `UNRESOLVED_INCONCLUSIVE` — the worst possible outcome, since it does not
  even surface as something to triage." (Remediation plan item 5.)
- **claimant:** `docs/REMEDIATION_PLAN.md` item 5 (originally from the
  external audit)
- **check performed:** Builder session on branch
  `fix/nested-function-invisibility`. Added `_direct_nested_function_defs`
  (recurses through if/try/for/while/with to find a `FunctionDef`/
  `AsyncFunctionDef` belonging to the current scope, stopping at a nested
  function/class boundary) and `_index_function_and_nested` (indexes a
  function, then its nested defs, qualnamed the way Python's own
  `__qualname__` does: `module.outer.<locals>.inner`), wired into both the
  top-level and class-method indexing loops in
  `sentinel_zero/resolvers/python_resolver.py`. Extended `walk_fn` with an
  `enclosing_param_names` accumulator so a nested function's own
  `param_names` set includes every enclosing function's parameters too
  (closure-correct taint classification), and extended `walk_stmts` to
  recurse into a nested `FunctionDef`/`AsyncFunctionDef` as a real scope of
  its own — but ONLY when walking inside a real function scope
  (`fn_node is not None`), not when walking the true module scope, which
  already has its own dedicated top-level loop.
- **regression hit during implementation:** the first version of the
  `walk_stmts` change had no such guard, so the module-level walk's own
  pass over `tree.body` ALSO matched every top-level `FunctionDef` as a
  "nested" def, producing a second, duplicate `CallSite` per top-level
  function under a qualname missing the module prefix. Caught immediately
  by the existing suite (`26 failed, 109 passed`), root-caused to that
  scope conflation, fixed with the `fn_node is not None` guard. Full suite
  returned to green before any new tests were even written.
- **tests added:** `tests/test_nested_function_visibility.py` (6 tests) —
  a sink call in a one-level-nested function now produces exactly one
  finding plan (`mod.outer.<locals>.inner`); a closure over the ENCLOSING
  function's own parameter classifies as `parameter` taint, not `unknown`;
  three levels of nesting resolve to the correctly-chained qualname; a
  nested def buried inside an `if` block is still found; and two explicit
  regression guards confirm a plain top-level function and a plain class
  method each still produce exactly one finding with their original,
  unmodified qualname (no spurious `.<locals>.` duplicate).
- **`git stash` confirmation:** stashing just the
  `python_resolver.py` change and rerunning the new test file: 4 of 6
  failed (the two scoped on pre-existing behavior still passed, as
  expected) — `assert 0 == 1` on every nested-function case, confirming the
  bug was real and the tests actually exercise the fix. Popping the stash
  and rerunning: 6/6 pass. Full suite: **141 passed, 0 failed** (135
  pre-existing + 6 new).
- **verdict:** CONFIRMED by the Builder's own testing — **pending a fresh,
  non-forked Tier-1 Verifier pass** before this is asserted as closed to
  anyone outside this session, per IVP (a Builder's own regression tests
  for a bug the Builder found and fixed do not close an item on their own).
- **date:** 2026-10-21

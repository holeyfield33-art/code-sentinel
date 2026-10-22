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

### sz-2026-10-21-19
- **claim:** "The probe can run with real OS-level isolation (network
  segmentation, dropped capabilities, read-only root, non-root user,
  resource caps) instead of the in-process monkeypatch table, closing
  the gap recorded in sz-2026-10-21-14."
- **claimant:** Builder session (this conversation), at the user's
  direction to port the execution-sandbox logic from their own
  readme-tester project (no code dependency taken on that repo — the
  security-flag pattern was read and re-implemented by hand in a new,
  standalone file)
- **verifier:** UNABLE_TO_VERIFY end-to-end in this session — `docker`
  the CLI is present but no daemon is reachable here
  (`docker_available()` genuinely returns `False`, confirmed by a real
  call, not assumed). What WAS checked in this session: argument/flag
  construction for the execute phase (every lock-down flag present:
  `--network none`, `--cap-drop ALL`, `--security-opt
  no-new-privileges`, `--read-only`, `--pids-limit`, `--cpus`,
  `--memory`, `--user 1000:1000`), the env-allowlist discipline (a
  non-allowlisted real value never appears in the constructed args),
  the nonce-authenticated result parser (accepts a correctly-nonced
  line, rejects a forged/mismatched one, handles empty output), and the
  backend dispatcher (requesting `docker` without a reachable daemon
  returns a clear `call_failed`, never a silent fallback to the
  subprocess backend; an unknown backend name is rejected the same way;
  the default, unset-env-var path is unchanged and still produces a
  real `sink_reached` result).
- **method:** New module `sentinel_zero/probes/docker_sink_executor.py`
  (standalone — no import of readme-tester's package), wired in as an
  opt-in backend via `SENTINEL_ZERO_PROBE_BACKEND=docker` in
  `sink_reachability_probe.py`'s now-dispatching
  `run_sink_reachability_probe`; the original subprocess logic moved,
  byte-for-byte, into `_run_sink_reachability_probe_subprocess` and
  remains the untouched default. Two-phase design (install with network
  on, best-effort `pip install` from a manifest if one exists; execute
  with network off and the lock-down flags above) runs the project's
  own, already-hardened `_sink_reachability_harness.py` completely
  unchanged — none of this evening's nonce/trusted-output hardening had
  to be reimplemented, only re-launched under a different isolation
  boundary. `tests/test_docker_sink_probe.py` (10 tests, all passing).
  Full suite: 145 passed.
- **verdict:** CONFIRMED at the construction/parsing/dispatch level
  tested; UNABLE_TO_VERIFY for the actual container-isolation claim
  itself, for lack of a reachable Docker daemon in this session. Not
  default, not claimed production-ready. Needs a real smoke test
  (actually launching a container against a real target) wherever
  Docker runs — the user's own machine or CI — before this backend is
  trusted for any real finding, let alone promoted to the default.
- **disclosed gap vs. the ported pattern's own source:** no pinned image
  digest yet (`python:3.12-slim`, a floating tag) — readme-tester's own
  executor pins by digest; this is a real, intentional narrowing stated
  here rather than silently matched to the stronger claim.
- **date:** 2026-10-21

### sz-2026-10-21-24
- **claims:**
  1. (P2) "On a host where Sentinel runs under a UID other than 1000,
     the install container creates `/env/src` and the venv inside the
     bind-mounted temp dir as UID 1000 at mode 0755, so the host
     process cannot remove their contents on cleanup, and an otherwise-
     completed probe raises `PermissionError`."
  2. (P2) "`|| true` on either pip install line defeats `set -e`, makes
     the install container exit successfully even when pip genuinely
     fails, and causes `_install()` to report success — the harness
     then probes a partial environment, which can produce misleading
     reachability evidence instead of the promised `call_failed`."
  3. (P2) "`test_docker_is_genuinely_unavailable_in_this_environment`
     unconditionally asserts `docker_available()` is `False`, which
     fails outright on any developer or CI machine with a reachable
     Docker daemon — exactly the environment this backend is supposed
     to be smoke-tested in."
  4. (P1, separately flagged to the user rather than decided
     unilaterally — see below) "The nonce is exposed in the target's own
     process environment; the already-documented
     `_io.FileIO('/proc/self/environ')` bypass can recover it and forge
     a nonced result, since the container isolates the shared process
     from the HOST, not the harness from the imported target it shares
     a process with."
- **claimant:** Codex automated review on PR #5 (sz-2026-10-21-19's own
  PR), commit `0245b11`, comment_ids 4344098481 (claim 1), 4344098475
  (claim 2), 4344098486 (claim 3), 4344098471 (claim 4)
- **check performed (claims 1-3):** fixed directly, each a small, local,
  confident fix on the Builder's own PR, per the standing PR-steward
  policy. Claim 1: `_install_user()` added, returning the host's own
  `os.getuid():os.getgid()` (falling back to the previous `1000:1000`
  only when `os.getuid`/`getgid` don't exist, i.e. non-Linux/macOS),
  used for the INSTALL phase's `--user` flag only — the EXECUTE phase
  intentionally keeps its hardcoded non-root `1000:1000` for security,
  unaffected by this (it mounts `/env` read-only, so it never writes
  anything the host needs to clean up). Claim 2: both `|| true`s
  removed from `_INSTALL_SCRIPT`; the "never hard-fail just because
  there's nothing to install" bound is untouched since those `pip`
  lines are inside `if [ -f ... ]` branches skipped entirely when no
  manifest exists. Claim 3: the test now self-skips (via
  `pytest.skip`) when Docker IS actually reachable, instead of
  asserting a machine-specific fact; a new mocked test
  (`test_dispatcher_reports_a_clear_failure_when_docker_is_unavailable_mocked`)
  covers the exact same dispatcher path deterministically regardless of
  the real host, per Codex's own suggested fix.
- **tests added:** `test_install_script_never_swallows_a_real_pip_failure`,
  `test_install_user_matches_the_host_uid_so_cleanup_can_remove_its_files`,
  `test_install_user_falls_back_to_a_fixed_uid_without_getuid`, and the
  mocked dispatcher test above — 4 new, plus the renamed/skip-guarded
  existing one. `git stash` confirmation: stashing just
  `docker_sink_executor.py` made the test module fail to even COLLECT
  (`ImportError: cannot import name '_install_user'`) — the strongest
  possible "fails pre-fix" signal — and independently, the stashed
  file's `_INSTALL_SCRIPT` was confirmed (by direct `grep`) to still
  contain both `|| true` lines. Popping the stash: full suite **149
  passed, 0 failed**.
- **check performed (claim 4):** independently reproduced as describing
  a real, architecturally significant gap — NOT fixed unilaterally.
  This is the same root-cause class already recorded in
  sz-2026-10-21-14 (two independent Verifier rounds breaking the
  subprocess backend's in-process monkeypatch sandbox via different
  unpatched primitives) and sz-2026-10-21-17 (the `_io.FileIO`/`os.open`
  bypass specifically, folded into that decision rather than patched
  piecemeal). Codex's point is sharper than a restatement, though: the
  Docker backend's whole reason for existing was to replace in-process
  monkeypatching with real OS-level isolation, but containerizing the
  process does nothing for the harness/target boundary WITHIN that one
  process — the nonce still crosses no boundary the target can't
  inspect, so the container's isolation claim and the nonce's
  authentication claim are independent, and this backend currently only
  delivers the first. A real fix needs the harness and the target to
  run in genuinely separate processes with the nonce confined to the
  one the target never touches (e.g. a supervising parent process that
  never lets the nonce enter the child's environment at all, appending
  it to the child's raw, un-authenticated result only after reading it
  back) — a real architecture change to `_sink_reachability_harness.py`,
  shared with the subprocess backend, not a local patch to this file.
- **decision:** put to the user per the standing PR-steward policy for
  an ambiguous/architecturally-significant finding on a PR the Builder
  opened, rather than deciding unilaterally whether to invest in that
  redesign now or accept and re-disclose the gap. **User decision:
  accept and disclose — merge as-is, no harness redesign now.** The
  module docstring's own "Explicit, disclosed gap in this module's OWN
  isolation claim" section (added in the same commit as the other three
  fixes, 4adc640) already states this plainly for anyone reading the
  code, consistent with the module's existing "STATED PLAINLY, NOT
  GLOSSED OVER" posture on its other known gaps (no pinned image digest,
  no real-daemon smoke test yet). This remains a real, open limitation —
  accepting it is not the same as closing it — and the same gap applies
  equally to the subprocess backend's own nonce protocol, already
  covered by the existing sz-2026-10-21-14/-17 decision record.
- **date:** 2026-10-22

### sz-2026-10-22-01
- **claim:** From sz-2026-10-21-08 claim 1 / `docs/REMEDIATION_PLAN.md` item 7:
  "A ledger over 5 MB crashes the scan with no partial output" —
  `dogfood_scan.py`'s hardcoded `5_000_000`-byte cap passed to
  `safe_write_text` raises a bare `ValueError` when exceeded, and neither
  `dogfood_scan.run()` nor `cli.cmd_analyze()` caught that specific
  exception, so it propagated as an uncaught traceback instead of this
  project's own `CRITICAL_TOOL_FAILURE` convention.
- **claimant:** External audit (previously UNABLE_TO_VERIFY in
  sz-2026-10-21-08, not reproduced with an actual oversized run).
- **check performed:** Reproduced for real, not just reasoned about.
  Built a synthetic 3500-module Python repo, each module with its own
  `os.system(user_input)` sink call, and ran
  `python -m sentinel_zero.cli analyze` against it. The scan found 3500
  real sink findings, serialized them to a genuine 5,548,527-byte ledger,
  and crashed with:
  `ValueError: refused: 5548527 bytes is over the 5000000-byte limit`
  as an uncaught traceback through `dogfood_scan.py:687` ->
  `ledger_writer.py:24` — exactly the mechanism sz-2026-10-21-08 predicted,
  now confirmed with a real run rather than left as a plausible read of
  the source.
- **fix:** Added `_write_or_fail_cleanly()` in `dogfood_scan.py`, a thin
  wrapper around `safe_write_text()` that catches the specific
  oversize `ValueError` and re-raises it as a `ToolFailure` naming the
  real byte count, the cap, and that the scan's own results were real
  but too large to write out — never silently truncated, never a bare
  traceback. Applied to both the `verification_ledger.json` write and the
  `graph.json` write in `run()`. The equivalent `report.md` write in
  `cli.cmd_analyze()` had the identical gap (it sat entirely outside the
  `except (ToolFailure, UnknownAttackClass)` block) — moved inside that
  block and wrapped the same way, so a report.md over its own 5MB cap
  now also produces a clean `CRITICAL_TOOL_FAILURE` and exit code 3,
  with the already-written ledger left intact rather than lost.
- **tests added:** `tests/test_tool_failure.py`:
  `test_run_raises_tool_failure_not_a_bare_valueerror_when_the_ledger_is_too_big`
  (monkeypatches `safe_write_text` to reproduce the exact oversize raise
  cheaply, asserts `ToolFailure` not `ValueError`, asserts the real byte
  count and cap appear in the message),
  `test_write_or_fail_cleanly_still_writes_normally_sized_output`
  (regression guard: the common case is unaffected), and
  `test_cmd_analyze_reports_a_clean_critical_tool_failure_when_the_markdown_report_is_too_big`
  (same shape for the `report.md` path, also asserts the ledger file
  itself was written successfully first — this is not a total loss).
- **stash confirmation:** `git stash push -- sentinel_zero/dogfood_scan.py
  sentinel_zero/cli.py`; all 3 new tests failed pre-fix with the exact
  predicted shape (an uncaught `ValueError` propagating out of
  `cli.cmd_analyze`, visible in the pytest traceback); `git stash pop`;
  all 10 tests in the file passed post-fix; full suite (154 tests) passed.
  Also re-ran the original 3500-module real-world repro end-to-end
  against the fixed code: now prints a single `CRITICAL_TOOL_FAILURE:
  could not write the verification ledger to verification_ledger.json:
  ...` line to stderr and exits 3 — no traceback.
- **verdict:** CONFIRMED (claim) / fixed, pending fresh Verifier pass.
- **date:** 2026-10-22

### sz-2026-10-22-03
- **claim:** Codex P2 review on PR #9, commit `0f833fc`: "Preserve
  non-size write refusal reasons" — `write_or_fail_cleanly()`'s blanket
  `except ValueError` assumes every `ValueError` from `safe_write_text`
  is the byte-cap refusal and always says "too large... were
  discarded", but `safe_write_text` can also raise a plain `ValueError`
  from `resolve_inside`'s path-containment check (a symlink escaping
  `out_dir`) or from a `UnicodeEncodeError` (a `ValueError` subclass)
  encoding `text`. For either, the original wrapper's message would be
  flatly wrong about why the write failed.
- **claimant:** `chatgpt-codex-connector[bot]`, PR #9 review comment
  (comment_id 4348521066).
- **check performed:** Confirmed real by reading `ledger_writer.py`
  directly: `resolve_inside` raises `ValueError(f'refused: {relative}
  is not inside {root}')` on a path-containment failure, a distinct
  branch from the byte-cap check, and both are plain `ValueError`
  (`UnicodeEncodeError` is a `ValueError` subclass in the standard
  library). The original `write_or_fail_cleanly` caught `ValueError`
  generically with no way to tell the two apart, so it would mislabel
  either case as a size refusal. Confirmed this is currently
  unreachable from this project's own call sites specifically (every
  `relative` argument at every call site is a fixed literal with no
  `..`, so `resolve_inside`'s escape branch can't fire; `json.dumps(...,
  indent=2)` defaults to `ensure_ascii=True`, which escapes everything
  outside ASCII, so the `.encode('utf-8')` it's piped into can't raise)
  -- but a latent correctness bug worth fixing cheaply regardless, since
  mislabeling a future path-containment refusal (a genuinely
  security-relevant signal) as an innocuous "too large" is exactly the
  kind of wrong-but-plausible-sounding message this project's own
  CRITICAL_TOOL_FAILURE convention exists to prevent.
- **fix:** `write_or_fail_cleanly()` now independently recomputes
  `len(text.encode("utf-8")) > max_bytes` before choosing which message
  to raise, rather than assuming every `ValueError` is the size refusal.
  Only the oversize case gets the "too large... discarded" framing;
  anything else gets an honest message naming the real cause, still
  wrapped as `ToolFailure` (not re-introducing the original item-7 bug
  for those cases). Also deduplicated `cli.cmd_analyze()`'s separate
  copy of the same wrapping logic around the `report.md` write -- it
  had the identical flaw and would have needed the identical fix a
  second time -- by having it call `dogfood_scan.write_or_fail_cleanly()`
  directly instead of maintaining its own copy (renamed from
  `_write_or_fail_cleanly` to `write_or_fail_cleanly` to be
  cross-module-callable).
- **tests added:** `tests/test_tool_failure.py`:
  `test_write_or_fail_cleanly_does_not_mislabel_a_non_size_valueerror_as_too_big`
  (monkeypatches `safe_write_text` to raise the path-containment
  `ValueError` with `text` well under the cap, asserts the message
  names the real reason and contains neither "too large" nor
  "discarded"); updated the two existing report.md-path tests to patch
  `dogfood_scan.safe_write_text` instead of a now-removed
  `cli.safe_write_text`, since `cli.cmd_analyze` no longer imports
  `safe_write_text` directly.
- **stash confirmation:** `git stash push -- sentinel_zero/dogfood_scan.py
  sentinel_zero/cli.py`; all 3 touched/added tests failed pre-fix (the
  mislabel test and the still-writes-normally test failed because
  `write_or_fail_cleanly` didn't exist yet under that name; the
  report.md test failed because `cli.cmd_analyze` didn't yet route
  through the shared helper, so the monkeypatch on
  `dogfood_scan.safe_write_text` had no effect on cli.py's separate,
  then-still-direct call); `git stash pop`; full suite (155 tests)
  passed. Re-ran the original 3500-module real-world repro end-to-end
  again post-fix: unchanged clean `CRITICAL_TOOL_FAILURE` output, exit
  code 3.
- **verdict:** CONFIRMED (claim) / fixed, pending fresh Verifier pass.
- **date:** 2026-10-22

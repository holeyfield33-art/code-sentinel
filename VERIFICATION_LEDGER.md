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

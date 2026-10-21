# Sentinel-Zero — Remediation Plan (from the 2026-10-21 audit)

Every item here closes only via the IVP Gate (`docs/IVP.md`): fix lands,
a fresh non-forked Verifier session tries to break the specific claim below,
the verdict is logged to `VERIFICATION_LEDGER.md`, and only then is an item
marked done. A Builder's own new unit test for a bug the Builder found and
fixed does not close an item on its own (same reasoning as IVP §9).

Ordered by: how much other correctness depends on it, not by estimated
effort. Items 1–2 are the root-trust fixes everything else in the probe
pipeline rests on; items 3–4 are promotion-logic bugs downstream of that
trust; items 5–6 are coverage gaps in a different part of the system
entirely (the static resolvers, not the probe) and can proceed in parallel
once 1–2 land; items 7–8 are believed-true-but-unverified (ledger entry
sz-2026-10-21-08) and are checked for real before any fix is written.

---

## 1. Probe verification channel is forgeable — STATUS: hardened twice, claim downgraded, not closed
**Ledger:** sz-2026-10-21-02, -09, -10, -11, -12, -13, -14
**Why first:** every VERIFIED_TRUE promotion in the whole tool flows through
this one unauthenticated stdout-parsing function. Nothing downstream of it
can be trusted until it is.

**What actually happened (two Verifier rounds, two real breaks, both fixed):**
round 1 added a per-call nonce (env-var, popped before import) plus a
scratch cwd and env allowlist; a fresh Verifier broke it via unpatched
`os.open`/`os.read` reading `/proc/self/environ` (the kernel's `execve()`
snapshot, untouched by `os.environ.pop()`). Round 2 patched `os.open`; a
second, independently-fresh Verifier broke THAT via unpatched `io.FileIO`/
`io.open`, a different file-opening primitive entirely. Both are now
patched (confirmed empirically safe against `importlib.import_module`,
same diligence already applied to `builtins.open`/`exec`).

**Revised, honest acceptance claim (replaces the original one above, which
two rounds of real verification showed was too strong):** "The probe's
nonce check and `_patch_sinks()` table raise the bar against
unsophisticated-to-moderately-sophisticated forgery and sandbox-escape
attempts, and are confirmed to defeat the five specific vectors found and
tested so far (stdout replay, `os.environ` read, `os.open`+`os.read`,
`os.open`+`os.write`, `io.FileIO`). This is NOT, and must never be
represented as, a claim that VERIFIED_TRUE from this probe is unforgeable
against a determined, in-process adversary — true unforgeability would
require OS-level isolation (a container, seccomp, a genuinely separate
restricted process), which this harness does not have and a Python-level
monkeypatch table cannot provide, no matter how many more primitives get
added to it."

**Decision, recorded sz-2026-10-21-14:** stop chasing individual I/O
primitives (`mmap`, `codecs.open`, `os.posix_spawn`, version-specific
`pathlib` internals, and — already disclosed from round 1 — `ctypes`/
native-syscall access are all still open, unverified, and likely to stay
that way under more patching). Closing this for real is a separate,
larger decision: either (a) build genuine OS-level isolation for the probe
subprocess — real scope, not a quick follow-up — or (b) stop labeling
probe-only promotions as the same "VERIFIED_TRUE" used for static-only
findings, so the report itself carries the honest, narrower claim instead
of the mechanism having to be bulletproof. (b) is cheap and immediately
available; (a) is not. Neither is started — this is a decision queued for
Ashura, not one made unilaterally here.

**This item does not get a "done" entry in this plan.** It gets this
status note instead, which is itself the IVP working as intended: a
claim that got weaker, not stronger, the more it was actually checked.

---

## 2. No real process isolation (cwd/env leak) — STATUS: see item 1
**Ledger:** sz-2026-10-21-03, -10, -11, -13 (folded into item 1's resolution
— the write-escape half shared item 1's exact root cause and was closed by
the same two patching rounds; the env-secret-leak half was REFUTED as a
real problem on the first Verifier pass and never broke on either round:
`subprocess.run(..., env=...)` genuinely replaces the child's `envp`, so a
real secret in the scan process's own environment was never reachable by
any of the five tested vectors. That specific, narrower claim — "a real
secret in the parent's environment cannot leak to the probed target" —
does hold and is the one part of the original item 1/2 claims this plan
still states without qualification.)
**Why second:** same file, same subprocess call as item 1 — fix both in one
pass rather than touching this hot path twice.

**Fix direction:** `subprocess.run()` in `run_sink_reachability_probe` gets
an explicit `cwd=` pinned to a fresh, scan-scoped temp directory (created and
torn down per probe call, never the scan's own cwd or the target repo), and
an explicit `env=` built from an explicit allowlist (just `PATH` and whatever
the Python interpreter itself needs to start) rather than inherited
wholesale. Document plainly in the harness docstring that this still does
not sandbox arbitrary target code execution in general (that was never the
full claim) — it only closes the specific "writes land somewhere real" and
"reads the real environment" gaps.

**Acceptance claim for the Verifier:** "A target module whose import-time
code writes a file via a relative path, or reads an injected environment
variable, cannot write outside the probe's scratch directory or observe a
real secret placed in the scan process's own environment."

**Verifier method hint:** two fixture modules — one that does
`Path("escape.txt").write_text("x")` at import time, one that does
`os.environ.get("FAKE_SECRET")` and raises if it finds the real one you
set before invoking the probe. Confirm neither succeeds against the real
process/environment.

---

## 2a. Related, separate gap surfaced while closing item 1–2 (not yet planned)
**Ledger:** sz-2026-10-21-09/10/11 (the real Tier-1 Verifier pass on items 1–2)

Closing the forgery/sandbox gap required patching `os.open` in the probe
harness's sink table, alongside `builtins.open`. That's a probe-isolation
fix, not a static-analysis one — but it surfaces a real, separate question
this plan hasn't looked at yet: does `_SINK_KIND_BY_NAME` in
`dogfood_scan.py` (the STATIC resolver's sink table) even recognize
`os.open` as a FILE_IO sink at all? If not, a real `os.open(user_path, ...)`
call in target code — a plausible path-traversal shape — produces no
finding plan whatsoever, the same invisibility problem as items 5–6, just
in a different table. Also noted honestly: patching `os.open` closes two
concrete breaks, not every conceivable one — `ctypes`/native-syscall access
bypasses any Python-level monkeypatch entirely, since there is no real
OS-level sandbox boundary here. That's an accepted, disclosed residual
bound, not something queued to "fix" — closing it for real would mean a
genuinely different mechanism (container/seccomp isolation), which is a
different scale of project than this one, not a next item on this list.

Not triaged into a numbered item yet — flagging it here so it isn't lost,
per IVP's own point about a durable record over a transcript that scrolls
away.

---

## 3. Wrong-call promotion (same-sink, different call site)
**Ledger:** sz-2026-10-21-04

**Fix direction:** `_promote_if_sink_reached` needs to compare against the
specific `call` object's identity (its `lineno`/`order` within the caller),
not just `call.target.qualified_name`. Since the harness can only report
*which symbol* fired, not *which source line* within the caller triggered
it, the honest fix is probably narrower than "exact call-site match": when
a caller has more than one call site resolving to the same sink symbol, a
single probe run cannot disambiguate which one actually fired, so promotion
must either (a) only ever fire when there is exactly one call site for that
sink symbol in that caller, or (b) be re-architected to report which call
site via some runtime marker. Pick (a) first — it is the honest, bounded
fix; don't reach for (b)'s added complexity unless (a) proves to not be
enough in practice.

**Acceptance claim for the Verifier:** "A function with two call sites to
the same sink symbol, only one of which is actually reachable, does not
have its unreachable call site promoted to VERIFIED_TRUE."

**Verifier method hint:** exactly the fixture described in the ledger entry
— two `os.system(...)` calls in one function, the second dead code after a
`return`. Confirm only the live one (if either) promotes.

---

## 4. Literal-argument probe path mislabels reachability as exploit
**Ledger:** sz-2026-10-21-07

**Fix direction:** the harvested-literal-argument path proves something real
(this path is live and reachable) but not what VERIFIED_TRUE currently
implies for every other promotion. Split the disposition language — and
ideally the status itself, e.g. a dedicated `VERIFIED_REACHABLE_ONLY` or a
clearly-labeled sub-reason — so a human skimming the report cannot mistake
"we called this with a known-safe constant and it ran" for "an attacker can
reach this." At minimum, `_promote_if_sink_reached`'s `call_desc` branch for
the harvested-argument case must say plainly, in the reason text, that the
arguments used were proven non-attacker-controlled and this result says
nothing about exploitability under attacker input.

**Acceptance claim for the Verifier:** "Reading the disposition reason text
for a harvested-literal-argument VERIFIED_TRUE finding, a reader cannot
reasonably conclude the finding demonstrates attacker-controlled input
reaching the sink."

**Verifier method hint:** generate one such finding against a real fixture,
read only the reason text (not the code), and judge whether it overclaims.

---

## 5. Nested Python functions are invisible to the resolver
**Ledger:** sz-2026-10-21-05

**Fix direction:** `walk_stmts()`'s skip of nested `FunctionDef` needs a
matching "and also walk it, as its own scope" step — the same shape as the
existing class-method pass (lines 745–752), but recursive: a nested function
needs a qualname of its own (e.g. `module.outer.<locals>.inner`, mirroring
Python's own `__qualname__` convention) and its own `walk_fn` invocation.
Watch for the obvious recursion case (a function nested three deep) and for
closures that reference the *enclosing* function's parameters, not just
their own — `_param_names` likely needs to accumulate across nesting levels,
not reset per scope, or a parameter captured by closure will misclassify as
"unknown" taint instead of "parameter."

**Acceptance claim for the Verifier:** "A sink call inside a function nested
inside another function produces a finding plan, with correct parameter
taint classification for a variable captured from the enclosing scope."

**Verifier method hint:** the ledger's own fixture (a closure with a real
`os.system` call) plus a second fixture where the sink argument is a
parameter of the *outer* function, referenced inside the inner one.

---

## 6. Inline JS/TS function literals (callbacks) are invisible
**Ledger:** sz-2026-10-21-06

**Fix direction:** mirror item 5's shape on the JS side: when
`findCallsInExpr` hits a `FunctionExpression`/`ArrowFunctionExpression` that
is NOT a named declaration or `const x = () => {}` assignment (i.e. it's an
argument expression — the callback case), it still needs its own scope
walked and indexed, with a qualname derived from its position (e.g. the
enclosing call's resolved callee + an ordinal, since it's genuinely
anonymous). This is the highest real-world-impact item in the whole list —
prioritize it over polish on items 1–4 once those are closed, since it's
the gap most likely to produce real false negatives on real Node codebases
today.

**Acceptance claim for the Verifier:** "A sink call inside an anonymous
arrow function passed directly as a call argument (the
`app.get('/x', (req,res)=>{...})` shape) produces a finding plan."

**Verifier method hint:** the ledger's own fixture, plus a second, more
realistic one pulled from an actual small Express app shape (a handful of
routes, one with a sink in the inline handler, one without) to catch an
over-narrow fix that only handles the single-argument pattern.

---

## 7–8. Output-cap crash and missing wheel asset
**Ledger:** sz-2026-10-21-08 — not yet independently verified to be real.

**Before writing any fix:** reproduce both, for real, in this session or the
next one:
- Run a scan that genuinely produces a ledger over 5 MB and confirm what
  actually happens (clean `CRITICAL_TOOL_FAILURE` message, or an uncaught
  traceback — the ledger entry only has a plausible mechanism, not a
  reproduction).
- Build the actual wheel (`python -m build` or equivalent) in a clean venv,
  install it, and try to run a scan that needs the JS probe harness from the
  installed package rather than the source checkout.

Only once each is reproduced does it get its own ledger entry and its own
item in this plan with a fix direction — writing a fix for an unreproduced
claim is exactly the self-certification pattern this whole plan exists to
avoid.

---

## Sequencing for this and future sessions

Do not batch items 1–6 into one commit/PR. Each item: fix → tests →
fresh Verifier pass → ledger entry → **then** move to the next item. This
is slower per item and that's the point — "one thing at a time, no
overbuilding" applies to the remediation work itself, not just to feature
work.

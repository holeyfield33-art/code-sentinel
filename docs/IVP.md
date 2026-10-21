**Independent Verification Protocol (IVP)**

*A two-node verification system for solo-agent development --- closing the self-certification gap*

Prepared for: Aletheia Sovereign Systems

Trigger case: the Sentinel-Zero independent audit, 2026-10-21

Applies to: every repo in the portfolio, not Sentinel-Zero alone

0\. Why this document exists

An independent audit of Sentinel-Zero (run outside this conversation, on the real source at commit 9762422) returned a NO-GO verdict for the tool as a vulnerability scanner. Re-checking that audit\'s claims directly against the source --- not trusting the audit, and not reflexively defending the tool --- confirmed six of its core findings as real, including defects in the exact mechanism the tool uses to call its own output VERIFIED_TRUE (the dynamic sandbox probe can be fed a forged result by the code it is probing; its symbol-match fix only guards against the wrong SINK, not the wrong CALL SITE of the same sink; its literal-argument probe path proves an argument is safe and then labels that proof a verified attack).

That is not a story about one buggy tool. It is a story about process: a single agent, in a single context, told the user the tool was \"a complete, demoable thing\" minutes before an independent check showed it wasn\'t. The agent was not lying --- it was grading its own work using the work\'s own self-reported status labels (VERIFIED_TRUE, UNRESOLVED_INCONCLUSIVE) as if they were external evidence, rather than re-deriving whether those labels could themselves be wrong. That failure mode generalizes to every project in this portfolio, every time a single agent session both builds something and declares it done.

This document specifies a structural fix: a protocol under which no completion claim is treated as true until a second, disinterested check has tried to break it --- with a durable record of that check, not just a verbal assurance. It is written to be read once and applied by hand from then on; nothing in it depends on new tooling that doesn\'t already exist in this workflow.

1\. The problem, precisely

Three distinct failure modes collapse into what looks like one problem --- \"the AI said it was done and it wasn\'t\" --- but they need different fixes, so they are worth separating.

1.1 Self-certification bias

The same context that writes code, writes the tests for that code, and then reports the tests passed has every incentive --- not malicious, just structural --- to interpret ambiguous results charitably. It wrote the thing; it is primed to see it work. This is the same reason a human engineer doesn\'t review their own pull request as the sole gate before merge. It is not a competence problem. A second, equally capable reviewer with no authorship stake catches things the author structurally cannot, regardless of how carefully the author re-reads their own work.

1.2 Status-label laundering

A tool that produces its own internal status field (VERIFIED_TRUE, PASSED, DONE, GREEN) makes it easy to mistake \"the tool\'s own classifier said X\" for \"X is independently true.\" In the Sentinel-Zero case, VERIFIED_TRUE was treated --- by me, in the prior turn --- as settled evidence, when it was actually the output of a specific, checkable mechanism (a subprocess probe reading unauthenticated stdout) that itself needed verifying. A status label is a claim made by code. It is not evidence until something outside that code has tried to falsify it.

1.3 No durable record of what was actually checked

Even when real verification happens --- a test suite run, a Codex review reply, a manual source read --- it lives in a chat transcript that scrolls away. There is no single place that says, for a given claim, who checked it, what method they used, and what they found. Without that record, the next session (or the next person) has no way to tell a verified claim from an asserted one without redoing the work.

2\. Core principle

**No completion claim stands without an independent check from a party with no authorship stake in the claim, and no claim counts as checked unless that check is logged.**

\"No authorship stake\" has a precise test: could this checker\'s own reputation, continuity of reasoning, or prior framing of the problem bias it toward confirming the claim? If yes, it is not an independent checker, however fresh its context looks. This rules out the builder re-reading its own diff and calling that a review. It does not rule out a fresh agent session with the same underlying model, provided that session starts with zero inherited framing --- see Section 3.2 on why a forked context fails this test and a fresh one passes it.

3\. The two roles: Builder and Verifier

3.1 Builder

Writes the code, the fix, the feature, the report --- whatever the deliverable is. Is allowed, and expected, to run its own tests and do its own sanity checks; that is ordinary engineering discipline (self-verification), not the gate this protocol adds. The Builder\'s self-checks make a claim worth checking. They never close it.

3.2 Verifier

A separate agent invocation, started fresh, given only: (a) the specific claim to check, stated as a falsifiable sentence, not a vibe (\"this scan\'s VERIFIED_TRUE findings are not forgeable by target code\" --- not \"check if the scanner is good\"); (b) the artifact itself (the code, the file, the repo path); and (c) explicit permission and instruction to look for the way the claim is false, not to confirm it looks fine. It is never a forked session of the Builder\'s own context.

Why not a fork: a fork inherits the Builder\'s framing, including its blind spots. The Sentinel-Zero scanner itself demonstrates exactly this pattern at the code level --- the dynamic probe\'s Milestone 16 fix was written by someone who already believed the mechanism was basically sound and was patching the one gap they\'d spotted; it did not re-ask whether the mechanism\'s whole premise (trust unauthenticated subprocess stdout) was sound. A fresh, non-forked Verifier is the only way to get a check that isn\'t pre-committed to the Builder\'s own framing of what could go wrong.

Verifier output is always one of three verdicts per claim, never a prose paragraph of vague reassurance:

-   CONFIRMED --- reproduced the failure, or found direct source/behavioral evidence the claim is false, with a concrete failure scenario (specific input, specific line, specific observed output).

-   REFUTED --- actively tried to break the claim using the method that would most likely break it, and could not; states what was tried, not just \"looks fine.\"

-   UNABLE TO VERIFY --- the claim could not be checked with the access/tools available; this is reported, never silently treated as REFUTED. (Mirrors Sentinel-Zero\'s own UNRESOLVED_INCONCLUSIVE status --- the tool already knows this distinction matters for its own output; this protocol only asks that the same honesty apply to claims about the tool, and about everything else.)

4\. The Verification Gate

The Gate is the rule that decides when Section 3\'s Verifier step is mandatory before a claim may be described, to the user or in any document, using words like \"done,\" \"complete,\" \"verified,\" \"ready,\" \"fixed,\" or \"demo-ready.\"

4.1 When the Gate fires

-   Any claim that a bug is fixed, where the bug was a correctness or security defect (not a typo).

-   Any claim that a feature is complete and ready to use or demo.

-   Any claim that a scan, test run, or audit found zero issues (a clean result is itself a claim needing a check, not an absence of claims).

-   Any claim that output of one tool (a scanner, a probe, a classifier) can be trusted as evidence for a different, higher-stakes claim (\"VERIFIED_TRUE\" being read as \"this is a real vulnerability\").

-   Any claim made to a third party --- a PR description, a bug bounty report, a README, marketing copy --- since those carry reputational and, for bug bounty work, potentially legal weight if wrong.

4.2 When it does not fire

Routine, low-stakes, easily-reversible work does not need a second agent invocation for every step --- that is the overbuilding this protocol is explicitly designed to avoid. A typo fix, a renamed variable, a docs tweak, a work-in-progress status update (\"still debugging X\") carry no claim of completion and need no Gate. The Gate exists for the moment a claim is about to be asserted as true, not for every keystroke leading up to it.

5\. The Claim Ledger

A single append-only file per project --- not a new piece of infrastructure, a markdown or JSON file sitting next to .agent-sdlc.yaml --- recording every claim that passed through the Gate. This is the same idea Sentinel-Zero already uses on itself (verification_ledger.json, Finding Plan lifecycle PENDING → VERIFIED_TRUE / VERIFIED_FALSE / UNRESOLVED_INCONCLUSIVE / TOOL_FAILURE), turned outward onto claims about the project\'s own state, not just onto the code the project scans.

5.1 Schema

  ------------ --------------------------------------------------------- --------------------------------------------- -------------- -------------------------------------------------
  **Field**    **Meaning**                                               **Example**                                   **Required**   **Notes**

  claim_id     short unique id                                           sz-2026-10-21-01                              yes            date-prefixed, sequential

  claim_text   the falsifiable sentence being claimed                    \"npm.cmd PATHEXT fix resolves on Windows\"   yes            one sentence, no hedging words

  claimant     who/what made the claim                                   Builder session (Claude, this convo)          yes            

  verifier     who/what checked it                                       fresh Claude session, no fork                 yes            name the model/session distinctly from claimant

  method       what the verifier actually did                            read python_resolver.py:663-719 directly      yes            must be reproducible by a third party

  verdict      CONFIRMED / REFUTED / UNABLE_TO_VERIFY                    CONFIRMED                                     yes            never a fourth value

  evidence     the specific pointer: file:line, test name, repro steps   dogfood_scan.py:357                           yes            must let someone else go look

  date         UTC date of the check                                     2026-10-21                                    yes            
  ------------ --------------------------------------------------------- --------------------------------------------- -------------- -------------------------------------------------

5.2 Worked entry (from today\'s audit)

claim_id: sz-2026-10-21-01

claim_text: \"The dynamic sink-reachability probe\'s VERIFIED_TRUE output cannot be

forged by the code it is probing.\"

claimant: Builder session (prior Claude turn, stated tool was \"demo-ready\")

verifier: This same conversation, re-reading source directly (ad-hoc --- no

dedicated fresh Verifier session was spun up; see §8.2 for why that

matters and should be fixed going forward)

method: Read sink_reachability_probe.py and \_sink_reachability_harness.py in

full; traced the stdout-parsing path in run_sink_reachability_probe().

verdict: CONFIRMED (claim is FALSE)

evidence: sink_reachability_probe.py, run_sink_reachability_probe(): takes

completed.stdout.strip().splitlines()\[-1\] and json.loads()s it with

no check on which process wrote that line. Target code that prints a

matching JSON line and exits 0 before the real call satisfies this.

date: 2026-10-21

6\. KPI and benchmark layer

A Claim Ledger stops false claims from being asserted as done. It does not, by itself, answer a harder question the audit also raised: even when a mechanism works as designed, is it actually good at the job --- catching real vulnerabilities, missing few, false-alarming rarely? That needs numbers measured against something fixed, not impressions from whichever three repos got scanned this week.

6.1 Why \"it ran and produced output\" is not a KPI

Sentinel-Zero\'s own dogfooding runs, cited in the audit, produced 483 finding plans across five repos with 480 landing on UNRESOLVED_INCONCLUSIVE and three VERIFIED_TRUE promotions that --- per §3 above --- turned out to rest on a forgeable, mis-scoped mechanism. A number like \"483 findings\" sounds like output; it is not a benchmark, because nothing says how many of those 483 are real, how many real vulnerabilities in those five repos were missed entirely, or how many of the three VERIFIED_TRUE calls would survive adversarial input. A KPI has to be measured against a fixed, known answer key, the way the OWASP Benchmark project the audit cites is built: a frozen set of test cases where the vulnerable/safe status of every case is already known, so precision and recall can be computed instead of guessed at from vibes.

6.2 The four KPI categories

  ------------------------ --------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  **Category**             **Question it answers**                                         **How it\'s measured**

  Correctness              Of what the tool flags/claims, how much is real?                Precision and recall against a frozen fixture set of known-vulnerable and known-safe code, built once, never edited casually, with the correct answer recorded before the tool is run against it.

  Coverage                 How much of the real codebase does it even look at?             Explicit count: files parsed vs. files present, by extension; function/scope shapes known to be skipped (nested functions, inline callbacks, class statics, etc.) listed by name, not assumed away. Reported every run, not just when someone asks.

  Adversarial robustness   Can the thing being checked fool the checker?                   A standing red-team fixture: deliberately hostile input designed to make the tool report a false positive or false negative on purpose (exactly the \"target forges verification\" fixture the audit used). Run every time the verification mechanism itself changes.

  Delivery integrity       Does the shipped artifact actually do what the dev copy does?   Build the real distributable (the wheel, the npm package, the installer) in a clean environment and run the same fixture set against THAT, not the dev checkout. Catches the \"wheel omits the JS probe harness\" class of bug structurally, every time.
  ------------------------ --------------------------------------------------------------- -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

These four categories are deliberately the minimum, not an exhaustive QA program. A fifth or sixth category can be added to a specific project\'s benchmark file when that project\'s own failure modes call for it --- but adding categories nobody has needed yet is exactly the overbuilding this protocol is trying to prevent.

7\. SDLC integration

Sentinel-Zero\'s own CLAUDE.md already points at an .agent-sdlc.yaml with five rules: roi-first, spec-adherence, self-verification, security-guardrails, minimal-dependency-tax. This protocol does not replace that file --- it adds one rule to it, and defines what \"self-verification\" has to mean from now on so it can\'t be satisfied by the Builder alone.

Proposed addition to .agent-sdlc.yaml (every project, not just Sentinel-Zero):

\- independent-verification:

description: \>

No claim of \"done\", \"fixed\", \"verified\", or \"ready\" may be made

to the user, in a PR, or in any shipped document without a logged

Verifier pass from a non-forked session. See /docs/IVP.md.

gate_triggers: \[bug_fix_claim, feature_complete_claim, clean_scan_claim,

tool_output_trust_claim, third_party_facing_claim\]

ledger_path: ./VERIFICATION_LEDGER.md

benchmark_path: ./benchmarks/ \# frozen fixtures per §6, created once per project

self-verification (the existing rule --- \"run the real checks before calling it done\") stays exactly as written. It is necessary and unchanged; it has just never been sufficient, and this makes that explicit rather than implicit.

8\. Mapping onto the multi-model relay (TMRP)

The existing methodology --- Claude as orchestrator/synthesizer, other models (Gemini, Grok, Copilot, DeepSeek) as specialized execution nodes --- already has the right shape for this protocol; it just hasn\'t been pointed at verification specifically.

8.1 Two honest tiers of \"independent\"

-   Tier 1 --- fresh same-model session (minimum bar). A new, non-forked Claude Code session, given only the claim and the artifact, with explicit instructions to try to break the claim. Catches self-certification bias and status-label laundering. Does not catch a blind spot shared by the model itself across both sessions.

-   Tier 2 --- different-model session (stronger bar, reserved for high-stakes claims: bug-bounty submissions, anything shipped to a third party, anything a monetization decision rests on). Route the same claim and artifact to a different TMRP execution node. A genuinely different model is far less likely to share Claude\'s specific blind spots, at the cost of real latency/cost.

Use Tier 1 as the default Gate requirement from §4. Reserve Tier 2 for the subset of claims in §4.1\'s bullet list that carry outside-facing consequences --- exactly the discipline \"one thing at a time, no overbuilding\" calls for: not every claim needs the expensive check, but the ones that do should not get the cheap one.

8.2 What was missing today

Today\'s audit was effectively a one-off Tier 2 check --- a separate, independently-commissioned review --- but it wasn\'t logged as one in a Claim Ledger, and the re-verification done in this same conversation afterward was a same-session re-read, not even a fresh Tier 1 session. Section 5.2\'s worked entry above is marked accordingly. Going forward, the fix is mechanical: spin up a fresh (never forked) session for Tier 1, and write the result to the ledger file before the claim is repeated to the user --- not after, from memory.

9\. Worked example --- closing out today\'s six confirmed defects

This is not a build-it-now instruction (per the standing \"no more work or build on Sentinel-Zero right now\" direction) --- it is what the protocol looks like in use, so it reads as a procedure rather than theory the next time it\'s picked up.

  ----------------------------------------------------- ----------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------
  **Defect**                                            **Fix claim (hypothetical, once fixed)**                                                                          **What Tier 1 Verifier must try**

  Unauthenticated probe stdout                          \"Probe result now carries a nonce the harness signs and the parent checks.\"                                     Write a fixture module that prints a forged signed-looking line and exits 0; confirm the parent rejects it.

  Symbol-only promotion match                           \"Promotion now matches the specific call site, not just the sink name.\"                                         Two identical-sink calls in one function, one dead; confirm only the live one promotes.

  Nested Python functions invisible                     \"Nested function scopes are now indexed and walked.\"                                                            A closure with a real os.system call inside; confirm a finding plan is produced for it.

  Inline JS/TS callbacks invisible                      \"Anonymous function literals passed as call arguments are now walked.\"                                          A minimal Express-style handler with a sink inside the inline arrow callback; confirm a finding.

  Literal-arg probe mislabels reachability as exploit   \"VERIFIED_TRUE from the literal-argument path is now relabeled/split from attacker-controlled VERIFIED_TRUE.\"   Confirm the ledger/report text no longer implies attacker control when the harvested argument was proven literal.

  Sandbox lacks real isolation                          \"Probe subprocess now runs with cwd pinned inside a scratch dir and a scrubbed env.\"                            A target module that writes a file via a relative path and reads an injected env var; confirm neither escapes/leaks.
  ----------------------------------------------------- ----------------------------------------------------------------------------------------------------------------- ----------------------------------------------------------------------------------------------------------------------

Each row only earns a Claim Ledger entry with verdict CONFIRMED (meaning: the fix holds) once a fresh session has actually run that specific adversarial check against the fixed code --- not once the Builder\'s own new unit test for the fix passes. A unit test the Builder wrote for a bug the Builder found and fixed is still self-certification, even when it\'s green.

10\. Adoption checklist --- the minimal starting kit

Deliberately small. This is the whole of what changes day-to-day; everything above is the reasoning for why these four things are the right four.

-   1\. Drop a VERIFICATION_LEDGER.md (Section 5.1\'s table, as a markdown table or simple list) into any project the moment the first Gate-triggering claim happens in it. Don\'t pre-create it everywhere; create it on first need.

-   2\. Before saying \"done,\" \"fixed,\" \"verified,\" or \"ready\" to the user about anything matching §4.1, open a fresh (non-forked) session, hand it the claim and the artifact, and get a CONFIRMED / REFUTED / UNABLE_TO_VERIFY verdict with evidence.

-   3\. Write that verdict to the ledger before repeating the claim --- the ledger entry comes first, the sentence to the user comes second, not the other way around.

-   4\. For anything third-party-facing (bug bounty reports, PRs to someone else\'s repo, anything with monetization or legal weight), escalate to a Tier 2 different-model check per §8.1 before it goes out.

Nothing here requires new infrastructure, a new tool, or a new skill file to be built before it can be used --- the Agent/subagent mechanism already available in this environment is sufficient to run a Tier 1 Verifier pass today, on the next claim that needs one.

Appendix A --- Claim Ledger template

Copy this block into a new VERIFICATION_LEDGER.md for any project the first time the Gate fires in it.

\## \<project name\> --- Verification Ledger

\### \<claim_id\>

\- \*\*claim:\*\*

\- \*\*claimant:\*\*

\- \*\*verifier:\*\*

\- \*\*method:\*\*

\- \*\*verdict:\*\* CONFIRMED \| REFUTED \| UNABLE_TO_VERIFY

\- \*\*evidence:\*\*

\- \*\*date:\*\*

Appendix B --- Verifier prompt template

Use this shape when spinning up the fresh Tier 1 session. Fill in the two blanks only --- everything else stays as written, because the instruction to try to break the claim, not confirm it, is the entire point.

You are an independent verifier. You did not write the code or claim below,

and you have no stake in it being true. Your job is to try to show the claim

is FALSE, using the most realistic method available to you. If you cannot

break it after a genuine attempt, say so plainly \-- that is a real REFUTED

result, not a failure on your part.

CLAIM TO CHECK:

\<one falsifiable sentence\>

ARTIFACT:

\<file path(s) / repo path \-- read the actual source, do not rely on a

summary or on what anyone has told you about it\>

Report exactly one of:

CONFIRMED \<the claim is false \-- give the concrete failure: input, line, output\>

REFUTED \<you tried to break it via \<method\> and could not; be specific

about what you actually tried\>

UNABLE_TO_VERIFY \<what access/tool you lacked to check this at all\>

*--- end of document ---*

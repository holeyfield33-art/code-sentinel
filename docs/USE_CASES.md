# Sentinel-Zero — Use Cases

**Purpose of this document:** a security program's first job is accurate,
honest documentation of what an application is *for* — and, just as
important, what it is explicitly *not* for. A tool whose capabilities are
only described by what it happens to do, with no stated boundary, invites
both misuse by its operators and false confidence by anyone reading its
output. This document states both sides plainly.

## 1. What Sentinel-Zero is

A source-code reachability analyzer. Given read access to a repository
(its own files only — see §6), it reports, as a schema-checked Finding
Plan with an explicit disposition, whether a call into a known-dangerous
operation (process execution, file I/O, deserialization) is reachable
from the project's own code, whether a resolved, real guard provably
blocks it, and — for a narrow and explicitly safety-bounded subset — a
dynamically confirmed "this path is live" result from actually invoking
the containing function in an isolated, patched subprocess.

## 2. Intended use cases

1. **Pre-review triage of a codebase for dangerous-sink reachability.** A
   security reviewer or the repository's own maintainer runs a scan
   before a manual review, to get a ranked, evidence-tagged starting
   list rather than starting from zero or from `grep`.
2. **Confirming a specific hypothesis with real (bounded) dynamic
   evidence**, for the subset of call shapes the probe can safely attempt
   (an exported, zero-argument function, or one reachable via a real
   call site's own literal-constant arguments) — turning "this sink call
   is reachable from an exported entry point" from a static guess into a
   confirmed, reproducible observation.
3. **Tracking a codebase's own exposure over time.** Re-running a scan
   after a change and diffing the ledger's `VERIFIED_TRUE` /
   `UNRESOLVED_INCONCLUSIVE` counts and specific plan IDs is a legitimate,
   intended way to see whether a change widened or narrowed this
   surface — this is the seed of the trending capability described in
   `docs/SECURITY_MONITORING.md`.
4. **Programmatic use via the `sentinel-zero-mcp` MCP tool**, so an agent
   (human-supervised) can call this engine as a disposition authority
   instead of asserting its own unverified guess about reachability.
5. **Dogfooding and regression-testing this project's own resolvers**
   against real, unrelated repositories, exactly as every milestone in
   `README.md` has been — this is how false positives in the guard/sink
   logic itself get found and fixed (e.g. Milestone 19's CFG-dominance
   fix, found by re-scanning Block-Wise).

## 3. Explicitly disallowed use cases

These are not hypothetical edge cases — each one is disallowed because
the tool's actual mechanism cannot support it safely, cannot support it
at all, or because using it this way would misrepresent what its output
means.

1. **Running the dynamic probe against any repository without the
   repository owner's authorization.** The probe executes real code (the
   target function itself, inside a patched sandbox) — this is not a
   passive read. It must only ever be run against code the operator owns
   or has explicit authorization to execute, exactly like any other
   dynamic analysis or penetration-testing activity.
2. **Treating `UNRESOLVED_INCONCLUSIVE` as "safe" or "not vulnerable."**
   It means neither. It is, overwhelmingly, this tool's actual output —
   see §4 — and it means only "static analysis found a resolved sink call
   and did not find a dominating guard, and the dynamic probe either
   wasn't eligible to run or didn't settle the question." Reporting an
   `UNRESOLVED_INCONCLUSIVE` finding upstream as "scanned, clean" is a
   misuse of this tool's output, not a limitation of the tool.
3. **Treating a guard-dominance hit as proof the sink is not
   exploitable.** Real CFG dominance (Milestone 19) proves a resolved
   guard *call* runs on every path to the sink. It does not, and cannot
   from static structure alone, prove the guard's own internal condition
   corresponds to attacker-controlled input. This is exactly why the
   engine itself never promotes a guard-dominance hit to
   `VERIFIED_FALSE` — no downstream consumer of this tool's output should
   either.
4. **Using this as a fuzzer, a penetration-testing tool against live
   network services, or an intrusion-detection/prevention system.** It
   does not send network traffic, does not mutate inputs adversarially,
   and does not monitor anything at runtime. (See
   `docs/SECURITY_MONITORING.md` for the separate, smaller, explicitly-
   scoped monitoring concept this project does take on.)
5. **Running it against a repository containing secrets the operator
   does not want read.** The resolvers parse real source text (including
   string literals, via the AST) to do taint classification and literal-
   argument harvesting — nothing is sent anywhere external by this
   project itself, but the operator is responsible for not scanning a
   repo whose literal contents they would not want present in this
   process's memory or in a Finding Plan's `argument_taint`/harvested-args
   evidence.
6. **Scanning anything other than the target repository's own files.**
   The resolvers only walk the given `repo_root`; this tool has no
   capability and no license, implied or otherwise, to reach outside it.
7. **Treating the bundled ASI catalog snapshot as current.** A scan run
   without an explicit `--catalog` falls back to a point-in-time snapshot
   and says so explicitly in its output (`catalog.is_bundled_snapshot:
   true`). Using that snapshot's classification as if it were checked
   against the live, current catalog is a misuse of the `is_bundled_snapshot`
   flag's entire purpose.
8. **Treating a clean run (`VERIFIED_TRUE: 0`) as "no sinks in this
   codebase."** A scan that found zero `VERIFIED_TRUE` findings may
   simply mean nothing was eligible for the dynamic probe, or that the
   guard/sink tables (stated as non-exhaustive in `README.md`'s Known
   Bounds) don't yet cover the sink kind actually present.

## 4. Honest baseline, stated plainly

As of this document's writing, the great majority of findings this tool
reports resolve to `UNRESOLVED_INCONCLUSIVE`, not `VERIFIED_TRUE` or
`VERIFIED_FALSE` — `VERIFIED_FALSE` has never actually been set by any
code path in this project to date. This is not a defect being hidden; it
is the correct, honest ceiling of what static analysis plus a narrow,
safety-bounded dynamic probe can claim. Any documentation, dashboard, or
report built on top of this tool's output must preserve that honesty,
not round `UNRESOLVED_INCONCLUSIVE` up to anything cleaner-sounding.

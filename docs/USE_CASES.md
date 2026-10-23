# Review workflows

Sentinel-Zero helps maintainers and security reviewers organize source
evidence around supported security-sensitive calls. It provides review
leads with explicit uncertainty, not a repository-wide safety certificate.

## Before a manual security review

Run a static scan of the relevant checkout. Read the ledger's parse errors
and unresolved-call count before selecting finding plans to investigate.
Use source locations, sink identities, argument labels, guard evidence,
and reached package references to choose where to inspect the code.

For each lead, establish the actual application entry point, input trust,
runtime conditions, and relevant authorization checks yourself. A
`parameter` label or a guard-shaped call does not settle those questions.

## After a code change

Retain before/after outputs in separate directories and compare them with
the library or graph viewer. Keep the scanner, catalog, language, source
path, and probe mode comparable. Review source changes when interpreting
added/removed UIDs; line movement can change identity.

See [saved scans and comparison](SECURITY_MONITORING.md).

## Investigate an execution hypothesis

For code you are authorized to execute, diagnostic mode can attempt a
supported invocation in a locked-down Docker worker. Its report is an
untrusted observation for investigation. Inspect the parent-requested
site, eligibility, ambiguity, and failure details; independently establish
whether the target site and security condition are real.

Diagnostics do not authenticate their own stdout, generate adversarial
inputs, install target packages, or boot arbitrary applications. Container
isolation and proof authority are separate concerns.

## Explore or communicate the call graph

Use the viewer to inspect modules/functions, focus by name or disposition,
retain one-hop caller context, and compare node states against a baseline.
The viewer displays serialized evidence, including historical status labels;
it does not upgrade a finding's authority by rendering it.

## Integrate with a local agent

The MCP server returns the same ledger structure through
`analyze_repository`. Preserve inconclusive statuses and failure details
when summarizing results. An agent should not convert a zero-plan result,
a negative diagnostic, or a guard hit into an unsupported safety claim.

## Boundaries

| Intended use | Unsupported conclusion |
| --- | --- |
| Prioritize source review | All vulnerabilities have been found |
| Inspect modeled guard/caller relationships | Every runtime path is protected |
| Record a target-controlled diagnostic | A vulnerability or exact site is independently verified |
| Compare retained finding identities | Removed findings are necessarily fixed vulnerabilities |
| Review loaded catalog classifications | A bundled snapshot is the latest taxonomy |

The project does not provide runtime intrusion detection, network testing,
whole-program taint analysis, fuzzing, dependency vulnerability scanning,
or exhaustive language/sink coverage. Use [analysis limits](isbg-limits.md)
and the [security model](SECURITY.md) to scope each review.

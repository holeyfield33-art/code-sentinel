# Engineering verification policy

This policy defines how to support claims about Sentinel-Zero. It is
separate from the finding dispositions produced by the scanner. Passing
a development test does not grant a target finding `VERIFIED_TRUE`.

## State a falsifiable claim

Describe the behavior, artifact revision, and relevant environment. For
example, a claim about container isolation should specify the synthetic
operation, expected boundary, language, daemon/platform, and result.
Avoid broad completion or safety claims inferred from a status label.

## Match evidence to the claim

| Claim | Appropriate evidence |
| --- | --- |
| Parser or scope behavior | Source fixture, resolved target/caller, and graph-edge assertions |
| Finding classification | Plan fields and catalog provenance for a representative fixture |
| Verified-state rejection | Both transition and serialization boundary tests, including forged fields |
| Container isolation | Real daemon execution with synthetic env/cwd/write/network probes and positive controls |
| Lifecycle error handling | Fault-injection tests preserving primary and cleanup failures; real CLI coverage separately |
| Installed package behavior | Clean wheel build, fresh environment, and execution outside the source checkout |
| Viewer behavior | Unit tests for transformations plus a built application driven in a real browser |
| Type-check gate | Pinned tools/configuration and the complete documented command |

Flag-only, mocked, or shape-only tests are valuable unit coverage. They
do not establish end-to-end execution or report authenticity.

## Review independence

For security-boundary changes, obtain a review that actively looks for
counterexamples instead of accepting the implementation's own report.
A separate human or independently scoped review can supply evidence the
author's self-checks missed. State the review's actual independence and
limitations; do not label a repeated self-check as independent verification.

Use synthetic data and authorized targets. A positive control should
show that a protection test is exercising the intended path rather than
passing because nothing ran. A useful regression fails for the original
defect and passes after the change.

## Record evidence without publishing private runs

Keep commit IDs, commands, tool versions, platforms, outputs, test totals,
skip reasons, and artifacts in CI or the project's chosen private evidence
store. Do not commit chat transcripts, personal paths, credentials, target
source, or local scan ledgers into product documentation.

When summarizing an audit, distinguish:

- `VERIFIED`: the stated check was run and its output examined within the
  documented scope.
- `SUSPECT`: a tool or review suggests an issue that has not been confirmed.
- `FALSE_POSITIVE`: a specific counter-check shows the reported issue does
  not apply; state that counter-check rather than dismissing it generally.

These are evidence labels, not product disposition states. A failed,
skipped, queued, or infrastructure-blocked check is not a passing check.
Use the [regression index](../VERIFICATION_LEDGER.md) for maintained test
locations and [development](DEVELOPMENT.md) for reproducible commands.

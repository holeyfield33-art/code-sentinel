# Dogfood workflow

Use this guide to repeat source scans against authorized repositories and
investigate analysis regressions. This file is a maintained procedure,
not a public log of private targets, local paths, or development sessions.
Historical run notes remain in Git history.

## Prepare a run

1. Record the scanner revision/version and target revision in your evidence
   store. Inspect the target's language mix and choose explicit resolver runs.
2. Select the catalog and note whether it is a bundled snapshot. Keep the
   target stable while source files are read.
3. Start with static mode. Choose an output directory outside the target
   checkout and use a fresh directory for each retained run.

```sh
sentinel-zero analyze "/path/to/project" --language python --format md --out "../scan-artifacts/before"
```

For JS/TS, install the scanner's JS dependencies once, then use
`--language javascript`. That does not install the target's npm dependencies.

## Inspect evidence

Read the command result, parse errors, unresolved-call count, catalog
provenance, and a sample of finding plans. Trace source locations back to
the actual code. Inspect aliases, lexical scope, argument evidence, and
guard paths rather than accepting a count or status label on its own.

For a missing or surprising finding, reduce the relevant shape to a
synthetic reproduction in an OS temporary directory. Once its behavior
is understood, add a focused permanent regression test if appropriate.
Do not copy confidential source, credentials, or personal run reports
into tracked tests or docs.

## Optional diagnostic pass

Set up the [Docker boundary](SECURITY.md#docker-setup), then request a
separate diagnostic run only for code you are authorized to execute:

```sh
sentinel-zero analyze "/path/to/project" --language python --probe-mode diagnostic --format md --out "../scan-artifacts/diagnostic"
```

Record whether a probe was attempted, its requested site, raw diagnostic
status, and failure detail. A target-controlled `sink_reached` report is
not independent proof. A `call_failed` report must not be counted as a
successful runtime check or a negative finding.

## Compare and retain

Run the same resolver/settings after a change into a separate `after`
directory. Use [library diffing or the viewer](SECURITY_MONITORING.md).
Keep source paths and line shifts in mind when interpreting finding UIDs.

Retain the command, exit code, environment/tool versions, target/scanner
revisions, catalogs, output artifacts, test counts, and skip reasons in
CI or private storage. Report what was checked and what was not checked.
Do not promote a local run summary into a permanent blanket product claim.

## Viewer checks

Load the retained `graph.json`, inspect nodes, test name/category filters,
and compare a saved baseline. For repeatable synthetic browser checks,
use `npm --prefix viewer run test:e2e` after building the viewer and
installing Chromium, as described in the [viewer guide](../viewer/README.md).
The force layout is quadratic per step; a successful small graph check
is not a performance benchmark for large repositories.

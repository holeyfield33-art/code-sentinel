# Code Sentinel — agent entrypoint

**Product:** Sentinel-Zero is a source-code **security triage** tool for Python, JavaScript and TypeScript. A detected sink is a **review lead**, never proof of exploitation or attacker reachability. Read `README.md` for actual usage and `docs/isbg-limits.md` for supported analysis. **Default mode is static; optional Docker diagnostics execute untrusted target code only with explicit authorization.**

## Read order — one current truth

1. [README.md](README.md): what exists, product claims, CLI/installation.
2. [docs/STATUS.md](docs/STATUS.md): **single living current status** (revision, run evidence, blockers and next 1–3 maintenance actions); reconcile the status SHA with actual `git rev-parse HEAD`.
3. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): boundaries, test matrix and repository maintenance.
4. When relevant: [security and Docker execution](docs/SECURITY.md), [verification policy](docs/IVP.md), [analysis limitations](docs/isbg-limits.md), [calibration](docs/CALIBRATION.md), and [verification index](VERIFICATION_LEDGER.md). Historical audit/benchmark/remediation reports are source evidence, **not** automatic current readiness.

## Engineering constraints — no extra features during maintenance

- Do not replace source-oriented calibration with a count of flagged calls. Preserve the `UNRESOLVED_INCONCLUSIVE` disposition and the explicit distinction between source analysis, optional target-controlled diagnostic observations and **independent verification**. No new `VERIFIED_TRUE` or `VERIFIED_FALSE` without an actual independent verifier.
- **Avoid false assurance:** missing/failed source files, incomplete CVE pairs, stale/dirty fixtures, parser errors and ambiguous sink sites cannot count as negatives, complete scans or verified fixes. Do not edit calibration baselines/fixtures to force a pass; any approved fixture change requires new manifest/integrity review and independent labels.
- Scan only authorized code. Never execute untrusted target code in the host process; optional diagnostic runs require reviewed Docker isolation, pinned images and explicit authorization. Do not widen execution, egress or filesystem permissions to make tests pass.
- Maintain source/resolver coverage, diagnostic isolation, truthfulness of evidence, graph IDs, viewer input validation and installed-wheel behavior as separate test dimensions. Tests using mocks are not proof of real Docker isolation or Chromium behavior.
- Keep working edits surgical. First reproduce a concrete failure or establish a missing acceptance criterion, then fix it with the fewest code changes and a permanent positive/negative regression. **Pause scanner feature expansion** until measurable accuracy and release evidence justify it.
- Studio is advisory engineering knowledge, **not a Code Sentinel runtime dependency or release authority**. No automatic dependency, registry relationship or cross-repo synchronization.

## Test selection

Run from a clean, pinned checkout and a dedicated environment. The [development guide](docs/DEVELOPMENT.md) owns full setup, reproducible commands, CI and maintenance cadence.

```sh
python -m pytest tests -m "not docker_integration" -q -ra --tb=short --strict-markers
python calibration/calibrate.py
python -m mypy --ignore-missing-imports --no-error-summary sentinel_zero tests
npm --prefix viewer test
npm --prefix viewer run build
```

These commands do not replace real Docker, browser E2E, installed-wheel and cross-platform gates when those claims matter. Do **not** claim PASS when they have not actually executed; distinguish `PASS`, `FAIL`, `SKIP`, `NOT_RUN`, `BLOCKED` and `UNKNOWN`.

## Handoff

Report the base/head SHA, exact files and diff, risk and applicable controls, command/environment/output evidence, omitted tests, new vs historical findings, and next 1–3 actions. Update **only** [docs/STATUS.md](docs/STATUS.md) for current truth, `CHANGELOG.md` for shipped behavior, and stable engineering docs when rules change. Keep test artifacts in CI/private evidence storage. No new dated current-status dashboard, automatic release/merge, production claim or destructive host operation.

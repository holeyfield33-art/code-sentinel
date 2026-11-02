# Development and validation

## Environment

Clone the project and create a user-owned virtual environment using the
[installation guide](../README.md#install-from-source). From the checkout,
with that environment active:

```sh
python -m pip install -e ".[dev]" build tomli
npm --prefix sentinel_zero/resolvers/js ci
npm --prefix viewer ci
```

The development extra pins pytest 9.1.1, mypy 2.4.0, and
`types-PyYAML==6.0.12.20260906`. The stubs type the optional YAML import;
they do not install PyYAML into diagnostic containers. `tomli` supports
the packaging tests on Python 3.10. `build` enables the real-wheel test.

Editable installation avoids `PYTHONPATH` workarounds. Keep environments,
private scan outputs, and one-off reproductions outside the tracked tree.
The viewer and AST extractor have separate package manifests and lockfiles.

## Type checking

```sh
python -m mypy --ignore-missing-imports --no-error-summary sentinel_zero tests
```

The checked-in configuration targets Python 3.10, checks unannotated
function bodies, and flags unused ignores. Narrow `Symbol | Unresolved`
with control-flow branches and validate external JSON shapes before using
them. Use explicit module attribute replacement for intentional diagnostic
monkeypatches. Do not disable whole error categories to hide a local defect.

## Python suite and real Docker tests

The static and mocked test selection can run without a Docker executable:

```sh
python -m pytest tests -m "not docker_integration" -q -ra --tb=short --strict-markers
```

Live delegated-site scenarios use the integration marker; synthetic parent
output/timeout tests mock executable discovery as well as subprocess calls.
This selection does not establish runtime isolation.

Install Docker and pull the images in the [security guide](SECURITY.md#docker-setup).
A legacy integration fixture also checks the local `python:3.12-slim` tag.
Point that local tag at the same pinned image:

```sh
python -c "import subprocess; from sentinel_zero.probes.container_runner import IMAGES; subprocess.run(['docker','tag',IMAGES['python'],'python:3.12-slim'],check=True)"
python -m pytest tests -q -ra --tb=short
python -m pytest tests -m docker_integration -q -ra --tb=short
```

The full suite includes real target execution in containers and therefore
needs the daemon and images. `docker_integration` identifies live-backend
scenarios; flag assertions, mocked launch/cleanup faults, and JSON parser
unit tests do not establish end-to-end isolation. Some tests intentionally
skip an unavailable-daemon assertion when Docker is available. Inspect
skip reasons and collection totals rather than using a fixed test count.

Synthetic Linux source fixtures explicitly allow the fixed worker UID to
read their newly created temporary directories, even when the host test
user has a different UID. This does not change real repository permissions.

## Viewer

Use a Node version satisfying `viewer/package.json` (22.12+ is a convenient
shared choice). Vite and Playwright are pinned; transitive packages are
resolved by the lockfile.

```sh
npm --prefix viewer test
npm --prefix viewer run build
node viewer/node_modules/@playwright/test/cli.js install chromium
npm --prefix viewer run test:e2e
npm --prefix viewer audit --json
npm --prefix viewer outdated
```

Linux browser installations may need
`node viewer/node_modules/@playwright/test/cli.js install --with-deps chromium`.
The E2E suite starts a fresh built preview server, uses real Chromium/WebGL,
and checks uploads, filters, caller context, inspection, comparison, and
malformed-input refusal. It uses one worker, no retries, and OS-temp output.
Build before running E2E. Review advisories and supported upgrade paths
deliberately; do not use `npm audit fix --force` as a substitute for review.

## Clean installed-wheel smoke test

```sh
python scripts/ci_wheel_smoke.py
python scripts/ci_wheel_smoke.py --docker
```

The helper copies package source into a temporary build tree without stale
build metadata or Node modules, builds a wheel, installs it in a fresh
environment, installs that wheel's JS parser dependencies, and scans Python
and JS fixtures from outside the checkout using isolated Python. The
`--docker` variant also exercises both installed diagnostic harnesses.
It needs network access for package installation, plus Docker/images for
the diagnostic variant. It removes its temporary environment afterward.

## CI coverage

The [workflow](../.github/workflows/ci.yml) defines:

| Job | Coverage |
| --- | --- |
| Linux Python 3.10, 3.12, 3.14 | Pinned mypy, full pytest suite, and real Docker scenarios with a no-skipped-integration check |
| Windows and Linux viewer/parser | JS/TS parser regressions, viewer unit tests, production build, and Chromium E2E |
| Windows and Linux wheel | Fresh installed-wheel static scans; Linux also runs installed diagnostic harnesses |
| Manual Windows Docker | Dedicated self-hosted `Windows`, `X64`, `sentinel-docker-linux` runner with Linux-container Docker Desktop |

The manual workflow input `windows_docker` enables the last job. An
unconfigured or skipped job is not platform verification. Python jobs
upload JUnit results; inspect the actual run, job steps, and annotations.
A queued or infrastructure-blocked workflow has not tested the code.

## Repository maintenance — OWASP-informed, risk-adaptive

The [OWASP Web Security Testing Framework](https://wstg.owasp.org/stable/3-The_OWASP_Testing_Framework/0-The_Web_Security_Testing_Framework/) covers security work before development, in definition/design, during implementation/deployment, and throughout maintenance. For Sentinel-Zero this means maintaining a **source-code security analysis tool**, **not** requiring a web penetration test of every Python change. The reusable [Studio repository-maintenance convention](https://github.com/holeyfield33-art/software-research-studio/blob/main/docs/REPOSITORY_KNOWLEDGE_LAYOUT.md) is guidance only; Studio is not a runtime requirement.

**Read order:** root [AGENTS.md](../AGENTS.md), README, [single current STATUS](STATUS.md), then this guide and [security](SECURITY.md)/[calibration](CALIBRATION.md) for the affected subsystem. The [verification ledger](../VERIFICATION_LEDGER.md) maps behavior to tests; it is not an additional current-status document. Past findings, CI artifacts and frozen fixture data must not be reinterpreted as a fresh run.

### Maintenance stages and what to check

| When | Required judgment / selected gates | Maintained evidence |
| --- | --- | --- |
| **New change / PR** | Pin branch/HEAD, scope and existing code flow. Review relevant Python/Node AST handling, source-root containment, guards, output truthfulness, Docker isolation and viewer input validation. Add positive and adversarial negative controls for a real bug; avoid broad refactors and new scanner features. | Scoped diff, relevant `pytest` tests, mypy/parser/viewer checks as applicable, skip reasons, unchanged invariants |
| **Calibration/scoring change** | Freeze and inspect fixture/manifest, source SHA and scorer revision. Run `python calibration/calibrate.py`; confirm source coverage, parse errors, complete scoring, exact affected pairs and independently labeled truth. Never rerun `--update-baseline`/`--update-manifest` merely to silence failures. | Before/after score, denominators, missing/unscored pairs, expected group/call counts, unchanged frozen truth (unless separately reviewed), source/scanner digests |
| **Package, Python or JS/TS parser change** | Validate supported Python 3.10/3.12/3.14 and applicable Node versions. Install from pinned manifests, run Python and JS resolver tests, clean-wheel static scans outside checkout and viewer unit/build tests. Verify user-facing CLI/API and errors. | Package and lockfile hashes/revisions, selected platform results, installed-wheel evidence, no untested compatibility claim |
| **Release/deployment candidate** | Confirm exact candidate SHA and release authority, completed CI job steps, lint/type/tests and static/full relevant suites, real Docker isolation/cleanup in approved synthetic environments, browser E2E, packaging/license/provenance, authorization and rollback. | Source/CI SHA, run IDs, executed steps, PASS/FAIL/SKIP/NOT_RUN, independent reviewer, product release/HOLD decision |
| **Advisory/incident/security report** | Inspect affected dependencies, reachability and exposed interfaces; treat reports as hypotheses. Investigate raw target-code handling, parser time/memory bounds, Docker mounts/egress, generated data, graph import, calibration corruption and false-assurance claims. | Advisory/reproduction IDs, supported root cause, new regression or explicit unresolved gap, severity/owner and follow-up |
| **Post-release or post-change** | For an authorized delivered change, compare saved before/after scan and graph for the **same pinned target, resolver and settings**; review differences caused by file renumbering, parsing/coverage and changed triage policy. Validate critical CLI and viewer journeys; independent verification required for security-effect claims. | Exact before/after source and scanner revisions, parse/error coverage, approved changes, observed regression/rollback |
| **Periodic health** | **Propose monthly** while this active security tool is under development, or sooner after major dependency advisories, parser changes or incident. Review PR backlog, CI blockers, Python/npm locks, critical advisories, fixture integrity, drift between README and source, viewer/packaging compatibility, noisy priority rankings, resource caps and docs links. | Review date/owner, executed checks, outstanding risks, next review trigger; scheduling is **not** enabled by this document |

### Release and correctness floors

- **Static-only is the safe default.** Never run arbitrary downloaded/untrusted target code in the host process. Only use the optional Docker execution path on explicitly authorized synthetic targets with a reviewed daemon, pinned images and containment.
- A source file that could not be parsed/read, an unresolved symbol or incomplete scanner run is **UNKNOWN**, not absence of a vulnerability. An incomplete CVE pair is **unscored**, not a fix. Use current `docs/CALIBRATION.md` evidence integrity rules.
- A reported sink remains an `UNRESOLVED_INCONCLUSIVE` lead until independent authority exists. Docker diagnostics and model reports cannot self-certify `VERIFIED_TRUE`/`VERIFIED_FALSE`. Avoid unsupported marketing claims.
- Mocks validate logic; **real** Docker isolation, browser Chromium interactions and installed-wheel behavior require the corresponding executed gates. A CI workflow marked failed before any steps ran is **BLOCKED/NOT_RUN**, not a failing app suite.
- Before a release, compare the exact source, environment and results with the candidate intended to ship. Human review/acceptance decides security-sensitive releases and false-positive/true-positive classifications.

### Maintenance handoff without document sprawl

After each material review, record the observed date, commit/version, known maintainer or `UNKNOWN`, user/operational trigger, security invariants touched, tests and actual outputs, skip/NOT_RUN reasons, calibration impact, release or HOLD verdict, owners, and up to three next actions in [STATUS.md](STATUS.md). Store sensitive scan logs, local reproduction content and CI attachments outside the public repo. Update `CHANGELOG.md` for shipped behavior/contract changes, not a simple policy review; keep preserved test manifests, frozen source keys and historical reports intact.

**This maintenance procedure is documentation, not an executed check.** CI, real runtime isolation, recalibrated CVEs and Windows/browser tests remain unverified until actually run on the pinned revision.

## Documentation and releases

Keep CLI examples aligned with `sentinel-zero analyze --help`, tool pins
aligned with manifests, and Docker image references aligned with `IMAGES`.
Update [CHANGELOG.md](../CHANGELOG.md) for user-visible changes. Record
run-specific evidence in CI artifacts or private external files, not in
the README or committed conversation transcripts. Keep shipped behavior,
proposed work, and historical reports clearly distinguished.

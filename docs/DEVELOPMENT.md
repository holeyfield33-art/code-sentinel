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

## Documentation and releases

Keep CLI examples aligned with `sentinel-zero analyze --help`, tool pins
aligned with manifests, and Docker image references aligned with `IMAGES`.
Update [CHANGELOG.md](../CHANGELOG.md) for user-visible changes. Record
run-specific evidence in CI artifacts or private external files, not in
the README or committed conversation transcripts. Keep shipped behavior,
proposed work, and historical reports clearly distinguished.

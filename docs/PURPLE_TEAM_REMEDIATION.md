# Purple-team remediation

This change implements the code repairs from the October 29, 2026 engineering
review. It does not grant a commercial launch GO. The previously open PRs 25
and 26 were merged before this work; the repair branch starts from their merged
main revision `0f639d94064f0846accda82a2becfe7ea0a69f7e`.

## Implemented repairs

| Review item | Result | Regression evidence |
| --- | --- | --- |
| F01: conditional definitions lost | Module-level suites and supported class method suites retain function bodies and sink calls | `tests/test_purple_analysis.py` |
| F02: Python module collisions | Physical files retain distinct identities and calls; import namespaces and collision warnings are separate | `tests/test_purple_analysis.py` |
| F03: skipped guard credit | Short-circuit/conditional expressions, comparisons, assertions and deferred async/generator paths cannot certify an unconditional guard | `tests/test_purple_analysis.py`, `tests/test_guard_dominance.py` |
| F04: external source links | Both static resolvers reject escaping/dangling source-file links; contained regular-file links remain supported | `tests/test_static_source_boundary.py` |
| F05: special-file reads | Nonregular files and files over 8,000,000 bytes are refused before parsing; pipe regression has an external test timeout | `tests/test_static_source_boundary.py` |
| F06: invalid calibration credit | Scored files require analysis evidence; failed pairs remain unscored and withhold headline rates | `tests/test_cve_pairs.py`, `tests/test_lab_truth.py` |
| F07: dirty frozen caches | Modified/untracked/ignored files and hidden index flags are refused; successful results retain source/scanner digests | `tests/test_cve_pairs.py` |
| F08: graph entity collisions | Schema 2 gives module/function/external entities separate IDs, preserves symbols and physical ownership | `tests/test_graph_export.py` |
| F09: malformed viewer values | Validate consumed values, unique IDs and endpoints before replacing a graph; preserve unambiguous historical graphs and comparison | `viewer/test/graphLoader.test.js`, `viewer/test/diff.test.js` |

The original nine analysis scenarios were replayed: conditional and colliding
fixtures now retain their sink plans, and skipped validators leave those sinks
priority. Independent cross-review also identified chained comparisons,
unawaited async validators, unsafe pre-scan lab quote reads and Git index flags;
those paths now have regression coverage.

Async/generator guard handling is deliberately conservative. Correctly awaited
async validation also receives no synchronous guard credit until asynchronous
execution is modeled. Its sink calls remain indexed. Guard prose describes
the modeled control flow rather than claiming complete runtime dominance.

## Executed validation

On Linux with Python 3.12.14 and Node 24.22.1:

- `python -m pytest tests -m "not docker_integration" -q -ra --tb=short --strict-markers`:
  421 passed, 49 integration cases deselected; no skips or failures in that selection.
- Pinned mypy over `sentinel_zero tests`: passed, using a separate cache.
- Viewer Node tests: 32 passed. Production build: passed, with its bundle-size warning.
- Clean installed-wheel smoke: Python and JavaScript static scans passed outside
  the checkout in a fresh environment.
- Offline synthetic calibration: no regressions, 35/44 cases correct. The frozen
  fixture manifest and accepted baseline were not changed to manufacture a pass.
- Real collision source was parsed, exported and loaded through the Node viewer
  validation/layout path with distinct module/function positions.

Four real delegated-site Docker cases now carry the integration marker and
require the daemon and pinned image. Two synthetic lifecycle tests mock Docker
executable discovery along with subprocess behavior. This removes the six
environment-dependent failures from the old static selection without claiming
that live runtime isolation has been exercised.

## Remaining release gates

| Gate | Status after these repairs |
| --- | --- |
| Demonstrated analysis/data-loss regressions | Repaired with executed tests; broader static coverage remains bounded |
| Untrusted hosted intake | Open: source checks are not an isolated parser worker or a CPU/memory watchdog; stable source is still required |
| Calibration integrity | Repaired; full remote CVE/lab numbers must be regenerated with the new scorer before being recertified |
| Viewer release validation | Node tests/build pass; real Chromium E2E remains unexecuted in this environment |
| Runtime/platform assurance | Live Docker, installed diagnostic harness execution, Windows and the advertised Python matrix remain unverified here |
| Enforced release process | Actual passing CI/artifact promotion checks remain required; the earlier failed hosted jobs ran no steps |
| Commercial signal | Distinct independently labeled safe supported-API controls and human-reviewed pilot evidence remain required; existing lab negatives cannot supply a false-positive rate |

The synthetic set still records known limits including partial argument guard
coverage, module-level constant propagation and unsupported sink families.
The release decision remains NO-GO for dependable enterprise or unattended
scanner assurance. A supervised static review engagement is a narrower offer
with explicit supported scope and human-validated evidence.

See [security](SECURITY.md), [analysis limits](isbg-limits.md), and
[calibration](CALIBRATION.md) for the implemented contracts and their limits.

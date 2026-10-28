# Triage calibration

Sentinel-Zero never claims a verdict: every finding stays
`UNRESOLVED_INCONCLUSIVE`, and its value is the order of the list. So
calibration scores **ranking**, not detection: a reachable, attacker-influenced
sink should be `priority`; the same sink made safe by one thing should not.

```sh
python calibration/calibrate.py                    # score; compare with the baseline
python calibration/calibrate.py --update-baseline  # accept an intended change
python calibration/calibrate.py --update-manifest  # accept edited fixtures
```

`tests/test_calibration.py` runs the same check in the normal test suite, so a
triage regression fails `pytest`.

## Fixtures

`calibration/cases.py` holds small, hand-written, generic Python programs. Each
is labeled before any scan:

| Family | Correct triage |
|---|---|
| `reachable` | a plan that **is** priority |
| `near_miss` | a plan that is **not** priority (real guard, constant arguments, test/example code, low-signal sink) |
| `coverage_gap` | a real sink the scanner does not model yet; scored by how it was missed |

Each case names the one triage rule it exercises (`dimension`) and, where it
exists, its `pair`: the case one change away. Cases may also assert the exact
`guarded_by` and `constant_arguments` tags. `manifest.json` pins a digest of
every fixture, so a metric change is attributable to a scanner change, never
to silently edited fixtures (exit code 2 until re-pinned).

Coverage gaps are classified from the call graph, not from a global count:

- `resolved-not-sink`: the call resolved to the expected name, which is not in
  the sink registry yet (a table entry away);
- `unresolved`: the call on that line could not be resolved (honest
  uncertainty);
- `silent`: no trace at all (the worst case).

## Metrics

| Metric | Meaning |
|---|---|
| `reachable_priority_rate` | share of reachable cases ranked priority |
| `near_miss_downgrade_rate` | share of detected near-misses correctly *not* priority |
| `youden` | the first minus the near-miss priority rate; 1.0 is perfect ranking, 0 is chance |
| `priority_precision` | of everything ranked priority, the share that is truly reachable |
| `guard_evidence_accuracy` | `guarded_by` tags that match the label |
| `constant_accuracy` | `constant_arguments` tags that match the label |

The gate fails when a previously correct case turns incorrect, or when
`youden`, `near_miss_downgrade_rate` or `reachable_priority_rate` falls. It does
not gate on plan counts: finding more sinks while mis-tagging guards should fail.

## Baseline (2026-10-28)

32/40 correct; `youden` 0.9, `priority_precision` 0.958, guard evidence 1.0,
constant accuracy 0.833. Misses:

- `const-module-constant`: `subprocess.run(COMMAND)` with a module-level
  constant is still ranked priority (constant propagation through a module
  name is not modeled).
- Coverage gaps: `urlopen`, `requests.get`, `shutil.rmtree` resolve but are not
  sinks; `getattr(os, "system")`, `__import__("os")` and pathlib methods are
  unresolved. None are silent.

## Limits

The fixtures are synthetic. They test the rules, not real-world prevalence;
`docs/BENCHMARK.md` (held-out real repositories) is the cross-check against
tuning to these idioms. Checks that exist but are weak (a string-prefix path
check) are out of reach for static triage by design; dynamic probes such as
Block-Wise's security-block probes cover that.

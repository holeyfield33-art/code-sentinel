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

32/41 correct; `youden` 0.858, `priority_precision` 0.958, guard evidence
0.917, constant accuracy 0.833. Misses:

- `guard-caller-partial`: a guard is credited when it covers *any* variable the
  sink reads, so `read(base, name)` with only `name` validated is hidden even
  though the caller still chooses `base`. Guard relevance should require every
  caller-influenced argument to be covered.

- `const-module-constant`: `subprocess.run(COMMAND)` with a module-level
  constant is still ranked priority (constant propagation through a module
  name is not modeled).
- Coverage gaps: `urlopen`, `requests.get`, `shutil.rmtree` resolve but are not
  sinks; `getattr(os, "system")`, `__import__("os")` and pathlib methods are
  unresolved. None are silent.

## Real CVEs (vulnerable vs fixed commit)

`calibration/cve_pairs.py` scores Sentinel-Zero on published Python
vulnerabilities. It clones the projects, so it is not part of `pytest`:

```sh
python calibration/cve_pairs.py --out calibration/cve_results.json
```

**Selection, by rule only.** `calibration/cve_tools/` runs three steps:

1. Read the PyPA advisory database (commit `30d5858`) and keep the 528
   advisories whose text names a modeled sink family and links a fix.
2. Fetch the 512 fix commits, of which 495 were reachable.
3. Keep fixes that remove or rewrite a call to a modeled Python sink in
   non-test source. The sink must match the advisory's family, the vulnerable
   site is the function enclosing that call at the parent commit, there is one
   pair per repository, and repositories are capped at 3,000 `.py` files.

That gives 51 pairs with 102 vulnerable sites. The 380 fixes that only add a
guard (typical for path traversal) are counted but not scored, because their
site cannot be read off the diff without guessing.

**Result (2026-10-28):**

| Measure | Value |
|---|---|
| Vulnerable sites ranked priority (recall) | **93/102 (0.91)**. 7 more were ranked but not priority; 2 were missed. |
| Sites no longer priority after the fix (quiet on fix) | **89/102 (0.87)**. 86 gone, 3 downgraded, 13 still flagged. |
| Share of *all* plans that are priority in the same 51 repos | 0.30 (3,769 of 12,751) |
| Share of plans on the *same sink* that are priority, averaged over sites | 0.71 |

Read the last two rows before the first. Recall is about 3x the overall
priority rate, so the ranking carries signal. But against plans on the same sink
it is only about 1.3x. Most of the recall comes from the sink being dangerous,
not from the triage rules singling out the vulnerable call. Sentinel-Zero does
not hide these bugs; it does not yet pick them out of a crowd either. A reviewer
still faces a median of 47 priority plans per repository.

**Why each site was not detected:**

| Cause | Sites | Fix |
|---|---|---|
| A wrapper the scanner does not model: Radicale's own `open()` calls `codecs.open` | 2 missed | Add `codecs.open` as a sink |
| A producer credited as a guard: ms-swift's `cls.rollout(*args)` *builds* the shell command and can raise, so it was credited as the callee-raises guard of the `os.system` it feeds | 3 | A call whose return value flows into the sink must not count as its guard |
| A `doc` package directory treated as documentation (`docling_core/types/doc/`) | 1 | Match docs directories at the top level only, as tooling directories already are |
| A feature predicate credited as a guard: onnx's `if not uses_external_data(t): continue` | 1 | Not fixable by name-based rules. A known limit of static guard crediting. |
| Constant arguments (cobbler) | 2 | The paths really are constants. Whether that down-rank is right depends on the advisory's mechanism, which is not verified here. |

**Still flagged after the fix (13):** the fix kept the sink and made it
safe in a way static triage cannot see. Examples are eval in a restricted
namespace, shell quoting, and path validation done with stdlib calls. That is
expected from the static model and is reported, not tuned away.

**Bias to keep in mind:** the set holds only fixes that touch the sink line,
and only Python. Guard-only fixes are a separate, harder population. A
vulnerable-lab ground truth, in progress, will add JS/TS and documented intent.

## Limits

The fixtures are synthetic. They test the rules, not real-world prevalence;
`docs/BENCHMARK.md` (held-out real repositories) is the cross-check against
tuning to these idioms. Checks that exist but are weak (a string-prefix path
check) are out of reach for static triage by design; dynamic probes such as
Block-Wise's security-block probes cover that.

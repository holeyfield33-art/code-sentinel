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

## Calibration integrity

The CVE and lab scorers now require every scored source file to appear in
the ledger's `analyzed_files` and to have no relevant parse/input failure.
A genuinely deleted fixed-side file can count as gone; a present file that
was not analyzed cannot. Unrelated per-file failures are retained in scan
evidence. The shared checkout helper refuses modified, untracked and ignored
extra files rather than assuming a matching commit SHA means clean bytes.
Assume-unchanged and skip-worktree index flags are refused because Git status
can hide modified tracked bytes under those flags. Lab quote validation uses
the same contained, bounded regular-file reader before invoking the scanner.
It never resets an operator's changes; use a fresh cache after preserving them.

New CVE result documents use `sentinel-cve-calibration-v2`. Each successful
pair retains source/scanner digests, pinned source commits and scan diagnostics.
Failed pairs retain expected group/call counts. If any pair is unscored,
`complete` is false, headline recall/quiet-on-fix rates are null, partial rates
are explicitly named `scored_only_rates`, and the command exits 1. No failed
file is credited as a successful fix. The lab scorer fails on an unscorable
required file and retains source identities in successful results.

The committed CVE/lab performance numbers below are historical runs from
before this integrity change. They have not been recertified by the new
scorer. The frozen answer key is unchanged. Neither a passing synthetic
regression gate nor the existing lab negatives establishes an enterprise
false-positive rate; distinct safe supported-API controls remain required.

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

## Baseline

2026-10-29, after the calibration fixes below: **35/44 correct**. Three cases
were added, one per fix that the synthetic set can express
(`guard-callee-producer`, `const-local-variable`, `const-local-rebound`). All
three are correct, and none of the original 41 changed outcome.

2026-10-28: 32/41 correct; `youden` 0.858, `priority_precision` 0.958, guard
evidence 0.917, constant accuracy 0.833. Misses (still open):

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
   non-test source, applying these rules:
   - Each call is located by its line in the parent commit, read from the diff.
   - The sink must match the advisory's family.
   - Calls in files the fix deleted are not scored (214 calls). A removal is
     not a fix, and "gone" afterwards would be trivially true.
   - There is one pair per repository.
   - Repositories are capped at 3,000 `.py` files.

That gives 55 pairs with 109 vulnerable calls, in 97 groups. A group is one
sink in one function. The 386 fixes that only add a guard (typical for path
traversal) are counted but not scored, because their site cannot be read off
the diff without guessing.

**Scoring unit.** At the vulnerable commit every call is matched by its exact
line, so a group counts as detected only if every call in it is priority. At
the fixed commit lines move, so the group is judged as a whole.

**Result (2026-10-28):**

| Measure | Value |
|---|---|
| Groups ranked priority (recall) | **89/97 (0.92)**. 6 more were ranked but not priority; 2 were missed. Per call: 101/109 (0.93). |
| Groups no longer priority after the fix (quiet on fix) | **84/97 (0.87)**. 83 gone, 1 downgraded, 13 still flagged. |
| Share of *all* plans that are priority in the same 55 repos | 0.29 (3,930 of 13,739) |
| Share of plans on the *same sink* that are priority, averaged over groups | 0.72 |

Read the last two rows before the first. Recall is about 3x the overall
priority rate, so the ranking carries signal. But against plans on the same sink
it is only about 1.3x. Most of the recall comes from the sink being dangerous,
not from the triage rules singling out the vulnerable call. Sentinel-Zero does
not hide these bugs; it does not yet pick them out of a crowd either. A reviewer
still faces a median of 32 priority plans per repository.

**Why each group was not detected:**

| Cause | Groups | Fix |
|---|---|---|
| A wrapper the scanner did not model: Radicale's own `open()` calls `codecs.open` | 2 missed | **Fixed** (`codecs.open`, `io.open` are sinks). Radicale is now flagged at the real sink, the wrapper's `codecs.open(abs_path)`. The pair still scores "missed": its sites are the wrapper's *callers*, which the selection regex labeled `builtins.open`. That is an answer-key error, left as is because the pair set is frozen. |
| A producer credited as a guard: ms-swift's `cls.rollout(*args)` *builds* the shell command and can raise, so it was credited as the callee-raises guard of the `os.system` it feeds | 3 | **Fixed**: a call whose result is assigned to a variable the sink reads is never its guard |
| A `doc` package directory treated as documentation (`docling_core/types/doc/`) | 1 | **Fixed**: docs directories match at the top level only |
| A feature predicate credited as a guard: onnx's `if not uses_external_data(t): continue` | 1 | Not fixable by name-based rules. A known limit of static guard crediting. |
| A top-level `scripts/` file treated as build tooling (cobbler `scripts/services.py`) | 1 | Correct by the rule as written. Whether that script is deployed is not visible statically. |

**Still flagged after the fix (13):** the fix kept the sink and made it
safe in a way static triage cannot see. Examples are eval in a restricted
namespace, shell quoting, and path validation done with stdlib calls. That is
expected from the static model and is reported, not tuned away.

**Bias to keep in mind:** the set holds only fixes that touch the sink line,
and only Python. Guard-only fixes are a separate, harder population. A
vulnerable-lab ground truth, in progress, will add JS/TS and documented intent.

## Vulnerable labs (independent answer key)

`calibration/labs/vuln_labs_manifest.json` is an answer key for six deliberately
vulnerable applications, built by a separate research agent that never ran
Sentinel-Zero:

- Python: pygoat, DSVW and Vulnerable-Flask-App
- JavaScript and TypeScript: dvws-node, NovaTrust bank and OWASP Juice Shop

Each lab is pinned to a commit. Every entry quotes its sink line and cites the
lab's own documentation of the vulnerability. The key's status is PARTIAL: some
catalog entries could not be located in source (see
`calibration/labs/vuln_labs_report.md`).

```sh
python calibration/lab_truth.py calibration/labs/vuln_labs_manifest.json
```

The scorer follows the key's handoff rules:

- Score only entries that are located, documented, vulnerable and in scope.
- Count a sink line shared by several challenges once.
- Keep weak entries (low-signal JSON parsers, a constant command) apart.
- Never score unlocated entries as misses.

Before scoring, it re-checks every quoted line against the pinned source. All
306 located quotes matched. The bundled key and report are the research agent's
frozen bytes (`calibration/labs/SHA256SUMS`).

**Result (2026-10-28):**

| Set | Sites | Detected (priority) | Under-ranked | Missed |
|---|---|---|---|---|
| Direct cases | 25 | **24 (0.96)** | 0 | 1 |
| Weak cases | 5 | 1 | 4 | 0 |

The weak cases behave as designed: the four JSON parsers are low signal, so
they are not priority. The fifth, Vulnerable-Flask-App's
`check_output("cat restapi.log")`, *should* be down-ranked but is priority.

**Read this beside the base rate.** In these labs, 39% of all plans and 90% of
plans on the same sinks are priority. NovaTrust is scored within its declared
`vuln-bank/` folder; the rest of that monorepo is other applications. Small
training apps put a vulnerability behind almost every dangerous call. So the labs show that Sentinel-Zero does
not hide these bugs; they cannot show that it ranks well.

**Defects found:**

| Cause | Site | Fix |
|---|---|---|
| Calls inside a `function` declared inside another function were not recorded at all, nor were callbacks inside it. This was a *silent* gap: no edge, no unresolved marker. (Earlier described as "inside a callback"; the real shape is a nested declaration with a callback inside it.) | dvws-node `src/utils/vulnerable-xml.js:64`, `fs.readFileSync` | **Fixed**: nested declarations are walked as `outer.<locals>.inner` |
| A constant reached through a local variable was not recognized as constant (`command = "cat restapi.log"`, then `check_output(command, shell=True)`) | Vulnerable-Flask-App line 68 | **Fixed** for locals whose every binding is the same kind of constant assignment. Module-level constants are still the open synthetic miss. |

**Limits of this layer:** it has 25 direct sites, and only one negative
control sits on a supported sink. That control (`juice-shop-rceChallenge`)
shares its line with a vulnerable entry, so it cannot act as a negative at site
level. False positives are therefore not measured here.

## After the calibration fixes (2026-10-29)

Each defect above was fixed in its own commit with a regression test, then
every layer was rerun with the same caches and pinned commits.

| Layer | Measure | Before | After |
|---|---|---|---|
| Synthetic | correct cases | 32/41 | 35/44 (+3 new cases, all correct; no case changed) |
| CVE pairs | groups ranked priority (recall) | 89/97 (0.92) | **93/97 (0.96)**; per call 101/109 -> 105/109 |
| CVE pairs | quiet on fix | 84/97 (0.87) | 83/97 (0.86) |
| CVE pairs | priority share, all plans | 0.286 (3,930 of 13,739) | 0.290 (4,005 of 13,817) |
| CVE pairs | priority share, same sink | 0.72 | 0.74 |
| Labs | direct sites detected | 24/25 | **25/25** |
| Labs | weak cases wrongly priority | 1 | 0 |
| Labs | priority share, all plans / same sink | 0.39 / 0.90 | 0.38 / 0.88 |
| Held-out benchmark | priority plans (swr, stytch-node, DefectDojo, chia) | 0, 0, 0, 52 | 0, 0, 0, 52, the identical set |

Attribution: the 4 CVE groups that moved are ms-swift (3, producer-not-guard)
and docling (1, docs directories). Docling's fix only switched
`Loader=yaml.FullLoader` to `yaml.SafeLoader`, which static triage does not
distinguish, so it is now "still flagged" after the fix; that is the single
point quiet-on-fix lost, and it was "downgraded" before only because the
directory rule hid the whole file. The lab gains are dvws-node (nested JS
functions) and Vulnerable-Flask-App (local constants, both its Linux and
Windows copies).

How to read it: recall went up on real bugs and the held-out repositories did
not move, so nothing was tuned at their expense. But the same-sink priority
share went up too (0.72 to 0.74 on CVEs), so these fixes recover missed bugs;
they do not make the vulnerable call stand out more from its neighbors.
Ranking sharpness is still the open problem. Next candidates from this run:
`yaml.load` with an explicit safe loader, and module-level constants.

## Limits

The fixtures are synthetic. They test the rules, not real-world prevalence;
`docs/BENCHMARK.md` (held-out real repositories) is the cross-check against
tuning to these idioms. Checks that exist but are weak (a string-prefix path
check) are out of reach for static triage by design; dynamic probes such as
Block-Wise's security-block probes cover that.

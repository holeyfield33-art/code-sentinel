# Held-out benchmark

Sentinel-Zero was built and calibrated against Vercel's OSS repositories.
A clean result there shows only that the scanner remembers its training
ground. This benchmark scans repositories it was **not** tuned on, with one
Vercel repository kept as a control: if the control changes, the scanner
regressed; if the held-out repos degrade, it is over-fitted.

All targets are public and in scope as source code on HackerOne programs.
Scans are static (`--probe-mode static`), so no target code is executed.

## Targets (pinned)

| Role | Repository | Commit | Language | Program |
|---|---|---|---|---|
| Control | `vercel/swr` | `8148ef0` | TS | Vercel |
| Held-out | `stytchauth/stytch-node` | `d5e9dd6` | TS | Twilio |
| Held-out | `DefectDojo/django-DefectDojo` | `4ac58d7` | Python | DefectDojo (VDP) |
| Held-out | `Chia-Network/chia-blockchain` | `2e906ab` | Python | Chia |

## Rerun

```sh
for r in vercel/swr stytchauth/stytch-node DefectDojo/django-DefectDojo Chia-Network/chia-blockchain; do
  git clone --depth 1 "https://github.com/$r" "targets/$(basename $r)"
done
for n in swr stytch-node django-DefectDojo chia-blockchain; do
  sentinel-zero analyze "targets/$n" --format md --out "results/$n"
done
```

For an exact comparison, check out the commits above rather than `HEAD`.

## Results

### 2026-10-28, before triage and the graph-cap fix

| Repo | Exit | Report | Plans | Real leads |
|---|---|---|---|---|
| swr | 0 | yes | 7 | 0 |
| stytch-node | 0 | yes | 0 | — |
| django-DefectDojo | **3** | **no** (graph 59 MB > cap) | 486 | 0 |
| chia-blockchain | **3** | **no** (graph 38 MB > cap) | 271 | 0 |

- 483/486 DefectDojo plans were `json.load`/`json.loads` labelled AAC-27.
- 47% of chia plans were in tests, CI, or benchmarks.
- Every high-risk sink checked by hand (3 `pickle.loads`, 3 `subprocess`)
  was in test or build code.

### 2026-10-28, after triage and the graph-cap fix

| Repo | Exit | Report | Plans | Priority | Graph |
|---|---|---|---|---|---|
| swr | 0 | yes | 7 | 0 | written |
| stytch-node | 0 | yes | 0 | 0 | written |
| django-DefectDojo | 0 | yes | 486 | 0 | skipped (over cap) |
| chia-blockchain | 0 | yes | 271 | 58 | skipped (over cap) |

The only candidate lead found while hand-reviewing chia's priority list
(`chia/data_layer/data_layer_server.py`, a request-derived path passed to
`open`) is guarded by `is_filename_valid`, which accepts only the canonical
hex filename, so it is a false positive. The scanner did not credit that guard
because it only recognizes guards that raise inside the called function, not
the caller-side `if not valid(x): raise` pattern. That is the next precision
gap to close.

### 2026-10-28, caller-side guards and constant arguments

| Repo | Plans | Priority | Guarded (data-relevant) | Constant args |
|---|---|---|---|---|
| swr | 7 | 0 | 0 | 0 |
| stytch-node | 0 | 0 | 0 | 0 |
| django-DefectDojo | 486 | 0 | 4 | 9 |
| chia-blockchain | 271 | **51** (was 58) | 23 | 9 |

- `chia/data_layer/data_layer_server.py` (both handlers) is now credited to
  `is_filename_valid` and leaves the priority list.
- A first version credited any project call in an exiting `if` test, which
  over-credited (`if not self.synced(): return` before an `open`). A guard
  now counts only if its arguments read a variable the sink's arguments
  read, directly or through an earlier assignment. The same relevance rule
  now decides whether the older callee-raises guard affects triage; it had
  been crediting calls such as `calculate_iterations_quality`.
- Expected a sharp drop; got 58 to 51. Of the 51, 36 sinks take arguments
  of unknown origin (config and computed paths). Without a model of where
  untrusted input enters (HTTP handlers, CLI arguments), the scanner cannot
  separate a pid-file path from a request path. That is the next real gap.

## Open gaps

- No entry-point (source) model: the scanner does not know which functions
  receive untrusted input, so most remaining priority plans are internal
  file and process calls of unknown argument origin.
- Caller-side guards are Python-only; the JS resolver does not record them.
- `stytch-node` returned 0 plans with 825 unresolved call sites; 0 is not yet
  a demonstrated true negative.
- Graphs for large repositories exceed the cap even when written compact.

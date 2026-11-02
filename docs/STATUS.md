# Code Sentinel — current engineering status

**Observed:** 2026-11-01 (repository and published CI metadata, **read-only** review).  
**Pinned base `main`:** `303267e4786735b068ed544936480b2368194b01` (merged purple-team remediation PR #27).  
**Package:** `sentinel-zero` `0.12.0` per `pyproject.toml`.  
**Disposition:** **experimental / supervised security triage; NO-GO for unattended or enterprise-grade vulnerability verdicts.** Not a production security guarantee. This document is the **only current mutable status authority**, not a second verification ledger.

## What the repository currently implements (source inspected)

- Static-by-default Python and JS/TS source resolution, graph and sink-oriented *triage plans*. The collected extensions include `.py`, `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts` and `.cts`, with a **single resolver per run**; mixed-language projects need separate runs. `sentinel_zero/repo_detect.py` and `docs/isbg-limits.md` agree on these extensions.
- Optional Docker-backed diagnostics with **target-controlled** observations; the project does **not** independently establish a true/false vulnerability verdict. `VERIFIED_TRUE`/`VERIFIED_FALSE` are not authorized by present target-produced reports.
- Exportable graph/ledger and interactive viewer, plus source, parser, packaging, calibration and failure/isolation regression tests.
- The current remediation document describes fixes to conditional definition visibility, collision attribution, guard dominance, safe source reads, calibration integrity and graph IDs. Read [historical remediation evidence](PURPLE_TEAM_REMEDIATION.md) rather than treating its test counts as a new execution at this SHA.

## Evidence obtained in this maintenance review

| Claim / check | Recorded result | Actual evidence boundary |
| --- | --- | --- |
| Repository and baseline | **OBSERVED** | GitHub current `main` commit `303267e`, source tree and manifests |
| Static support and scanner safety claims | **SOURCE-INSPECTED** | README, architecture, resolver input/extension contract, security and limits docs; not a new executable test |
| Previous local non-Docker regression suite | **HISTORICAL**: 421 passed, 49 Docker cases deselected | `docs/PURPLE_TEAM_REMEDIATION.md`; earlier Linux/Python 3.12.14 run, not rerun on present main |
| Previous viewer tests and build | **HISTORICAL**: 32 Node tests passed; production build passed | Same past remediation record; Chromium E2E not proven by that test set |
| Previous synthetic calibration | **HISTORICAL**: 35/44 cases correctly ranked | `docs/CALIBRATION.md`; this is ranking quality, not vulnerability detection accuracy |
| Frozen real CVE/lab calibration metrics | **RE-CERTIFICATION NOT_RUN** | New scorer enforces analyzed-file completeness/clean source and withholds headline rates for unscored pairs. The older 93/97 and 25/25 figures predate its integrity changes and are not accepted as fresh |
| Main commit CI `40888646058` | **BLOCKED / NOT_RUN** | Seven required GitHub Actions jobs concluded failure **with zero executed steps**; optional Windows Docker job skipped. This is not an application test result |
| Later non-main CI `41142096510` | **BLOCKED / NOT_RUN** | Seven jobs with zero executed steps; run targets a different commit, `51a0395`, not this pinned main |
| New maintenance review: local pytest, mypy, npm, Docker and Chromium | **NOT_RUN** | This environment could inspect GitHub contents but could not clone the repository or run the toolchain |
| Independent calibration proof and supervised external accuracy | **NOT_ESTABLISHED** | Existing safe negative controls are insufficient to quantify an enterprise false-positive rate; source labels and review required |

Do not count any of these historical checks or CI job titles as proof that the current HEAD passed a full test matrix.

## Highest-leverage gaps and priorities

1. **Establish runnable CI and reproduce the exact revision:** fix account/runner execution, then record actual job steps, tests/skips, upload artifacts and the corresponding SHA. Verify clean wheel, JS/TS parser, browser E2E and Docker isolation only in appropriate environments.
2. **Make calibration claims defensible:** rerun full pinned CVE-pair/lab scoring under new integrity gates; report `complete=false`/scored-only rates where any pair is unscored. Before commercial precision claims, obtain independently labeled **safe supported-API negative controls** (not synthetic controls sharing vulnerable lines) and human-reviewed pilot evidence. Do not alter frozen answer keys simply to obtain passing metrics.
3. **Preserve a small, maintainable software surface:** use [project-specific maintenance](DEVELOPMENT.md) for dependency/cross-platform/advisory checks, documented support and post-change comparison. Reconcile stale documentation without new scanner features, automation or metrics dashboards.

## Product and operations boundaries

- A triage lead is not an exploit finding, and a missing plan is not a security guarantee. Mixed-language/parse-failed files must not count as scanned or safe.
- Source reads are restricted to bounded, contained regular files, but immutable filesystem snapshots and parser sandboxing are not established. For hosted/untrusted multi-tenant ingestion, additional isolation review is required before accepting arbitrary targets.
- Real diagnostic containment, signature/provenance authority, independent verification, Windows Docker and browser behavior require separate executed evidence. Do not promote product status from documentation.
- The repository is **not** enrolled in an automatic periodic maintenance task. A suggested monthly review for this security tool remains an operator choice, not a task already running.
- The original research and frozen CVE keys remain owned by Code Sentinel. Software Research Studio is an engineering knowledge reference, not a dependency. MOTHERSHIP vulnerability intelligence remains separate.

**Next status update rule:** replace only this living record after observed evidence or material decisions change; keep historic calibration and purple-team reports as source documents, and preserve CI logs or sensitive audit runs outside the tracked repository.

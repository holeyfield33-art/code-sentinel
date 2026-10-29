# Changelog

Changes are grouped by their effect on users and maintainers. Release dates
and historical version tags are not inferred from development commits.

## Unreleased

### Security and behavior changes

- Default CLI, library, and MCP scans to static analysis. Target execution
  requires the explicit `diagnostic` probe mode.
- Reject `VERIFIED_TRUE` and `VERIFIED_FALSE` authorization at disposition
  transition and serialization boundaries until an independent verifier exists.
- Record target reports as untrusted observations tied to a parent-requested
  site. Validate report objects, statuses, and field types, including JS `null`.
- Require Docker isolation for both diagnostic backends. Use pinned images,
  a non-root worker, read-only source/root filesystems, private scratch space,
  fixed environment values, no network, and bounded resources/output.
- Remove host-process fallback and automatic target manifest installation.
  Preserve execution errors when bounded container cleanup also fails.
- Suppress ambiguous same-symbol diagnostic attempts across direct and
  transitive call sites. A sink name or nonce is not proof of call-site identity.
- Add `sentinel-zero pull-images [--language ...]` to explicitly pull the
  digest-pinned runtime images. Scans still never pull (`--pull never`); a
  missing image now fails closed with the missing digest and this command
  instead of an opaque Docker exit 125.
- Validate both bind-mount paths (target source and harness install) against
  Docker's `--mount` CSV parser: reject `,`, `"`, CR/LF, and leading/trailing
  whitespace with a named error before any `docker run`. `=` stays allowed:
  Docker splits each field on its first `=`, so it is carried intact.

### Analysis

- Add a vulnerable-lab calibration layer (`calibration/lab_truth.py`) scored
  against an independently built answer key for six labs (pygoat, DSVW,
  Vulnerable-Flask-App, dvws-node, NovaTrust bank, Juice Shop). 24 of 25
  direct sites ranked priority; 90% same-sink base rate, so this shows
  coverage, not ranking. Found a silent JS gap (calls in functions declared
  inside callbacks) and a missed local-variable constant.

- Add a real-CVE calibration layer (`calibration/cve_pairs.py`, not in
  `pytest` because it clones repositories). 55 vulnerable/fixed pairs (97
  function/sink groups, 109 calls), selected by rule from the PyPA advisory
  database. Recall 0.92 (per call 0.93), quiet on fix 0.87, against a 0.29
  overall priority rate and a 0.72 same-sink priority rate. Three triage defects found (producer credited as a guard,
  nested `doc` packages treated as docs, `codecs.open` unmodeled); see
  docs/CALIBRATION.md.

- Add a triage calibration harness (`calibration/`, `docs/CALIBRATION.md`): 40
  labeled fixtures across reachable, near-miss and coverage-gap families,
  digest-pinned, scored on ranking (Youden, downgrade rate, guard and constant
  tag accuracy), with a baseline gate in the test suite. Baseline: 32/41,
  Youden 0.858.

- Recognise caller-side guards (`if not check(x): raise`/`return`/`continue`/
  `break` with a project-defined check) that dominate a sink. A guard, of
  either shape, takes a plan out of the priority list only when its arguments
  read the sink's data. Sinks whose arguments are all constants are no longer
  priority. Dispositions are unchanged. Held-out benchmark: chia 58 to 52
  priority plans; see docs/BENCHMARK.md for why the drop is small.

- Add generic triage tags (`signal`, `code_context`, `priority`) to every plan
  plus a ledger `triage_summary`; the report lists priority plans first. No
  plan is removed and no disposition changes. Measured on held-out repos
  (django-DefectDojo, chia-blockchain): the 764 undifferentiated plans become 58
  priority plans, all in chia.
- A call graph over its 20 MB cap no longer aborts the run (exit 3, no report)
  on large repositories. It is written compact; if still too large it is
  skipped whole and recorded in `artifacts.graph`.

- Recover named/default exported JavaScript and TypeScript declarations,
  named re-exports, JSX/TSX and `.mts`/`.cts` source. Include genuine source
  directories named `build`, `dist` and `coverage`.
- Preserve colliding module identities instead of overwriting files;
  normalize Node builtin `node:` imports to the supported sink identities.
- Expose collection, parsing, exclusions, unsupported source files and
  resolution warnings in the ledger, graph export and Markdown report.
  Star re-exports remain explicitly unsupported.
- Index nested Python functions and pre-bind siblings across a lexical
  scope, including forward references, while respecting modeled shadowing.
- Record supported inline JavaScript/TypeScript callback scopes.
- Classify Python `os.open` and its import aliases as static `FILE_IO` sinks.
- Keep catalog loading typed and validate its indexing fields while preserving
  extension data and explicitly labeling bundled taxonomy use.

### Reports and packaging

- Send scanner progress summaries to stderr so MCP stdout contains only
  protocol messages; retain the CLI's artifact-path output.
- Keep JSON ledger, graph, and optional Markdown output on the shared scanner
  pipeline, with catalog provenance and stable finding identifiers.
- Surface output-size, path-containment, and invalid UTF-8 refusals as tool failures.
- Include the JS diagnostic harness and parser assets in wheels; validate
  clean builds and installed-wheel scans outside the source checkout.

### Viewer and development

- Pin Vite 7.3.7 and Playwright 1.64.1; the viewer lockfile resolves esbuild
  0.28.2. Declare the viewer's Node engine requirement.
- Add real Chromium E2E coverage for rendering, uploads, filtering, inspection,
  baseline comparison, and malformed-input handling.
- Pin pytest 9.1.1, mypy 2.4.0, and PyYAML stubs in the development extra.
  Type-check unannotated function bodies, including tests, targeting Python 3.10.
- Define Linux Python 3.10/3.12/3.14 CI with live Docker, Windows/Linux parser
  and viewer checks, clean-wheel jobs, and an opt-in Windows Docker runner job.
- Reorganize installation, usage, security, architecture, and contributor
  documentation around current behavior instead of development-session notes.

### Compatibility notes

Re-scan older reports before relying on verified labels produced by earlier
implementations. Current diagnostics intentionally provide less authority.
Existing JSON status names remain readable by comparison tools and the viewer.
See [usage](USAGE.md), [security](docs/SECURITY.md), and
[development](docs/DEVELOPMENT.md) for migration and setup details.

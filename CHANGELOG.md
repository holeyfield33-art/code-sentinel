# Changelog

Changes are grouped by their effect on users and maintainers. Release dates
and historical version tags are not inferred from development commits.

## Unreleased

### Graph Studio first milestone

- Preserve source coverage in the viewer and expose missing-endpoint limitations.
- Replace random force layout with deterministic directory/module clusters;
  render containment, resolved directional calls and reversible module collapse.
- Add bounded investigation, connection navigation, separate visible/source
  counts, camera framing, and explicit collision identity comparison warnings.
- Distinguish tool failures from reported confirmed findings and state when
  independent evidence is unavailable.
- Add a paired synthetic path traversal regression with an independent HTTP
  observer and patched/benign controls. Scanner and Docker backend logic are unchanged.

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

### Analysis

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

# Sentinel Graph Studio v0

A local Three.js viewer for Sentinel-Zero's `graph.json` exports. Explore
modules, functions, call edges, finding locations, and changes between
saved scans. The viewer displays existing report data; it does not scan
source or independently verify findings.

## Install and start

From the repository root, use Node 20.19+ in the 20.x line or Node 22.12+:

```sh
npm --prefix viewer ci
npm --prefix viewer run dev -- --host 127.0.0.1
```

Open the local URL printed by Vite. The initial graph is a bundled,
historical demonstration. Choose **Load graph.json** and select the graph
from your own [CLI scan](../README.md#run-a-scan). Select `graph.json`,
not `verification_ledger.json`.

Uploaded files are read locally with the browser File API; the viewer
does not send them to an analysis server. The initial sample is fetched
from the local viewer server. Report data can contain sensitive paths
and symbols, so use an environment appropriate for the source repository.

## Navigate a report

| Control | Behavior |
| --- | --- |
| Orbit / zoom | Inspect the 3D layout using the mouse controls |
| Click a node | Show file, line, guard fields, worst disposition, and finding IDs |
| Architecture | Deterministic directory/module clusters and original containment edges |
| Module inspector | Collapse/expand functions; purple aggregate edges are display-only and cite original edges |
| Investigation / depth | Select a function and follow recorded resolved calls, bounded to one or two hops |
| Inspector connections | Navigate incoming/outgoing resolved calls; unavailable endpoints cannot be followed |
| Frame visible graph | Fit the camera to visible nodes |
| Coverage and limitations | Show exported coverage and missing endpoints; unavailable data is stated explicitly |
| Filter by name | Match node IDs; retain direct callers of matches as dim context |
| Legend swatches | Toggle disposition categories |
| Isolate VERIFIED_TRUE | Select that historical status with caller context; in comparison mode select new/changed nodes |
| Reset filter | Clear the category/text filter |

Spheres represent modules and functions. Teal lines show original
containment; blue directional lines show resolved calls between present
nodes. Unresolved, external or missing targets use short red stubs, never
invented endpoint nodes. Purple aggregated connections are display-only.
`TOOL_FAILURE` is purple and distinct from red `VERIFIED_TRUE`.
Visible counts include stubs and aggregates; source totals remain separate.
Every rendered original edge retains its source-array index.

Current scanner diagnostics never authorize verified dispositions. A
verified label in a historical graph retains that report's original
limitations; rendering it does not make the label stronger.

## Compare two scans

1. Load the current scan's `graph.json`.
2. Choose **Load baseline graph.json** and select the older graph.
3. Inspect new, changed, and unchanged nodes. The summary lists removed
   baseline nodes, which are not drawn in the current layout.
4. Use **Clear comparison** to return to disposition colors.

Comparison uses node identity, worst disposition, and attached finding-UID
sets. It is node-level, unlike the library's finding-level status diff.
Changes to paths/lines can change finding UIDs. See
[saved scans and comparison](../docs/SECURITY_MONITORING.md).
Adding a module-name collision can change existing module/function IDs.
The comparison warns when collision metadata is present and preserves exact
IDs; an added/removed classification is not evidence of a new vulnerability.

## Production build and local preview

```sh
npm --prefix viewer run build
npm --prefix viewer run preview -- --host 127.0.0.1 --port 4173 --strictPort
```

The build is written to `viewer/dist`. Preview serves that build locally;
it is not a hosted analysis service. Rebuild after changing application
code. The Node dependencies and viewer source are separate from the Python
wheel and the scanner's JS extractor dependencies.

## Tests and dependency maintenance

Vite 7.3.7 and Playwright 1.64.1 are pinned. The lockfile resolves transitive
dependencies, including esbuild. Consult the [Vite release policy](https://vite.dev/releases)
when planning an upgrade and inspect advisories before selecting versions.

```sh
npm --prefix viewer test
npm --prefix viewer run build
node viewer/node_modules/@playwright/test/cli.js install chromium
npm --prefix viewer run test:e2e
npm --prefix viewer audit --json
npm --prefix viewer outdated
```

The Node test runner checks pure data transformations and color mappings.
The Chromium suite runs the built preview with real WebGL rendering and
exercises uploads, search/caller context, isolate/reset, click inspection,
baseline comparison, and malformed-input refusal. Build first. On Linux,
Playwright's `install --with-deps chromium` can prepare system dependencies.

Browser checks use software WebGL, one worker, no retries, and a fresh
preview server. Their artifacts go to the OS temporary directory. CI
defines these tests on Windows and Linux; an unexecuted job is not evidence
of platform coverage. See [development](../docs/DEVELOPMENT.md).

## Limits

Layout uses sorted identities, containment and actual call connectivity;
identical inputs produce identical positions without a random force simulation.
Positions are not guaranteed unchanged when topology changes. Directory
paths remove a common source root where possible; exports do not supply an
authoritative repository root. Missing containment stays unassigned.
The default render limit is 2,500 nodes; larger graphs require an explicit
focus export and are rejected without silently sampling. The full Next.js
graph is not a default browser workload. There is no large-graph performance
guarantee or 2D fallback. Removed
baseline nodes are summarized rather than assigned positions. Sample
graphs are not automatically regenerated, and malformed uploads are
rejected while the current scene is retained.

This first milestone consumes `graph.json`, including its optional coverage.
It does not load independent proof or ledger details yet: the inspector
states **Evidence unavailable**, and the attached-proof counter remains zero.
Ledger/evidence integration and a single portable report generator are later
milestones; do not treat the current viewer as commercial security assurance.

For optional real-artifact browser validation, set `SENTINEL_STUDIO_FOCUS`
to the existing 182-node focus graph and `SENTINEL_STUDIO_ARTIFACTS` to an
output directory before running `npm --prefix viewer run test:e2e`. This
records a screenshot and measured load/selection timings. Without the local
focus artifact, that one test is explicitly skipped. The maintained
[paired fixture](../tests/fixtures/path_traversal/README.md) has a separate
live Docker impact test; it does not change scanner verification policy.

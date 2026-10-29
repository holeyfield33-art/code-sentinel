# Graph viewer

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

Current exports use graph schema 2: module/function IDs occupy separate
namespaces and the inspector displays the original qualified symbol.
Unambiguous older graphs remain readable and comparable. Duplicate historical
IDs cannot be repaired reliably by the viewer; regenerate those exports.
Malformed records, annotation arrays and endpoint references are refused
before replacing the displayed graph.

Uploaded files are read locally with the browser File API; the viewer
does not send them to an analysis server. The initial sample is fetched
from the local viewer server. Report data can contain sensitive paths
and symbols, so use an environment appropriate for the source repository.

## Navigate a report

| Control | Behavior |
| --- | --- |
| Orbit / zoom | Inspect the 3D layout using the mouse controls |
| Click a node | Show file, line, guard fields, worst disposition, and finding IDs |
| Filter by name | Match node IDs; retain direct callers of matches as dim context |
| Legend swatches | Toggle disposition categories |
| Isolate VERIFIED_TRUE | Select that historical status with caller context; in comparison mode select new/changed nodes |
| Reset filter | Clear the category/text filter |

Spheres represent modules and functions. Lines represent calls rather
than module containment. A resolved call uses a dim blue edge; an
unresolved target uses a short red stub. Colors group `VERIFIED_TRUE`
with `TOOL_FAILURE`, show `UNRESOLVED_INCONCLUSIVE` separately, and retain
historical `VERIFIED_FALSE` and unannotated-node categories.

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

The force layout uses pairwise repulsion with quadratic work per step.
There is no large-graph performance guarantee or 2D fallback. Removed
baseline nodes are summarized rather than assigned positions. Sample
graphs are not automatically regenerated, and malformed uploads are
rejected while the current scene is retained.

# Sentinel-Zero Graph Viewer

A standalone 3D viewer for the `graph.json` export produced by
`sentinel-zero analyze` (see `../sentinel_zero/graph_export.py` and
`../docs/ARCHITECTURE.md` §4 for the data this reads). Built fresh for
this project specifically — it shares no code with, and has no
dependency on, any other visualizer in this account's portfolio (e.g.
CodeVerse). It is scoped to exactly one job: open a `graph.json`, lay it
out in 3D, and let a reviewer see at a glance which nodes carry which
disposition.

## Running it

```bash
cd viewer
npm install
npm run dev
```

Opens a local dev server. On first load it tries to show the bundled
`public/sample-graph.json` (a real self-scan of sentinel-zero itself);
use the "Load graph.json…" button to open any other scan's output —
the file is read entirely in your browser and never leaves it.

## What it shows

- **A sphere per module/function node**, color-coded by that node's
  *worst* disposition across every Finding Plan that touches it:
  red = `VERIFIED_TRUE`/`TOOL_FAILURE`, yellow = `UNRESOLVED_INCONCLUSIVE`,
  green = `VERIFIED_FALSE`, slate = no finding attached to this node at all.
- **Lines for `calls` edges** (not `contains` edges — module-to-function
  containment is implied by proximity after layout, not drawn as a line).
  A resolved call is a dim blue line; an unresolved call (the target
  didn't resolve to a known symbol) is a short red stub from the caller.
- **Click any node** to open an inspector panel with its file, line,
  guard-shape flags (functions only), worst disposition, and the exact
  Finding Plan IDs that produced that disposition — so a reviewer can go
  straight from "what's this red node" to the specific entry in
  `verification_ledger.json`.

## Filtering (Milestone 22)

Click any legend swatch to toggle that category on/off, or type in the
search box to filter by node id substring. A node that doesn't match is
hidden entirely — but a matching node's **direct callers (one hop)** stay
visible as dim, uncolored "context" nodes, so isolating a disposition
shows the *path* to it, not just disconnected dots. "Isolate
VERIFIED_TRUE" is a one-click shortcut to exactly that; "Reset filter"
clears both the search box and the category selection.

## Comparing two scans (Milestone 22)

"Load baseline graph.json…" loads a second `graph.json` and diffs it,
node by node, against whatever is currently rendered. Diffing uses each
node's `finding_uids` (`sentinel_zero/disposition.py`'s stable
`finding_uid`, Milestone 21 — see `../docs/SECURITY_MONITORING.md` §2),
not just the `worst_disposition` string, so a node whose underlying set
of findings changed (one resolved, a different one appeared) is still
correctly flagged as changed even when its worst-status label happens to
read the same in both scans. Legend switches to New / Changed / Unchanged;
a node present in the baseline but entirely gone from the current scan is
listed in the summary panel rather than rendered (this view lays out the
*current* graph — a removed node has no position to draw it at). "Clear
comparison" returns to normal disposition coloring. The diff computation
itself is `src/diff.js`, covered by `test/diff.test.js` — it is
deliberately node-level, the coarser counterpart to
`sentinel_zero/scan_diff.py`'s finding-level ledger diff.

## Layout

A small, dependency-free 3D force simulation (`src/layout.js`) — nodes
repel, edges attract, settled for a fixed number of steps on load. No
graph-layout library was added for this; see that file's own docstring
for why that's a deliberate choice at this project's actual graph sizes,
not an oversight.

## Testing it

The viewer pins Vite 7.3.7 on the [maintained 7.3 release line](https://vite.dev/releases).
It requires Node.js 20.19+ in the 20.x line, or 22.12+. Three.js is
unchanged by this tooling upgrade. Use the checked-in lockfile with
`npm ci` for reproducible dev dependencies.

```bash
npm test     # node's built-in test runner, test/*.test.js — pure-function
             # unit tests for graphLoader.js and diff.js, no browser needed
npm run build
npx playwright install chromium
npm run test:e2e
             # starts the built preview on loopback and drives Chromium:
             # actual WebGL rendering, file upload, search/caller context,
             # isolate/reset, click inspection, baseline diff, bad-input refusal
```

The browser tests use one worker, no retries, and a fresh preview server.
Their output goes to the OS temporary directory. CI runs these checks on
Windows and Linux; Linux browser setup uses Playwright's `--with-deps`.

## Status

First scaffold (Milestone 20) plus filtering, isolate, and scan-diffing
(Milestone 22). What it does today: loads and validates a real
`graph.json`, lays it out in 3D, renders it, supports click-to-inspect,
filters/isolates by disposition or name with path context, and diffs two
scans node-by-node. What it doesn't do yet: a 2D fallback for very large
graphs, or rendering *removed* nodes in their own right (currently
summarized as text, not drawn — see "Comparing two scans" above for why).

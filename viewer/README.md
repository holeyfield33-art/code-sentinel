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

## Layout

A small, dependency-free 3D force simulation (`src/layout.js`) — nodes
repel, edges attract, settled for a fixed number of steps on load. No
graph-layout library was added for this; see that file's own docstring
for why that's a deliberate choice at this project's actual graph sizes,
not an oversight.

## Status

This is the first scaffold (Milestone 20), not a finished feature. What
it does today: loads and validates a real `graph.json`, lays it out in
3D, renders it, and supports click-to-inspect. What it doesn't do yet:
search/filter by disposition or file, a 2D fallback for very large
graphs, or any way to diff two scans against each other (see
`../docs/SECURITY_MONITORING.md` for the related, separate trending
proposal this would eventually consume).

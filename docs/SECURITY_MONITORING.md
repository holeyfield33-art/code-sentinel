# Sentinel-Zero — Security Monitoring & Trending (concept)

**Status: partially implemented (Milestone 21/22).** Item 2 (stable
finding identity) and the core of item 3 (a diff report) now exist —
see the per-section notes below for exactly what landed and what's
still only proposed. This document describes
what a "basic security infrastructure that allows monitoring and trending
of attacks against an organization's applications" means *for this
project specifically* — Sentinel-Zero is a point-in-time static/bounded-
dynamic analyzer, not a running service with live traffic, so this is
scoped to what that actually means here: not an IDS watching a network,
but a durable record of *this tool's own scan history*, so exposure can
be tracked over time instead of re-discovered from scratch on every run.
Nothing in this document is wired up yet; it exists so the next
implementation step has a stated target instead of being designed ad hoc
mid-commit.

## 1. Why this belongs in a security program, and why it's scoped narrowly

The prompt that motivated this document (an application-security program
checklist) calls for monitoring and trending of *attacks against* an
organization's applications and network — that is a runtime/network
concern (an actual IDS/IPS, SIEM correlation, etc.), which is explicitly
**out of scope for this project** (see `docs/USE_CASES.md` §3.4 — this is
not an IDS and must not be represented as one). What *is* in scope, and
genuinely useful, is the narrower adjacent thing: tracking how this
analyzer's own findings about a codebase change over time, which is the
closest honest analogue available from a static/bounded-dynamic tool —
"trending of weaknesses found," not "trending of attacks observed."

## 2. What should be recorded, and where

Each `sentinel-zero` run already produces two artifacts
(`verification_ledger.json`, `graph.json`) that are overwritten on every
run. The proposal is additive, not a replacement:

1. **A scan-history index** — one append-only JSON Lines file per
   target repository (e.g. `out/<repo>/scan_history.jsonl`), one line per
   run, each line holding: timestamp, catalog version used (and whether
   it was the bundled snapshot), total finding-plan count, and a count
   per disposition status (`VERIFIED_TRUE`, `VERIFIED_FALSE`,
   `UNRESOLVED_INCONCLUSIVE`, `TOOL_FAILURE`). This is the minimum needed
   to plot a trend line without re-parsing every historical ledger.
   **Still not implemented** — nothing writes this file yet; today, diffing
   (item 3) requires the operator to have kept two full ledgers/graph
   exports around themselves.
2. **Plan-ID stability across runs — IMPLEMENTED, Milestone 21.**
   `plan_id` is still sequentially assigned per run (`fp_sz_0001`, ...)
   and still not comparable across two scans — that hasn't changed. What's
   new: every `FindingPlan.as_dict()` now also carries a `finding_uid`
   (`sentinel_zero/disposition.py::_compute_finding_uid`), a stable hash
   of the finding's `(source_node, sink_node)` pair — exactly the
   identity this section originally proposed, derived from the same
   pair `graph_export.py` already used as its own lookup key. Two scans
   of the same unchanged call site always produce the same `finding_uid`,
   independent of plan_id, target_repository, or disposition. Covered by
   `tests/test_scan_diff.py`. `graph_export.py` also now carries a
   `finding_uids` list on every node/edge (alongside the existing
   `finding_plan_ids`), so a graph-level consumer (e.g. the viewer) can
   use the same stable identity, not just the ledger.
3. **A diff report — IMPLEMENTED at the ledger level, Milestone 21:**
   `sentinel_zero/scan_diff.py::diff_ledgers(old_plans, new_plans)` takes
   two `verification_ledger.json` `plans` lists and returns which
   `finding_uid`s are new, removed, changed-disposition, or unchanged.
   Pure comparison, no re-analysis — see that module's own docstring.
   Tested in `tests/test_scan_diff.py` (new/removed/changed/unchanged/
   identical/missing-uid cases). **Also wired into the 3D viewer**
   (`viewer/src/diff.js` + `viewer/README.md`'s "Comparing two scans"
   section) as a node-level diff for visualization — load a second
   `graph.json` as a baseline and the scene recolors by diff
   classification. **Still not implemented:** nothing calls
   `diff_ledgers` from the CLI yet (no `sentinel-zero diff a.json b.json`
   command) — today it's a library function with tests and one consumer
   (the viewer), not an end-user-facing report on its own.

## 3. What this explicitly does not do

- It does not watch network traffic, parse request logs, or correlate
  with any live system. See `docs/USE_CASES.md` §3.4.
- It does not alert in real time. A trend report is something a human
  (or a scheduled CI job) asks for after the fact, not a push
  notification system.
- It does not replace an actual IDS/IPS or SIEM for an organization's
  running applications — it is scoped to *this tool's own scan history
  of source code*, nothing broader.

## 4. Suggested next step

Items 2 and the ledger-diff half of item 3 are done (Milestone 21); the
viewer's node-level diff consumes them (Milestone 22). What's left,
in priority order: (a) the scan-history index (item 1) — nothing
durable is written between runs yet, so a diff today requires the
operator to have manually kept an old ledger/graph export around; (b) a
`sentinel-zero diff` CLI subcommand exposing `scan_diff.diff_ledgers`
directly, so this doesn't stay viewer-only. Neither is committed to by
this document — both remain proposals.

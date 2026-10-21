# Sentinel-Zero — Security Monitoring & Trending (concept)

**Status: design proposal, not yet implemented.** This document describes
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
2. **Plan-ID stability across runs** — `plan_id` is currently
   sequentially assigned per run (`fp_sz_0001`, ...), which means it is
   *not* stable across two scans of the same repo and cannot be diffed
   directly today. A durable identity needs to be derived from what
   actually identifies a finding independent of scan order: the triple
   `(file_path, lineno, sink qualified_name)` that `graph_export.py`
   already uses internally as its own lookup key. Before any trending
   dashboard is built, this triple (or a hash of it) should become the
   finding's durable identity, so "this exact finding went from
   `UNRESOLVED_INCONCLUSIVE` to `VERIFIED_TRUE` between run N and run
   N+1" is answerable by a direct lookup, not a fuzzy match.
3. **A simple trend/diff report**, built from (1) and (2): given two
   scan-history entries (or two full ledgers) for the same repo, report
   which specific findings are new, which disappeared (code removed, or a
   guard added), and which changed disposition — this is the "trending"
   half of the checklist item, scoped honestly to what a static/bounded-
   dynamic analyzer can actually observe.

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

Implement item (2) above first (stable finding identity) — everything
else in this document depends on it, and it is a small, isolated,
testable change to `graph_export.py`/`dogfood_scan.py` with no new
runtime dependency. This is flagged as a candidate for a future
milestone, not committed to by this document.

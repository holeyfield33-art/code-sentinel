# Sentinel-Zero — Dogfood Log

A running record of what each milestone's dogfood pass actually found —
real numbers, real repos, real rough edges — kept separate from
`README.md`'s per-milestone summaries so the evidence behind a claim
("honest result, not oversold") has a permanent, append-only home instead
of living only in a commit message. Newest entry at the top. This is a
test-evidence record, not a changelog — it exists to answer "how do we
know this works," not "what changed."

---

## 2026-10-20 — Milestones 20-22 (3D viewer: scaffold, filter/isolate, scan diff)

**What was run:** `sentinel-zero analyze` against sentinel-zero's own
`master` branch, three times across this session as the engine itself
changed underneath it (227 nodes → 238 nodes, growing by exactly the new
`scan_diff.py`/test files added along the way) — then the resulting
`graph.json` exports were loaded into the viewer, built (`npm run build`)
and driven headlessly (Playwright against `vite preview`) rather than
just eyeballed, because "it looks right in the screenshot" is not the
same claim as "it renders correctly."

**Confirmed working, with real numbers, not just "no errors thrown":**

- **Filter/isolate.** Starting from 238 rendered nodes, clicking "Isolate
  VERIFIED_TRUE" correctly dropped the scene to 2 nodes: the one real
  `VERIFIED_TRUE` node in this codebase (`sentinel_zero.cli._install_js_deps`,
  `fp_sz_0003`) plus exactly one caller shown as dim path-context — proving
  the one-hop-caller expansion works, not just the base category filter.
  "Reset filter" restored all 238. A text search for `"cli"` narrowed to
  15 nodes.
- **Scan diffing.** Comparing the final scan (238 nodes) against an
  earlier one from the same session (227 nodes) reported **11 new, 12
  changed, 215 unchanged, 0 removed** — and a separate, deliberate check
  confirmed `diff_ledgers` against a genuinely IDENTICAL pair of
  post-Milestone-21 ledgers reports **0 new / 0 removed / 0 changed / 17
  unchanged**, i.e. it does not manufacture noise when nothing actually
  changed. Click-to-inspect on a node mid-diff correctly showed its `vs.
  baseline` classification alongside its normal fields.
- **A real, not hypothetical, backward-compatibility edge case.**
  Diffing the *very first* self-scan from this session (taken before
  Milestone 21 added `finding_uid`) against a later one raised the
  documented `ValueError` ("this ledger predates Milestone 21 and cannot
  be diffed") instead of silently mis-comparing or under-counting. This
  wasn't manufactured as a test fixture — it is an artifact of this
  exact session's own history, which is exactly the kind of case
  dogfooding against real, evolving data catches and a synthetic unit
  test fixture might not have thought to construct.

**Rough edges found, not yet fixed (flagged honestly, per this project's
own stated practice — see `viewer/README.md`'s own "Status" section for
the up-to-date list):**

- A removed node (present in a baseline, gone from the current scan) is
  only listed as text in the comparison summary panel, never drawn in
  3D — stated as a deliberate scope limit (this view lays out the
  *current* graph; a removed node has no position to draw it at), not an
  oversight, but worth revisiting if someone actually wants to see
  *where* something used to sit.
- `npm audit` still flags a moderate/high `esbuild` advisory inherited
  from `vite` — specific to the local dev server (`npm run dev`), does
  not affect the built output this viewer ships, not chased down tonight
  (would require a vite major-version bump).
- The bundled `viewer/public/sample-graph.json` /
  `sample-graph-baseline.json` pair will go stale the moment the engine
  changes again — they are real scan output, not synthetic fixtures, so
  they are exactly as perishable as any other point-in-time scan. Nothing
  automatically regenerates them on `npm run build`; a future milestone
  could add that.

**What this pass did NOT cover** (so a future reader doesn't assume more
test coverage than actually exists): no test against a second, unrelated
real repository's `graph.json` (everything tonight was sentinel-zero
scanning itself); no test of the filter+diff combination at the same
time beyond what Playwright exercised in sequence; no performance check
at a graph size larger than ~250 nodes (the force layout's own docstring
already states its O(n²) repulsion pass as a stated, not-yet-needed
bound — see `viewer/src/layout.js`).

# Using Sentinel-Zero for bug hunting

A one-page walkthrough: install it, point it at a repo, and know what to
trust in the result. If you haven't read `README.md`'s **Known bounds**
section, read that first — this guide assumes you know what the tool
does and doesn't claim.

## 1. Install

```bash
pip install .            # from a checkout of this repo
sentinel-zero --help
```

If your target is JS/TS, run this once:

```bash
sentinel-zero install-js-deps
```

## 2. Run it

```bash
sentinel-zero analyze /path/to/target-repo --format md
```

This defaults to static-only analysis and never executes target code.
The ledger records `probe_mode: static`.

Diagnostics are an explicit option and require Docker plus the pinned
runtime images described in the README:

```bash
sentinel-zero analyze /path/to/trusted-repo --probe-mode diagnostic --format md
```

Diagnostic output is target-controlled and cannot authorize `VERIFIED_TRUE`.
The parent's requested call site and the validated report are recorded in
`verification_method.probe_observation`; `site_verified` remains false.
No current probe independently verifies runtime events.
Both language adapters execute only inside locked-down Linux containers,
with read-only source, private scratch cwd, fixed environment values, and
no network. Missing isolation or dependencies produce `call_failed`, never
a fallback to the scan user's Python or Node. Target manifests are not installed.

`--format md` is worth using for bug hunting — it writes a `report.md`
you can skim, grouped by disposition, alongside the full
`verification_ledger.json`. Both land in `<target-repo-name>.sentinel-
zero/` next to the target by default (`--out DIR` to change that).

You'll see a line like:

```
NOTICE: no --catalog given -- using the ASI catalog snapshot bundled with
this install (version 0.2.0-draft, generated 2026-09-12, status=draft).
```

That's not an error — it's telling you which taxonomy version labeled
your findings. If you have a fresher ASI catalog export, pass
`--catalog path/to/asi-catalog.json` and that notice won't appear.

## 3. Read the dispositions — this is the part that matters

Every finding in `plans` has a `disposition.status`. There are exactly
four, and they mean specific, different things:

| Status | What it actually means | What to do with it |
|---|---|---|
| **`VERIFIED_TRUE`** | Reserved for independent verification. Current scans never grant it from a probe self-report. | Treat this status in older reports according to the older scanner's limitations. |
| **`UNRESOLVED_INCONCLUSIVE`** | Static analysis found a resolved call to a sink, and either found no guard or found a guard whose protection isn't fully proven (same-function call order, not full CFG dominance — see Known bounds). | This is a worklist, not noise. Triage by `asi_classification.category` and whether `hypothesis.external_dependencies_reached` looks interesting. Read `disposition.reason` for exactly what was and wasn't checked. |
| **`VERIFIED_FALSE`** | Reserved for a future independent verifier; current scans never establish safety from a negative probe report. | — |
| **`TOOL_FAILURE`** | The engine itself broke partway through. | This should never appear inside `plans` — a `TOOL_FAILURE` halts the whole run (nonzero exit, nothing written) rather than showing up as one finding among others. If the CLI exits nonzero with `CRITICAL_TOOL_FAILURE: ...`, that's this — read the message, it names exactly what failed (bad catalog, resolver crash, missing Node.js, etc). |

**The one rule that matters most:** `UNRESOLVED_INCONCLUSIVE` is not
"probably fine." It means exactly what it says — the tool could not
resolve this to either confirmed-reachable or confirmed-safe. Treat the
whole `UNRESOLVED_INCONCLUSIVE` list as the actual bug-hunting surface;
Current diagnostic reports do not prove reachability or safety on their own.

## 4. Triage order that works in practice

1. Sort by `asi_classification.attack_id` — `AAC-11` (process execution)
   findings are usually the highest-value to check by hand first.
2. Within a category, read `hypothesis.external_dependencies_reached` —
   a finding on a path that also reaches third-party packages is a wider
   blast radius if it's real.
3. For each `UNRESOLVED_INCONCLUSIVE` finding you care about, open
   `hypothesis.source_node` (`file:line`) and manually check whether
   user/attacker-controlled input can actually reach that call — this is
   exactly the step the tool is explicit it does not do for you (see
   "Guard precedes sink" in Known bounds).
4. If you confirm a finding is real, that's your bug report:
   `hypothesis.sink_node`, `hypothesis.symbol_binding`, and the file:line
   are enough to point someone straight at it.

## 5. As an MCP tool instead of a CLI

If you're driving this from an agent rather than a terminal:

```bash
sentinel-zero-mcp
```

exposes `analyze_repository(repo_path, language=None, catalog_path=None)`
returning the same ledger as a dict. Same triage rules apply — the
agent still has to read `disposition.status` and `disposition.reason`
per finding, the tool does not summarize "is this repo safe" for you,
on purpose: a single boolean would hide exactly the nuance this guide
just walked through.

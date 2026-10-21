# Sentinel-Zero

A standalone AI-security assessment engine, built fresh instead of gluing
together the earlier multi-repo pipeline (aletheia-redteam-kit + Code
Atlas + friends). It exists to structurally close two confirmed failure
modes from that pipeline, not just avoid them by convention:

- **Silent tool failure reported as a clean pass.** The old pipeline's
  `_run_tool_json` never checked subprocess exit status. Here, a tool
  failure is a hard `ToolFailure` exception that halts the run — it can
  never be absorbed into a quiet pass (`disposition.py`).
- **Hardcoded, drifting attack-taxonomy labels.** Code Atlas's `asi.ts` had
  attack-class IDs mapped to the wrong names, by hand, with nothing to
  catch drift. Here, every Finding Plan's attack-class ID is resolved
  against a *live* Agent Security Index catalog export; an unknown ID is
  a hard error (`UnknownAttackClass`), never a silent pass-through.

This document is a **Phase 2 checkpoint** — it describes the project as of
Milestone 13 (packaging), on top of the correctness fixes landed in
Milestone 12, locked in with a full passing test suite and dogfooding
evidence against real, unrelated repositories for every capability below.
It is not a promise of future scope; see **Known bounds** for what is
explicitly not done.

## Core idea: the ISBG

Everything downstream of parsing operates on one language-agnostic IR —
the Interprocedural Symbol & Binding Graph (`sentinel_zero/graph.py`):
`Symbol`, `Unresolved`, `CallSite`, `FunctionInfo`, `WrapperClass`,
`WrapConstruction`, `ExternalReference`, `ModuleGraph`, `ProjectGraph`.
`graph.py` itself imports nothing language-specific — by design, so a
resolver that tries to sneak language-specific logic into the shared IR
has nowhere to put it.

Two rules follow directly from that shape, and are the structural fix for
specific bugs found in the earlier pipeline:

- **Sink/guard/dependency matching is always by resolved identity, never
  by name string.** This is what keeps a guard-name heuristic from ever
  matching an unrelated `.checkbox()` call the way the old pipeline's
  `check*` wildcard did.
- **An unresolved binding is recorded as `Unresolved`, with a reason —
  never silently dropped.** A call that can't be statically resolved must
  surface as `UNRESOLVED_INCONCLUSIVE`, never read as a clean pass.

## Architecture

| File | Role |
|---|---|
| `sentinel_zero/graph.py` | The ISBG shapes. No language-specific code anywhere in this file. |
| `sentinel_zero/callgraph.py` | Generic, language-agnostic machinery on top of the ISBG: bounded/cycle-safe cross-function guard delegation (`transitively_guard_shaped`), external-dependency indexing, `find_wrap_constructions` (shared by both resolvers). |
| `sentinel_zero/resolvers/python_resolver.py` | The Python resolver. Walks real `ast` trees, two passes per project (index everything, then resolve calls). The only file that knows Python's import/assignment syntax. |
| `sentinel_zero/resolvers/js_resolver.py` + `resolvers/js/extract_graph.js` | The JS/TS resolver. `extract_graph.js` runs as a Node subprocess with a real parser — `acorn` for `.js`/`.mjs`/`.cjs`, `@typescript-eslint/typescript-estree` for `.ts` — and emits JSON; `js_resolver.py` translates that into the exact same dataclasses the Python resolver builds. |
| `sentinel_zero/disposition.py` | The only place a raw observation becomes a reviewed Finding Plan. Validates attack-class IDs against a live ASI catalog; enforces the `PENDING → {VERIFIED_TRUE, VERIFIED_FALSE, UNRESOLVED_INCONCLUSIVE, TOOL_FAILURE}` disposition model. |
| `sentinel_zero/catalog_loader.py` | Loads and indexes the ASI catalog JSON export. |
| `sentinel_zero/schema_check.py` | Validates a Finding Plan has every required field before it can be trusted downstream. |
| `sentinel_zero/ledger_writer.py` | Path-confined, size-capped file writer (`resolve_inside` rejects any write that escapes the target root via `..` or a symlink) — what actually puts a ledger on disk. |
| `sentinel_zero/graph_export.py` | Serializes the in-memory `ProjectGraph` as `graph.json` (nodes + edges), annotated with the finding plans that touch each one. Pure re-serialization of data the resolver already computed and the ledger already reports — never a second, independently computed view of a disposition. The prerequisite for any future 3D rendering or Code Atlas adapter work. |
| `sentinel_zero/probes/` | Milestone 6's bounded dynamic reachability probe, widened in Milestone 16 past PROCESS_EXEC to also cover FILE_IO and DESERIALIZATION, and ported to JS/TS in Milestone 18 (`js_sink_reachability_probe.py` + `js/_sink_reachability_harness.js`, alongside the original Python driver). Subprocess-isolated (`python -I` / `node`), exported-and-zero-argument-only, and can only ever promote to `VERIFIED_TRUE` — never demotes to `VERIFIED_FALSE`, since neither side attempts adversarial inputs. `builtins.eval`/`builtins.exec` (Python) and `fs.readFileSync` (JS) are excluded from probing entirely (see Known bounds). |
| `sentinel_zero/dogfood_scan.py` | The orchestrator. Wires a resolver + its sink table + the disposition engine + (for Python) the dynamic probe + the ledger writer together into one run. |
| `sentinel_zero/cli.py` | The `sentinel-zero` command (installed via `pyproject.toml`'s `[project.scripts]`). A thin wrapper over `dogfood_scan.run()` — language auto-detection, the bundled-catalog fallback, and `--format md` rendering live here; no analysis logic. |
| `sentinel_zero/mcp_server.py` | The `sentinel-zero-mcp` command — same `run()` call, exposed as one MCP tool (`analyze_repository`) so an agent can call this engine as a disposition authority instead of guessing. |
| `sentinel_zero/repo_detect.py` | Shared by `cli.py` and `mcp_server.py`: language auto-detection by file-extension count, and the JS/TS `node_modules` presence check. |
| `sentinel_zero/data/asi-catalog-snapshot.json` | A point-in-time ASI catalog export bundled into the package so a fresh install has a taxonomy to check findings against with zero setup. Used only when the caller passes no `--catalog`/`catalog_path`, and every ledger produced this way says so explicitly (`catalog.is_bundled_snapshot: true`, plus the snapshot's own version/generatedAt) — this is a default *path* into the same live-catalog mechanism, never a second, hardcoded taxonomy. |

## Milestones (Phase 1: 1 through 11)

| # | What it added | Resolver(s) |
|---|---|---|
| 1–2 | Core ISBG + Python resolver + disposition engine; sink/guard matching by resolved identity | Python |
| 3 | Cross-function/cross-file guard delegation (a thin wrapper with no `raise` of its own still resolves as guard-shaped if it delegates to a real guard) | Python |
| 4 | Wrapper-middleware detection (`__init__` stores a param, `__call__` forwards to it, structurally — the real Horos `BearerAuthMiddleware` miss) | Python |
| 5 | External-dependency mapping. Two real false-positive bug classes found and fixed via dogfooding before being trusted (`add = lines.append` alias; `metadata = meta_payload` alias-of-an-alias) | Python |
| 6 | Bounded dynamic sandbox-verification probe — the first real `VERIFIED_TRUE` promotions | Python |
| 7 | JS/TS resolver via a Node/acorn subprocess — proof the ISBG is genuinely language-agnostic | JS |
| 8 | External-dependency mapping for JS — reused Python's `callgraph.py`/`dogfood_scan.py` machinery completely unmodified | JS |
| 9 | Wrapper-middleware detection for JS, generalized beyond Python's `__call__` convention (JS has none — detects any forwarding method by shape) | JS |
| 10 | TypeScript support (`.ts`, not `.tsx`) via `@typescript-eslint/typescript-estree` alongside acorn | TS |
| 11 | Class method bodies walked for call-site recording — closed a gap where a sink call inside *any* Python method was entirely invisible, not even `UNRESOLVED_INCONCLUSIVE` | Python |
| 12 | Closed the correctness gaps Milestone 11 deferred: Python `cls.foo()` dispatch resolves (not just `self`); JS/TS class method *and constructor* bodies are now walked for call-site recording the same way Python's are; TS parameter-property constructor sugar is detected directly from the constructor's param list; the guard-presence check now requires an actual `raise` for the cross-function delegation case (a bare `return` in a delegate doesn't protect the caller) | Python, JS, TS |
| 13 | Packaging: `pip install`-able with a `sentinel-zero` console command and a `sentinel-zero-mcp` MCP server, a bundled ASI catalog snapshot so a fresh install needs no external file to get started, and explicit regression tests for the three invariants below | — |
| 14 | `graph.json` export — the full node/edge ISBG, annotated with which finding touches which node/edge, written alongside every ledger. No rendering yet; this is the prerequisite data for that | — |
| 15 | Bounded sink-argument taint classification (each sink call's positional arguments classified `literal`/`parameter`/`unknown` from the real AST node, same-function evidence only, never changes a disposition status — see `graph.py`'s `CallSite.arg_taint` docstring); widened sink tables (`pickle.load`/`loads`, `yaml.load`, `builtins.eval`/`exec` for Python, Node's `vm` module for JS); and a correctness fix found while widening — a bare `open(...)`/`eval(...)`/`exec(...)` call was resolving to the bare name, never `"builtins.X"`, so `"builtins.open"` had been dead data in the sink table since it was added. Fixing it surfaced 154 previously-invisible `builtins.open` call sites in Block-Wise alone (126 → 285 finding plans on a re-scan) | Python, JS, TS |
| 16 | Widened the Milestone 6 dynamic probe past PROCESS_EXEC-only to also cover FILE_IO and DESERIALIZATION (`builtins.open`, `json.load`/`loads`, `pickle.load`/`loads`, `yaml.load`), and fixed a real bug found while widening it: the probe patches every known sink at once and reports whichever fires first, so a second, never-actually-reached sink in the same zero-arg function was wrongly promoted to `VERIFIED_TRUE` off the first one's evidence — now checked against the specific finding's own sink identity before promoting. `builtins.eval`/`builtins.exec` are deliberately excluded from probing entirely (not just promotion): CPython's import machinery itself runs on the builtin `exec()`, so patching it would either break every import or risk a false positive from a probed function's own nested import. Renamed `process_exec_probe.py` → `sink_reachability_probe.py` to match the real scope. Re-scanning Block-Wise: `VERIFIED_TRUE` findings went from 3 to 39 | Python |
| 17 | The probe can now call a function that *requires* arguments, not just a zero-arg one — if a real call site elsewhere in the project passes it only literal-constant arguments (Milestone 15's taint classifier says so), those exact values are harvested via `ast.literal_eval` on that call site's own source text and used to make the probe call. Never synthesized, never guessed; a call site that fails this test (parameter-derived, too few values for the required params, a required keyword-only param) is simply not attempted, same as before. Honest result on this project's own repo sample: the mechanism is correct and covered by 6 unit tests, but across 5 real Python repos re-scanned (vibe-check, vibe-explainer, aletheia-redteam-kit, aletheia-sentinel, horos) it never actually fired — real call sites in practice almost always pass a variable, not a literal. Worth having for repos with more "hardcoded driver call" shapes; not a universal lift | Python |
| 18 | Ported the Milestone 6/16 dynamic probe to JS/TS — closes the "Python-only" bound two rows up, for the exported-and-zero-argument call shape the probe already knows how to handle. Same safety model (isolated `node` subprocess, hard timeout, patch sinks before `require()`, raise-to-short-circuit before the real sink runs) and the same Milestone 16 symbol-match correctness rule, now shared between both languages via one `_promote_if_sink_reached` helper. The one function that is unsafe to patch differs per language and had to be found empirically for each: Python's is `builtins.eval`/`exec` (breaks CPython's import machinery); JS's is `fs.readFileSync` (breaks Node's `require()`) — `eval`, `Function`, and the whole `vm` module are all safe to patch on the JS side, the opposite of Python's pattern. Eligibility is also decided differently: Python checks call shape statically from the AST; JS decides it at runtime inside the harness, via the real exported function's `fn.length === 0`, because JS silently fills a missing argument with `undefined` instead of raising the way Python raises `TypeError` — a static "requires no arguments" check would not actually guarantee a safe call there. Honest result, not oversold: across 2 real JS/TS repos re-scanned (runtime-firewall-mvp, vercel-cli) this produced zero actual `VERIFIED_TRUE` lift — see Known bounds for the two specific, diagnosed reasons (a self-executing test file, and a `.ts` file that can't `require()` cleanly under plain Node). The mechanism itself is correct, proven by 7 unit tests covering promotion, the symbol-mismatch guard, the `fs.readFileSync` exclusion, unexported functions, and non-zero-arg functions | JS, TS |

Every milestone above was dogfooded against ≥2–3 real, unrelated
repositories before being trusted, and every surprising result was
investigated to a confirmed root cause before being reported. The targets
used across this phase: `block-wise`, `vibe-explainer`, `horos/mcp`,
`runtime-firewall-mvp` (JS, zero-dep by design), `vercel/vercel`'s
`packages/cli` (the real TS stress test — 2,194 modules), and this
author's own `js-tutorial` (a genuinely small, JS-only sanity check).

## The three invariants

Everything in `cli.py` and `mcp_server.py` is a transport over
`dogfood_scan.run()` and must never weaken these (see
`tests/test_invariants.py` and `tests/test_tool_failure.py` for the
regression coverage):

1. **No silent tool failure.** A bad repo path, a missing/unreadable/
   malformed catalog, a resolver crash, `node`/`npm` missing for a JS/TS
   target, an unknown attack-class ID — every one of these is a hard
   exception (`ToolFailure` or `UnknownAttackClass`) that halts the run
   with a nonzero exit, never a quiet empty or partial ledger.
2. **Live ASI catalog only.** There is no hardcoded attack-class name/
   label table anywhere in this codebase — only ever an `attack_id` key
   resolved against whatever `Catalog` `disposition.load_catalog()`
   returns. The catalog snapshot bundled with the package (used only when
   you don't pass `--catalog`) goes through that exact same
   `load_catalog()` path and is always labeled as a snapshot, with its
   own version/date, in the resulting ledger — see `catalog.is_bundled_
   snapshot` and `catalog.metadata` in the output shape below.
3. **Finding Plan required.** Every reported hypothesis is a `FindingPlan`
   built by `disposition.build_finding_plan()`, which forces the
   attack-class resolution and the required-field check
   (`schema_check.require_finding_plan_fields`) to happen before anything
   can be reported — never a bare dict assembled ad hoc by a caller.

## Known bounds — explicitly deferred, not silently missing

These are stated limits, not bugs waiting to be noticed:

- **`.tsx` (JSX-in-TS) is out of scope.** A `.tsx` file is silently not
  collected, not attempted and reported as a parse error. (Milestone 10)
- **"Guard precedes sink" is same-function call order, an approximation of
  control dependency — not full CFG dominance.** A guard that runs but
  whose result is ignored still reads as "guard present," and whether the
  condition that triggers the guard's `raise` corresponds to
  attacker-controlled input is not evaluated. (Tightened in Milestone 12
  to require an actual `raise`, not a `return`, for the cross-function
  delegation case — see `callgraph.transitively_guard_shaped`.)
- **Loop bodies are not given their own branch tag** in either resolver;
  calls inside a loop are recorded at the enclosing branch path.
- **Python's `import a.b.c` without an alias** binds only the top-level
  package name, per Python's real binding rule — `a.b.c.fn()` through that
  form resolves to `Unresolved`, not guessed at.
- **The dynamic probe (Milestone 6, widened in Milestone 16, ported to
  JS/TS in Milestone 18) only ever calls an exported, zero-argument
  function** (or, on the Python side only, one reachable via Milestone
  17's literal-argument harvesting). It is gated off entirely for
  anything it can't safely construct/call (a class method, a function
  requiring arguments the harvester can't satisfy, an unexported JS/TS
  function). Everything outside that shape tops out at
  `UNRESOLVED_INCONCLUSIVE`, which is the correct, honest ceiling for
  what static analysis alone can claim, not a bug.
- **`builtins.eval`/`builtins.exec` (Python) and `fs.readFileSync` (JS)
  are never dynamically probed, even though they're in their respective
  sink tables.** CPython's own import machinery runs every module's
  bytecode via the builtin `exec()`; Node's own `require()` reads the
  target's source via the real `fs.readFileSync` — patching either before
  import/require breaks every import, not just a target that itself
  calls the patched function, and there is no safe "patch after
  import/require" workaround either (a probed function's own lazy
  import/require would trip it falsely). Probing a finding whose own
  sink IS one of these would mean actually executing it for real in the
  subprocess, which this probe's whole safety model forbids — so these
  stay static-evidence-only. (Notably the unsafe function is *different
  per language* — JS's `eval`/`Function`/`vm` are all safe to patch,
  unlike Python's — confirmed empirically before either harness was
  written, not assumed by symmetry.)
- **The JS/TS probe needs a genuinely CommonJS-exported, plain-Node-`require()`-able
  target.** A top-level function this project's own static resolver finds
  is not necessarily reachable that way: CommonJS requires an explicit
  `module.exports`/`exports.x` assignment, and ESM `export` syntax isn't
  `require()`-able by plain Node at all — so most real `.ts` files (and
  any `.js` file relying on a bundler/loader) fail at the `require()` step
  and report `call_failed`, not a false `VERIFIED_TRUE`. Dogfooding against
  2 real repos surfaced a second, narrower confound worth naming plainly: a
  target file that self-executes its own test assertions at `require()`
  time (a test file imported as if it were a plain module) can make the
  whole harness process exit nonzero before it reports cleanly, because
  this project's own directory-skip list (`SKIP_DIR_NAMES` in
  `extract_graph.js`) does not exclude `__tests__`/test directories from
  scanning in the first place. Neither is fixed in Milestone 18 — both are
  stated bounds, not silent gaps.
- **The sink tables are a starting set, not exhaustive.** Python's table
  covers `open`/`json.load(s)`/the `subprocess.*` family; the JS/TS table
  covers `child_process.*`/`eval`/`Function`/`fs.*`/`JSON.parse`. Neither
  covers, e.g., `pickle`, `yaml.load`, or Node's `vm` module yet.
- **The MCP server (`sentinel-zero-mcp`) is a single tool** —
  `analyze_repository`, a synchronous wrapper over one full scan. It has
  no incremental/partial-rescan mode and no resource endpoints yet.

## Install

Requires Python 3.10+. Node.js 18+ is only needed if you'll scan a JS/TS
target.

```bash
pip install .
# or, for development (editable install + test deps):
pip install -e ".[dev]"
```

This installs two commands: `sentinel-zero` (the CLI) and
`sentinel-zero-mcp` (the MCP server). Nothing here needs `PYTHONPATH`
set — that was only ever a workaround for running the module tree
directly out of a git checkout without installing it (still works, see
"Running without installing" below, and still what the test suite uses).

If you're going to scan a JS/TS repository, install the JS/TS resolver's
own subprocess dependencies once:

```bash
sentinel-zero install-js-deps
```

A scan needs a taxonomy to check findings against. If you have a live
Agent Security Index catalog export, pass it with `--catalog`; if you
don't, the CLI falls back to the snapshot bundled with the package and
says so explicitly, both on the console and in the output ledger (see
**The three invariants** above) — never silently.

## Running a scan

```bash
sentinel-zero analyze /path/to/some/repo
sentinel-zero analyze /path/to/some/repo --format md          # also renders report.md
sentinel-zero analyze /path/to/some/repo --language javascript # skip auto-detection
sentinel-zero analyze /path/to/some/repo --catalog /path/to/asi-catalog.json
sentinel-zero analyze /path/to/some/repo --out /tmp/some-repo-scan
```

Language is auto-detected by counting `.py` files against
`.js`/`.mjs`/`.cjs`/`.ts` files under the target — pass `--language`
explicitly if that guess would be wrong for an unusual layout. Output
defaults to `<repo-name>.sentinel-zero` next to the target repo.

See **[`USAGE.md`](USAGE.md)** for a one-page walkthrough of actually
using the output for bug hunting — install, run, and how to read
`VERIFIED_TRUE` vs. `UNRESOLVED_INCONCLUSIVE` vs. `TOOL_FAILURE`.

### As an MCP server

```bash
sentinel-zero-mcp
```

Runs over stdio, exposing one tool, `analyze_repository(repo_path,
language=None, catalog_path=None)`, returning the same ledger dict the
CLI writes to disk. Point an MCP-capable agent's client config at this
command to let it call Sentinel-Zero as a disposition authority instead
of eyeballing a call graph and guessing.

### Running without installing

Still works, and is what `tests/` uses:

```bash
export PYTHONPATH="$(pwd)"
pytest tests/ -v
python3 -m sentinel_zero.cli analyze /path/to/some/repo
```

As of this checkpoint: **108 tests, all passing**, covering both
resolvers, the shared `callgraph.py` delegation walk, the dynamic probe,
external-dependency mapping, wrapper-middleware detection, every
documented gap above, the `cli.py`/`mcp_server.py` transports, the
`graph.json` export, and the three invariants end-to-end.

### Output shape

`verification_ledger.json` contains:

```
target_repository, modules_scanned, functions_indexed, unresolved_call_sites,
plan_count, plans, wrapper_middleware_detected, wrapper_construction_sites,
external_dependencies, parse_errors, catalog
```

Every entry in `plans` is a Finding Plan with a `disposition.status` of
exactly one of `VERIFIED_TRUE`, `VERIFIED_FALSE`, `UNRESOLVED_INCONCLUSIVE`,
or `TOOL_FAILURE` — never anything else, and never silently absent for a
finding that exists. `catalog` records exactly which ASI catalog this run
checked attack-class IDs against: `path`, `is_bundled_snapshot`, and
`metadata`.

Every scan also writes `graph.json` next to the ledger: the full
node/edge graph (every module and function as a node, every resolved or
unresolved call as an edge), with each node/edge carrying the
`finding_plan_ids` and `worst_disposition` of any finding that touches
it. This is a lossless re-serialization of the ledger's own data, not a
second analysis pass — every `plan_id` in the ledger appears on exactly
one edge in `graph.json`, never zero and never more than one (see
`tests/test_graph_export.py`). Nothing renders this yet; it exists so a future 3D view, or an adapter
into another tool's own graph viewer, has real data to consume instead
of re-deriving the graph from the flat findings alone.
`metadata` (the catalog export's own `version`/`generatedAt`/`status`).

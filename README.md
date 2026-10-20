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

This document is a **Phase 1 checkpoint** — it describes the project as of
Milestone 11, locked in with a full passing test suite and dogfooding
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
| `sentinel_zero/probes/` | Milestone 6's bounded dynamic reachability probe. Python-only, subprocess-isolated (`python -I`), PROCESS_EXEC-only, zero-argument-function-only, and can only ever promote to `VERIFIED_TRUE` — never demotes to `VERIFIED_FALSE`, since it never attempts adversarial inputs. |
| `sentinel_zero/dogfood_scan.py` | The orchestrator and CLI entry point. Wires a resolver + its sink table + the disposition engine + (for Python) the dynamic probe + the ledger writer together into one run. |

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

Every milestone above was dogfooded against ≥2–3 real, unrelated
repositories before being trusted, and every surprising result was
investigated to a confirmed root cause before being reported. The targets
used across this phase: `block-wise`, `vibe-explainer`, `horos/mcp`,
`runtime-firewall-mvp` (JS, zero-dep by design), `vercel/vercel`'s
`packages/cli` (the real TS stress test — 2,194 modules), and this
author's own `js-tutorial` (a genuinely small, JS-only sanity check).

## Known bounds — explicitly deferred, not silently missing

These are stated limits, not bugs waiting to be noticed:

- **Python `cls.foo()` (classmethod dispatch) is not resolved.** Only
  `self` is bound to the owning class; a call through `cls` falls to an
  unresolved bare symbol. (Milestone 11)
- **JS/TS class method *bodies* are still not walked for call-site
  recording** — only Python closed this (Milestone 11). A JS wrapper's
  dispatch method is detected structurally (by its forwarding shape)
  without needing its own calls in the graph, so wrapper detection itself
  isn't blocked by this, but a plain sink call inside any JS/TS method is
  still invisible.
- **TS parameter-property constructor sugar is not detected** by
  wrapper-middleware detection: `constructor(private inner: Foo) {}`
  auto-assigns with no statement in the body for the detector to find.
  (Milestone 10)
- **`.tsx` (JSX-in-TS) is out of scope.** A `.tsx` file is silently not
  collected, not attempted and reported as a parse error. (Milestone 10)
- **"Guard precedes sink" is same-function call order, an approximation of
  control dependency — not full CFG dominance.** A guard that runs but
  whose result is ignored still reads as "guard present."
- **Loop bodies are not given their own branch tag** in either resolver;
  calls inside a loop are recorded at the enclosing branch path.
- **Python's `import a.b.c` without an alias** binds only the top-level
  package name, per Python's real binding rule — `a.b.c.fn()` through that
  form resolves to `Unresolved`, not guessed at.
- **The dynamic probe (Milestone 6) is Python-only, PROCESS_EXEC-only, and
  zero-argument-function-only.** It is gated off entirely for JS/TS scans
  and for anything it can't safely construct/call (a class method, a
  function requiring arguments).

## Setup

Requires Python 3.10+ and Node.js 18+.

```bash
# Python test/runtime deps
pip install pytest

# JS/TS resolver's own subprocess deps (acorn, typescript-estree)
cd sentinel_zero/resolvers/js && npm install && cd -
```

Running anything under `sentinel_zero/` as a module needs the repo root on
`PYTHONPATH` (there is no installed package / `pyproject.toml` yet):

```bash
export PYTHONPATH="$(pwd)"
```

A scan also needs a live Agent Security Index catalog export (the
`asi-catalog.json` from the `agent-security-index` repo) — `disposition.py`
refuses to run without one.

## Running the test suite

```bash
export PYTHONPATH="$(pwd)"
pytest tests/ -v
```

As of this checkpoint: **38 tests, all passing**, covering both resolvers,
the shared `callgraph.py` delegation walk, the dynamic probe, external-
dependency mapping, wrapper-middleware detection, and every documented
gap above (each one has a test asserting the real, current — not
aspirational — behavior).

## Running a scan

```bash
python3 -m sentinel_zero.dogfood_scan REPO_ROOT ASI_CATALOG_JSON OUT_DIR [python|javascript]
```

- `REPO_ROOT` — the target repository to scan (not this one).
- `ASI_CATALOG_JSON` — path to a live `asi-catalog.json` export.
- `OUT_DIR` — where `verification_ledger.json` is written.
- Fourth argument is optional, `python` (default) or `javascript` — the
  JS/TS resolver handles `.js`/`.mjs`/`.cjs`/`.ts` in one pass.

```bash
# Python target
python3 -m sentinel_zero.dogfood_scan \
  /path/to/some/python/repo \
  /path/to/agent-security-index/public/export/asi-catalog.json \
  /tmp/out/some-repo \
  python

# JS/TS target
python3 -m sentinel_zero.dogfood_scan \
  /path/to/some/js-or-ts/repo \
  /path/to/agent-security-index/public/export/asi-catalog.json \
  /tmp/out/some-repo \
  javascript
```

### Output shape

`OUT_DIR/verification_ledger.json` contains:

```
target_repository, modules_scanned, functions_indexed, unresolved_call_sites,
plan_count, plans, wrapper_middleware_detected, wrapper_construction_sites,
external_dependencies, parse_errors
```

Every entry in `plans` is a Finding Plan with a `disposition.status` of
exactly one of `VERIFIED_TRUE`, `VERIFIED_FALSE`, `UNRESOLVED_INCONCLUSIVE`,
or `TOOL_FAILURE` — never anything else, and never silently absent for a
finding that exists.

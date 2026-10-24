# Analysis coverage and limits

Use this reference when deciding what a report can establish. The graph,
sink tables, and argument evidence are intentionally bounded. Unsupported
behavior can produce unresolved calls or no matching finding plans.

## Files and languages

| Resolver | Collected files | Parser |
| --- | --- | --- |
| Python | `.py` | The scan interpreter's `ast` module |
| JavaScript/TypeScript | `.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.mts`, `.cts` | Acorn with JSX and TypeScript ESTree through the shipped Node extractor |

JSX/TSX files are collected. A run selects one resolver; auto-detection
is a source-file count, not mixed-language analysis. Dependency and cache
directories are skipped according to resolver-specific lists. JS/TS source
under `build`, `dist` and `coverage` is included. Declaration-only `.d.ts`,
`.d.mts` and `.d.cts` files are recorded as excluded. Tests are
not universally excluded. Python grammar support follows the interpreter
used for the scan, so newer target syntax can produce parse errors on an
older scan interpreter.

Per-file parse failures are retained in `parse_errors`; they do not
necessarily stop analysis of other files. Unresolved calls remain graph
edges, but only supported resolved sinks generate plans. Always inspect
both coverage indicators before interpreting a zero-plan result.

JS/TS `coverage` records collected/parsed counts, skipped directories,
excluded declarations and recognized unsupported source extensions.
Warnings expose parse failures, unreadable directories, unresolved local
imports, star re-exports and module-name collisions. This is an inventory
of recognized source types, not a claim to classify every possible file.
Named/default declarations and named re-exports are modeled; star
re-exports, TypeScript path aliases and package export maps are not complete.
Colliding legacy dotted module names receive distinct encoded file identities;
adding a collision can change identifiers used in graph comparisons.

## Supported sink families

| Kind | Python | JavaScript/TypeScript |
| --- | --- | --- |
| Process execution | `os.system`, subprocess run/call/check/Popen functions, `eval`, `exec` | child_process exec/execFile/spawn/fork variants, `eval`, `Function`, selected `vm` APIs |
| File I/O | `builtins.open`, `os.open` | fs readFile/writeFile sync and callback variants |
| Deserialization | json and pickle load/loads, `yaml.load` | `JSON.parse` |

The exact registries are `_SINK_KIND_BY_NAME` and `_JS_SINK_KIND_BY_NAME`
in `sentinel_zero/dogfood_scan.py`. These are review categories; a listed
API is not automatically exploitable, and an unlisted API is not safe.
Classification names come from the loaded ASI catalog.

## Call and scope resolution

- Imports, supported aliases, project functions, and modeled method
  receivers are resolved structurally. Dynamic imports, reflection,
  `getattr` dispatch, and arbitrary runtime rebinding are not complete.
- Python nested definitions and forward sibling references are indexed
  lexically, including supported control-flow suites. This does not
  prove a conditional definition executes or simulate closure timing.
- Python lambda bodies are not modeled as independent caller scopes.
- JS/TS supports selected direct inline function/arrow callback arguments.
  Arbitrary higher-order function values and framework dispatch are not
  reconstructed as a complete runtime call graph.
- Method receiver modeling is bounded. Inheritance and dynamic subclass
  dispatch do not become a full polymorphic dispatch analysis.

## Guards and arguments

Branch-path dominance and call order provide structural evidence for
guards. They do not prove the guard checks the right input, cannot be
bypassed by another application entry point, or covers every loop and
exception path. Python loop bodies receive a coarse branch tag, not
iteration-sensitive control-flow modeling; language resolvers have
different supported control-flow shapes.

Argument evidence follows parameters, literals, and selected one-hop
expressions. It is not whole-program taint tracking. A parameter can be
trusted or untrusted at runtime; a literal used in a diagnostic does not
establish attacker influence. Guard and argument evidence never authorize
`VERIFIED_FALSE` or `VERIFIED_TRUE`.

## Diagnostic coverage

Diagnostics require explicit opt-in and Docker. They attempt supported
top-level Python invocations or callable CommonJS exports; they are not
a general TS transpiler, ESM/bundler loader, fuzzer, or application boot
environment. Required dependencies may be absent from the runtime image.
Python `eval`/`exec` and Node `fs.readFileSync` findings are excluded from
probing. Same-symbol direct/transitive ambiguity can also suppress probes.

No current report proves a specific runtime site fired. A well-formed
`sink_reached` report remains target-controlled. No observation is proof
of safety when a sink is not reached or a call fails. See
[execution and trust](SECURITY.md) for the container and authority boundaries.

## Comparison and scale

Finding UIDs depend on source path, line, and sink identity. Moving a
checkout or inserting lines can change them. Same-symbol calls on one
line can share a UID. Graph comparisons are node-level, and library
comparisons detect status changes rather than arbitrary semantic edits.

The viewer's force layout uses pairwise repulsion, with quadratic work
per layout step. There is no large-graph performance guarantee or 2D
fallback. Removed baseline nodes are listed rather than drawn in the
current graph's layout.

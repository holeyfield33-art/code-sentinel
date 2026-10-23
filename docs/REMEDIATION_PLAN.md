# Remediation status and roadmap

This document separates implemented controls from remaining design work.
It is a capability/reference map, not a local audit log or a claim that
all security risks have been resolved. Historical issue IDs are mapped
in the [regression index](../VERIFICATION_LEDGER.md).

## Implemented controls

| Area | Current behavior | Regression coverage |
| --- | --- | --- |
| Probe authority | Static by default; target-controlled reports cannot authorize verified states at either disposition boundary | `test_probe_evidence_policy.py` |
| OS isolation | Mandatory Docker for Python and JS, fixed environment, read-only mounts, private scratch, no network, no host fallback | `test_container_isolation.py` |
| Lifecycle | Bounded teardown; primary execution errors survive cleanup failures; public CLI outcomes are structured | `test_container_lifecycle.py` |
| Site ambiguity | Direct/transitive same-symbol competition suppresses indistinguishable diagnostics | `test_ambiguous_sink_promotion.py`, `test_sink_ambiguity_languages.py` |
| Python scopes | Nested functions, forward siblings, modeled shadowing and rebindings are represented in call edges | `test_nested_function_visibility.py` |
| JS/TS callbacks | Supported direct inline function/arrow callbacks have their own scopes and evidence | `test_js_inline_callback_visibility.py` |
| File-I/O coverage | `os.open` and aliases join the supported Python static sink table | `test_widened_sinks.py` |
| Output failures | Byte caps, containment, and invalid Unicode become explicit tool failures | `test_tool_failure.py` |
| Catalog shape | Typed document validation preserves extension data and reports unusable indexing shapes | `test_tool_failure.py` |
| Wheel assets | JS harness/parser assets ship; builds and installed scans use clean environments | `test_packaging.py`, `scripts/ci_wheel_smoke.py` |
| Development gate | Pinned mypy/pytest/YAML stubs; unannotated bodies checked; CI includes live Docker and browser tests | `pyproject.toml`, `.github/workflows/ci.yml` |
| Viewer tooling | Pinned Vite/Playwright, locked esbuild resolution, real Chromium behavior checks | `viewer/e2e/viewer.e2e.js` |

Test filenames above are under `tests/` unless another path is shown.
Coverage is not a claim that the current hosted workflow or every platform
has passed; consult the actual run and its artifacts.

## Remaining work

### Independent runtime proof authority

An independent observer must bind runtime evidence to a specific call
site, distinguish competing sites, resist target-controlled stdout,
serializer/frame manipulation, and mutable-report forgery, and preserve
failure semantics. Container execution alone does not supply this proof.
Verified dispositions must remain unavailable until that authority exists
and adversarial tests support it.

### Stable source snapshots

Pre-mount link checks assume a stable source tree. An atomic readable
snapshot would improve the boundary against concurrent filesystem changes
and address additional source ownership/permission cases. No such snapshot
is currently created by the diagnostic runner.

### Broader analysis coverage

JSX/TSX, richer dynamic/higher-order dispatch, Python lambda caller scopes,
more complete loop/exception modeling, broader sink coverage, and deeper
dataflow remain bounded or unsupported. Each extension needs semantic
fixtures and explicit uncertainty; it must not turn absent evidence into
a safety claim.

### Comparison and visualization

A history index, diff CLI, richer finding identity across source movement,
large-graph performance work, and rendering removed baseline nodes remain
future work. The existing library/viewer comparisons do not implement
these capabilities implicitly.

## Change discipline

Specify the observable behavior, preserve a regression for the defect,
run the relevant installed/runtime checks, update user-facing compatibility
notes, and seek independent review for security claims. Record execution
results in CI/private evidence stores. Use the [verification policy](IVP.md)
and [development guide](DEVELOPMENT.md); do not replace unresolved design
work with stronger wording in the README.

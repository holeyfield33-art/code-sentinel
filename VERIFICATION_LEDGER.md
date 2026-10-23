# Regression and verification index

This index maps maintained behavior to tests. Run-specific evidence belongs
in CI artifacts or a private external evidence store, not in a committed
conversation or local audit transcript. Older versions of this file recorded
development-session claims; Git history retains those records. They are
not current product guarantees.

## Current coverage

| Behavior | Primary coverage |
| --- | --- |
| Static defaults across CLI/MCP and rejected verified authorization | [Evidence policy](tests/test_probe_evidence_policy.py) |
| Python/JS forged reports, serializer/frame attacks, invalid JS objects | [Evidence policy](tests/test_probe_evidence_policy.py), [adversarial harness fixtures](tests/test_probe_verification_hardening.py) |
| Mandatory real OS boundary, environment/cwd confinement, non-root execution, read-only source | [Container isolation](tests/test_container_isolation.py) |
| Output limits, timeouts, cleanup faults, public CLI diagnostics | [Container lifecycle](tests/test_container_lifecycle.py), [isolation](tests/test_container_isolation.py) |
| Nonce/report parsing and Docker argument contracts | [Docker adapter unit/dispatch tests](tests/test_docker_sink_probe.py) |
| Direct/transitive same-symbol ambiguity in both languages | [Ambiguity regressions](tests/test_ambiguous_sink_promotion.py), [language fixtures](tests/test_sink_ambiguity_languages.py) |
| Nested Python definitions, forward siblings, lexical shadowing | [Nested function visibility](tests/test_nested_function_visibility.py) |
| Supported JS/TS inline callbacks | [Callback visibility](tests/test_js_inline_callback_visibility.py) |
| Supported sinks including `os.open` and aliases | [Widened sink coverage](tests/test_widened_sinks.py) |
| Argument classification, guards, methods, wrappers, dependency references | [Test directory](tests/) |
| Output refusal and malformed catalog handling | [Tool failures](tests/test_tool_failure.py) |
| CLI/MCP catalog and failure contracts; MCP stdout free of scanner summaries | [Transport invariants](tests/test_invariants.py) |
| Clean wheel contents and installed-package execution | [Packaging](tests/test_packaging.py), [wheel smoke helper](scripts/ci_wheel_smoke.py) |
| Stable identity, graph export, and ledger comparison | [Graph export](tests/test_graph_export.py), [scan diff](tests/test_scan_diff.py) |
| Actual viewer rendering, filtering, inspection, comparison, and input refusal | [Chromium E2E](viewer/e2e/viewer.e2e.js) |

Unit checks of flags or mock calls are not substitutes for the real Docker
and browser scenarios. Read [development](docs/DEVELOPMENT.md) for setup,
test selection, type checking, and clean installed-wheel commands.

## Historical issue references

These identifiers remain useful when reading source comments and older
commits. The table points to current controls; it does not certify every
historical claim or reproduce personal run records.

| Legacy reference | Current topic |
| --- | --- |
| `sz-2026-10-21-01` | Scope completion claims using [verification policy](docs/IVP.md) |
| `sz-2026-10-21-02`, `-09`, `-16` | Forged stdout, nonce, serializer, and frame reports; authority denial |
| `sz-2026-10-21-03`, `-10`, `-11`, `-12`, `-13` | Host environment/cwd/read/write exposure; real container isolation |
| `sz-2026-10-21-04` | Wrong-site attribution and direct/transitive ambiguity |
| `sz-2026-10-21-05` | Nested Python visibility and binding |
| `sz-2026-10-21-06`, `-22`, `-25` | Inline JS/TS callback scopes |
| `sz-2026-10-21-07` | Literal-input diagnostics do not establish attacker influence or verification |
| `sz-2026-10-21-08` | Output and installed-wheel behavior |
| `sz-2026-10-21-14`, `-17` | Isolation and evidence-authority design boundaries |
| `sz-2026-10-21-19`, `-24` | Docker execution, platform-safe source mounts, and lifecycle |
| `sz-2026-10-22-01`, `-03` | Output caps and non-size/Unicode refusal handling |
| `sz-2026-10-22-02`, `-04` | Shipped JS harness and clean package builds |

The prefixes abbreviated in later cells continue the full date prefix in
the same row. Current limits and unfinished proof authority are maintained
in [analysis limits](docs/isbg-limits.md), [security](docs/SECURITY.md), and
the [roadmap](docs/REMEDIATION_PLAN.md).

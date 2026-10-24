# Sentinel-Zero

Source-code security triage for Python, JavaScript, and TypeScript.

Sentinel-Zero resolves imports, aliases, and call relationships to identify
calls to security-sensitive APIs. It produces finding plans with source
locations, argument classifications, guard evidence, and explicit uncertainty.
Review the results as JSON, Markdown, or an interactive 3D call graph.

**Scans are static by default.** Optional Docker diagnostics execute target
code and record untrusted observations. Current scans do not grant
`VERIFIED_TRUE` or `VERIFIED_FALSE`; an inconclusive result needs review.

## What you can do

- Find supported process-execution, file-I/O, and deserialization calls by
  resolved API identity, including Python `os.open` and aliased imports.
- Inspect project call relationships, structural guards, and external
  package references without importing the target in the scan process.
- Follow nested Python functions, forward sibling references, class
  methods, and supported JavaScript/TypeScript inline callbacks.
- Compare saved scans and explore caller context in the browser viewer.
- Call the same analysis through a CLI, Python library, or local MCP server.

Coverage is deliberately bounded. A resolved sink call is a review lead,
not proof of attacker reachability or exploitability. See
[analysis limits](docs/isbg-limits.md).

## Requirements

| Component | Requirements |
| --- | --- |
| Python analysis and CLI | Python 3.10+ and pip |
| JavaScript/TypeScript analysis | Node.js and npm; Node 22.12+ is recommended for a shared scanner/viewer environment |
| 3D viewer | Node 20.19+ in the 20.x line, or Node 22.12+; a WebGL-capable browser |
| Optional diagnostics | A running Linux-container Docker daemon and the pinned runtime images |

The resolvers collect `.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.jsx`, `.tsx`,
`.mts`, and `.cts` files. A run uses one language resolver;
scan mixed-language repositories separately with `--language`.

## Install from source

Clone the repository and install into a user-owned virtual environment.
The environment below lives next to the checkout, keeping it out of scans
and source control.

### Linux / POSIX shell

```sh
git clone https://github.com/holeyfield33-art/code-sentinel.git
cd code-sentinel
python3 -m venv ../code-sentinel-venv
. ../code-sentinel-venv/bin/activate
python -m pip install .
sentinel-zero --help
```

### Windows PowerShell

```powershell
git clone https://github.com/holeyfield33-art/code-sentinel.git
Set-Location code-sentinel
py -3 -m venv ..\code-sentinel-venv
..\code-sentinel-venv\Scripts\Activate.ps1
python -m pip install .
sentinel-zero --help
```

If PowerShell blocks activation, use the environment's interpreter directly:

```powershell
..\code-sentinel-venv\Scripts\python.exe -m pip install .
..\code-sentinel-venv\Scripts\python.exe -m sentinel_zero.cli --help
```

Installing exposes `sentinel-zero` and `sentinel-zero-mcp`. No `PYTHONPATH`
configuration is required. To check the installed package version, use
`python -m pip show sentinel-zero`.

### Enable JavaScript and TypeScript analysis

After installing Python dependencies, run once in the same environment:

```sh
sentinel-zero install-js-deps
```

This runs npm for the installed package's AST extractor. It does not
install the target repository's dependencies. The virtual environment
must be writable by your user. The viewer has its own separate npm setup.

## Run a scan

Replace the target path with a local checkout you are authorized to inspect:

```sh
sentinel-zero analyze "/path/to/project" --language python --format md --out "./results/python"
sentinel-zero analyze "/path/to/project" --language javascript --format md --out "./results/javascript"
```

PowerShell uses the same flags with Windows paths:

```powershell
sentinel-zero analyze "C:\path\to\project" --language python --format md --out ".\results\python"
```

Omit `--language` to select the language with the most supported source
files. Omit `--out` to write to `<project-name>.sentinel-zero` beside the
target checkout. Default scans do not need Docker.

Each successful run writes:

| File | Contents |
| --- | --- |
| `verification_ledger.json` | Finding plans, evidence, catalog provenance, parse errors, and scan summary |
| `graph.json` | Modules, functions, and call edges for the viewer |
| `report.md` | Human-readable summary, when `--format md` is selected |

With no `--catalog`, the scanner uses its bundled ASI catalog snapshot and
marks it in the output. Supply a maintained export when needed:

```sh
sentinel-zero analyze "/path/to/project" --catalog "/path/to/asi-catalog.json" --format md
```

Exit code zero means the analysis command completed, not that the
repository is safe. Read `parse_errors`, `unresolved_call_sites`, and each
plan's `disposition.reason`. A failed diagnostic can also be recorded in
an otherwise successful scan. [Usage and troubleshooting](USAGE.md)
explains these distinctions and all CLI flags.

## Explore the 3D report

From the source checkout:

```sh
npm --prefix viewer ci
npm --prefix viewer run dev -- --host 127.0.0.1
```

Open the local URL printed by Vite, then choose **Load graph.json** and
select a scan's graph export. Search by name, inspect nodes, filter
dispositions, or load a baseline for comparison. The initial bundled
sample is a historical demonstration, not a report about your checkout.
See the [viewer guide](viewer/README.md) for builds and browser tests.

## Optional execution diagnostics

`--probe-mode diagnostic` executes eligible target code inside Docker.
Set up the pinned images and read the [execution and trust model](docs/SECURITY.md)
before enabling it:

```sh
sentinel-zero analyze "/path/to/project" --probe-mode diagnostic --format md --out "./results/diagnostic"
```

Both language backends require Docker isolation. There is no host-process
fallback or automatic target dependency installation. Diagnostic reports
remain target-controlled and cannot authorize verified dispositions.

## MCP integration

Run `sentinel-zero-mcp` in the installed environment to start the stdio
server. It exposes `analyze_repository(repo_path, language=None,
catalog_path=None, probe_mode="static")` and returns the ledger as structured
data. See [MCP configuration](USAGE.md#mcp-server) for client examples.

## Documentation

| Guide | Purpose |
| --- | --- |
| [Usage](USAGE.md) | CLI reference, report interpretation, MCP, and troubleshooting |
| [Changelog](CHANGELOG.md) | Current development changes and compatibility notes |
| [Viewer](viewer/README.md) | Graph navigation, comparison, builds, and E2E tests |
| [Security model](docs/SECURITY.md) | Docker setup, execution boundary, and evidence trust |
| [Analysis limits](docs/isbg-limits.md) | Supported analysis and known coverage gaps |
| [Architecture](docs/ARCHITECTURE.md) | Components, data flow, and report contracts |
| [Development](docs/DEVELOPMENT.md) | Pinned tools, tests, clean wheels, and CI |
| [Scan comparison](docs/SECURITY_MONITORING.md) | Stable identity, library diffing, and retained artifacts |
| [Use cases](docs/USE_CASES.md) | Where the tool fits in a review workflow |
| [Remediation and roadmap](docs/REMEDIATION_PLAN.md) | Implemented controls and remaining engineering work |
| [Verification policy](docs/IVP.md) | Evidence standards for engineering claims |
| [Regression index](VERIFICATION_LEDGER.md) | Coverage and historical issue references |
| [Dogfood workflow](docs/DOGFOOD_LOG.md) | Repeating scans without publishing private run logs |

## License

MIT, as declared in [pyproject.toml](pyproject.toml).

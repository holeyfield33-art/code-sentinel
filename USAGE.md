# Usage guide

Start with the [installation instructions](README.md#install-from-source).
Use a writable virtual environment; run `sentinel-zero install-js-deps`
once if you will analyze JavaScript or TypeScript.

## CLI reference

```text
sentinel-zero analyze PATH [--probe-mode {static,diagnostic}]
  [--format {json,md}] [--language {python,javascript}]
  [--catalog PATH] [--out DIRECTORY]
sentinel-zero install-js-deps
```

`python -m sentinel_zero.cli` accepts the same arguments when the package
is installed in that interpreter's environment.

| Option | Default | Behavior |
| --- | --- | --- |
| `PATH` | Required | Local target repository directory |
| `--probe-mode` | `static` | Parse source only; `diagnostic` additionally attempts eligible container probes |
| `--format` | `json` | Write ledger and graph; `md` also writes `report.md` |
| `--language` | Auto-detected | `python` or `javascript`; the latter includes JS/TS, JSX/TSX and MTS/CTS files |
| `--catalog` | Bundled snapshot | Use the supplied ASI catalog export and record its provenance |
| `--out` | Sibling `<target-name>.sentinel-zero` | Output directory; existing same-name artifacts can be overwritten |

Auto-detection counts supported source files and picks the larger language
group, choosing Python on a tie. It is not a combined scan. For a mixed
repository, keep two outputs:

```sh
sentinel-zero analyze "/path/to/project" --language python --format md --out "./results/python"
sentinel-zero analyze "/path/to/project" --language javascript --format md --out "./results/javascript"
```

TypeScript, TSX and JSX use `--language javascript`. Declaration-only
`.d.ts`, `.d.mts` and `.d.cts` files are excluded explicitly. Genuine source
directories named `build`, `dist` and `coverage` are included.

## Read the output

`verification_ledger.json` is the primary analysis record. Important fields:

| Field | Meaning |
| --- | --- |
| `probe_mode` | Whether the operator selected static analysis or execution diagnostics |
| `catalog` | Source path, snapshot flag, and taxonomy metadata |
| `plans` / `plan_count` | Finding plans for supported, resolved sink calls |
| `parse_errors` | Files the resolver could not parse; the rest of the project may still be analyzed |
| `coverage` | JS/TS collection and parsing counts, directory/declaration exclusions, unsupported source files and warnings |
| `unresolved_call_sites` | Call targets the resolver could not establish |
| `external_dependencies` | Package references reached through the modeled call graph |

For each plan, read `hypothesis.source_node` for the file and line,
`hypothesis.sink_node` for the API, and `hypothesis.symbol_binding` for the
enclosing caller. `argument_taint` describes bounded argument evidence;
`parameter` is a review lead, not proof of attacker control.

### Triage

Every plan carries a `triage` block, and the ledger a `triage_summary`.
Triage orders the report; it never removes a plan or changes a disposition.

- `signal`: `low` for sinks that cannot run code by themselves (JSON
  parsing: `json.load`, `json.loads`, `JSON.parse`); `high` otherwise.
- `code_context`: `test`, `example`, `docs`, `build_tooling`, or
  `production`. Test, example, and docs directory names match at any depth;
  tooling names (`scripts`, `tools`, `.github`, `benchmarks`, ...) only as
  the repository's top-level directory, because nested `tools/` is often
  product code. Anything unmatched is `production`.
- `priority`: high signal in production code. The report lists these
  first; everything else follows under "Lower-priority findings".
- `context_rule` and `signal_reason` name the rule that produced each tag.

### Dispositions

| Status | Interpretation |
| --- | --- |
| `UNRESOLVED_INCONCLUSIVE` | Current scan output: the evidence does not establish a vulnerability or safety |
| `VERIFIED_TRUE` | Reserved for independent verification; current code rejects attempts to authorize this status |
| `VERIFIED_FALSE` | Reserved for independent verification; current code rejects attempts to authorize this status |
| `TOOL_FAILURE` | A schema-supported failure status; ordinary CLI analysis failures are surfaced as a nonzero command result |

`PENDING` is an internal construction state, not a completed review result.
Older ledgers can contain verified statuses from earlier policies. Re-scan
with the current implementation before comparing their certainty to new output.

### Diagnostics

After [Docker setup](docs/SECURITY.md#docker-setup), opt in explicitly:

```sh
sentinel-zero analyze "/path/to/project" --probe-mode diagnostic --format md --out "./results/diagnostic"
```

Where a probe is attempted, `verification_method.probe_observation` holds
the parent's requested call site, `trust: "target_controlled"`,
`site_verified: false`, and a shape-validated report. Report statuses are
`sink_reached`, `not_reached`, or `call_failed`. None grants a verified
disposition. Some findings are deliberately not probed; absence of an
observation is not a negative runtime result.

Missing Docker, unavailable pinned images, missing target dependencies,
timeouts, and malformed worker reports can become `call_failed` observations
while the overall analysis command still exits zero.

## Exit codes and incomplete runs

| Code | Meaning |
| --- | --- |
| `0` | Command completed; inspect findings, coverage, parse errors, and diagnostic failures |
| `2` | CLI argument parsing failed |
| `3` | CLI-reported tool/catalog/setup failure, such as an invalid target or unavailable JS extractor |

`pull-images` returns zero once the pinned images are present and reports
a missing daemon or failed pull as code 3.
`install-js-deps` returns zero on success, reports missing npm as code 3,
and reports an npm installation failure as a nonzero result. Run `--help`
for the current parser rather than assuming unsupported flags or subcommands.

Output files are written individually. An error writing a later artifact
can leave earlier files in place; an old output directory can also contain
stale artifacts. Use a new directory for each retained scan and check the
command result before consuming its files. Size caps are 5,000,000 bytes
for the ledger and Markdown report and 20,000,000 bytes for the graph. A graph
over its cap is skipped whole (never truncated): the scan still exits zero,
`artifacts.graph.written` is `false` with the reason, stderr prints a
`graph_skipped` warning, and any older `graph.json` in that directory is
removed so it cannot be mistaken for this run's graph.
Path, size, and UTF-8 encoding refusals surface as `ToolFailure`.

## MCP server

Start the installed stdio server:

```sh
sentinel-zero-mcp
```

For a client that uses an `mcpServers` configuration object:

```json
{
  "mcpServers": {
    "sentinel-zero": {
      "command": "/path/to/code-sentinel-venv/bin/sentinel-zero-mcp"
    }
  }
}
```

On Windows, use an absolute executable path such as
`C:/path/to/code-sentinel-venv/Scripts/sentinel-zero-mcp.exe`.
Adapt the surrounding configuration to your client's format.

The tool signature is:

```python
analyze_repository(repo_path, language=None, catalog_path=None, probe_mode="static")
```

Use an absolute target path. The tool returns the ledger dictionary;
temporary server-side output files are removed after the request. To keep
graph exports or Markdown reports, use the CLI. Diagnostic mode requires
the server host's Docker setup, not merely Docker on the MCP client.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `sentinel-zero` is not found | Activate the installation environment or use its Python with `-m sentinel_zero.cli` |
| JS/TS extractor dependencies missing | Run `sentinel-zero install-js-deps` in the same installed environment |
| npm cannot write into the package | Reinstall into a user-owned virtual environment; avoid a protected global installation |
| Auto-detection chooses the wrong language | Pass `--language` and scan each language separately |
| No finding plans | Review supported sinks, file extensions, parse errors, and unresolved calls; zero plans is not a safety verdict |
| Docker diagnostic fails | Check daemon availability, pinned images, source readability, mount paths, and the observation's detail |
| Observation says a pinned runtime image is not installed | Run `sentinel-zero pull-images` (or `--language python`/`javascript`) once; scans never pull images |
| Viewer rejects an upload | Select `graph.json`, not `verification_ledger.json`; inspect the validation message |
| Catalog rejected | Use a valid ASI export with an `attackClasses` array and usable IDs/aliases, or omit `--catalog` for the bundled snapshot |

See [analysis limits](docs/isbg-limits.md) and the
[execution model](docs/SECURITY.md) before interpreting missing evidence.

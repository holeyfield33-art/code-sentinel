# Execution and trust model

## Static analysis

Static mode is the default for the CLI, library orchestrator, and MCP tool.
It parses source and does not import or invoke the target repository.
The JS/TS resolver runs the shipped Node AST extractor; this is distinct
from executing the target's JavaScript.

Use a stable, authorized checkout. File parsing is not an operating-system
sandbox or an atomic snapshot of a hostile filesystem. Analysis artifacts
can include source paths, symbols, argument descriptions, and diagnostic
details; treat them according to the target's data classification.

Both static resolvers refuse collected source-file paths that resolve outside
the repository, dangling links, nonregular files such as named pipes, and
files over 8,000,000 bytes. Refusals are retained in `parse_errors`, so they
must not be interpreted as clean source. File symlinks to regular files
inside the repository are supported. Reads recheck file type and size;
nonblocking and no-follow flags are used where the host supports them.
Keep ancestor directories unchanged throughout a run.

These checks close known file-input attacks; they do not limit Python parser
CPU or heap use or establish a hosted-service boundary. Unattended processing
of untrusted repositories still requires a separately isolated worker with
wall-time and memory limits. A failed or omitted worker check does not grant
permission to process customer source under the service's normal account.

## Docker setup

Diagnostics require a Linux-container daemon. On Windows, use Docker
Desktop in Linux-container mode and ensure it can mount the checkout.
The scanner never automatically pulls runtime images: probes run with
`--pull never` so a scan cannot fetch code from a registry. Pull the pinned
images explicitly, once, before requesting diagnostics:

```sh
sentinel-zero pull-images                       # both runtimes
sentinel-zero pull-images --language python     # or just one
```

That command pulls exactly the digests in
`sentinel_zero/probes/container_runner.py::IMAGES`. The equivalent manual
commands are:

```sh
docker pull python@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
docker pull node@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d
```

If an image is missing, each affected probe records `call_failed` with the
missing digest and this remedy, instead of an opaque Docker exit code.
Pull only the runtime needed for your target language, or both for the full
integration suite. Pull success also establishes image compatibility with
your daemon's platform. Named image tags are not a substitute for these digests.

```sh
sentinel-zero analyze "/path/to/project" --probe-mode diagnostic --format md --out "./results/diagnostic"
```

`SENTINEL_ZERO_PROBE_BACKEND` accepts `docker`; Docker is already the default
diagnostic backend. Setting that variable does not opt a static scan into
execution. Other values fail closed; there is no subprocess fallback.

## Container boundary

| Control | Implementation |
| --- | --- |
| Worker identity | UID/GID `1000:1000` |
| Filesystems | Read-only root, source at `/repo`, shipped harnesses at `/harness` |
| Scratch | Private tmpfs at `/scratch` and `/tmp`; working directory `/scratch` |
| Network | Docker `--network none` |
| Privileges | All capabilities dropped; `no-new-privileges` |
| Resources | 1 CPU, 512 MB memory, 64 processes |
| Target execution budget | 10 seconds; Docker discovery and cleanup have separate bounded waits |
| Captured output | 128,000-byte cap on each drained output stream |
| Environment | Fixed PATH, HOME, temp, locale, and Node option values; a Python nonce is supplied separately |

Host environment secrets, host cwd, and application environment variables
are not forwarded. Docker itself runs on the host and uses its normal
daemon configuration. The Docker executable is located through absolute
PATH entries from a trusted working directory.

Source must be readable by the non-root worker. Prepare an appropriate
readable checkout rather than changing broad host directory permissions.
Escaping/unreadable source links and Windows junctions are refused before
mounting. Commas in the source mount path are unsupported. Keep the tree
unchanged during a run: link validation is not an atomic snapshot.

No target pip/npm manifests are installed. Python diagnostics have the
runtime image's environment; JS diagnostics require code that the worker's
Node loader can load with the mounted repository. Missing dependencies or
unsupported loaders become diagnostic failures.

## Evidence authority

Target code can emit stdout, alter serializers, inspect frames, or fabricate
otherwise well-shaped results. Neither a nonce nor a container authenticates
an in-process report. Sink patching is an observation mechanism inside the
container, not the OS isolation boundary.

The parent accepts only bounded, allowlisted report fields. It supplies
the requested site context itself and records `trust: "target_controlled"`
and `site_verified: false`. Observations never authorize `VERIFIED_TRUE`
or `VERIFIED_FALSE`; both status transitions and plan serialization reject
such authorization without an independent verifier.

Diagnostic eligibility is narrow. Python uses supported top-level function
invocations with zero or harvested literal arguments. JS requires a callable
CommonJS export. Competing direct or transitive sites for the same sink
symbol suppress attempts that cannot distinguish the source site. Python
`eval`/`exec` and Node `fs.readFileSync` findings are excluded from probing.
These restrictions do not make arbitrary target imports safe outside Docker.

## Failures and interpretation

Unavailable isolation, runtime errors, invalid reports, timeouts, and output
overflow produce `call_failed` observations. Cleanup is bounded; cleanup
failures are reported without replacing the original execution error.
No failure enables a weaker backend. A scan may still produce a ledger and
exit zero when a diagnostic fails; inspect each observation.

Containerization reduces host exposure but does not prove the absence of
container/runtime vulnerabilities. Limit diagnostics to code you are
authorized to execute. Use static mode when execution is unnecessary.

## Security review

Review code changes against [analysis limits](isbg-limits.md),
[verification policy](IVP.md), and the [regression index](../VERIFICATION_LEDGER.md).
Keep private targets, secrets, reproduction artifacts, and personal run logs
out of tracked documentation. Report a suspected security issue to the
repository maintainer without including secrets or confidential target code
in a public issue.

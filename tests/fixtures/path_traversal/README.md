# Paired local path traversal control

This maintained synthetic fixture demonstrates CWE-22 without reading host
files or contacting external services. It is not a Next.js finding.

The HTTP `file` query at `src/server.mjs:4` is passed at line 6 to
`readPublicFile`. The vulnerable `src/files.mjs:4` joins an unchecked path
under `/fixture/public` and reads it. `../private/canary.txt` escapes that
directory. The patched implementation resolves the real path and rejects
paths outside the public directory before its read at line 7.

Run the real Docker regression from the repository root:

```sh
python -m pytest tests/test_path_traversal_control.py -q -ra
```

Requirements: installed resolver dependencies, Docker in Linux-container
mode, and the pinned JavaScript image in `container_runner.IMAGES` already
present. There is no automatic pull, target dependency installation or
host fallback. Set `SENTINEL_PAIRED_REPORT` to a writable output filename
to retain a JSON evidence record; keep local audit output outside tracked
documentation.

Both variants use the same image, environment allowlist, resource bounds,
read-only source mount and random private canary. Each must serve the
public positive control. An observer in a separate interpreter and UID
sends loopback HTTP requests; the host compares its response to the random
canary. The target's stdout is not used as evidence. Bounded cleanup checks
that every test-owned container is absent before writing a success report.

Passing demonstrates this exact local effect and patched control. It does
not authorize scanner `VERIFIED_TRUE`/`VERIFIED_FALSE`, prove arbitrary
repository safety, or replace external human review.

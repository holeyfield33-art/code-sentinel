# Saved scans and comparison

Sentinel-Zero provides point-in-time source analysis and comparison
primitives. It does not watch traffic, run a monitoring service, schedule
scans, or maintain a scan-history database.

## Retain separate artifacts

Give each scan a distinct output directory:

```sh
sentinel-zero analyze "/path/to/project" --language python --format md --out "./results/before"
# Review or change the target checkout, then scan again.
sentinel-zero analyze "/path/to/project" --language python --format md --out "./results/after"
```

Record the target revision, scanner revision/version, language, selected
catalog, probe mode, and relevant environment alongside retained artifacts
in your own evidence store. Keep private paths, source descriptions, and
diagnostic data out of public documentation. Use the same settings for
comparable runs and inspect parse errors and unresolved-call counts.

## Finding identity

`plan_id` is sequential within a run and is not a comparison key.
`finding_uid` is derived from the hypothesis's `(source_node, sink_node)`
pair. An unchanged source location and sink therefore keep the same UID
across scans regardless of disposition or plan numbering.

The source node includes a path and line number. Moving a checkout,
renaming a file, or shifting lines can appear as removal plus addition.
Multiple calls to the same sink on the same line can share a UID. These
identifiers are not semantic hashes of an entire code path.

## Compare finding lists in Python

The installed library exposes `diff_ledgers`; there is no `sentinel-zero
diff` subcommand. Run this from a directory containing the saved outputs:

```python
import json
from pathlib import Path
from sentinel_zero.scan_diff import diff_ledgers

before = json.loads(Path("results/before/verification_ledger.json").read_text(encoding="utf-8"))
after = json.loads(Path("results/after/verification_ledger.json").read_text(encoding="utf-8"))
comparison = diff_ledgers(before["plans"], after["plans"])
print(json.dumps(comparison, indent=2))
```

The result contains `new_findings`, `removed_findings`,
`changed_disposition`, `unchanged_count`, `old_total`, and `new_total`.
Shared UIDs are classified as changed only when their disposition status
changes; argument/reason changes alone do not appear in that category.
Input plans missing a finding UID raise `ValueError`. Duplicate UIDs are
indexed as a single identity, so inspect original plans when same-line
calls matter.

## Compare graph exports

In the [viewer](../viewer/README.md), load the current `graph.json` and
then the older graph as its baseline. Nodes are classified as new,
changed, or unchanged using their worst disposition and attached finding
UID sets. Removed nodes are listed in the comparison summary.

Current schema 2 graph IDs include the node kind (`module:` or `function:`);
`qualified_name` retains the original analysis symbol. The viewer compares
kind plus qualified name, so unambiguous historical bare IDs can still be
used as a baseline. Historical graphs with duplicate IDs are refused and
must be regenerated; the viewer cannot recover an identity already lost in
an earlier export.

This is a different granularity from the ledger library: graph nodes
can contain several finding UIDs, and a changed UID set can change a
node even when its worst disposition stays the same. Neither comparison
performs fresh analysis or independently verifies a fix.

## Interpretation and future work

An added finding can reflect code changes, parser coverage, a relocated
source line, or a different scanner/catalog configuration. A removed
finding does not by itself establish a remediated vulnerability. Current
scans retain inconclusive dispositions; historical verified labels must
be read under the policy of the scanner that produced them.

A history index, scheduled scans, a diff CLI, and trend dashboards remain
possible future work. No component currently writes an append-only
history index or sends alerts. Consult the
[roadmap](REMEDIATION_PLAN.md) before treating a proposal as shipped behavior.

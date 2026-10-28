"""Generic triage tags for finding plans: how much signal a sink carries,
and what kind of code a finding sits in.

Why this exists: the 2026-10-28 held-out benchmark (stytch-node,
django-DefectDojo, chia-blockchain, with vercel/swr as a control) found
zero real leads among 764 plans. Two causes dominated:

  * plain JSON parsing (Python json.load/loads, JS JSON.parse) was reported
    as AAC-27 Serialization Injection -- 483 of DefectDojo's 486 plans --
    although parsing JSON builds plain data and cannot run code;
  * findings in tests, CI, benchmarks and examples were reported with the
    same weight as application code (47% of chia's plans).

Nothing here removes a plan or changes a disposition. Tags only rank: every
plan stays in the ledger, and the report lists "priority" plans (high
signal, production context) first. The rules are path- and sink-name based
on purpose, so they apply to any repository without per-project tuning.
Each tag records the rule that produced it, so a reader can overrule it.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

# Sinks that are recognised (so coverage stays visible) but cannot by
# themselves execute code or construct arbitrary objects.
LOW_SIGNAL_SINKS: dict[str, str] = {
    "json.load": "JSON parsing builds plain dicts/lists/strings and cannot execute code; "
                 "only a concern if the parsed data later reaches an unsafe sink.",
    "json.loads": "JSON parsing builds plain dicts/lists/strings and cannot execute code; "
                  "only a concern if the parsed data later reaches an unsafe sink.",
    "JSON.parse": "JSON.parse builds plain objects and cannot execute code; only a concern if the "
                  "result reaches an unsafe merge (prototype pollution) or an execution sink.",
}

# Directory names, matched case-insensitively. Test, example and docs
# names match at any depth (packages/a/__tests__ is still tests). Build and
# tooling names match only as the repo's top-level directory: a nested
# "tools" is often product code -- django-DefectDojo's dojo/tools/ holds
# its scanner parsers, the core feature -- and must not be down-ranked.
# Order matters: the first context whose rule matches wins.
_CONTEXT_DIRS: list[tuple[str, frozenset[str]]] = [
    ("test", frozenset({
        "test", "tests", "_tests", "__tests__", "testing", "unittests", "unit_tests",
        "integration_tests", "e2e", "spec", "specs", "fixtures", "__fixtures__",
        "__mocks__", "mocks", "testdata", "test_data",
    })),
    ("example", frozenset({"example", "examples", "demo", "demos", "sample", "samples", "playground"})),
    ("docs", frozenset({"doc", "docs", "documentation"})),
]
_TOP_LEVEL_TOOLING_DIRS = frozenset({
    ".github", ".circleci", ".gitlab", ".ci", "ci", "scripts", "script", "build_scripts",
    "tools", "tooling", "benchmark", "benchmarks", "bench", "docker", "devtools",
})

_TEST_FILE = re.compile(
    r"(^test_.*\.py$|.*_tests?\.py$|^conftest\.py$|.*\.(test|spec)\.(c|m)?(j|t)sx?$)",
    re.IGNORECASE,
)


def code_context(source_path: str, repo_root: str) -> tuple[str, str]:
    """Classify where a finding lives. Returns (context, rule).

    context is one of production, test, example, docs, build_tooling.
    Anything not matched is production: unknown code is never down-ranked.
    """
    path = source_path.replace("\\", "/")
    root = repo_root.replace("\\", "/").rstrip("/") + "/"
    if path.startswith(root):
        path = path[len(root):]
    parts = PurePosixPath(path).parts
    name = parts[-1] if parts else path
    if _TEST_FILE.match(name):
        return "test", f"file name {name!r}"
    for segment in parts[:-1]:
        lowered = segment.lower()
        for context, names in _CONTEXT_DIRS:
            if lowered in names:
                return context, f"directory {segment!r}"
    if len(parts) > 1 and parts[0].lower() in _TOP_LEVEL_TOOLING_DIRS:
        return "build_tooling", f"top-level directory {parts[0]!r}"
    return "production", "no non-production path rule matched"


def sink_signal(sink_name: str) -> tuple[str, str]:
    """Returns (signal, reason). signal is high or low."""
    if sink_name in LOW_SIGNAL_SINKS:
        return "low", LOW_SIGNAL_SINKS[sink_name]
    return "high", "sink can execute code, read/write files, or construct objects"


def triage_for(source_node: str, sink_name: str, repo_root: str) -> dict:
    """The triage block attached to every plan."""
    source_path = source_node.rsplit(":", 1)[0]
    context, context_rule = code_context(source_path, repo_root)
    signal, signal_reason = sink_signal(sink_name)
    return {
        "priority": signal == "high" and context == "production",
        "signal": signal,
        "signal_reason": signal_reason,
        "code_context": context,
        "context_rule": context_rule,
        "rules_version": 1,
    }


def summarize(plans: list[dict]) -> dict:
    """Counts for the ledger. Plans without a triage block are counted as
    untriaged rather than guessed."""
    summary: dict = {"priority": 0, "by_signal": {}, "by_context": {}, "untriaged": 0}
    for plan in plans:
        tag = plan.get("triage")
        if not tag:
            summary["untriaged"] += 1
            continue
        summary["priority"] += 1 if tag["priority"] else 0
        summary["by_signal"][tag["signal"]] = summary["by_signal"].get(tag["signal"], 0) + 1
        summary["by_context"][tag["code_context"]] = summary["by_context"].get(tag["code_context"], 0) + 1
    return summary

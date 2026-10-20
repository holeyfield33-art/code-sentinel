"""JS/TS resolver (Milestone 7): proves graph.py's IR is actually
language-agnostic, not just promised in prose.

All real parsing happens in resolvers/js/extract_graph.js, run as a Node
subprocess with a real parser (acorn) -- never regex/string matching on JS
source, same rule python_resolver.py enforces with Python's own `ast`
module. This file's only job is translating that subprocess's JSON output
into the exact same dataclasses python_resolver.py builds (Symbol,
Unresolved, CallSite, FunctionInfo, ModuleGraph, ProjectGraph). Nothing
downstream -- callgraph.py's delegation walks, dogfood_scan.py's sink/guard
matching -- needs to know or care which resolver populated the graph.

Deliberately NOT at parity with the Python resolver's five milestones (see
extract_graph.js's module docstring for the exact bounds: top-level
functions only, no wrapper-class detection). Milestone 8 added external-
dependency classification (graph.external_references is now populated for
JS too, same shape as Python's). graph.wrapper_classes and
graph.wrap_constructions are still simply left empty for a JS project --
real future increments, not silently claimed here.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sentinel_zero.graph import (
    CallSite,
    ExternalReference,
    FunctionInfo,
    ModuleGraph,
    ProjectGraph,
    Symbol,
    Unresolved,
)

_EXTRACT_SCRIPT = Path(__file__).parent / "js" / "extract_graph.js"
EXTRACT_TIMEOUT_SECONDS = 60


class JsResolverFailure(Exception):
    """Raised when the Node-side extractor itself could not run (missing
    node, missing extract_graph.js, non-zero exit, unparseable output).
    A per-file parse error inside the target project is NOT this -- that is
    reported per-file in the `errors` list and does not raise."""


def _target_to_dataclass(raw: dict) -> Symbol | Unresolved:
    if raw["kind"] == "symbol":
        return Symbol(qualified_name=raw["qualified_name"])
    return Unresolved(reason=raw["reason"])


def build_project_graph(repo_root: Path) -> ProjectGraph:
    if not _EXTRACT_SCRIPT.is_file():
        raise JsResolverFailure(f"extractor script missing at {_EXTRACT_SCRIPT}")

    try:
        completed = subprocess.run(
            ["node", str(_EXTRACT_SCRIPT), str(repo_root)],
            capture_output=True,
            text=True,
            timeout=EXTRACT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise JsResolverFailure(f"extractor exceeded {EXTRACT_TIMEOUT_SECONDS}s on {repo_root}") from exc
    except FileNotFoundError as exc:
        raise JsResolverFailure("`node` executable not found -- JS/TS resolver requires Node.js") from exc

    if completed.returncode != 0:
        raise JsResolverFailure(
            f"extractor exited {completed.returncode} on {repo_root}: {completed.stderr.strip()[-2000:]}"
        )

    try:
        data = json.loads(completed.stdout)
    except ValueError as exc:
        raise JsResolverFailure(f"could not parse extractor output for {repo_root}: {exc}") from exc

    if data.get("error"):
        raise JsResolverFailure(f"extractor reported: {data['error']}")

    graph = ProjectGraph()
    for module_qualname, mod in data["modules"].items():
        calls = [
            CallSite(
                caller=c["caller"],
                target=_target_to_dataclass(c["target"]),
                lineno=c["lineno"],
                order=c["order"],
                args=tuple(c.get("args", ())),
                branch_path=tuple(tuple(pair) for pair in c.get("branch_path", ())),
            )
            for c in mod["calls"]
        ]
        graph.modules[module_qualname] = ModuleGraph(
            module_qualname=module_qualname, file_path=mod["file_path"], calls=calls
        )

    for qualname, fn in data["functions"].items():
        graph.functions[qualname] = FunctionInfo(
            qualified_name=fn["qualified_name"],
            is_guard_shaped=fn["is_guard_shaped"],
            file_path=fn["file_path"],
            lineno=fn["lineno"],
        )

    graph.external_references = [
        ExternalReference(
            caller=ref["caller"],
            package=ref["package"],
            qualified_name=ref["qualified_name"],
            file_path=ref["file_path"],
            lineno=ref["lineno"],
        )
        for ref in data.get("external_references", [])
    ]

    # Per-file parse errors are real, reportable facts about specific files
    # (e.g. a .js file this parser's grammar subset can't handle) -- they do
    # NOT halt the whole-project scan, same "a resolver-level failure halts,
    # a per-item gap does not" split dogfood_scan.py already draws for
    # Python's unresolved call sites.
    graph.parse_errors = data.get("errors", [])
    return graph


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: js_resolver.py REPO_ROOT")
        return 2
    try:
        graph = build_project_graph(Path(argv[0]))
    except JsResolverFailure as exc:
        print(f"JS_RESOLVER_FAILURE: {exc}")
        return 3
    print(
        f"{len(graph.modules)} modules, {len(graph.functions)} functions indexed, "
        f"{len(graph.all_calls())} calls, {len(getattr(graph, 'parse_errors', []))} per-file parse errors"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

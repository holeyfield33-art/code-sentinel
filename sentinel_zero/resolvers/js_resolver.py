"""JS/TS resolver (Milestone 7): proves graph.py's IR is actually
language-agnostic, not just promised in prose.

All real parsing happens in resolvers/js/extract_graph.js, run as a Node
subprocess with real parsers -- acorn for .js/.mjs/.cjs,
@typescript-eslint/typescript-estree for .ts (Milestone 10) -- never regex/
string matching on source, same rule python_resolver.py enforces with
Python's own `ast` module. This file's only job is translating that
subprocess's JSON output into the exact same dataclasses python_resolver.py
builds (Symbol, Unresolved, CallSite, FunctionInfo, ModuleGraph,
ProjectGraph). Nothing downstream -- callgraph.py's delegation walks,
dogfood_scan.py's sink/guard matching -- needs to know or care which
resolver, or which of the two JS/TS parsers, populated the graph.

Deliberately NOT at parity with the Python resolver's five milestones (see
extract_graph.js's module docstring for the exact bounds: top-level
functions only). Milestone 8 added external-dependency classification
(graph.external_references, same shape as Python's). Milestone 9 added
wrapper-middleware detection (graph.wrapper_classes) and switched to a
real project-wide two-pass (index everything, then resolve calls) --
graph.wrap_constructions is populated via callgraph.find_wrap_constructions,
the same shared, language-agnostic helper python_resolver.py now calls too.
Milestone 10 originally added plain .ts support. The resolver now also
collects TSX, JSX, MTS and CTS, with explicit coverage accounting. Dogfooded against
Vercel's own CLI (vercel/vercel, packages/cli): 2194 modules / 2034
functions indexed from real TS source, versus 209 modules of mostly dev-
server test fixtures before this milestone, when every real .ts file in
that repo was invisible to this resolver.

Milestone 12 closed two gaps this file used to log here as known limits:
class method bodies (including the constructor) are now walked for call
sites too, with `this` bound to the owning class's qualname the same way
`self`/`cls` are bound on the Python side (see extract_graph.js's
walkCalls); and TS parameter-property constructor sugar
(`constructor(private x: Foo) {}`, common in NestJS-style code) is now
detected directly from the constructor's own parameter list rather than
relying on a body-walk that could never find it, since the sugar emits no
assignment statement at all. See tests/test_js_resolver.py and
tests/test_ts_resolver.py for the regression coverage that replaced the
old "known gap" pins.

Milestone 15 mirrors python_resolver.py's bounded sink-argument taint
classification: extract_graph.js's classifyArgTaint walks each call's
positional-argument AST nodes and reports "literal" / "parameter" /
"unknown" per argument, exactly the same three labels and the same
same-function-only bound as the Python side (see graph.py's
CallSite.arg_taint docstring). This file just carries the `arg_taint`
array through into CallSite the same way it already carries `args`.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from sentinel_zero.callgraph import find_wrap_constructions
from sentinel_zero.graph import (
    CallSite,
    ExternalReference,
    FunctionInfo,
    ModuleGraph,
    ProjectGraph,
    Symbol,
    Unresolved,
    WrapperClass,
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
            encoding="utf-8",
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
                arg_taint=tuple(c.get("arg_taint", ())),
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
            raises_on_guard=fn["raises_on_guard"],
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

    for qualname, wc in data.get("wrapper_classes", {}).items():
        graph.wrapper_classes[qualname] = WrapperClass(
            qualified_name=wc["qualified_name"],
            wrapped_param_index=wc["wrapped_param_index"],
            dispatch_method=wc["dispatch_method"],
            dispatch_is_guarded=wc["dispatch_is_guarded"],
        )
    graph.wrap_constructions = find_wrap_constructions(graph)

    # Per-file parse errors are real, reportable facts about specific files
    # (e.g. a .js file this parser's grammar subset can't handle) -- they do
    # NOT halt the whole-project scan, same "a resolver-level failure halts,
    # a per-item gap does not" split dogfood_scan.py already draws for
    # Python's unresolved call sites.
    graph.parse_errors = data.get("errors", [])
    graph.coverage = data.get("coverage", {})
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

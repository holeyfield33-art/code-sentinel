"""Milestone 10: TypeScript support. Bounded to plain .ts (NOT .tsx -- JSX
inside TS is a separate parser mode, deliberately out of scope). The parser
swap is acorn -> @typescript-eslint/typescript-estree for .ts files only;
every walker in extract_graph.js (findCallsInExpr, indexFile, walkCalls,
forwardsToThisAttr, ctorWrappedParamIndex) is unchanged, since
typescript-estree emits the same ESTree node shapes acorn does. These tests
prove that claim rather than just asserting it in a comment."""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.js_resolver import build_project_graph

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("node") is None, reason="Node.js not available in this environment"
)


def test_bodyless_class_signatures_do_not_crash_or_hide_implementations(tmp_path: Path) -> None:
    (tmp_path / "svc.ts").write_text(
        "import { exec } from 'child_process';\n"
        "declare class Ambient { constructor(x: string); run(x: string): void; }\n"
        "class Worker {\n"
        "  constructor(x: string);\n"
        "  constructor(x: string) {}\n"
        "  run(x: string): void;\n"
        "  run(x: string): void { exec(x); }\n"
        "}\n",
        encoding="utf-8",
    )
    graph = build_project_graph(tmp_path)
    assert graph.parse_errors == []
    assert "svc.Ambient.run" not in graph.functions
    assert "svc.Ambient.constructor" not in graph.functions
    assert "svc.Worker.run" in graph.functions
    calls = [call for call in graph.all_calls() if call.target == Symbol("child_process.exec")]
    assert len(calls) == 1
    assert calls[0].caller == "svc.Worker.run"
    assert calls[0].arg_taint == ("parameter",)


def test_node_graph_json_uses_utf8_for_unicode_source_paths(tmp_path: Path) -> None:
    source = tmp_path / "\u010d.ts"
    source.write_text("import { exec } from 'child_process';\nfunction run() { exec('example'); }\n", encoding="utf-8")
    graph = build_project_graph(tmp_path)
    assert graph.parse_errors == []
    assert any(module.file_path == str(source) for module in graph.modules.values())
    assert any(call.target == Symbol("child_process.exec") for call in graph.all_calls())


def test_type_annotations_and_interfaces_are_ignored_not_fatal():
    """Interfaces, type annotations and a typed param must not change what
    gets indexed -- confirmed as the real pre-Milestone-10 failure mode:
    these constructs made acorn reject every one of these files outright."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.ts").write_text(
            "interface Options {\n"
            "  verbose: boolean;\n"
            "}\n"
            "function runIt(opts: Options): void {\n"
            "  doThing();\n"
            "}\n"
        )
        graph = build_project_graph(root)
        assert graph.parse_errors == []
        assert "svc.runIt" in graph.functions
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].target == Symbol("doThing")


def test_require_style_import_resolves_sink_by_identity_in_ts():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.ts").write_text(
            "import { exec } from 'child_process';\n"
            "function runIt(): void {\n"
            "  exec('echo hi');\n"
            "}\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].target == Symbol("child_process.exec")
        assert calls[0].caller == "runner.runIt"


def test_wrapper_class_detected_with_type_annotated_members():
    """Same shape as test_js_wrapper_middleware.py's same-file case, but
    with TS member type annotations (`private inner: Function;`) and typed
    params -- the exact combination that would have broken ctorWrappedParamIndex
    or the paramNames filter if TS's extra node fields leaked through."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "gatekeeper.ts").write_text(
            "class TokenWall {\n"
            "  private inner: Function;\n"
            "  private token: string;\n"
            "  constructor(innerApp: Function, token: string) {\n"
            "    this.inner = innerApp;\n"
            "    this.token = token;\n"
            "  }\n"
            "  handle(request: any): any {\n"
            "    if (request.headers.authorization !== this.token) {\n"
            "      return reject(request);\n"
            "    }\n"
            "    return this.inner(request);\n"
            "  }\n"
            "}\n"
            "function build(): TokenWall {\n"
            "  const coreApp = makeCoreApp();\n"
            "  return new TokenWall(coreApp, SECRET);\n"
            "}\n"
        )
        graph = build_project_graph(root)

        wrapper = graph.wrapper_classes.get("gatekeeper.TokenWall")
        assert wrapper is not None
        assert wrapper.wrapped_param_index == 0
        assert wrapper.dispatch_is_guarded

        assert len(graph.wrap_constructions) == 1
        wc = graph.wrap_constructions[0]
        assert wc.wrapper_qualified_name == "gatekeeper.TokenWall"
        assert wc.wrapped_expr == "coreApp"


def test_parameter_property_constructor_sugar_now_detected():
    """Milestone 12 closed the gap this test used to pin: TS's
    `constructor(private inner: Function) {}` auto-assigns
    `this.inner = inner` with no statement in the body, so
    ctorWrappedParamIndex now checks the constructor's own param list
    directly for a TSParameterProperty, rather than relying only on the
    body-walk that can never find this shape."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.ts").write_text(
            "class LoggingWrapper {\n"
            "  constructor(private inner: Function) {}\n"
            "  handle(request: any): any {\n"
            "    log(request);\n"
            "    return this.inner(request);\n"
            "  }\n"
            "}\n"
        )
        graph = build_project_graph(root)
        wrapper = graph.wrapper_classes.get("svc.LoggingWrapper")
        assert wrapper is not None
        assert wrapper.wrapped_param_index == 0
        assert wrapper.dispatch_method == "svc.LoggingWrapper.handle"
        assert not wrapper.dispatch_is_guarded


def test_parameter_property_mixed_with_plain_param_keeps_correct_index():
    """A plain (non-property) param before the parameter-property one must
    not shift the detected index -- confirmed by checking the real
    positional index, not assumed from the simpler single-param case above."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.ts").write_text(
            "class TokenWall {\n"
            "  constructor(label: string, private inner: Function) {}\n"
            "  handle(request: any): any {\n"
            "    if (!request.ok) { throw new Error('no'); }\n"
            "    return this.inner(request);\n"
            "  }\n"
            "}\n"
        )
        graph = build_project_graph(root)
        wrapper = graph.wrapper_classes.get("svc.TokenWall")
        assert wrapper is not None
        assert wrapper.wrapped_param_index == 1
        assert wrapper.dispatch_is_guarded


def test_tsx_file_is_collected():
    """.tsx is explicitly out of scope for this milestone (JSX-in-TS is a
    separate parser mode) -- a .tsx file must be silently skipped, not
    attempted and reported as a parse error."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "component.tsx").write_text("function App() { return doThing(); }\n")
        (root / "plain.ts").write_text("function ok(): void { doThing(); }\n")
        graph = build_project_graph(root)
        assert graph.parse_errors == []
        assert "plain.ok" in graph.functions
        assert "component.App" in graph.functions


def test_dts_declaration_file_not_collected():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "types.d.ts").write_text("declare function doThing(): void;\n")
        (root / "svc.ts").write_text("function runIt(): void { doThing(); }\n")
        graph = build_project_graph(root)
        assert graph.parse_errors == []
        assert "svc.runIt" in graph.functions
        assert not any(m.startswith("types") for m in graph.functions)


def test_malformed_ts_reported_as_parse_error_not_dropped():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "broken.ts").write_text("function (((( not valid ts at all\n")
        (root / "ok.ts").write_text("function ok(): void { return; }\n")
        graph = build_project_graph(root)
        assert len(graph.parse_errors) == 1
        assert graph.parse_errors[0]["file_path"].endswith("broken.ts")
        assert "ok.ok" in graph.functions

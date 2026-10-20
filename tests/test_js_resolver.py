"""Proves graph.py's IR is actually language-agnostic, not just promised in
prose: these tests build a ProjectGraph via js_resolver.py (a Node/acorn
subprocess, zero Python AST involved) and then run the SAME generic
machinery python_resolver.py's tests rely on -- callgraph.py's guard/
delegation walk, sink matching by resolved identity -- completely
unmodified. If any of this needed a JS-specific branch anywhere outside
js_resolver.py itself, that would be the real failure this test is for."""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.callgraph import build_direct_callee_index, transitively_guard_shaped
from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.js_resolver import JsResolverFailure, build_project_graph

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("node") is None, reason="Node.js not available in this environment"
)


def test_require_binding_resolves_sink_by_identity():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.js").write_text(
            "const { exec } = require('child_process');\n"
            "function runIt() {\n"
            "  exec('echo hi');\n"
            "}\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].target == Symbol("child_process.exec")
        assert calls[0].caller == "runner.runIt"


def test_guard_shape_detected_same_as_python_early_return():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "auth.js").write_text(
            "function requireAdmin(user) {\n"
            "  if (!user.isAdmin) {\n"
            "    throw new Error('forbidden');\n"
            "  }\n"
            "}\n"
        )
        graph = build_project_graph(root)
        assert graph.functions["auth.requireAdmin"].is_guard_shaped is True


def test_delegation_walk_from_callgraph_py_works_unmodified_on_js_graph():
    """The real proof: callgraph.py was written for Python's ISBG and never
    touched for this milestone. A JS wrapper that delegates to a guard-
    shaped helper in another file must still resolve as guard-shaped
    through callgraph.py's existing bounded delegation walk."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "guard.js").write_text(
            "function requireRole(user, role) {\n"
            "  if (user.role !== role) {\n"
            "    throw new Error('forbidden');\n"
            "  }\n"
            "}\n"
            "module.exports = { requireRole };\n"
        )
        (root / "handler.js").write_text(
            "const { requireRole } = require('./guard');\n"
            "function requireAdmin(user) {\n"
            "  requireRole(user, 'admin');\n"
            "}\n"
        )
        graph = build_project_graph(root)
        callee_index = build_direct_callee_index(graph)
        # handler.requireAdmin has no raise/throw of its own -- only
        # resolves as guard-shaped through delegation to guard.requireRole.
        assert graph.functions["handler.requireAdmin"].is_guard_shaped is False
        assert transitively_guard_shaped("handler.requireAdmin", graph, callee_index) is True


def test_unresolvable_dynamic_callee_is_unresolved_not_guessed():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "dynamic.js").write_text(
            "function dispatch(handlers, name) {\n"
            "  return handlers[name]();\n"  # computed member access -- out of scope, must be Unresolved
            "}\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].target.__class__.__name__ == "Unresolved"


def test_class_methods_indexed_and_now_walked_for_calls():
    """Milestone 12 closed the gap this test used to pin (matching
    Python's Milestone 11 fix): every class method IS indexed as a
    FunctionInfo, AND its body is now walked for CallSite recording too."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.js").write_text(
            "const { exec } = require('child_process');\n"
            "class Service {\n"
            "  run() {\n"
            "    exec('echo hi');\n"
            "  }\n"
            "}\n"
            "module.exports = Service;\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].caller == "svc.Service.run"
        assert calls[0].target == Symbol("child_process.exec")
        assert "svc.Service.run" in graph.functions
        assert graph.functions["svc.Service.run"].is_guard_shaped is False


def test_this_dispatch_resolves_to_the_real_method_qualname_js():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.js").write_text(
            "class Service {\n"
            "  dispatch() {\n"
            "    return this.helper();\n"
            "  }\n"
            "  helper() {\n"
            "    return 1;\n"
            "  }\n"
            "}\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].caller == "svc.Service.dispatch"
        assert calls[0].target == Symbol("svc.Service.helper")


def test_constructor_body_is_also_walked_for_calls():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.js").write_text(
            "const { exec } = require('child_process');\n"
            "class Service {\n"
            "  constructor() {\n"
            "    exec('echo hi');\n"
            "  }\n"
            "}\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].caller == "svc.Service.constructor"
        assert calls[0].target == Symbol("child_process.exec")


def test_unparseable_file_reported_not_silently_dropped():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "broken.js").write_text("function (((( not valid js at all\n")
        (root / "ok.js").write_text("function ok() { return 1; }\n")
        graph = build_project_graph(root)
        assert len(graph.parse_errors) == 1
        assert graph.parse_errors[0]["file_path"].endswith("broken.js")
        assert "ok.ok" in graph.functions  # the rest of the project still scanned

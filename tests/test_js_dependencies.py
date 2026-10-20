"""JS/TS Milestone 8: external-dependency mapping. Mirrors
tests/test_dependencies.py's Python coverage exactly -- same three facts,
proven for the JS resolver instead: a Node builtin is never flagged, a
real external package is, and the transitive closure through delegation
(callgraph.py's external_packages_reached, written for Python and never
touched here) works unmodified on a JS-built graph."""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.callgraph import build_direct_callee_index, build_direct_external_index, external_packages_reached
from sentinel_zero.resolvers.js_resolver import build_project_graph

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("node") is None, reason="Node.js not available in this environment"
)


def test_builtin_not_flagged_third_party_is():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.js").write_text(
            "const fs = require('fs');\n"
            "const axios = require('axios');\n"
            "function fetchAndSave() {\n"
            "  axios.get('http://example.com');\n"  # third-party
            "  fs.readFileSync('/tmp/x');\n"  # builtin -- must not be flagged
            "}\n"
        )
        graph = build_project_graph(root)
        packages = {ref.package for ref in graph.external_references}
        assert packages == {"axios"}, f"expected only axios flagged, got {packages}"


def test_node_prefixed_builtin_not_flagged():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.js").write_text(
            "const fs = require('node:fs');\n"
            "function save() {\n"
            "  fs.writeFileSync('/tmp/x', 'y');\n"
            "}\n"
        )
        graph = build_project_graph(root)
        assert graph.external_references == []


def test_cross_file_require_not_flagged_as_external():
    """A require('./sibling') resolving to another file in THIS project
    must never be misread as an external npm package -- the exact class
    of bug Milestone 7 fixed for delegation, now checked for dependency
    classification too."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "guard.js").write_text(
            "function requireRole(user) { return user.role; }\n"
            "module.exports = { requireRole };\n"
        )
        (root / "handler.js").write_text(
            "const { requireRole } = require('./guard');\n"
            "function handle(user) {\n"
            "  requireRole(user);\n"
            "}\n"
        )
        graph = build_project_graph(root)
        assert graph.external_references == []


def test_local_variable_method_call_not_flagged_as_dependency():
    """Regression, same bug class as Python's: a plain local variable's
    method call (lines.push(x)) must not read as a dependency on a
    package named 'lines'."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "report.js").write_text(
            "function build(rows) {\n"
            "  const lines = [];\n"
            "  lines.push(rows);\n"
            "  return lines;\n"
            "}\n"
        )
        graph = build_project_graph(root)
        assert graph.external_references == []


def test_transitive_dependency_follows_delegation_unmodified_callgraph():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "net.js").write_text(
            "const axios = require('axios');\n"
            "function callApi(url) {\n"
            "  return axios.get(url);\n"
            "}\n"
            "module.exports = { callApi };\n"
        )
        (root / "handler.js").write_text(
            "const { callApi } = require('./net');\n"
            "function handle(req) {\n"
            "  return callApi(req.url);\n"  # handle never requires axios itself
            "}\n"
        )
        graph = build_project_graph(root)
        callee_index = build_direct_callee_index(graph)
        external_index = build_direct_external_index(graph)
        reached = external_packages_reached("handler.handle", graph, callee_index, external_index)
        assert reached == frozenset({"axios"}), f"expected axios reachable through delegation, got {reached}"

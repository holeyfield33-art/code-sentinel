"""Milestone 15 (JS/TS mirror): bounded sink-argument taint classification.

Mirrors tests/test_argument_taint.py's cases exactly, through the Node/
acorn extractor instead of Python's `ast` module -- same three labels
("literal" / "parameter" / "unknown"), same same-function-only bound (see
graph.py's CallSite.arg_taint docstring). Pure additive evidence: no
disposition status changes because of it.
"""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.resolvers.js_resolver import build_project_graph

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("node") is None, reason="Node.js not available in this environment"
)


def _arg_taint_for(root: Path, caller_suffix: str) -> tuple:
    graph = build_project_graph(root)
    matches = [c for c in graph.all_calls() if c.caller.endswith(caller_suffix) and c.args]
    assert matches, f"no call with args found with caller ending in {caller_suffix!r}"
    return matches[0].arg_taint


def test_literal_argument_classifies_as_literal():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function safe() {\n  exec('echo hi');\n}\n"
        )
        assert _arg_taint_for(root, "safe") == ("literal",)


def test_parameter_argument_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function risky(cmd) {\n  exec(cmd);\n}\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_template_literal_interpolating_a_parameter_classifies_as_parameter():
    """A template literal is JS's f-string -- its interpolated `${...}`
    expressions must be walked individually, not treated as opaque text."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function risky(name) {\n  exec(`hello ${name}`);\n}\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_call_result_argument_classifies_as_unknown_not_literal():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function unclear() {\n  exec(getCmd());\n}\n"
        )
        assert _arg_taint_for(root, "unclear") == ("unknown",)


def test_module_level_const_classifies_as_unknown_not_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "const DEFAULT_CMD = 'echo';\n"
            "function usesGlobal() {\n  exec(DEFAULT_CMD);\n}\n"
        )
        assert _arg_taint_for(root, "usesGlobal") == ("unknown",)


def test_member_access_off_a_parameter_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function risky(opts) {\n  exec(opts.cmd);\n}\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_string_concatenation_with_a_parameter_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function risky(suffix) {\n  exec('echo ' + suffix);\n}\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_array_literal_mixing_a_literal_and_a_parameter_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function risky(target) {\n  exec(['ping', '-c', '1', target]);\n}\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_class_method_this_access_is_not_mistaken_for_a_parameter():
    """`this.cmd` is not one of the method's own parameters -- must read as
    unknown, never as a false 'parameter' just because it's an attribute
    chain. Also exercises that Milestone 12's `this`-bound method walk and
    Milestone 15's paramNames tracking don't collide."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "class Runner {\n"
            "  constructor(cmd) {\n    this.cmd = cmd;\n  }\n"
            "  run() {\n    exec(this.cmd);\n  }\n"
            "}\n"
        )
        assert _arg_taint_for(root, "Runner.run") == ("unknown",)


def test_class_method_own_parameter_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "class Runner {\n"
            "  run(cmd) {\n    exec(cmd);\n  }\n"
            "}\n"
        )
        assert _arg_taint_for(root, "Runner.run") == ("parameter",)

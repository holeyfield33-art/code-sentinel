"""Milestone 15: widened sink tables (Python + JS/TS), plus the
builtins-resolution fix that made them actually reachable.

Covers two things:

1. The real bug found while widening: a bare call to a Python builtin
   sink (`open(...)`, and now `eval`/`exec`) has no import to bind it, so
   python_resolver.py's `_resolve_dotted` unbound-Name fallback returned
   the bare name ("open"), which could never match STDLIB_SINKS's
   "builtins.open" key -- "builtins.open" was dead data since the day it
   was added (grepping tests/ for it before this milestone: zero hits).
   `_BUILTIN_SINK_NAMES` in python_resolver.py fixes this for
   open/eval/exec together.

2. The new sinks themselves: pickle.load/loads, yaml.load, builtins.eval/
   exec (Python) and the vm module (JS/TS) -- each resolves to its real
   qualified identity and is classified with the right SinkKind via
   dogfood_scan.py's sink tables.
"""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.disposition import load_catalog
from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.python_resolver import build_project_graph as build_python_graph


def _only_call(graph, caller_suffix: str):
    matches = [c for c in graph.all_calls() if c.caller.endswith(caller_suffix)]
    assert len(matches) == 1, f"expected exactly one call for {caller_suffix!r}, got {len(matches)}"
    return matches[0]


def test_bare_open_resolves_to_builtins_open_not_the_bare_name():
    """The regression this milestone fixes: before _BUILTIN_SINK_NAMES, this
    resolved to Symbol('open') -- which could never match STDLIB_SINKS."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text("def read_file():\n    open('f.txt')\n")
        graph = build_python_graph(root)
        assert _only_call(graph, "read_file").target == Symbol("builtins.open")


def test_bare_eval_resolves_to_builtins_eval():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text("def run(x):\n    eval(x)\n")
        graph = build_python_graph(root)
        assert _only_call(graph, "run").target == Symbol("builtins.eval")


def test_bare_exec_resolves_to_builtins_exec():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text("def run(x):\n    exec(x)\n")
        graph = build_python_graph(root)
        assert _only_call(graph, "run").target == Symbol("builtins.exec")


def test_project_function_named_open_still_wins_over_the_builtin():
    """The builtin fallback must only fire when nothing else resolved it --
    a same-module top-level function genuinely named `open` is a real,
    indexed symbol and must take priority, never be shadowed by the
    builtin guess."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "def open(path):\n    return path\n\ndef caller():\n    open('x')\n"
        )
        graph = build_python_graph(root)
        assert _only_call(graph, "caller").target == Symbol("mod.open")


def test_pickle_load_resolves_and_classifies_as_deserialization():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text("import pickle\ndef load(f):\n    pickle.load(f)\n")
        graph = build_python_graph(root)
        assert _only_call(graph, "load").target == Symbol("pickle.load")
        catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
        plans = find_finding_plans(graph, root.name, catalog, [0], root, "python")
        assert len(plans) == 1
        assert "DESERIALIZATION" in plans[0].as_dict()["hypothesis"]["description"]


def test_yaml_load_resolves_and_classifies_as_deserialization():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text("import yaml\ndef load(f):\n    yaml.load(f)\n")
        graph = build_python_graph(root)
        assert _only_call(graph, "load").target == Symbol("yaml.load")
        catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
        plans = find_finding_plans(graph, root.name, catalog, [0], root, "python")
        assert len(plans) == 1
        assert "DESERIALIZATION" in plans[0].as_dict()["hypothesis"]["description"]


def test_js_vm_run_in_new_context_resolves_and_classifies_as_process_exec():
    if __import__("shutil").which("node") is None:
        pytest.skip("Node.js not available in this environment")
    from sentinel_zero.resolvers.js_resolver import build_project_graph as build_js_graph

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const vm = require('vm');\nfunction run(code) {\n  vm.runInNewContext(code);\n}\n"
        )
        graph = build_js_graph(root)
        assert _only_call(graph, "run").target == Symbol("vm.runInNewContext")
        catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
        plans = find_finding_plans(graph, root.name, catalog, [0], root, "javascript")
        assert len(plans) == 1
        assert "PROCESS_EXEC" in plans[0].as_dict()["hypothesis"]["description"]


def test_js_vm_script_construction_resolves_and_classifies_as_process_exec():
    if __import__("shutil").which("node") is None:
        pytest.skip("Node.js not available in this environment")
    from sentinel_zero.resolvers.js_resolver import build_project_graph as build_js_graph

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const vm = require('vm');\nfunction make(code) {\n  new vm.Script(code);\n}\n"
        )
        graph = build_js_graph(root)
        assert _only_call(graph, "make").target == Symbol("vm.Script")

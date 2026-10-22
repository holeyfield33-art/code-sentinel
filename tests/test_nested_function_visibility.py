"""VERIFICATION_LEDGER.md sz-2026-10-21-05, docs/REMEDIATION_PLAN.md item 5:
a nested Python function was completely invisible to the resolver --
neither indexed in project_functions nor walked for its own CallSites --
so a sink call inside one produced ZERO finding plans, not even
UNRESOLVED_INCONCLUSIVE. The fix makes a nested function a real, walked
scope of its own, qualnamed the way Python's own __qualname__ does
(`module.outer.<locals>.inner`), with parameter taint classification that
correctly accounts for a variable captured from an ENCLOSING function's
parameter, not just the nested function's own parameters.
"""
import tempfile
from pathlib import Path

from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.resolvers.python_resolver import build_project_graph

_CATALOG_PATH = str(bundled_snapshot_path())


def _run(root: Path) -> list[dict]:
    graph = build_project_graph(root)
    catalog = load_catalog(_CATALOG_PATH, is_bundled_snapshot=True)
    plans = find_finding_plans(graph, root.name, catalog, [0], root)
    return [p.as_dict() for p in plans]


def test_sink_call_inside_a_nested_function_is_no_longer_invisible():
    """The core regression: before the fix, this produced ZERO finding
    plans -- the sink call simply vanished, the worst possible outcome
    (worse than UNRESOLVED_INCONCLUSIVE, which at least surfaces as
    something to triage)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def outer():\n"
            "    def inner():\n"
            "        os.system('echo hi')\n"
            "    inner()\n"
        )
        plans = _run(root)
        assert len(plans) == 1, "a sink call inside a nested function must produce a finding plan"
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.outer.<locals>.inner"


def test_closure_over_an_enclosing_parameter_classifies_as_parameter_taint():
    """The real correctness boundary the plan called out explicitly: a
    nested function's sink argument that is actually the ENCLOSING
    function's own parameter, captured by closure, must classify as
    'parameter' taint -- not 'unknown' -- or a real attacker-controlled
    path would get UNDER-reported relative to its actual risk."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def outer(cmd):\n"
            "    def inner():\n"
            "        os.system(cmd)\n"
            "    inner()\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.outer.<locals>.inner"
        assert "parameter" in plans[0]["hypothesis"]["argument_taint"]


def test_three_levels_of_nesting_still_resolves_correctly():
    """Depth is not hand-waved -- a function nested three deep still gets
    its own correctly-qualnamed scope, confirming this isn't a
    one-level-only special case."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def level1():\n"
            "    def level2():\n"
            "        def level3():\n"
            "            os.system('echo hi')\n"
            "        level3()\n"
            "    level2()\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.level1.<locals>.level2.<locals>.level3"


def test_a_nested_function_inside_an_if_block_is_still_found():
    """A nested def doesn't have to sit directly in the function's own
    top-level body -- _direct_nested_function_defs must walk through
    control-flow constructs (if/try/for/while/with) to find one buried
    inside a conditional, the same way CallSite recording already does
    for calls."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def outer(flag):\n"
            "    if flag:\n"
            "        def inner():\n"
            "            os.system('echo hi')\n"
            "        inner()\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.outer.<locals>.inner"


def test_top_level_functions_are_not_duplicated_by_the_nested_function_fix():
    """Regression guard for the exact bug this fix's own development hit:
    recursing into nested defs from the wrong scope (the module-level
    walk itself) double-walked every top-level function. A plain
    zero-arg top-level function must still produce exactly ONE finding,
    with its ORIGINAL qualname -- no '.<locals>.' in sight."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef run_it():\n    subprocess.run(['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.run_it"
        assert "<locals>" not in plans[0]["hypothesis"]["symbol_binding"]


def test_class_methods_are_not_duplicated_by_the_nested_function_fix():
    """Same guard, for the class-method walk path: a plain method with no
    nested function of its own must still produce exactly one finding."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "class Runner:\n"
            "    def run_it(self):\n"
            "        subprocess.run(['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.Runner.run_it"

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

import pytest

from sentinel_zero.callgraph import build_direct_callee_index, transitively_guard_shaped
from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.python_resolver import build_project_graph

_CATALOG_PATH = str(bundled_snapshot_path())


@pytest.mark.parametrize("second_def", [
    "    def second():\n        pass\n",
    "    if enabled:\n        def second():\n            pass\n",
    "    async def second():\n        pass\n",
])
def test_forward_sibling_call_has_qualified_target_and_direct_edge(tmp_path, second_def):
    (tmp_path / "mod.py").write_text(
        "def outer(enabled=True):\n    def first():\n        second()\n" + second_def + "    first()\n"
    )
    graph = build_project_graph(tmp_path)
    caller = "mod.outer.<locals>.first"
    target = "mod.outer.<locals>.second"
    assert [c.target for c in graph.all_calls() if c.caller == caller] == [Symbol(target)]
    assert build_direct_callee_index(graph)[caller] == {target}


@pytest.mark.parametrize("shadow", [
    "    def first(second):\n        second()\n",
    "    def first():\n        second()\n        second = None\n",
    "    def first():\n        from external import second\n        second()\n",
    "    def first():\n        global second\n        second()\n",
    "    def first():\n        def second():\n            pass\n        second()\n",
])
def test_forward_sibling_prebinding_respects_child_shadowing(tmp_path, shadow):
    (tmp_path / "mod.py").write_text("def outer():\n" + shadow + "    def second():\n        pass\n")
    graph = build_project_graph(tmp_path)
    assert "mod.outer.<locals>.second" not in build_direct_callee_index(graph).get(
        "mod.outer.<locals>.first", set()
    )


def test_sibling_local_import_does_not_leak_into_another_scope(tmp_path):
    (tmp_path / "mod.py").write_text(
        "def outer():\n    def first():\n        second()\n"
        "    def unrelated():\n        from external import second\n"
        "    def second():\n        pass\n"
    )
    graph = build_project_graph(tmp_path)
    assert build_direct_callee_index(graph)["mod.outer.<locals>.first"] == {"mod.outer.<locals>.second"}


@pytest.mark.parametrize("rebind", ["second = None", "from external import second", "class second: pass"])
def test_later_rebinding_in_enclosing_scope_is_not_a_stale_sibling_edge(tmp_path, rebind):
    (tmp_path / "mod.py").write_text(
        "def outer():\n    def first():\n        second()\n"
        f"    def second():\n        pass\n    {rebind}\n    first()\n"
    )
    graph = build_project_graph(tmp_path)
    assert not build_direct_callee_index(graph).get("mod.outer.<locals>.first")


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


def test_a_call_to_a_nested_function_by_its_local_name_resolves_to_its_qualname():
    """Codex review, PR #7 (ledger sz-2026-10-21-21's own follow-up): a
    call to a nested function by its local name -- `inner()`, the normal
    way to call it, whether from a sibling statement in the enclosing
    scope or recursively from inside the nested function itself -- must
    resolve to its real qualname (`mod.outer.<locals>.inner`), not an
    unbound bare `Symbol("inner")`. Before this fix, build_direct_callee_
    index silently dropped the edge entirely (the bare symbol never
    matched any key in project_functions), so transitive guard and
    dependency propagation never saw a nested function's own callers at
    all."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def outer():\n"
            "    def inner():\n"
            "        os.system('echo hi')\n"
            "    inner()\n"
        )
        graph = build_project_graph(root)
        outer_calls = [c for c in graph.all_calls() if c.caller == "mod.outer"]
        assert len(outer_calls) == 1
        assert outer_calls[0].target == Symbol("mod.outer.<locals>.inner")
        callee_index = build_direct_callee_index(graph)
        assert callee_index.get("mod.outer") == {"mod.outer.<locals>.inner"}


def test_a_nested_function_calling_itself_recursively_also_resolves():
    """The self-recursion half of the same fix: a nested function calling
    itself by its own local name must also resolve to its own qualname,
    confirming the local-name binding is visible from inside the nested
    scope too, not just from sibling statements in the enclosing one."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def outer(n):\n"
            "    def countdown(k):\n"
            "        if k <= 0:\n"
            "            os.system('echo done')\n"
            "            return\n"
            "        countdown(k - 1)\n"
            "    countdown(n)\n"
        )
        graph = build_project_graph(root)
        inner_calls = [c for c in graph.all_calls() if c.caller == "mod.outer.<locals>.countdown"]
        self_calls = [c for c in inner_calls if c.target == Symbol("mod.outer.<locals>.countdown")]
        assert len(self_calls) == 1


def test_a_function_nested_inside_a_match_case_body_is_indexed_and_walked():
    """Codex review, PR #7: `match value: case ...: def inner(): ...` is
    real, supported Python 3.10+ syntax. Before this fix,
    _direct_nested_function_defs never descended into a case body (no
    Match branch at all), so `inner` was absent from project_functions
    entirely; separately, the statement walker's generic ast.walk
    fallback for Match attributed any call inside a case body to the
    OUTER function directly, bypassing the nested-scope recursion."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import os\n"
            "def dispatch(value):\n"
            "    match value:\n"
            "        case 'run':\n"
            "            def inner():\n"
            "                os.system('echo hi')\n"
            "            inner()\n"
            "        case _:\n"
            "            pass\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["hypothesis"]["symbol_binding"] == "mod.dispatch.<locals>.inner"
        graph = build_project_graph(root)
        dispatch_calls = [c for c in graph.all_calls() if c.caller == "mod.dispatch"]
        assert len(dispatch_calls) == 1
        assert dispatch_calls[0].target == Symbol("mod.dispatch.<locals>.inner")


def test_a_guard_shaped_function_nested_inside_a_match_case_is_still_guard_shaped():
    """Confirms the Match fix covers the actual motivating callgraph.py
    concern (transitively_guard_shaped), not just CallSite attribution:
    a guard-shaped function defined inside a case body must still be
    found by _direct_nested_function_defs and correctly classified."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "def dispatch(value, user):\n"
            "    match value:\n"
            "        case 'run':\n"
            "            def require_admin():\n"
            "                if not user.is_admin:\n"
            "                    raise PermissionError('forbidden')\n"
            "            require_admin()\n"
            "        case _:\n"
            "            pass\n"
        )
        graph = build_project_graph(root)
        assert graph.functions["mod.dispatch.<locals>.require_admin"].is_guard_shaped is True
        callee_index = build_direct_callee_index(graph)
        assert transitively_guard_shaped("mod.dispatch", graph, callee_index) is True

"""Proves cross-function/cross-file guard delegation actually works, with
a synthetic two-file fixture -- not just asserted in the module docstring."""
import tempfile
from pathlib import Path

from sentinel_zero.callgraph import build_direct_callee_index, transitively_guard_shaped
from sentinel_zero.resolvers.python_resolver import build_project_graph


def test_thin_wrapper_delegates_cross_file():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "auth").mkdir()
        (root / "auth" / "__init__.py").write_text("")
        # the real guard: has its own if/raise, lives in auth/checks.py
        (root / "auth" / "checks.py").write_text(
            "def require_role(user, allowed):\n"
            "    if user.get('role') not in allowed:\n"
            "        raise PermissionError('nope')\n"
        )
        # a THIN WRAPPER with no raise of its own, in a different file,
        # that just delegates to the real guard
        (root / "auth" / "wrappers.py").write_text(
            "from auth.checks import require_role\n"
            "def require_admin(user):\n"
            "    require_role(user, allowed=['admin'])\n"
        )
        # the handler: calls the WRAPPER (not the real guard directly),
        # then a sink -- this is the shape the delegation hop exists for
        (root / "handler.py").write_text(
            "from auth.wrappers import require_admin\n"
            "import json\n"
            "def handle(req, user):\n"
            "    require_admin(user)\n"
            "    return json.loads(req)\n"
        )

        graph = build_project_graph(root)
        callee_index = build_direct_callee_index(graph)

        # the wrapper itself has no raise -- same-function check alone
        # would call it not-a-guard. Prove the wrapper's OWN FunctionInfo
        # is not guard-shaped, to make sure the test is exercising
        # delegation and not accidentally passing some other way.
        wrapper_info = graph.functions["auth.wrappers.require_admin"]
        assert not wrapper_info.is_guard_shaped, "the wrapper has no raise of its own"

        # but delegation must still resolve it as a guard
        assert transitively_guard_shaped("auth.wrappers.require_admin", graph, callee_index), (
            "a thin wrapper delegating to a real guard must resolve as guard-shaped"
        )

        # and a function that calls neither must NOT resolve as a guard
        assert "handler.json" not in graph.functions  # sanity: json.loads isn't ours to index
        assert not transitively_guard_shaped("json.loads", graph, callee_index)


def test_cycle_safe_no_infinite_recursion():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "cyclic.py").write_text(
            "def a(x):\n    return b(x)\n\n"
            "def b(x):\n    return a(x)\n"
        )
        graph = build_project_graph(root)
        callee_index = build_direct_callee_index(graph)
        # must terminate and return False -- neither function ever raises
        assert transitively_guard_shaped("cyclic.a", graph, callee_index) is False

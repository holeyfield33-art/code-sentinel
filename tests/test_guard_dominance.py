"""Milestone 19: real CFG dominance for the guard-precedes-sink check,
replacing the old order+mutually_exclusive heuristic. The central case
below is a confirmed false positive the old heuristic had and this one
fixes -- see python_resolver.dominates's own docstring for the worked-out
reasoning.
"""
import tempfile
from pathlib import Path

from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.resolvers.python_resolver import build_project_graph, dominates

_CATALOG_PATH = str(bundled_snapshot_path())


def _run(root: Path) -> list[dict]:
    graph = build_project_graph(root)
    catalog = load_catalog(_CATALOG_PATH, is_bundled_snapshot=True)
    plans = find_finding_plans(graph, root.name, catalog, [0], root, "python")
    return [p.as_dict() for p in plans]


def test_dominates_unit_the_exact_old_false_positive():
    """A guard inside a bare `if`, no `else`, does NOT dominate a sink
    that sits at an outer, unconditional level -- the old
    order+mutually_exclusive check wrongly said it did."""
    assert dominates((), (("node1", "body"),)) is True  # top-level guard dominates anything nested after it
    assert dominates((("node1", "body"),), ()) is False  # conditional guard does NOT dominate an outer sink
    assert dominates((("node1", "if"),), (("node1", "else"),)) is False  # disjoint arms, same as the old check caught


def test_guard_inside_bare_if_does_not_protect_outer_unconditional_sink():
    """End-to-end regression test for the exact false positive fixed this
    milestone: require_admin() only runs when `x` is truthy, but sink()
    runs unconditionally -- it must NOT read as guarded."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "auth.py").write_text(
            "def require_admin(user):\n"
            "    if not user:\n"
            "        raise PermissionError('no user')\n"
        )
        (root / "handler.py").write_text(
            "from auth import require_admin\n"
            "import os\n"
            "def handle(x):\n"
            "    if x:\n"
            "        require_admin(x)\n"
            "    os.system('echo hi')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "dominates" not in plans[0]["disposition"]["reason"] or "genuinely dominates" not in plans[0]["disposition"]["reason"]
        assert "no resolved, guard-shaped call precedes" in plans[0]["disposition"]["reason"]


def test_unconditional_guard_before_conditional_sink_still_detected():
    """The symmetric, still-correct case: an unconditional guard call
    really does dominate a sink that only runs inside a later `if` --
    must keep working exactly as before this milestone."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "auth.py").write_text(
            "def require_admin(user):\n"
            "    if not user:\n"
            "        raise PermissionError('no user')\n"
        )
        (root / "handler.py").write_text(
            "from auth import require_admin\n"
            "import os\n"
            "def handle(x, y):\n"
            "    require_admin(x)\n"
            "    if y:\n"
            "        os.system('echo hi')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "dominates its modeled branch paths" in plans[0]["disposition"]["reason"]
        assert "auth.require_admin" in plans[0]["disposition"]["reason"]


def test_guard_and_sink_in_disjoint_elif_branches_still_not_credited():
    """Unchanged from before this milestone: an elif sibling cannot have
    actually run alongside the sink's branch."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "auth.py").write_text(
            "def require_admin(user):\n"
            "    if not user:\n"
            "        raise PermissionError('no user')\n"
        )
        (root / "handler.py").write_text(
            "from auth import require_admin\n"
            "import os\n"
            "def handle(mode, x):\n"
            "    if mode == 'check':\n"
            "        require_admin(x)\n"
            "    elif mode == 'run':\n"
            "        os.system('echo hi')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "no resolved, guard-shaped call precedes" in plans[0]["disposition"]["reason"]


def test_both_guard_and_sink_nested_in_same_if_branch_still_detected():
    """A guard and sink both inside the SAME if-branch, in order, is still
    a real dominance hit -- the guard's path is a (non-strict) prefix of
    the sink's path (they're equal), and order breaks the tie."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "auth.py").write_text(
            "def require_admin(user):\n"
            "    if not user:\n"
            "        raise PermissionError('no user')\n"
        )
        (root / "handler.py").write_text(
            "from auth import require_admin\n"
            "import os\n"
            "def handle(x):\n"
            "    if x:\n"
            "        require_admin(x)\n"
            "        os.system('echo hi')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "dominates its modeled branch paths" in plans[0]["disposition"]["reason"]

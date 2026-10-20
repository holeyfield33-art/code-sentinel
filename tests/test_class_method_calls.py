"""Milestone 11: class method bodies are walked for call-site recording.
Closes the gap Milestone 6 logged and test_sandbox_probe.py pinned -- a
call inside ANY method used to be entirely invisible, not even
UNRESOLVED_INCONCLUSIVE. `self` is now bound to the owning class's
qualname for the duration of each method's walk, so `self.foo()` resolves
to the exact qualname _index_module_functions already indexes it under."""
import tempfile
from pathlib import Path

from sentinel_zero.callgraph import build_direct_callee_index, transitively_guard_shaped
from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.python_resolver import build_project_graph


def test_self_dispatch_resolves_to_the_real_method_qualname():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.py").write_text(
            "class Service:\n"
            "    def dispatch(self):\n"
            "        return self.helper()\n"
            "    def helper(self):\n"
            "        return 1\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].caller == "svc.Service.dispatch"
        assert calls[0].target == Symbol("svc.Service.helper")


def test_sink_inside_method_is_no_longer_invisible():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "class Runner:\n"
            "    def run_it(self):\n"
            "        subprocess.run(['echo', 'hi'])\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        assert calls[0].caller == "runner.Runner.run_it"
        assert calls[0].target == Symbol("subprocess.run")


def test_guard_delegation_across_self_dispatch_works_unmodified():
    """callgraph.py's existing delegation walk was written before this
    milestone and never touched for it -- this proves a method with no
    raise/return of its own still resolves as guard-shaped purely because
    it delegates to self.<guard>(), the same proof pattern
    test_callgraph.py uses for cross-file wrapper delegation."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.py").write_text(
            "class Service:\n"
            "    def guarded(self):\n"
            "        self.require_admin()\n"
            "        return self.do_thing()\n"
            "    def require_admin(self):\n"
            "        if not self.is_admin:\n"
            "            raise PermissionError('nope')\n"
            "    def do_thing(self):\n"
            "        return 1\n"
        )
        graph = build_project_graph(root)
        callee_index = build_direct_callee_index(graph)

        guarded_info = graph.functions["svc.Service.guarded"]
        assert not guarded_info.is_guard_shaped, "guarded() has no raise/return of its own"
        assert transitively_guard_shaped("svc.Service.guarded", graph, callee_index), (
            "guarded() delegates to self.require_admin(), which does raise"
        )


def test_classmethod_cls_dispatch_not_handled_known_gap():
    """Explicitly out of scope for this milestone: only `self` is bound,
    not `cls`. A classmethod calling another via cls.foo() must NOT
    silently resolve -- confirmed by checking it lands as a plain,
    unresolved Symbol rather than the real qualname, not assumed."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "svc.py").write_text(
            "class Service:\n"
            "    @classmethod\n"
            "    def dispatch(cls):\n"
            "        return cls.helper()\n"
            "    @classmethod\n"
            "    def helper(cls):\n"
            "        return 1\n"
        )
        graph = build_project_graph(root)
        calls = graph.all_calls()
        assert len(calls) == 1
        # "cls" is never bound, so this falls to the bare dotted fallback --
        # a Symbol, but NOT the real "svc.Service.helper" qualname.
        assert calls[0].target == Symbol("cls.helper")
        assert calls[0].target != Symbol("svc.Service.helper")

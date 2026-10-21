"""Proves Milestone 6's bounded dynamic-reachability probe: a zero-argument
top-level function that actually reaches a PROCESS_EXEC sink gets promoted
to VERIFIED_TRUE; one that doesn't, or that the probe can't safely call at
all, is left exactly where static analysis put it. This is the only
disposition this probe is allowed to produce -- it must never demote
anything to VERIFIED_FALSE, since it never attempts adversarial inputs."""
import json
import tempfile
from pathlib import Path

from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.resolvers.python_resolver import build_project_graph

_CATALOG_PATH = "/home/claude/agent-security-index/public/export/asi-catalog.json"


def _run(root: Path) -> list[dict]:
    graph = build_project_graph(root)
    catalog = load_catalog(_CATALOG_PATH)
    plans = find_finding_plans(graph, root.name, catalog, [0], root)
    return [p.as_dict() for p in plans]


def test_zero_arg_function_reaching_sink_is_verified_true():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "def run_it():\n"
            "    subprocess.run(['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "VERIFIED_TRUE"
        assert "subprocess.run" in plans[0]["disposition"]["reason"]


def test_function_requiring_args_is_not_probed_stays_unresolved():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "def run_it(cmd):\n"  # requires an argument -- out of probe scope
            "    subprocess.run(cmd)\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_guarded_path_not_taken_on_zero_arg_call_stays_unresolved_not_demoted():
    """The sink sits behind a condition that's false by default, so a
    zero-argument call never reaches it. The probe must NOT read this as
    "safe" / VERIFIED_FALSE -- it has no evidence about any other input."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "DANGEROUS = False\n"
            "def run_it():\n"
            "    if DANGEROUS:\n"
            "        subprocess.run(['rm', '-rf', '/'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_class_method_sink_is_not_probed_but_is_now_a_finding():
    """Milestone 11 closed the gap this test originally pinned:
    _resolve_module now walks class method bodies for call-site recording
    (see python_resolver.py's module docstring), so a sink call inside a
    method is no longer invisible -- it produces a real finding plan.

    The sandbox probe itself is unchanged and still correctly refuses this
    case: _top_level_function_node (and therefore _probe_invocation_for)
    returns None for any caller_qualname containing a dot beyond the module
    ("module.Runner.run_it"), so a class method is never probed regardless
    of its arity -- confirmed by the
    disposition below being UNRESOLVED_INCONCLUSIVE, not VERIFIED_TRUE."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "class Runner:\n"
            "    def run_it(self):\n"
            "        subprocess.run(['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"

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


def test_class_method_sink_is_not_probed_and_is_not_even_a_finding_yet():
    """Class methods are explicitly out of scope for this probe (no safe,
    generic way to construct an instance) -- must not be attempted.

    Found via this test, NOT a Milestone 6 bug, deliberately not fixed
    here: _resolve_module's call-walking skips ast.ClassDef entirely, so a
    sink call inside ANY method -- probed or not -- currently produces zero
    finding plans, not even UNRESOLVED_INCONCLUSIVE. That is a pre-existing
    gap in the core resolver affecting sink/guard/dependency detection in
    general, not something specific to this probe. Logged as a known gap
    for a future milestone; asserting the real current behavior (0 plans)
    here rather than papering over it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "class Runner:\n"
            "    def run_it(self):\n"
            "        subprocess.run(['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert len(plans) == 0, (
            "if this starts producing a plan, the ClassDef call-walking gap above "
            "has been closed elsewhere -- update this test to assert UNRESOLVED_INCONCLUSIVE "
            "(never probed) instead of 0 plans"
        )

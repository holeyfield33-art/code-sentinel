"""VERIFICATION_LEDGER.md sz-2026-10-21-04, docs/REMEDIATION_PLAN.md item 3:
_promote_if_sink_reached can only compare the probe's reported symbol
against a finding's own call.target.qualified_name -- a match by resolved
NAME, not by which specific call site actually fired. When a caller has
two call sites resolving to the same sink symbol and only one is actually
reachable, a single probe run cannot tell the caller which one it was, so
promoting either one off that single result is an overclaim. The fix:
find_finding_plans now refuses to even attempt the probe when a caller has
more than one call site resolving to the same sink symbol, rather than
promote either of them on an unverifiable guess.
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


def test_unreachable_duplicate_sink_call_is_not_promoted_off_the_reachable_ones_evidence():
    """The exact ledger fixture: two os.system(...) call sites in one
    zero-arg function, the second one dead code after an unconditional
    return. Before this fix, the probe's one real reachability result (for
    the first, live call) got reused to promote BOTH findings to
    VERIFIED_TRUE, including the dead one. Now neither is probed/promoted
    at all -- both must stay exactly where static analysis left them,
    which is the honest outcome when the probe genuinely cannot
    disambiguate which call site it reached."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import os\n"
            "def run_it():\n"
            "    os.system('echo first')\n"
            "    return\n"
            "    os.system('echo second')\n"  # unreachable -- dead code
        )
        plans = _run(root)
        assert len(plans) == 2
        statuses = {p["disposition"]["status"] for p in plans}
        assert statuses == {"UNRESOLVED_INCONCLUSIVE"}, (
            f"expected both to stay UNRESOLVED_INCONCLUSIVE (ambiguous, unprobed), got {statuses}"
        )
        # Every plan's reason text should explain the ambiguity, not just
        # say "no sandbox probe has run yet" with no reason given.
        for plan in plans:
            assert "2 separate call sites" in plan["disposition"]["reason"]


def test_single_call_site_to_a_sink_is_still_probed_and_promoted_normally():
    """Sanity check: the fix must not accidentally disable promotion for
    the ordinary, unambiguous case -- a zero-arg function with exactly one
    call site to a given sink symbol must still reach VERIFIED_TRUE, same
    as before this change."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import os\ndef run_it():\n    os.system('echo hi')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "VERIFIED_TRUE"


def test_two_different_sinks_in_one_caller_are_still_probed_independently():
    """A different-symbol pair (not the same sink twice) is not ambiguous
    at all and must be unaffected -- this is the ORIGINAL Milestone 16
    regression test's own scenario, still exercised here to confirm the
    new per-symbol counting doesn't over-trigger across different sinks."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import subprocess\n"
            "def run_it():\n"
            "    subprocess.run(['echo', 'first'])\n"
            "    subprocess.call(['echo', 'second'])\n"
        )
        plans = _run(root)
        by_sink = {p["hypothesis"]["sink_node"]: p["disposition"]["status"] for p in plans}
        assert by_sink["subprocess.run"] == "VERIFIED_TRUE"
        assert by_sink["subprocess.call"] == "UNRESOLVED_INCONCLUSIVE"

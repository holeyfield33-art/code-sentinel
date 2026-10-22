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
    plans = find_finding_plans(graph, root.name, catalog, [0], root, probe_mode="diagnostic")
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


def test_single_call_site_receives_only_an_untrusted_diagnostic():
    """A benign single site can report a sink without becoming verified."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "runner.py").write_text(
            "import os\ndef run_it():\n    os.system('echo hi')\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"


def test_unreachable_direct_call_is_not_promoted_off_a_helpers_delegated_reach():
    """VERIFICATION_LEDGER.md sz-2026-10-21-18 (Codex review on PR #3,
    comment_id 4340617860, P1): the original fix above only counted call
    sites WITHIN the same function. It missed that probing run_it() lets
    it run completely normally, including its call to helper() -- so
    helper's own, genuinely-reachable os.system call is just as real a
    source of the probe's "sink_reached: os.system" report as a second
    direct call site in run_it itself. Before this fix, run_it's own dead
    os.system call (after an unconditional return) was wrongly promoted
    to VERIFIED_TRUE off helper's reachable call -- the exact same
    disambiguation failure item 3 already named, just one hop further
    out through delegation. The helper may receive an untrusted diagnostic;
    run_it's competing site must not even be probed."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "delegated.py").write_text(
            "import os\n"
            "def helper():\n"
            "    os.system('echo reached-via-helper')\n"
            "def run_it():\n"
            "    helper()\n"
            "    return\n"
            "    os.system('echo this-direct-call-site-is-dead')\n"
        )
        plans = _run(root)
        by_line = {p["hypothesis"]["source_node"].split(":")[-1]: p["disposition"]["status"] for p in plans}
        assert by_line["3"] == "UNRESOLVED_INCONCLUSIVE"
        helper_plan = next(p for p in plans if p["hypothesis"]["source_node"].endswith(":3"))
        assert helper_plan["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        assert by_line["7"] == "UNRESOLVED_INCONCLUSIVE", (
            "run_it's dead direct call site must NOT be promoted off helper's delegated evidence"
        )
        dead_call_plan = next(p for p in plans if p["hypothesis"]["source_node"].endswith(":7"))
        assert "separate call sites" in dead_call_plan["disposition"]["reason"]


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
        assert by_sink["subprocess.run"] == "UNRESOLVED_INCONCLUSIVE"
        assert any(p["verification_method"].get("probe_observation", {}).get("report", {}).get("symbol") == "subprocess.run" for p in plans)
        assert by_sink["subprocess.call"] == "UNRESOLVED_INCONCLUSIVE"

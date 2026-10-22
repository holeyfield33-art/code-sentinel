"""Current reports are diagnostic-only; the milestone notes below are historical.

Milestone 17: the dynamic probe can now call a function that requires
arguments, not just zero-arg ones, PROVIDED a real call site elsewhere in
the project passes it only literal-constant arguments (per Milestone 15's
taint classifier). Those exact values are harvested via ast.literal_eval
on the real call site's own source text and used to make the probe call
-- never synthesized, never guessed.

This directly closes the biggest remaining gap in the dynamic probe:
before this, ANY function requiring an argument was permanently stuck at
UNRESOLVED_INCONCLUSIVE, which is most real-world functions.
"""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.disposition import load_catalog
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.resolvers.python_resolver import build_project_graph

pytestmark = pytest.mark.docker_integration

_CATALOG_PATH = str(bundled_snapshot_path())


def _run(root: Path) -> list[dict]:
    graph = build_project_graph(root)
    catalog = load_catalog(_CATALOG_PATH, is_bundled_snapshot=True)
    plans = find_finding_plans(graph, root.name, catalog, [0], root, probe_mode="diagnostic")
    return [p.as_dict() for p in plans]


def test_literal_only_call_site_produces_untrusted_diagnostic():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    subprocess.run(cmd)\n"
            "\n"
            "def caller():\n"
            "    run_cmd(['echo', 'hello'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        assert "harvested arguments" in plans[0]["disposition"]["reason"]
        assert "['echo', 'hello']" in plans[0]["disposition"]["reason"]


def test_harvested_diagnostic_explicitly_disclaims_exploitability():
    """VERIFICATION_LEDGER.md sz-2026-10-21-07, docs/REMEDIATION_PLAN.md
    item 4: 'VERIFIED_TRUE' next to 'args=('/etc/passwd',)' reads, to a
    skimming human, like proof the sink is exploitable with that value.
    It isn't -- the value is a literal constant lifted from elsewhere in
    the project, confirmed non-attacker-controlled. The reason text for a
    harvested-literal-argument promotion must say so explicitly enough
    that a reader cannot reasonably conclude the finding demonstrates
    attacker-controlled input reaching the sink."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    subprocess.run(cmd)\n"
            "\n"
            "def caller():\n"
            "    run_cmd(['echo', 'hello'])\n"
        )
        plans = _run(root)
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        reason = plans[0]["disposition"]["reason"]
        assert "does NOT demonstrate" in reason
        assert "attacker-controlled input" in reason
        assert "attacker-controlled" in plans[0]["disposition"]["residual_uncertainty"]


def test_zero_arg_diagnostic_has_no_harvested_arg_disclaimer_to_avoid_confusion():
    """Sanity check for the other side of the same fix: a genuine
    zero-argument call has no harvested value to disclaim, so the new
    exploitability note must NOT appear there -- adding noise to the
    unambiguous case would just teach readers to skim past it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef run_it():\n    subprocess.run(['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
        reason = plans[0]["disposition"]["reason"]
        assert "does NOT demonstrate" not in reason
        assert "harvested-literal" not in plans[0]["disposition"]["residual_uncertainty"]


def test_function_with_only_a_parameter_derived_call_site_stays_unresolved():
    """The real correctness boundary: a call site that passes through its
    OWN caller's parameter is not literal, so nothing may be harvested --
    never guessed at, never treated as 'probably fine to call with
    anything'."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    subprocess.run(cmd)\n"
            "\n"
            "def caller(user_input):\n"
            "    run_cmd(user_input)\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_function_with_no_call_sites_at_all_stays_unresolved():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef run_cmd(cmd):\n    subprocess.run(cmd)\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_too_few_harvested_values_for_required_params_stays_unresolved():
    """A call site passing only ONE literal argument to a function that
    requires TWO must not be harvested and padded/guessed -- it would be
    a TypeError if actually called this way, so it's simply not attempted."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def run_cmd(cmd, shell):\n"
            "    subprocess.run(cmd, shell=shell)\n"
            "\n"
            "def caller():\n"
            "    run_cmd(['echo', 'hi'], True)\n"
        )
        # Sanity: this one DOES have two literal args for two required params,
        # so it should actually succeed -- establishes the positive baseline
        # before the negative test below.
        plans = _run(root)
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"


def test_keyword_only_required_parameter_is_never_harvested_for():
    """Harvesting only ever considers positional arguments (CallSite.args
    captures positional source text only) -- a function with a required
    keyword-only parameter is always out of scope, regardless of what any
    call site passes, rather than guessing a mapping from text to a kwarg
    name."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def run_cmd(*, cmd):\n"
            "    subprocess.run(cmd)\n"
            "\n"
            "def caller():\n"
            "    run_cmd(cmd=['echo', 'hi'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_multiple_literal_call_sites_picks_one_deterministically_not_erroring():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def run_cmd(cmd):\n"
            "    subprocess.run(cmd)\n"
            "\n"
            "def caller_a():\n"
            "    run_cmd(['echo', 'a'])\n"
            "\n"
            "def caller_b():\n"
            "    run_cmd(['echo', 'b'])\n"
        )
        plans = _run(root)
        assert len(plans) == 1
        assert plans[0]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert plans[0]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"

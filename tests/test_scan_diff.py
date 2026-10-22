"""Milestone 21: stable finding_uid (disposition.py) and the scan-to-scan
diff it enables (scan_diff.py) -- see docs/SECURITY_MONITORING.md S2-3.
"""
import pytest

from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.disposition import build_finding_plan, load_catalog, set_disposition
from sentinel_zero.scan_diff import diff_ledgers

_CATALOG = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
_ATTACK_ID = next(iter(_CATALOG.classes_by_id))


def _make_plan(plan_id, source_node, sink_node, status, target_repository="repo"):
    plan = build_finding_plan(
        plan_id=plan_id,
        target_repository=target_repository,
        attack_id=_ATTACK_ID,
        catalog=_CATALOG,
        hypothesis={"source_node": source_node, "sink_node": sink_node},
        verification_method={"checker_type": "test", "required_evidence_tier": "x", "sandbox_validation_required": False},
        execution_gate={"tool_identifier": "test", "expected_exit_code": 0, "timeout_seconds": 1},
    )
    set_disposition(plan, "UNRESOLVED_INCONCLUSIVE", reason="r", residual_uncertainty="u")
    payload = plan.as_dict()
    # These are historical ledger inputs to the diff reader, not newly
    # authorized runtime findings. Current plans cannot grant verified states.
    payload["disposition"] = {**payload["disposition"], "status": status}
    return payload


def test_finding_uid_is_stable_across_different_plan_id_and_run_metadata():
    """Two plans describing the SAME call site (same source_node/sink_node)
    but with different plan_id, target_repository, and disposition must
    produce the SAME finding_uid -- that's the entire point of this field."""
    a = _make_plan("fp_0001", "mod.py:10", "os.system", "VERIFIED_TRUE", target_repository="repo-v1")
    b = _make_plan("fp_9999", "mod.py:10", "os.system", "UNRESOLVED_INCONCLUSIVE", target_repository="repo-v2")
    assert a["finding_uid"] == b["finding_uid"]


def test_finding_uid_differs_for_a_different_call_site():
    a = _make_plan("fp_0001", "mod.py:10", "os.system", "VERIFIED_TRUE")
    b = _make_plan("fp_0002", "mod.py:11", "os.system", "VERIFIED_TRUE")  # different line
    c = _make_plan("fp_0003", "mod.py:10", "subprocess.run", "VERIFIED_TRUE")  # different sink
    assert a["finding_uid"] != b["finding_uid"]
    assert a["finding_uid"] != c["finding_uid"]


def test_diff_ledgers_classifies_new_removed_changed_unchanged():
    old = [
        _make_plan("fp_0001", "mod.py:10", "os.system", "UNRESOLVED_INCONCLUSIVE"),  # will change -> VERIFIED_TRUE
        _make_plan("fp_0002", "mod.py:20", "subprocess.run", "VERIFIED_TRUE"),       # unchanged
        _make_plan("fp_0003", "mod.py:30", "builtins.open", "UNRESOLVED_INCONCLUSIVE"),  # will be removed
    ]
    new = [
        _make_plan("fp_0101", "mod.py:10", "os.system", "VERIFIED_TRUE"),            # same finding, new plan_id, changed status
        _make_plan("fp_0102", "mod.py:20", "subprocess.run", "VERIFIED_TRUE"),       # same finding, unchanged
        _make_plan("fp_0103", "mod.py:40", "json.loads", "UNRESOLVED_INCONCLUSIVE"),  # brand new
    ]
    result = diff_ledgers(old, new)

    assert len(result["new_findings"]) == 1
    assert result["new_findings"][0]["hypothesis"]["source_node"] == "mod.py:40"

    assert len(result["removed_findings"]) == 1
    assert result["removed_findings"][0]["hypothesis"]["source_node"] == "mod.py:30"

    assert len(result["changed_disposition"]) == 1
    changed = result["changed_disposition"][0]
    assert changed["old_status"] == "UNRESOLVED_INCONCLUSIVE"
    assert changed["new_status"] == "VERIFIED_TRUE"

    assert result["unchanged_count"] == 1
    assert result["old_total"] == 3
    assert result["new_total"] == 3


def test_diff_ledgers_identical_input_is_all_unchanged():
    plans = [_make_plan("fp_0001", "mod.py:10", "os.system", "VERIFIED_TRUE")]
    result = diff_ledgers(plans, plans)
    assert result["new_findings"] == []
    assert result["removed_findings"] == []
    assert result["changed_disposition"] == []
    assert result["unchanged_count"] == 1


def test_diff_ledgers_rejects_a_plan_missing_finding_uid():
    """A ledger built before Milestone 21 cannot be silently diffed as if
    nothing were missing -- this engine's own "no silent tool failure"
    posture, applied here too."""
    legacy_plan = _make_plan("fp_0001", "mod.py:10", "os.system", "VERIFIED_TRUE")
    del legacy_plan["finding_uid"]
    with pytest.raises(ValueError, match="finding_uid"):
        diff_ledgers([legacy_plan], [])

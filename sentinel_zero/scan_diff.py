"""Milestone 21: scan-to-scan diff, per docs/SECURITY_MONITORING.md S2-3.

Compares two verification_ledger.json "plans" lists (each a list of
FindingPlan.as_dict() output) and classifies every finding in either
scan as new, removed, changed-disposition, or unchanged -- keyed by
finding_uid (disposition.py's _compute_finding_uid), not plan_id, because
plan_id is only sequentially unique WITHIN one run and is never
comparable across two separate scans of the same repo (see that
function's own docstring).

This module does no analysis of its own -- it is a pure comparison over
two already-produced ledgers, exactly like graph_export.py is a pure
re-serialization of data the resolvers already computed. It never
re-derives a disposition and never second-guesses one; "changed" means
only "the same finding_uid has a different disposition.status string in
the two inputs," nothing more.
"""
from __future__ import annotations

from typing import Any


def _index_by_uid(plans: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for plan in plans:
        uid = plan.get("finding_uid")
        if not uid:
            # A plan produced before Milestone 21 (no finding_uid field)
            # cannot participate in a diff -- it is neither silently
            # skipped nor silently matched by guesswork. Surfacing this
            # as a hard error keeps the same "no silent tool failure"
            # posture the rest of this engine holds to, rather than a
            # diff that quietly under-counts.
            raise ValueError(
                f"plan {plan.get('plan_id', '<unknown>')!r} has no finding_uid -- "
                "this ledger predates Milestone 21 and cannot be diffed. Re-run the scan."
            )
        indexed[uid] = plan
    return indexed


def diff_ledgers(old_plans: list[dict[str, Any]], new_plans: list[dict[str, Any]]) -> dict[str, Any]:
    """Returns:
      {
        "new_findings": [plan, ...],       # finding_uid present only in new_plans
        "removed_findings": [plan, ...],   # finding_uid present only in old_plans
        "changed_disposition": [
            {"finding_uid": ..., "old_status": ..., "new_status": ..., "plan": new_plan}, ...
        ],
        "unchanged_count": int,
        "old_total": int,
        "new_total": int,
      }
    All three finding lists are sorted by finding_uid for deterministic
    output -- a diff report that reorders itself between two identical
    runs would be its own small, needless source of noise.
    """
    old_by_uid = _index_by_uid(old_plans)
    new_by_uid = _index_by_uid(new_plans)

    new_uids = sorted(set(new_by_uid) - set(old_by_uid))
    removed_uids = sorted(set(old_by_uid) - set(new_by_uid))
    shared_uids = sorted(set(old_by_uid) & set(new_by_uid))

    changed = []
    unchanged_count = 0
    for uid in shared_uids:
        old_status = old_by_uid[uid]["disposition"]["status"]
        new_status = new_by_uid[uid]["disposition"]["status"]
        if old_status != new_status:
            changed.append(
                {
                    "finding_uid": uid,
                    "old_status": old_status,
                    "new_status": new_status,
                    "plan": new_by_uid[uid],
                }
            )
        else:
            unchanged_count += 1

    return {
        "new_findings": [new_by_uid[u] for u in new_uids],
        "removed_findings": [old_by_uid[u] for u in removed_uids],
        "changed_disposition": changed,
        "unchanged_count": unchanged_count,
        "old_total": len(old_plans),
        "new_total": len(new_plans),
    }

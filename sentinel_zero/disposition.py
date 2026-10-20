"""Sentinel-Zero disposition authority.

The one place a raw observation is allowed to become a reviewed Finding Plan.
No scanner output is a "finding" until it passes through here. This module is
the structural fix for the two confirmed failure modes from the prior
multi-repo pipeline:

  - silent tool failure reported as a clean pass (aletheia-redteam-kit's
    _run_tool_json never checked subprocess exit status)
  - hardcoded, drifting attack-taxonomy labels (Code Atlas's asi.ts had
    AAC-02/AAC-11/AAC-16 mapped to the wrong class names)

Both are closed here mechanically, not by convention: catalog IDs are
resolved against a live export and an unknown ID is a hard error, not a
silent pass-through.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

from sentinel_zero.catalog_loader import load_asi_catalog
from sentinel_zero.schema_check import require_finding_plan_fields


class UnknownAttackClass(Exception):
    """Raised when a Finding Plan cites an attack-class ID absent from the
    live agent-security-index catalog. This must never be caught and
    downgraded to a warning -- that is exactly the taxonomy-drift bug this
    engine exists to prevent."""


class ToolFailure(Exception):
    """Raised when a required analysis step did not complete successfully.
    A TOOL_FAILURE must halt the run, never be absorbed into a quiet pass."""


@dataclass
class Catalog:
    """A loaded, indexed view of the live ASI catalog. Build once per run
    with load_catalog() -- never hardcode a class name/label pair."""

    classes_by_id: dict[str, dict]

    def resolve(self, attack_id: str) -> dict:
        cls = self.classes_by_id.get(attack_id)
        if cls is None:
            raise UnknownAttackClass(
                f"'{attack_id}' is not present in the active ASI catalog export. "
                "A Finding Plan may not cite an attack class the live catalog "
                "does not recognize."
            )
        return cls


def load_catalog(catalog_path: str) -> Catalog:
    """Load the assembled ASI export and index every class by its id and by
    any declared aliases/legacyId, so a plan can cite either form and still
    resolve against the one live source of truth."""
    data = load_asi_catalog(catalog_path, fallback=None)
    if data is None or "attackClasses" not in data:
        raise ToolFailure(
            f"could not load a usable ASI catalog from {catalog_path!r} -- "
            "refusing to run without a taxonomy to check findings against."
        )
    by_id: dict[str, dict] = {}
    for cls in data["attackClasses"]:
        by_id[cls["id"]] = cls
        for alias in cls.get("aliases", []):
            by_id.setdefault(alias, cls)
        legacy = cls.get("legacyId")
        if legacy:
            by_id.setdefault(legacy, cls)
    return Catalog(classes_by_id=by_id)


@dataclass
class FindingPlan:
    """The bounded, re-checkable unit this engine produces. Mirrors
    Block-Wise's plan -> generate -> check pattern: a hypothesis is not a
    finding until this object exists, its attack_id has been resolved
    against the live catalog, and its disposition has been set by code in
    this module -- never defaulted to a pass."""

    plan_id: str
    target_repository: str
    attack_id: str
    attack_name: str
    hypothesis: dict[str, Any]
    verification_method: dict[str, Any]
    execution_gate: dict[str, Any]
    disposition: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

    def as_dict(self) -> dict:
        payload = {
            "plan_id": self.plan_id,
            "target_repository": self.target_repository,
            "asi_classification": {"attack_id": self.attack_id, "category": self.attack_name},
            "hypothesis": self.hypothesis,
            "verification_method": self.verification_method,
            "execution_gate": self.execution_gate,
            "disposition": self.disposition,
            "generated_at": self.generated_at,
        }
        # Re-run the same structural gate the schema was built against --
        # a plan that can't pass its own field check never leaves this module.
        require_finding_plan_fields(payload)
        return payload


def build_finding_plan(
    *,
    plan_id: str,
    target_repository: str,
    attack_id: str,
    catalog: Catalog,
    hypothesis: dict[str, Any],
    verification_method: dict[str, Any],
    execution_gate: dict[str, Any],
) -> FindingPlan:
    """The only constructor for a FindingPlan. Resolves attack_id against the
    live catalog (raises UnknownAttackClass on drift) before anything else
    happens, and starts every plan PENDING -- disposition is earned by a
    verification step, never assumed."""
    resolved = catalog.resolve(attack_id)
    plan = FindingPlan(
        plan_id=plan_id,
        target_repository=target_repository,
        attack_id=resolved["id"],
        attack_name=resolved["name"],
        hypothesis=hypothesis,
        verification_method=verification_method,
        execution_gate=execution_gate,
        disposition={
            "status": "PENDING",
            "reason": "awaiting verification",
            "residual_uncertainty": "not yet assessed",
        },
    )
    return plan


def set_disposition(plan: FindingPlan, status: str, reason: str, residual_uncertainty: str) -> None:
    """The only way a plan's disposition changes. status must be one of the
    engine's explicit states -- there is no implicit "clean" default."""
    allowed = {"VERIFIED_TRUE", "VERIFIED_FALSE", "UNRESOLVED_INCONCLUSIVE", "TOOL_FAILURE", "PENDING"}
    if status not in allowed:
        raise ValueError(f"disposition status {status!r} is not one of {sorted(allowed)}")
    plan.disposition = {
        "status": status,
        "reason": reason,
        "residual_uncertainty": residual_uncertainty,
    }

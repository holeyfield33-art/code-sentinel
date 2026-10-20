def require_finding_plan_fields(plan: dict) -> None:
    for key in ('plan_id', 'target_repository', 'asi_classification', 'hypothesis', 'verification_method', 'execution_gate', 'disposition'):
        if key not in plan:
            raise KeyError(key)
    return None

"""Shape validation for target-controlled reports, not proof authentication."""
from __future__ import annotations


def validate_probe_result(raw: object) -> dict:
    """Allowlist bounded diagnostic fields; target claims never confer trust."""
    if not isinstance(raw, dict):
        return {"status": "call_failed", "detail": "invalid probe result: expected an object"}
    status = raw.get("status")
    if status == "sink_reached":
        symbol, args = raw.get("symbol"), raw.get("args")
        if not isinstance(symbol, str) or not symbol or not isinstance(args, str):
            return {"status": "call_failed", "detail": "invalid sink report: symbol and args must be strings"}
        if len(symbol) > 2000 or len(args) > 2000:
            return {"status": "call_failed", "detail": "invalid sink report: fields exceed the diagnostic limit"}
        return {"status": status, "symbol": symbol, "args": args}
    if status in ("not_reached", "call_failed") and isinstance(raw.get("detail"), str):
        return {"status": status, "detail": raw["detail"][:2000]}
    return {"status": "call_failed", "detail": "invalid probe result: unknown status or missing detail"}

import json
from pathlib import Path
from typing import Any, TypeGuard, TypedDict


class _CatalogClasses(TypedDict):
    attackClasses: list[dict[str, Any]]


class CatalogDocument(_CatalogClasses, total=False):
    catalog: dict[str, Any]


def load_asi_catalog(path: str, fallback: CatalogDocument | None = None) -> CatalogDocument | None:
    try:
        with open(path, encoding='utf-8') as handle:
            raw = json.load(handle)
    except (OSError, ValueError):
        return fallback
    return raw if _is_catalog_document(raw) else fallback


def _is_catalog_document(raw: object) -> TypeGuard[CatalogDocument]:
    """Validate fields used by the index without dropping catalog extensions."""
    if not isinstance(raw, dict) or not isinstance(raw.get("attackClasses"), list):
        return False
    for entry in raw["attackClasses"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
            return False
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list) or not all(isinstance(alias, str) for alias in aliases):
            return False
        if entry.get("legacyId") is not None and not isinstance(entry["legacyId"], str):
            return False
    meta = raw.get("catalog", {})
    if not isinstance(meta, dict):
        return False
    return True


def bundled_snapshot_path() -> Path:
    """Path to the ASI catalog snapshot shipped inside this package
    (sentinel_zero/data/asi-catalog-snapshot.json). Exists so a fresh
    install has a taxonomy to check findings against with zero setup --
    disposition.load_catalog still resolves through the exact same
    live-catalog mechanism, this just supplies a default *path*, and the
    caller is responsible for marking the result as a bundled snapshot
    (never silently treated as equivalent to a freshly-fetched export)."""
    return Path(__file__).parent / "data" / "asi-catalog-snapshot.json"

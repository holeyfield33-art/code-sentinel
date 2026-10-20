import json
from pathlib import Path


def load_asi_catalog(path: str, fallback: object=None) -> object:
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return fallback


def bundled_snapshot_path() -> Path:
    """Path to the ASI catalog snapshot shipped inside this package
    (sentinel_zero/data/asi-catalog-snapshot.json). Exists so a fresh
    install has a taxonomy to check findings against with zero setup --
    disposition.load_catalog still resolves through the exact same
    live-catalog mechanism, this just supplies a default *path*, and the
    caller is responsible for marking the result as a bundled snapshot
    (never silently treated as equivalent to a freshly-fetched export)."""
    return Path(__file__).parent / "data" / "asi-catalog-snapshot.json"

import json


def load_asi_catalog(path: str, fallback: object=None) -> object:
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return fallback

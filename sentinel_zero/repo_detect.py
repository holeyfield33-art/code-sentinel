"""Shared by cli.py and mcp_server.py -- the two transports into
dogfood_scan.run(). Lives here, not duplicated or reached into as a
"private" helper of one or the other, because both need the exact same
answer to "what language is this, and are the JS/TS resolver's own
subprocess dependencies installed."
"""
from __future__ import annotations

from pathlib import Path

from sentinel_zero.disposition import ToolFailure

LANGUAGE_EXTENSIONS = {
    "python": {".py"},
    "javascript": {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".mts", ".cts"},
}

_SKIP_DIR_NAMES = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".next", ".mypy_cache", ".pytest_cache",
}


def detect_language(repo_root: Path) -> str:
    """Counts source files by extension and picks whichever of the two
    supported resolvers has more to look at. Never guesses silently when
    there's nothing to count -- that is a ToolFailure, same as any other
    "can't proceed" condition, not a quiet default to "python"."""
    counts = {lang: 0 for lang in LANGUAGE_EXTENSIONS}
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIR_NAMES for part in path.relative_to(repo_root).parts):
            continue
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if path.suffix in exts:
                counts[lang] += 1
    best_lang = max(counts, key=lambda lang: counts[lang])
    if counts[best_lang] == 0:
        raise ToolFailure(
            f"could not auto-detect a supported language under {repo_root} -- "
            f"found no files matching {LANGUAGE_EXTENSIONS}. Pass --language explicitly "
            "if this is a supported project in an unusual layout."
        )
    return best_lang


def js_deps_installed() -> bool:
    return (Path(__file__).parent / "resolvers" / "js" / "node_modules").is_dir()

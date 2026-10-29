"""Bounded reads of regular source files from a stable repository checkout.

In-root file symlinks are supported; links outside the root and special files
are refused. This is input validation, not an immutable filesystem snapshot
or a CPU/memory sandbox for the parser.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

MAX_SOURCE_BYTES = 8_000_000


class SourceInputError(ValueError):
    """A collected source path cannot safely be read as repository source."""


def read_source_text(path: Path, repo_root: Path, *, max_bytes: int = MAX_SOURCE_BYTES) -> str:
    """Read at most max_bytes from a contained regular source file.

    Resolve before opening so a supported in-root symlink is opened by its
    real target. O_NONBLOCK and a second regular-file check prevent a special
    entry from blocking if it changes after the initial check. O_NOFOLLOW,
    where available, also rejects replacement of the final path by a link.
    Ancestor directories still require the documented stable-checkout rule.
    """
    root = repo_root.resolve(strict=True)
    try:
        target = path.resolve(strict=True)
        target.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SourceInputError(f"source path escapes the repository or is unreadable: {path}") from exc
    try:
        if not stat.S_ISREG(target.stat().st_mode):
            raise SourceInputError(f"source path is not a regular file: {path}")
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise SourceInputError(f"source path is not a regular file: {path}")
            if metadata.st_size > max_bytes:
                raise SourceInputError(f"source file exceeds the {max_bytes}-byte limit: {path}")
            data = source.read(max_bytes + 1)
            if len(data) > max_bytes:
                raise SourceInputError(f"source file exceeds the {max_bytes}-byte limit: {path}")
    except OSError as exc:
        raise SourceInputError(f"could not safely read source file {path}: {exc}") from exc
    return data.decode("utf-8")

"""Portable source permissions for synthetic live-Docker fixtures."""
import os
from pathlib import Path
import tempfile

import pytest


@pytest.fixture(autouse=True)
def docker_fixture_source_permissions(request, monkeypatch):
    if os.name == "nt" or request.node.get_closest_marker("docker_integration") is None:
        return
    # TemporaryDirectory defaults to 0700. Hosted Linux runners need not
    # have UID 1000 (the fixed worker UID), so explicitly make only these
    # newly created synthetic fixture directories readable/traversable.
    # Source mounts remain read-only; no real repository permissions change.
    original = tempfile.TemporaryDirectory

    class ReadableFixtureDirectory(original):
        def __enter__(self):
            directory = super().__enter__()
            Path(directory).chmod(0o755)
            return directory

    monkeypatch.setattr(tempfile, "TemporaryDirectory", ReadableFixtureDirectory)

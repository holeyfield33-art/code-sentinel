"""Static source files must stay inside the repository and never block reads."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from sentinel_zero.resolvers.python_resolver import build_project_graph as python_graph
from sentinel_zero.resolvers.js_resolver import build_project_graph as js_graph
from sentinel_zero.source_inputs import MAX_SOURCE_BYTES


@pytest.fixture(params=["python", "javascript"])
def language(request):
    if request.param == "javascript":
        dependencies = Path(__file__).parents[1] / "sentinel_zero/resolvers/js/node_modules"
        if not shutil.which("node") or not dependencies.is_dir():
            pytest.skip("Node and installed resolver dependencies required")
    return request.param


def _source(language):
    return ("import os\ndef PRIVATE_AUDIT_CANARY(command):\n    os.system(command)\n"
            if language == "python" else
            "const cp=require('child_process');function PRIVATE_AUDIT_CANARY(command){cp.exec(command);}\n")


def _filename(language):
    return "entry.py" if language == "python" else "entry.cjs"


def _scan(root, language):
    return (python_graph if language == "python" else js_graph)(root)


def _symlink(link, target):
    try:
        link.symlink_to(target)
    except OSError as error:
        pytest.skip(f"source symlink fixture unavailable: {error}")


def test_external_source_symlink_is_visible_and_never_indexed(tmp_path, language):
    root = tmp_path / "repo"
    root.mkdir()
    external = tmp_path / "private-source.txt"
    external.write_text(_source(language), encoding="utf-8")
    _symlink(root / _filename(language), external)
    graph = _scan(root, language)
    assert not graph.modules
    assert not graph.functions
    assert len(graph.parse_errors) == 1
    assert "escapes the repository" in graph.parse_errors[0]["error"]


def test_dangling_source_symlink_is_a_reported_input_error(tmp_path, language):
    _symlink(tmp_path / _filename(language), tmp_path / "absent-source")
    graph = _scan(tmp_path, language)
    assert not graph.modules
    assert len(graph.parse_errors) == 1


def test_in_root_regular_file_symlink_is_supported(tmp_path, language):
    target = tmp_path / "source.txt"
    target.write_text(_source(language), encoding="utf-8")
    _symlink(tmp_path / _filename(language), target)
    graph = _scan(tmp_path, language)
    assert not graph.parse_errors
    assert len(graph.modules) == 1
    assert any("PRIVATE_AUDIT_CANARY" in name for name in graph.functions)


def test_oversized_source_file_is_reported_without_parsing(tmp_path, language):
    path = tmp_path / _filename(language)
    with path.open("wb") as source:
        source.truncate(MAX_SOURCE_BYTES + 1)
    graph = _scan(tmp_path, language)
    assert not graph.modules
    assert len(graph.parse_errors) == 1
    assert "byte limit" in graph.parse_errors[0]["error"]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="named pipes unavailable on this platform")
def test_source_fifo_is_rejected_without_waiting_for_a_writer(tmp_path, language):
    os.mkfifo(tmp_path / _filename(language))
    # A regressed unbounded FIFO read must fail this test, not hang pytest.
    resolver = "python_resolver" if language == "python" else "js_resolver"
    program = (
        "import json,sys; from pathlib import Path; "
        f"from sentinel_zero.resolvers.{resolver} import build_project_graph; "
        "g=build_project_graph(Path(sys.argv[1])); "
        "print(json.dumps({'modules':len(g.modules),'errors':g.parse_errors}))"
    )
    result = subprocess.run([sys.executable, "-c", program, str(tmp_path)],
                            capture_output=True, text=True, timeout=10, check=True)
    data = json.loads(result.stdout)
    assert data["modules"] == 0
    assert len(data["errors"]) == 1
    assert "not a regular file" in data["errors"][0]["error"]


def test_source_contents_are_not_executed(tmp_path, language):
    marker = tmp_path / "must-not-exist"
    executable = (
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n"
        if language == "python" else
        f"require('fs').writeFileSync({json.dumps(str(marker))},'executed');\n"
    )
    (tmp_path / _filename(language)).write_text(executable + _source(language), encoding="utf-8")
    graph = _scan(tmp_path, language)
    assert len(graph.modules) == 1
    assert not marker.exists()

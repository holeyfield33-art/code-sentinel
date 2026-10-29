"""The CVE pair selector, end to end, against a local git repository.

Regression for the Codex review on #23: a removed call must be located by its
position in the parent file, not by searching for its text, because the same
call text can appear in several functions."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "calibration" / "cve_tools"

BEFORE = "def first(x):\n    return eval(x)\n\n\ndef second(x):\n    return eval(x)\n"
AFTER = "import ast\n\n\ndef first(x):\n    return eval(x)\n\n\ndef second(x):\n    return ast.literal_eval(x)\n"


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def remote(tmp_path: Path) -> tuple[Path, str]:
    work = tmp_path / "work"
    work.mkdir()
    git(work, "init", "-q")
    git(work, "config", "user.email", "t@example.com")
    git(work, "config", "user.name", "t")
    (work / "app.py").write_text(BEFORE)
    git(work, "add", ".")
    git(work, "commit", "-q", "-m", "vulnerable")
    (work / "app.py").write_text(AFTER)
    git(work, "commit", "-q", "-am", "fix eval in second")
    fix = git(work, "rev-parse", "HEAD")
    bare = tmp_path / "remote" / "owner" / "proj.git"
    bare.parent.mkdir(parents=True)
    subprocess.run(["git", "clone", "-q", "--bare", str(work), str(bare)], check=True)
    git(bare, "config", "uploadpack.allowFilter", "true")
    git(bare, "config", "uploadpack.allowAnySHA1InWant", "true")
    return tmp_path / "remote", fix


def test_selector_locates_the_changed_call_not_the_first_match(tmp_path, remote):
    base, fix = remote
    work = tmp_path / "sel"
    work.mkdir()
    candidates = [{"id": "TEST-1", "aliases": [], "package": "proj", "kinds": ["PROCESS_EXEC"],
                   "fix_refs": [["owner", "proj", fix, "FIX"]], "git_fixed": [], "text": "eval injection"}]
    (work / "candidates.json").write_text(json.dumps(candidates))
    env = {**os.environ, "SZ_GIT_BASE": base.as_uri()}
    subprocess.run([sys.executable, str(TOOLS / "fetch_diffs.py"), "candidates.json", "diffs"],
                   cwd=work, env=env, check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(TOOLS / "select_pairs.py"), "candidates.json", "diffs", "manifest.json", "abc123"],
                   cwd=work, env=env, check=True, capture_output=True, text=True)
    manifest = json.loads((work / "manifest.json").read_text())

    assert manifest["schema"] == "sentinel-cve-pairs-v1"
    assert manifest["source"]["commit"] == "abc123"
    sites = manifest["pairs"][0]["sites"]
    assert [(s["function"], s["line_at_vulnerable"]) for s in sites] == [("second", 6)]

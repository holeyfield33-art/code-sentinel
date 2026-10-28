"""Caller-side guards: `if not check(x): raise` before a sink, where check()
is project code that only returns a bool. Found on the held-out benchmark:
chia's data_layer_server opens a request-derived path after
`if not is_filename_valid(...): raise`, and the scanner reported it as
unguarded because only callee-raises guards were recognised.

A guard never changes the disposition (still UNRESOLVED_INCONCLUSIVE); it
records the guard and takes the plan out of the priority list."""
import json
from pathlib import Path

import pytest

from sentinel_zero import cli

VALIDATOR = "def is_safe(p):\n    return p.isalnum()\n\n"


def _plans(tmp_path: Path, body: str) -> list[dict]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import os\n" + VALIDATOR + body)
    out = tmp_path / "out"
    assert cli.main(["analyze", str(repo), "--language", "python", "--format", "json", "--out", str(out)]) == 0
    return json.loads((out / "verification_ledger.json").read_text())["plans"]


def _only(tmp_path, body):
    plans = [p for p in _plans(tmp_path, body) if p["hypothesis"]["sink_node"] == "builtins.open"]
    assert len(plans) == 1
    return plans[0]


@pytest.mark.parametrize("exit_stmt", ["raise ValueError('bad')", "return None"])
def test_exit_guard_is_credited(tmp_path, exit_stmt):
    plan = _only(tmp_path, f"def read(p):\n    if not is_safe(p):\n        {exit_stmt}\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] == "app.is_safe"
    assert plan["triage"]["priority"] is False
    assert "checks app.is_safe" in plan["disposition"]["reason"]
    assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"


def test_continue_guard_inside_loop(tmp_path):
    plan = _only(tmp_path, "def read_all(ps):\n    for p in ps:\n        if not is_safe(p):\n"
                           "            continue\n        open(p)\n")
    assert plan["triage"]["guarded_by"] == "app.is_safe"


def test_else_branch_exit_guard(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    if is_safe(p):\n        pass\n    else:\n"
                           "        raise ValueError(p)\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] == "app.is_safe"


def test_sink_in_safe_branch_of_guard(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    if not is_safe(p):\n        raise ValueError(p)\n"
                           "    else:\n        return open(p)\n")
    assert plan["triage"]["guarded_by"] == "app.is_safe"


# --- shapes that must NOT count as guarded ---------------------------------

def test_stdlib_predicate_is_not_a_guard(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    if not os.path.exists(p):\n        return None\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None
    assert plan["triage"]["priority"] is True


def test_check_without_exit_is_not_a_guard(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    if not is_safe(p):\n        print('warning')\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_sink_inside_exiting_branch_is_not_guarded(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    if not is_safe(p):\n        open(p)\n        raise ValueError(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_sink_before_the_check_is_not_guarded(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    f = open(p)\n    if not is_safe(p):\n        raise ValueError(p)\n"
                           "    return f\n")
    assert plan["triage"]["guarded_by"] is None


def test_conditional_check_does_not_dominate(tmp_path):
    plan = _only(tmp_path, "def read(p, strict):\n    if strict:\n        if not is_safe(p):\n"
                           "            raise ValueError(p)\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_check_in_sibling_branch_does_not_guard(tmp_path):
    plan = _only(tmp_path, "def read(p, mode):\n    if mode:\n        if not is_safe(p):\n"
                           "            raise ValueError(p)\n    else:\n        return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_unrelated_project_check_does_not_guard(tmp_path):
    # Benchmark false credit: chia's `if not self.synced(): return` before an
    # open() was counted as a guard. A check must read the sink's data.
    plan = _only(tmp_path, "def ready():\n    return True\n\ndef read(p):\n    if not ready():\n"
                           "        return None\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None
    assert plan["triage"]["priority"] is True


def test_check_on_a_different_variable_does_not_guard(tmp_path):
    plan = _only(tmp_path, "def read(p, q):\n    if not is_safe(q):\n        raise ValueError(q)\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_guard_reaches_sink_through_an_assignment(tmp_path):
    # chia data_layer_server shape: validate the parts, then build the path.
    plan = _only(tmp_path, "def serve(base, tree_id, filename):\n"
                           "    if not is_safe(tree_id + '-' + filename):\n        raise ValueError(filename)\n"
                           "    file_path = base.joinpath(tree_id).joinpath(filename)\n    return open(file_path)\n")
    assert plan["triage"]["guarded_by"] == "app.is_safe"


# --- Codex review on #21: each of these hid a reachable sink ---------------

def test_reassignment_after_check_invalidates_guard(tmp_path):
    plan = _only(tmp_path, "def read(p, q):\n    if not is_safe(p):\n        raise ValueError(p)\n"
                           "    p = q\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_tuple_reassignment_after_check_invalidates_guard(tmp_path):
    plan = _only(tmp_path, "def read(p, q):\n    if not is_safe(p):\n        raise ValueError(p)\n"
                           "    p, r = q, 1\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


@pytest.mark.parametrize("test_expr", ["strict and not is_safe(p)", "not (is_safe(p) or strict)"])
def test_short_circuited_check_does_not_guard(tmp_path, test_expr):
    plan = _only(tmp_path, f"def read(p, strict):\n    if {test_expr}:\n        return None\n    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None


def test_or_of_checks_still_guards(tmp_path):
    # Continuing past `if not a or not b: raise` means both ran and passed.
    plan = _only(tmp_path, "def read(p):\n    if not is_safe(p) or not p:\n        raise ValueError(p)\n"
                           "    return open(p)\n")
    assert plan["triage"]["guarded_by"] == "app.is_safe"


def test_call_inside_check_argument_is_not_the_guard(tmp_path):
    plan = _only(tmp_path, "def read(p):\n    if not bool(is_safe(p)):\n        raise ValueError(p)\n"
                           "    return open(p)\n")
    assert plan["triage"]["guarded_by"] is None

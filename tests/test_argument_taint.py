"""Milestone 15: bounded sink-argument taint classification (Python side).

The gap this closes: before this, a sink finding's hypothesis described
only "a resolved call to X exists" -- identical whether the call was
subprocess.run(["echo", "hi"]) (nothing) or subprocess.run(user_cmd)
(a real bug shape). This does NOT add interprocedural taint tracking --
see graph.py's CallSite.arg_taint docstring for the stated bound -- it
only classifies, by real AST structure, whether a sink's argument in THIS
call traces to the enclosing function's own parameter, is built entirely
from literal constants, or is neither (unknown). Pure additive evidence:
no disposition status changes because of it.
"""
import tempfile
from pathlib import Path

from sentinel_zero.resolvers.python_resolver import build_project_graph


def _arg_taint_for(root: Path, caller_suffix: str) -> tuple:
    graph = build_project_graph(root)
    for call in graph.all_calls():
        if call.caller.endswith(caller_suffix):
            return call.arg_taint
    raise AssertionError(f"no call found with caller ending in {caller_suffix!r}")


def test_literal_constant_argument_classifies_as_literal():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef safe():\n    subprocess.run(['echo', 'hi'])\n"
        )
        assert _arg_taint_for(root, "safe") == ("literal",)


def test_parameter_argument_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef risky(cmd):\n    subprocess.run(cmd)\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_fstring_interpolating_a_parameter_classifies_as_parameter():
    """A literal-looking f-string that embeds a parameter must still be
    flagged -- the whole point is this is NOT a text/string check, it's
    structural: JoinedStr's FormattedValue nodes are walked individually."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def risky(name):\n"
            "    subprocess.run(['echo', f'hello {name}'])\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_call_result_argument_classifies_as_unknown_not_literal():
    """The result of calling another function is genuinely unknown -- must
    never be reported as 'literal' (that would be a false claim of safety)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef unclear():\n    subprocess.run(get_cmd())\n"
        )
        assert _arg_taint_for(root, "unclear") == ("unknown",)


def test_module_global_name_classifies_as_unknown_not_parameter():
    """A bare Name that is NOT one of the enclosing function's own
    parameters (e.g. a module-level global) must not be mistaken for a
    parameter -- only this function's own declared params count."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "DEFAULT_CMD = ['echo']\n"
            "def uses_global():\n    subprocess.run(DEFAULT_CMD)\n"
        )
        assert _arg_taint_for(root, "uses_global") == ("unknown",)


def test_attribute_access_off_a_parameter_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def risky(opts):\n    subprocess.run(opts.cmd)\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_concatenation_with_a_parameter_classifies_as_parameter():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def risky(suffix):\n    subprocess.run('echo ' + suffix)\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_list_literal_mixing_a_literal_and_a_parameter_classifies_as_parameter():
    """Composite expressions must propagate the most-notable classification
    across elements -- one tainted element taints the whole argument."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def risky(target):\n    subprocess.run(['ping', '-c', '1', target])\n"
        )
        assert _arg_taint_for(root, "risky") == ("parameter",)


def test_finding_plan_hypothesis_carries_argument_taint_and_a_human_readable_note():
    """End-to-end through dogfood_scan.find_finding_plans: the evidence
    must reach the actual Finding Plan, not just exist inside the resolver."""
    from sentinel_zero.catalog_loader import bundled_snapshot_path
    from sentinel_zero.disposition import load_catalog
    from sentinel_zero.dogfood_scan import find_finding_plans

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\ndef risky(cmd):\n    subprocess.run(cmd)\n"
        )
        graph = build_project_graph(root)
        catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
        plans = find_finding_plans(graph, root.name, catalog, [0], root, "python")
        assert len(plans) == 1
        plan_dict = plans[0].as_dict()
        assert plan_dict["hypothesis"]["argument_taint"] == ["parameter"]
        assert "parameter" in plan_dict["disposition"]["reason"]

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


def test_sink_argument_that_is_an_inline_method_call_on_a_literal_traces_one_hop():
    """.spec/arg-taint-one-hop-widening.md, fixture 1: the sink argument
    is written inline as a method call on a literal receiver, not a bare
    name -- one hop is enough to see through to it, so this is no longer
    bare "unknown". (Note: `Path('x').read_text()` would NOT qualify here
    -- its receiver `Path('x')` is itself a call, which is a second hop
    this classifier deliberately does not chase; see the negative test
    below for exactly that case.)"""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import json\n"
            "def safe():\n    json.loads('{\"default\": true}'.strip())\n"
        )
        assert _arg_taint_for(root, "safe") == ("traced:literal",)


def test_sink_argument_that_is_an_inline_call_on_a_parameter_traces_one_hop():
    """Fixture 2: same shape, but the inner call's receiver traces to the
    enclosing function's own parameter instead of a literal."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import json\ndef risky(request):\n    json.loads(request.get_json())\n"
        )
        assert _arg_taint_for(root, "risky") == ("traced:parameter",)


def test_one_hop_method_call_inspects_its_arguments_not_just_its_receiver():
    """Regression for a Codex review finding on the PR that introduced
    _classify_call_result_taint: the inner call is a method call
    (`receiver.method(arg)`), and the taint-carrying value is the
    ARGUMENT (`request`), not the receiver (`base64`, which traces to
    neither a parameter nor a literal). The original implementation only
    inspected the receiver and missed this, reporting "unknown" instead
    of "traced:parameter"."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import json, base64\n"
            "def risky(request):\n    json.loads(base64.b64decode(request))\n"
        )
        assert _arg_taint_for(root, "risky") == ("traced:parameter",)


def test_one_hop_result_with_one_unknown_and_one_literal_constituent_stays_unknown():
    """Regression for a second Codex review finding: when a plain
    function call's arguments classify as a mix of "unknown" (an
    unresolved module global) and "literal", the result must stay
    "unknown" -- not every constituent is provably literal, so reporting
    "traced:literal" here would overstate certainty. Mirrors
    _combine_taint's own parameter > unknown > literal priority, which
    the original (literal-checked-before-unknown) implementation did
    not."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import json\n"
            "GLOBAL_VALUE = 'x'\n"
            "def build(a, b):\n    return a + b\n"
            "def safe():\n    json.loads(build(GLOBAL_VALUE, 'suffix'))\n"
        )
        assert _arg_taint_for(root, "safe") == ("unknown",)


def test_traced_parameter_inside_a_composite_propagates_not_downgraded_to_literal():
    """Regression for a third Codex review finding: a one-hop-traced
    constituent (here "traced:parameter", from a list element that is
    itself an inline call on a parameter) must propagate through
    _combine_taint when the whole composite (a list literal) is
    classified -- not silently fall through every explicit case and
    report the weakest possible "literal", which is what happened before
    _combine_taint recognized the traced:* labels at all."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\n"
            "def sanitize(x):\n    return x\n"
            "def risky(cmd):\n    subprocess.run([sanitize(cmd)])\n"
        )
        assert _arg_taint_for(root, "risky") == ("traced:parameter",)


def test_two_hop_call_chain_stays_unknown_not_silently_widened_further():
    """Negative test locking in the spec's explicit bound: the inner
    call's own receiver is ITSELF a call result (get_path()), so there is
    no literal or parameter to find at exactly one hop -- this must stay
    "unknown", not be chased through a second hop."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import json\n"
            "def get_path():\n    return 'config.json'\n"
            "def safe():\n    json.loads(get_path().read_text())\n"
        )
        assert _arg_taint_for(root, "safe") == ("unknown",)


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

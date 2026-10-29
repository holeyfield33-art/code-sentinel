"""Regression cases from the adversarial source-triage review.

The fixtures contain supported direct sinks. Scanning never invokes them;
the one runtime comparison replaces os.system with a harmless recorder.
"""
import json
import textwrap
from pathlib import Path

import pytest

from sentinel_zero import cli
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.callgraph import build_direct_callee_index, transitively_guard_shaped
from sentinel_zero.disposition import load_catalog
from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.python_resolver import build_project_graph


def _plans(root: Path) -> tuple:
    graph = build_project_graph(root)
    plans = find_finding_plans(
        graph, root.name, load_catalog(str(bundled_snapshot_path())), [0], root,
    )
    return graph, [plan.as_dict() for plan in plans]


@pytest.mark.parametrize("suite", [
    "if True:\n{definition}",
    "try:\n{definition}\nexcept Exception:\n    pass",
    "match True:\n    case True:\n{nested_definition}",
    "with contextlib.nullcontext():\n{definition}",
    "for _ in (True,):\n{definition}",
])
@pytest.mark.parametrize("async_prefix", ["", "async "])
def test_module_suite_function_sink_is_preserved(tmp_path: Path, suite: str, async_prefix: str) -> None:
    definition = f"{async_prefix}def run(cmd):\n    os.system(cmd)"
    source = "import os, contextlib\n" + suite.format(
        definition=textwrap.indent(definition, "    "),
        nested_definition=textwrap.indent(definition, "        "),
    )
    (tmp_path / "app.py").write_text(source)
    graph, plans = _plans(tmp_path)
    assert not graph.parse_errors
    assert "app.run" in graph.functions
    assert len(plans) == 1
    assert plans[0]["hypothesis"]["symbol_binding"] == "app.run"
    assert plans[0]["hypothesis"]["sink_node"] == "os.system"
    assert plans[0]["triage"]["priority"] is True


def test_conditional_module_class_and_method_suites_are_preserved(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\nif True:\n    class Runner:\n        if True:\n"
        "            def run(self, cmd):\n                os.system(cmd)\n"
    )
    graph, plans = _plans(tmp_path)
    assert "app.Runner.run" in graph.functions
    assert len(plans) == 1
    assert plans[0]["hypothesis"]["symbol_binding"] == "app.Runner.run"


_VALIDATOR = (
    "import os\ndef validate(cmd):\n    if ';' in cmd:\n        raise ValueError(cmd)\n"
)


@pytest.mark.parametrize("expression", [
    "strict and validate(cmd)",
    "strict or validate(cmd)",
    "validate(cmd) if strict else None",
    "None if strict else validate(cmd)",
    "[validate(cmd) for _ in []]",
    "(validate(cmd) for _ in [])",
    "lambda: validate(cmd)",
    "assert validate(cmd) is None",
    "False == True == validate(cmd)",
])
def test_skippable_validator_cannot_remove_sink_from_priority(tmp_path: Path, expression: str) -> None:
    (tmp_path / "app.py").write_text(
        _VALIDATOR + f"def run(cmd, strict=False):\n    {expression}\n    os.system(cmd)\n"
    )
    _, plans = _plans(tmp_path)
    assert len(plans) == 1
    assert plans[0]["triage"]["guarded_by"] is None
    assert plans[0]["triage"]["priority"] is True
    assert "executes on EVERY control-flow path" not in plans[0]["disposition"]["reason"]


@pytest.mark.parametrize("expression", ["validate(cmd)", "validate(cmd) and strict"])
def test_unconditional_validator_still_receives_structural_credit(tmp_path: Path, expression: str) -> None:
    (tmp_path / "app.py").write_text(
        _VALIDATOR + f"def run(cmd, strict=False):\n    {expression}\n    os.system(cmd)\n"
    )
    _, plans = _plans(tmp_path)
    assert len(plans) == 1
    assert plans[0]["triage"]["guarded_by"] == "app.validate"
    assert plans[0]["triage"]["priority"] is False


@pytest.mark.parametrize("expression,optimize", [
    ("strict and validate(cmd)", 0),
    ("validate(cmd) if strict else None", 0),
    ("assert validate(cmd) is None", 2),
    ("False == True == validate(cmd)", 0),
])
def test_runtime_skips_validator_while_sink_remains_a_priority_lead(
    tmp_path: Path, monkeypatch, expression: str, optimize: int,
) -> None:
    source = _VALIDATOR + f"def run(cmd, strict=False):\n    {expression}\n    os.system(cmd)\n"
    (tmp_path / "app.py").write_text(source)
    namespace: dict = {}
    exec(compile(source, "review_fixture", "exec", optimize=optimize), namespace)
    hits = []
    monkeypatch.setattr(namespace["os"], "system", lambda cmd: hits.append(cmd))
    namespace["run"]("review; marker")
    assert hits == ["review; marker"]
    _, plans = _plans(tmp_path)
    assert plans[0]["triage"]["priority"] is True


@pytest.mark.parametrize("vulnerable,safe", [
    ("worker/__init__.py", "worker.py"),
    ("a/b.py", "a.b.py"),
])
def test_colliding_module_names_retain_both_files_and_sink_plans(
    tmp_path: Path, vulnerable: str, safe: str,
) -> None:
    bad = tmp_path / vulnerable
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")
    (tmp_path / safe).write_text("def run(cmd):\n    return cmd\n")
    graph, plans = _plans(tmp_path)
    assert len(graph.modules) == 2
    assert {module.file_path for module in graph.modules.values()} == {str(bad), str(tmp_path / safe)}
    assert graph.coverage["collected_files"] == graph.coverage["parsed_files"] == 2
    assert any(warning["kind"] == "module_identity_disambiguated" for warning in graph.coverage["warnings"])
    assert len(plans) == 1
    assert plans[0]["hypothesis"]["source_node"].startswith(str(bad) + ":")
    assert plans[0]["triage"]["priority"] is True


def test_collision_imports_select_package_and_preserve_relative_submodule_resolution(tmp_path: Path) -> None:
    package = tmp_path / "worker"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import os\nfrom .helper import validate\ndef run(cmd):\n    validate(cmd)\n    os.system(cmd)\n"
    )
    (package / "helper.py").write_text("def validate(cmd):\n    if not cmd:\n        raise ValueError()\n")
    (tmp_path / "worker.py").write_text("def run(cmd):\n    return cmd\n")
    (tmp_path / "entry.py").write_text(
        "import worker\nfrom worker import run as dispatch\ndef main(cmd):\n    worker.run(cmd)\n    dispatch(cmd)\n"
    )
    graph, plans = _plans(tmp_path)
    package_id = next(module.module_qualname for module in graph.modules.values()
                      if module.file_path == str(package / "__init__.py"))
    imported_calls = [call for call in graph.all_calls() if call.caller == "entry.main"]
    assert len(imported_calls) == 2
    assert all(call.target == Symbol(package_id + ".run") for call in imported_calls)
    assert any(call.caller == package_id + ".run" and call.target == Symbol("worker.helper.validate")
               for call in graph.all_calls())
    assert len(plans) == 1
    assert plans[0]["triage"]["guarded_by"] == "worker.helper.validate"


def test_python_coverage_and_collision_warning_reach_cli_outputs(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "worker").mkdir()
    (root / "worker" / "__init__.py").write_text("import os\ndef run(cmd):\n    os.system(cmd)\n")
    (root / "worker.py").write_text("def run(cmd):\n    return cmd\n")
    (root / "broken.py").write_text("def broken(\n")
    out = tmp_path / "out"
    assert cli.main(["analyze", str(root), "--language", "python", "--out", str(out)]) == 0
    ledger = json.loads((out / "verification_ledger.json").read_text())
    export = json.loads((out / "graph.json").read_text())
    assert ledger["plan_count"] == 1
    assert ledger["modules_scanned"] == 2
    assert ledger["coverage"] == export["coverage"]
    assert ledger["coverage"]["collected_files"] == 3
    assert ledger["coverage"]["parsed_files"] == 2
    assert {warning["kind"] for warning in ledger["coverage"]["warnings"]} == {
        "module_identity_disambiguated", "parse_failures",
    }


@pytest.mark.parametrize("definition", [
    "async def validate(cmd):\n    if ';' in cmd:\n        raise ValueError(cmd)\n",
    "def validate(cmd):\n    if ';' in cmd:\n        raise ValueError(cmd)\n    yield True\n",
])
@pytest.mark.parametrize("delegated", [False, True])
@pytest.mark.parametrize("caller_check", [False, True])
def test_deferred_validator_cannot_hide_a_synchronous_sink(
    tmp_path: Path, monkeypatch, definition: str, delegated: bool, caller_check: bool,
) -> None:
    wrapper = "def wrapper(cmd):\n    return validate(cmd)\n" if delegated else ""
    target = "wrapper" if delegated else "validate"
    invocation = f"if not {target}(cmd):\n        return" if caller_check else f"{target}(cmd)"
    source = f"import os\n{definition}{wrapper}def run(cmd):\n    {invocation}\n    os.system(cmd)\n"
    (tmp_path / "app.py").write_text(source)

    # Neither a coroutine nor an unconsumed generator runs its validator
    # body here. Close recorded objects so this proof leaves no warnings.
    namespace: dict = {}
    exec(compile(source, "review_fixture", "exec"), namespace)
    deferred = []
    original = namespace["validate"]

    def record_object(cmd):
        result = original(cmd)
        deferred.append(result)
        return result

    namespace["validate"] = record_object
    hits = []
    monkeypatch.setattr(namespace["os"], "system", lambda cmd: hits.append(cmd))
    try:
        namespace["run"]("review; marker")
    finally:
        for result in deferred:
            result.close()
    assert hits == ["review; marker"]

    graph, plans = _plans(tmp_path)
    assert graph.functions["app.validate"].body_is_deferred is True
    assert not transitively_guard_shaped("app." + target, graph, build_direct_callee_index(graph))
    assert len(plans) == 1
    assert plans[0]["triage"]["guarded_by"] is None
    assert plans[0]["triage"]["priority"] is True


def test_nested_generator_does_not_disqualify_a_synchronous_validator(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\ndef validate(cmd):\n    def values():\n        yield True\n"
        "    if ';' in cmd:\n        raise ValueError(cmd)\n"
        "def run(cmd):\n    validate(cmd)\n    os.system(cmd)\n"
    )
    graph, plans = _plans(tmp_path)
    assert graph.functions["app.validate"].body_is_deferred is False
    assert plans[0]["triage"]["guarded_by"] == "app.validate"


def test_awaited_validation_is_conservatively_uncredited_without_async_flow_model(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os\nasync def validate(cmd):\n    if ';' in cmd:\n        raise ValueError(cmd)\n"
        "async def run(cmd):\n    await validate(cmd)\n    os.system(cmd)\n"
    )
    _, plans = _plans(tmp_path)
    assert len(plans) == 1  # A deferred caller's sink is still indexed.
    assert plans[0]["triage"]["guarded_by"] is None
    assert plans[0]["triage"]["priority"] is True

"""Success criterion for this round of fixes: 'the tool still fails hard
on any internal tool error.' Nothing here existed before -- ToolFailure
and UnknownAttackClass were real, wired-in mechanisms (disposition.py,
dogfood_scan.py) with zero direct test coverage proving they actually
fire rather than silently swallowing a problem."""
import json
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.disposition import (
    ToolFailure,
    UnknownAttackClass,
    build_finding_plan,
    load_catalog,
    set_disposition,
)
from sentinel_zero.dogfood_scan import run


def _write_catalog(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "attackClasses": [
                    {"id": "AAC-11", "name": "Unsafe Process Execution"},
                    {"id": "AAC-17", "name": "Path Traversal / File IO"},
                    {"id": "AAC-27", "name": "Serialization Injection"},
                ]
            }
        )
    )


def test_load_catalog_raises_tool_failure_on_missing_file():
    with pytest.raises(ToolFailure):
        load_catalog("/tmp/this-catalog-path-does-not-exist-sz-test.json")


def test_load_catalog_raises_tool_failure_on_malformed_json():
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "catalog.json"
        bad.write_text('{"not_attack_classes_key": []}')
        with pytest.raises(ToolFailure):
            load_catalog(str(bad))


def test_build_finding_plan_raises_on_unknown_attack_class():
    """The structural fix for Code Atlas's real asi.ts drift bug: an
    attack_id absent from the live catalog must be a hard error, never a
    silent pass-through or a guessed label."""
    with tempfile.TemporaryDirectory() as tmp:
        catalog_path = Path(tmp) / "catalog.json"
        _write_catalog(catalog_path)
        catalog = load_catalog(str(catalog_path))
        with pytest.raises(UnknownAttackClass):
            build_finding_plan(
                plan_id="fp_test_0001",
                target_repository="whatever",
                attack_id="AAC-9999-DOES-NOT-EXIST",
                catalog=catalog,
                hypothesis={},
                verification_method={},
                execution_gate={},
            )


def test_set_disposition_rejects_an_invalid_status():
    with tempfile.TemporaryDirectory() as tmp:
        catalog_path = Path(tmp) / "catalog.json"
        _write_catalog(catalog_path)
        catalog = load_catalog(str(catalog_path))
        plan = build_finding_plan(
            plan_id="fp_test_0002",
            target_repository="whatever",
            attack_id="AAC-11",
            catalog=catalog,
            hypothesis={},
            verification_method={},
            execution_gate={},
        )
        with pytest.raises(ValueError):
            set_disposition(plan, "DEFINITELY_FINE", reason="nope", residual_uncertainty="nope")


def test_run_raises_tool_failure_on_unknown_language():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        catalog_path = root / "catalog.json"
        _write_catalog(catalog_path)
        with pytest.raises(ToolFailure):
            run(root / "repo", str(catalog_path), root / "out", language="rust")


def test_run_raises_tool_failure_on_bad_catalog_path():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        with pytest.raises(ToolFailure):
            run(root / "repo", str(root / "no-such-catalog.json"), root / "out", language="python")


def test_run_wraps_a_resolver_crash_as_tool_failure_not_a_silent_empty_result(monkeypatch):
    """The exact failure mode disposition.py's own module docstring names:
    'silent tool failure reported as a clean pass.' If the resolver itself
    raises for any reason, run() must propagate that as ToolFailure --
    never catch it and quietly return as if nothing was found."""
    import sentinel_zero.dogfood_scan as dogfood_scan

    def _boom(repo_root):
        raise RuntimeError("simulated resolver crash")

    monkeypatch.setitem(dogfood_scan._RESOLVERS, "python", _boom)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        catalog_path = root / "catalog.json"
        _write_catalog(catalog_path)
        with pytest.raises(ToolFailure):
            run(root / "repo", str(catalog_path), root / "out", language="python")

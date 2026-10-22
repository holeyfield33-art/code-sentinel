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
from sentinel_zero.ledger_writer import safe_write_text


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


def test_run_raises_tool_failure_not_a_bare_valueerror_when_the_ledger_is_too_big(monkeypatch):
    """REMEDIATION_PLAN.md item 7 / VERIFICATION_LEDGER.md sz-2026-10-22-01.

    Reproduced for real before this fix (not just reasoned about): a
    synthetic 3500-file repo (each with its own os.system sink call)
    produced a genuine 5.5MB ledger, and run() crashed with an uncaught
    `ValueError: refused: 5548527 bytes is over the 5000000-byte limit`
    traceback -- not this project's own CRITICAL_TOOL_FAILURE convention.
    `safe_write_text`'s own refusal is correct and unchanged here; this
    monkeypatch reproduces its exact raise cheaply, without generating
    thousands of files, to pin the fix at the one place that must now
    catch it: `_write_or_fail_cleanly` in dogfood_scan.py."""
    import sentinel_zero.dogfood_scan as dogfood_scan

    def _always_too_big(root, relative, text, max_bytes):
        raise ValueError(f"refused: 99999999 bytes is over the {max_bytes}-byte limit")

    monkeypatch.setattr(dogfood_scan, "safe_write_text", _always_too_big)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        (repo / "mod.py").write_text("import os\ndef h(x):\n    os.system(x)\n")
        catalog_path = root / "catalog.json"
        _write_catalog(catalog_path)
        with pytest.raises(ToolFailure) as excinfo:
            run(repo, str(catalog_path), root / "out", language="python")
        assert "verification ledger" in str(excinfo.value)
        assert "99999999" in str(excinfo.value)


def test_write_or_fail_cleanly_still_writes_normally_sized_output():
    """Sanity/regression guard: the fix must not change behavior for the
    overwhelmingly common case where the write is well under the cap."""
    import sentinel_zero.dogfood_scan as dogfood_scan

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        dogfood_scan._write_or_fail_cleanly(
            str(out_dir), "small.json", '{"ok": true}', 5_000_000, what="a small file"
        )
        assert (out_dir / "small.json").read_text(encoding="utf-8") == '{"ok": true}'


def test_cmd_analyze_reports_a_clean_critical_tool_failure_when_the_markdown_report_is_too_big(
    monkeypatch, capsys
):
    """The other half of the same bug: `cli.cmd_analyze`'s own report.md
    write (--format md) used to sit entirely outside the
    `except (ToolFailure, UnknownAttackClass)` handler, so the exact same
    oversize ValueError from `safe_write_text` crashed there too, even
    after a successful scan. Moved inside the try block and wrapped as a
    ToolFailure; this pins that the CLI now prints the clean
    CRITICAL_TOOL_FAILURE message and returns exit code 3, never a raw
    traceback, while confirming the underlying ledger write (not
    monkeypatched) still succeeds first."""
    import argparse

    import sentinel_zero.cli as cli

    real_safe_write_text = safe_write_text

    def _fail_only_for_report_md(root, relative, text, max_bytes):
        if relative == "report.md":
            raise ValueError(f"refused: 99999999 bytes is over the {max_bytes}-byte limit")
        return real_safe_write_text(root, relative, text, max_bytes)

    monkeypatch.setattr(cli, "safe_write_text", _fail_only_for_report_md)

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        repo = root / "repo"
        repo.mkdir()
        (repo / "mod.py").write_text("import os\ndef h(x):\n    os.system(x)\n")
        out_dir = root / "out"

        args = argparse.Namespace(
            path=str(repo), out=str(out_dir), catalog=None, language="python", format="md"
        )
        exit_code = cli.cmd_analyze(args)

        assert exit_code == 3
        captured = capsys.readouterr()
        assert "CRITICAL_TOOL_FAILURE" in captured.err
        assert "report.md" in captured.err
        # the ledger itself was written successfully before the report.md
        # write failed -- this is not a total loss of the scan's work.
        assert (out_dir / "verification_ledger.json").is_file()

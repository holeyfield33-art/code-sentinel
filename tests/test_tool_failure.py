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


@pytest.mark.parametrize("document", [
    None, [], {}, {"attackClasses": None}, {"attackClasses": [None]},
    {"attackClasses": [{"id": 42}]},
    {"attackClasses": [{"id": "AAC-11", "aliases": "alias"}]},
    {"attackClasses": [{"id": "AAC-11", "aliases": [None]}]},
    {"attackClasses": [{"id": "AAC-11", "legacyId": []}]},
    {"attackClasses": [], "catalog": []},
])
def test_malformed_catalog_shape_is_a_tool_failure(tmp_path, document):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ToolFailure, match="usable ASI catalog"):
        load_catalog(str(path))


def test_typed_catalog_keeps_aliases_metadata_and_extension_fields(tmp_path):
    from sentinel_zero.catalog_loader import load_asi_catalog
    path = tmp_path / "catalog.json"
    document = {"attackClasses": [{"id": "AAC-11", "name": "Example", "aliases": ["old"],
                                    "legacyId": "legacy", "extension": {"value": 1}}],
                "catalog": {"version": "test"}, "extension": ["retained"]}
    path.write_text(json.dumps(document), encoding="utf-8")
    assert load_asi_catalog(str(path)) == document
    catalog = load_catalog(str(path))
    assert catalog.resolve("old") == catalog.resolve("legacy") == catalog.resolve("AAC-11")
    assert catalog.meta == {"version": "test"}


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
    catch it: `write_or_fail_cleanly` in dogfood_scan.py."""
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


def test_write_or_fail_cleanly_does_not_mislabel_a_non_size_valueerror_as_too_big():
    """VERIFICATION_LEDGER.md sz-2026-10-22-03 (Codex P2 on PR #9):
    `safe_write_text` can raise a plain `ValueError` for reasons that have
    nothing to do with the byte cap -- `resolve_inside`'s path-containment
    refusal (a symlink escaping out_dir) and a `UnicodeEncodeError` (a
    ValueError subclass) from encoding `text` are both real, if currently
    unreachable from this project's own hardcoded call sites. The original
    version of this wrapper caught ValueError generically and always
    claimed "too large... were discarded", which would be a flatly wrong
    message for either of those -- actively misleading about why the
    write failed, worse than no message at all. This pins that the
    "too large" framing only appears when `text` is actually over
    `max_bytes`."""
    import sentinel_zero.dogfood_scan as dogfood_scan

    def _refuse_for_an_unrelated_reason(root, relative, text, max_bytes):
        raise ValueError(f"refused: {relative} is not inside {root}")

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr(dogfood_scan, "safe_write_text", _refuse_for_an_unrelated_reason)
        with pytest.raises(ToolFailure) as excinfo:
            dogfood_scan.write_or_fail_cleanly(
                "/tmp/whatever", "small.json", '{"ok": true}', 5_000_000, what="a small file"
            )
        message = str(excinfo.value)
        assert "not inside" in message
        assert "too large" not in message
        assert "discarded" not in message


def test_write_or_fail_cleanly_reports_invalid_unicode_without_reencoding(tmp_path):
    from sentinel_zero.dogfood_scan import write_or_fail_cleanly
    with pytest.raises(ToolFailure, match="not valid UTF-8") as failure:
        write_or_fail_cleanly(str(tmp_path), "x", "\ud800", 10, what="test")
    assert isinstance(failure.value.__cause__, UnicodeEncodeError)
    assert not (tmp_path / "x").exists()


def test_write_or_fail_cleanly_still_writes_normally_sized_output():
    """Sanity/regression guard: the fix must not change behavior for the
    overwhelmingly common case where the write is well under the cap."""
    import sentinel_zero.dogfood_scan as dogfood_scan

    with tempfile.TemporaryDirectory() as tmp:
        out_dir = Path(tmp)
        dogfood_scan.write_or_fail_cleanly(
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
    after a successful scan. Moved inside the try block and now shares
    `dogfood_scan.write_or_fail_cleanly()` rather than a second copy of
    the same wrapping logic; this pins that the CLI prints the clean
    CRITICAL_TOOL_FAILURE message and returns exit code 3, never a raw
    traceback, while confirming the underlying ledger write (not
    monkeypatched) still succeeds first. Patches
    `dogfood_scan.safe_write_text` (not `cli.safe_write_text`, which no
    longer exists now that cli.py calls through write_or_fail_cleanly)
    since that's where write_or_fail_cleanly actually resolves the name
    at call time."""
    import argparse

    import sentinel_zero.cli as cli
    import sentinel_zero.dogfood_scan as dogfood_scan

    real_safe_write_text = safe_write_text

    def _fail_only_for_report_md(root, relative, text, max_bytes):
        if relative == "report.md":
            raise ValueError(f"refused: 99999999 bytes is over the {max_bytes}-byte limit")
        return real_safe_write_text(root, relative, text, max_bytes)

    monkeypatch.setattr(dogfood_scan, "safe_write_text", _fail_only_for_report_md)

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

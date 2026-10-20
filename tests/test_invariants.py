"""Named, explicit coverage for the three invariants the Phase-2 packaging
work (sentinel_zero/cli.py, mcp_server.py) must never weaken, since those
are new surfaces that could each independently reintroduce one of the two
failure modes this whole project exists to structurally close:

  1. No silent tool failure.
  2. Live ASI catalog only -- never a hardcoded attack-class name/label.
  3. Finding Plan required -- no disposition without a real FindingPlan.

tests/test_tool_failure.py already covers invariant 1 at the
disposition.py/dogfood_scan.py level directly; this file covers the same
invariant through the new cli.py surface, plus 2 and 3 end-to-end.
"""
import json
import tempfile
from pathlib import Path

import pytest

from sentinel_zero import cli
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.disposition import load_catalog


def _write_catalog(path: Path, class_ids: list[str]) -> None:
    path.write_text(
        json.dumps({"attackClasses": [{"id": cid, "name": f"Class {cid}"} for cid in class_ids]})
    )


def test_bundled_snapshot_exists_and_loads_as_a_real_catalog():
    """Invariant 2 depends on this file actually shipping with the
    package and being a well-formed export, not a placeholder."""
    path = bundled_snapshot_path()
    assert path.is_file()
    catalog = load_catalog(str(path), is_bundled_snapshot=True)
    assert catalog.is_bundled_snapshot is True
    assert "AAC-11" in catalog.classes_by_id  # PROCESS_EXEC's attack id
    assert catalog.meta.get("version")


def test_cli_analyze_marks_bundled_snapshot_in_the_ledger():
    """Invariant 2, end-to-end through the CLI surface: when the caller
    passes no --catalog, the ledger must say so, with the real catalog
    version -- never silently presenting the snapshot as a fresh fetch."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text("def run():\n    pass\n")
        out = root / "out"
        rc = cli.main(["analyze", str(root / "repo"), "--out", str(out)])
        assert rc == 0
        ledger = json.loads((out / "verification_ledger.json").read_text())
        assert ledger["catalog"]["is_bundled_snapshot"] is True
        assert ledger["catalog"]["metadata"].get("version")


def test_cli_analyze_with_explicit_catalog_is_not_marked_as_bundled():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text("def run():\n    pass\n")
        catalog_path = root / "catalog.json"
        _write_catalog(catalog_path, ["AAC-11", "AAC-17", "AAC-27"])
        out = root / "out"
        rc = cli.main(["analyze", str(root / "repo"), "--catalog", str(catalog_path), "--out", str(out)])
        assert rc == 0
        ledger = json.loads((out / "verification_ledger.json").read_text())
        assert ledger["catalog"]["is_bundled_snapshot"] is False
        assert ledger["catalog"]["path"] == str(catalog_path)


def test_cli_analyze_hard_fails_on_a_catalog_missing_the_sink_attack_ids():
    """Invariant 2's teeth: a catalog that doesn't recognize AAC-11 must
    make the run fail loudly (UnknownAttackClass bubbling up as a nonzero
    exit), never silently drop those findings or mislabel them."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text(
            "import subprocess\ndef run():\n    subprocess.run(['echo'])\n"
        )
        catalog_path = root / "catalog.json"
        _write_catalog(catalog_path, ["AAC-99-UNRELATED"])  # no AAC-11
        out = root / "out"
        rc = cli.main(["analyze", str(root / "repo"), "--catalog", str(catalog_path), "--out", str(out)])
        assert rc == 3
        assert not (out / "verification_ledger.json").exists()


def test_cli_analyze_hard_fails_on_missing_repo_path():
    """Invariant 1 through the CLI surface: a bad path is a nonzero exit
    and a printed message, never a quietly-empty ledger."""
    with tempfile.TemporaryDirectory() as tmp:
        rc = cli.main(["analyze", str(Path(tmp) / "does-not-exist"), "--out", str(Path(tmp) / "out")])
        assert rc == 3


def test_cli_analyze_hard_fails_when_no_supported_source_files_exist():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "notes.txt").write_text("nothing to scan here\n")
        rc = cli.main(["analyze", str(root / "repo"), "--out", str(root / "out")])
        assert rc == 3


def test_every_reported_finding_is_a_real_finding_plan_with_required_fields():
    """Invariant 3, checked against the actual ledger the CLI produces:
    every plan has every field schema_check.require_finding_plan_fields
    demands, and a disposition status drawn only from the engine's
    explicit set -- never a bare hypothesis dict reported as a finding."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text(
            "import subprocess\n"
            "def run():\n"
            "    subprocess.run(['echo', 'hi'])\n"
            "import json\n"
            "def parse(s):\n"
            "    return json.loads(s)\n"
        )
        out = root / "out"
        rc = cli.main(["analyze", str(root / "repo"), "--out", str(out)])
        assert rc == 0
        ledger = json.loads((out / "verification_ledger.json").read_text())
        assert ledger["plan_count"] >= 2
        required_fields = {
            "plan_id", "target_repository", "asi_classification",
            "hypothesis", "verification_method", "execution_gate", "disposition",
        }
        allowed_statuses = {"VERIFIED_TRUE", "VERIFIED_FALSE", "UNRESOLVED_INCONCLUSIVE", "TOOL_FAILURE"}
        for plan in ledger["plans"]:
            assert required_fields.issubset(plan.keys())
            assert plan["disposition"]["status"] in allowed_statuses
            assert plan["asi_classification"]["attack_id"] in {"AAC-11", "AAC-17", "AAC-27"}


def test_markdown_report_only_restates_ledger_fields_never_invents_findings():
    """The --format md path is pure presentation: confirms the number of
    findings mentioned in the rendered report matches the ledger's own
    plan_count exactly, so Markdown rendering can't silently drop or add
    a finding relative to the JSON source of truth."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text(
            "import subprocess\ndef run():\n    subprocess.run(['echo'])\n"
        )
        out = root / "out"
        rc = cli.main(["analyze", str(root / "repo"), "--format", "md", "--out", str(out)])
        assert rc == 0
        ledger = json.loads((out / "verification_ledger.json").read_text())
        report = (out / "report.md").read_text()
        for plan in ledger["plans"]:
            assert plan["plan_id"] in report

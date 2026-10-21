"""Milestone 14: graph_export.py's nodes+edges JSON, and dogfood_scan.run()'s
wiring of it into graph.json alongside the ledger. The core property this
file exists to prove: the export is a lossless re-serialization of the
exact same data the ledger already reports -- never a second, independently
computed view that could silently disagree with it (which was the whole
reason this module's docstring insists it reads plan dicts rather than
recomputing dispositions itself)."""
import json
import tempfile
from pathlib import Path

from sentinel_zero.graph_export import export_graph
from sentinel_zero.resolvers.python_resolver import build_project_graph
from sentinel_zero import cli


def _finding_plans_for(repo_root: Path):
    """Builds a real graph + finding plans the same way dogfood_scan.run()
    does, without going through the ledger file, so tests can inspect the
    export function directly."""
    from sentinel_zero.disposition import load_catalog
    from sentinel_zero.catalog_loader import bundled_snapshot_path
    from sentinel_zero.dogfood_scan import find_finding_plans

    graph = build_project_graph(repo_root)
    catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
    plan_counter = [0]
    plans = find_finding_plans(graph, repo_root.name, catalog, plan_counter, repo_root, "python")
    return graph, [p.as_dict() for p in plans]


def test_every_module_and_function_becomes_a_node():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "pkg").mkdir()
        (root / "pkg" / "__init__.py").write_text("")
        (root / "pkg" / "mod.py").write_text("def helper():\n    pass\ndef runner():\n    helper()\n")
        graph, plans = _finding_plans_for(root)
        doc = export_graph(graph, plans, root.name)
        node_ids = {n["id"] for n in doc["nodes"]}
        assert "pkg.mod" in node_ids  # module node
        assert "pkg.mod.helper" in node_ids
        assert "pkg.mod.runner" in node_ids
        assert doc["node_count"] == len(doc["nodes"])
        assert doc["edge_count"] == len(doc["edges"])


def test_a_module_contains_edge_links_module_to_its_functions():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text("def f():\n    pass\n")
        graph, plans = _finding_plans_for(root)
        doc = export_graph(graph, plans, root.name)
        contains = [e for e in doc["edges"] if e["kind"] == "contains"]
        assert {"source": "mod", "target": "mod.f", "kind": "contains"} in contains


def test_resolved_call_edge_and_unresolved_call_edge_both_appear():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "def helper():\n    pass\n"
            "def runner(handlers, name):\n"
            "    helper()\n"
            "    handlers[name]()\n"  # computed dispatch -- genuinely unresolved
        )
        graph, plans = _finding_plans_for(root)
        doc = export_graph(graph, plans, root.name)
        calls = [e for e in doc["edges"] if e["kind"] == "calls"]
        resolved = [e for e in calls if e["resolved"]]
        unresolved = [e for e in calls if not e["resolved"]]
        assert any(e["target"] == "mod.helper" for e in resolved)
        assert len(unresolved) >= 1
        assert unresolved[0]["target"] is None
        assert unresolved[0]["unresolved_reason"]


def test_every_finding_plan_id_in_the_ledger_appears_on_exactly_one_edge():
    """The property that matters most: no finding is silently dropped from
    the graph, and none is double-counted onto the wrong call site."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import subprocess\nimport json\n"
            "def run_it():\n    subprocess.run(['echo'])\n"
            "def parse_it(s):\n    return json.loads(s)\n"
        )
        graph, plans = _finding_plans_for(root)
        doc = export_graph(graph, plans, root.name)
        assert len(plans) >= 2

        ids_on_edges: dict[str, int] = {}
        for e in doc["edges"]:
            for pid in e.get("finding_plan_ids", []):
                ids_on_edges[pid] = ids_on_edges.get(pid, 0) + 1

        for plan in plans:
            pid = plan["plan_id"]
            assert ids_on_edges.get(pid) == 1, f"{pid} should appear on exactly one edge, got {ids_on_edges.get(pid)}"


def test_node_worst_disposition_matches_the_least_clean_status_among_its_findings():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.py").write_text(
            "import json\n"
            "def multi():\n"
            "    json.loads('{}')\n"
            "    json.loads('{}')\n"
        )
        graph, plans = _finding_plans_for(root)
        doc = export_graph(graph, plans, root.name)
        node = next(n for n in doc["nodes"] if n["id"] == "mod.multi")
        # Both calls in this toy case resolve to the same no-guard disposition;
        # the real assertion is that the node is annotated at all, with both
        # plan ids attached, not silently left blank because it has >1 finding.
        assert node["worst_disposition"] == "UNRESOLVED_INCONCLUSIVE"
        assert len(node["finding_plan_ids"]) == 2


def test_cli_analyze_writes_graph_json_alongside_the_ledger():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repo").mkdir()
        (root / "repo" / "app.py").write_text(
            "import subprocess\ndef run():\n    subprocess.run(['echo'])\n"
        )
        out = root / "out"
        rc = cli.main(["analyze", str(root / "repo"), "--out", str(out)])
        assert rc == 0
        graph_doc = json.loads((out / "graph.json").read_text())
        ledger = json.loads((out / "verification_ledger.json").read_text())
        ledger_plan_ids = {p["plan_id"] for p in ledger["plans"]}
        exported_plan_ids = {pid for e in graph_doc["edges"] for pid in e.get("finding_plan_ids", [])}
        assert exported_plan_ids == ledger_plan_ids

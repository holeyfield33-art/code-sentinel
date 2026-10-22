"""Probe evidence must identify one resolved source site in either language."""
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel_zero.callgraph import transitive_sink_symbol_counts
from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.disposition import load_catalog
from sentinel_zero.dogfood_scan import find_finding_plans
from sentinel_zero.resolvers.js_resolver import build_project_graph as build_js_graph
from sentinel_zero.resolvers.python_resolver import build_project_graph as build_python_graph


@pytest.fixture(params=["python", "javascript"])
def language(request):
    if request.param == "javascript":
        js_dir = Path(__file__).parents[1] / "sentinel_zero/resolvers/js/node_modules"
        if not shutil.which("node") or not js_dir.is_dir():
            pytest.skip("Node.js and the JS resolver dependencies are required")
    return request.param


def _plans(root, language, sources):
    for name, source in sources.items():
        (root / name).write_text(source, encoding="utf-8")
    graph = (build_python_graph if language == "python" else build_js_graph)(root)
    catalog = load_catalog(str(bundled_snapshot_path()), is_bundled_snapshot=True)
    return [p.as_dict() for p in find_finding_plans(graph, root.name, catalog, [0], root, language, probe_mode="diagnostic")]


def test_direct_duplicates_never_run_a_probe(tmp_path, language):
    sources = {
        "python": {"mod.py": "import os\ndef run_it():\n    os.system('first')\n    return\n    os.system('dead')\n"},
        "javascript": {"mod.cjs": "const cp=require('child_process');\nfunction run_it(){cp.exec('first');return;cp.exec('dead');}\nmodule.exports={run_it};\n"},
    }
    # A static status alone would also pass if a broken probe merely failed.
    # Verify ambiguous code is never executed in the first place.
    with patch("sentinel_zero.dogfood_scan.run_sink_reachability_probe") as py_probe, patch(
        "sentinel_zero.dogfood_scan.run_js_sink_reachability_probe"
    ) as js_probe:
        plans = _plans(tmp_path, language, sources[language])
    assert len(plans) == 2
    assert all(p["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE" for p in plans)
    assert all("2 separate call sites" in p["disposition"]["reason"] for p in plans)
    py_probe.assert_not_called()
    js_probe.assert_not_called()


@pytest.mark.parametrize("cross_file", [False, True])
def test_delegated_dead_site_is_unprobed_but_helper_has_a_report(tmp_path, language, cross_file):
    if language == "python":
        helper = "import os\ndef helper():\n    os.system('live')\n"
        runner = "def run_it():\n    helper()\n    return\n    os.system('dead')\n"
        sources = ({"helper.py": helper, "mod.py": "import os\nfrom helper import helper\n" + runner}
                   if cross_file else {"mod.py": helper + runner})
    else:
        helper = "const cp=require('child_process');\nfunction helper(){cp.exec('live');}\n"
        runner = "function run_it(){helper();return;cp.exec('dead');}\nmodule.exports={run_it};\n"
        sources = ({"helper.cjs": helper + "module.exports={helper};\n",
                    "mod.cjs": "const cp=require('child_process');\nconst {helper}=require('./helper.cjs');\n" + runner}
                   if cross_file else {"mod.cjs": helper + runner + "module.exports.helper=helper;\n"})
    plans = _plans(tmp_path, language, sources)
    assert len(plans) == 2
    by_caller = {p["hypothesis"]["symbol_binding"].rsplit(".", 1)[-1]: p for p in plans}
    assert by_caller["helper"]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
    assert by_caller["helper"]["verification_method"]["probe_observation"]["report"]["status"] == "sink_reached"
    assert by_caller["run_it"]["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
    assert "resolved callees" in by_caller["run_it"]["disposition"]["reason"]


def test_guard_evidence_is_preserved_when_probe_is_ambiguous(tmp_path, language):
    if language == "python":
        source = ("import os\ndef check():\n    if False:\n        raise ValueError()\n"
                  "def run_it():\n    check()\n    os.system('first')\n    os.system('second')\n")
        sources = {"mod.py": source}
    else:
        sources = {"mod.cjs": "const cp=require('child_process');\nfunction check(){if(false){throw Error();}}\nfunction run_it(){check();cp.exec('first');cp.exec('second');}\nmodule.exports={run_it};\n"}
    plans = _plans(tmp_path, language, sources)
    assert len(plans) == 2
    for plan in plans:
        assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
        assert "dominates" in plan["disposition"]["reason"]
        assert "2 separate call sites" in plan["disposition"]["reason"]


def test_harvested_literals_do_not_bypass_ambiguity_gate(tmp_path):
    plans = _plans(tmp_path, "python", {"mod.py": (
        "import os\ndef run_it(command):\n    os.system(command)\n    return\n"
        "    os.system(command)\ndef driver():\n    run_it('literal')\n"
    )})
    assert len(plans) == 2
    assert all(p["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE" for p in plans)


def test_delegation_counts_all_depths_without_double_counting_shared_helpers():
    index = {"root": {"left", "right"}, "left": {"shared"}, "right": {"shared"}, "shared": {"root"}}
    counts = {"root": {"sink": 1}, "shared": {"sink": 1}}
    assert transitive_sink_symbol_counts("root", index, counts) == {"sink": 2}
    # The old MAX_DEPTH limit of six would miss the competing deep site.
    index = {f"f{i}": {f"f{i + 1}"} for i in range(20)}
    assert transitive_sink_symbol_counts("f0", index, {"f0": {"sink": 1}, "f20": {"sink": 1}}) == {"sink": 2}

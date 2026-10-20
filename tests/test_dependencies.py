"""Proves external-dependency detection: stdlib calls must NOT be flagged
(they aren't a supply-chain concern), a genuine third-party import must be,
and the transitive closure must follow delegation the same way guard
detection does."""
import tempfile
from pathlib import Path

from sentinel_zero.callgraph import build_direct_callee_index, build_direct_external_index, external_packages_reached
from sentinel_zero.resolvers.python_resolver import build_project_graph


def test_stdlib_not_flagged_third_party_is():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text(
            "import json\n"
            "import requests\n"
            "def fetch(url):\n"
            "    data = requests.get(url)\n"  # third-party
            "    return json.dumps(data)\n"  # stdlib -- must not be flagged
        )
        graph = build_project_graph(root)
        packages = {ref.package for ref in graph.external_references}
        assert packages == {"requests"}, f"expected only requests flagged, got {packages}"


def test_local_variable_method_call_not_flagged_as_dependency():
    """Regression: lines.append(x), where `lines` is a plain local list,
    must NOT be reported as a dependency on a package named 'lines'.
    Found for real while dogfooding against Block-Wise, vibe-explainer and
    Horos -- 'lines', 'text', 'totals', 'row' all showed up as top
    'external dependencies' before this was fixed."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "report.py").write_text(
            "def build(rows):\n"
            "    lines = []\n"
            "    for row in rows:\n"
            "        lines.append(row.strip())\n"
            "    return lines\n"
        )
        graph = build_project_graph(root)
        packages = {ref.package for ref in graph.external_references}
        assert packages == set(), f"expected no external deps, got {packages}"


def test_local_method_alias_not_flagged_as_dependency():
    """Regression #2: `add = lines.append; add(x)` -- the exact pattern
    found for real in vibe-explainer's consultant_report.py, 448 call
    sites. The first local-variable fix (test above) gated the *use*
    site, but the alias assignment itself stored "lines.append" as
    add's resolved value unconditionally, so every later add(...) call
    still passed the use-site check (add itself IS bound -- just to a
    bogus value)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "report.py").write_text(
            "def build(rows):\n"
            "    lines = []\n"
            "    add = lines.append\n"
            "    for row in rows:\n"
            "        add(row.strip())\n"
            "    return lines\n"
        )
        graph = build_project_graph(root)
        packages = {ref.package for ref in graph.external_references}
        assert packages == set(), f"expected no external deps, got {packages}"


def test_local_variable_renamed_alias_not_flagged_as_dependency():
    """Regression #3: `metadata = meta_payload` -- the exact pattern found
    for real in vibe-explainer's asi_matrix.py. `meta_payload` is a local
    variable (assigned from a function call, never imported); renaming it
    to `metadata` must not make `metadata.get(...)` read as a call into a
    package named "meta_payload". This is a one-hop-further version of the
    `add = lines.append` bug: that fix gated storing a resolved *Attribute*
    chain as an alias, but a bare-Name RHS (`metadata = meta_payload`) still
    fell through the old unconditional bare-Name allowance."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "loader.py").write_text(
            "def load_json(path):\n"
            "    return {}\n"
            "\n"
            "def load(path):\n"
            "    meta_payload = load_json(path)\n"
            "    metadata = meta_payload\n"
            "    return metadata.get('key')\n"
        )
        graph = build_project_graph(root)
        packages = {ref.package for ref in graph.external_references}
        assert packages == set(), f"expected no external deps, got {packages}"


def test_transitive_dependency_follows_delegation():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "net.py").write_text(
            "import requests\n"
            "def call_api(url):\n"
            "    return requests.get(url)\n"
        )
        (root / "handler.py").write_text(
            "from net import call_api\n"
            "def handle(req):\n"
            "    return call_api(req.url)\n"  # handle never imports requests itself
        )
        graph = build_project_graph(root)
        callee_index = build_direct_callee_index(graph)
        external_index = build_direct_external_index(graph)

        # handle() doesn't call requests directly -- must still show up
        # transitively, same reasoning as guard delegation.
        reached = external_packages_reached("handler.handle", graph, callee_index, external_index)
        assert reached == frozenset({"requests"}), f"expected requests reachable through delegation, got {reached}"

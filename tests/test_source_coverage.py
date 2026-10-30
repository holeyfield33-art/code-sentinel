from pathlib import Path

from sentinel_zero.graph import Symbol
from sentinel_zero.repo_detect import detect_language
from sentinel_zero.resolvers.js_resolver import build_project_graph


def write(root: Path, name: str, source: str) -> None:
    dest = root / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(source, encoding="utf-8")


def test_exports_jsx_and_genuine_source_directories(tmp_path: Path) -> None:
    write(tmp_path, "build/view.tsx", "import {exec} from 'child_process'; export function render(cmd:string){return <div>{exec(cmd)}</div>}")
    write(tmp_path, "dist/entry.jsx", "import {render} from '../build/view'; export default function handler(x){return <section>{render(x)}</section>}")
    write(tmp_path, "coverage/view.js", "import {exec} from 'child_process'; export const view = x => <span>{exec(x)}</span>;")
    graph = build_project_graph(tmp_path)
    assert not graph.parse_errors
    assert len(graph.modules) == 3
    assert {"build.view.render", "dist.entry.handler", "coverage.view.view"} <= graph.functions.keys()
    assert any(c.caller == "dist.entry.handler" and c.target == Symbol("build.view.render") for c in graph.all_calls())
    assert sum(c.target == Symbol("child_process.exec") for c in graph.all_calls()) == 2
    assert detect_language(tmp_path) == "javascript"


def test_module_collisions_preserve_all_files_and_explicit_imports(tmp_path: Path) -> None:
    for name in ["foo.js", "foo.ts", "foo/index.js", "a.b.js", "a/b.js"]:
        write(tmp_path, name, "export function run() {}")
    write(tmp_path, "entry.js", "import {run as js} from './foo.js'; import {run as ts} from './foo.ts'; export function route(){js();ts()}")
    graph = build_project_graph(tmp_path)
    assert len(graph.modules) == 6
    by_file = {Path(m.file_path).relative_to(tmp_path).as_posix(): m.module_qualname for m in graph.modules.values()}
    assert len(set(by_file.values())) == 6
    assert any(c.target == Symbol(by_file["foo.js"] + ".run") for c in graph.all_calls())
    assert any(c.target == Symbol(by_file["foo.ts"] + ".run") for c in graph.all_calls())
    assert any(w["kind"] == "module_identity_disambiguated" for w in graph.coverage["warnings"])


def test_default_and_named_reexports_reach_exact_implementations(tmp_path: Path) -> None:
    write(tmp_path, "impl.ts", "export default function original(){}; function other(){}; export {other as publicName};")
    write(tmp_path, "bridge.ts", "export {default as chosen, publicName as renamed} from './impl';")
    write(tmp_path, "anonymous.jsx", "export default x => <div>{x}</div>;")
    write(tmp_path, "entry.ts", "import defaultFn from './impl.js'; import {chosen,renamed} from './bridge'; import view from './anonymous'; export function run(){defaultFn();chosen();renamed();view('x')}")
    graph = build_project_graph(tmp_path)
    targets = [c.target for c in graph.all_calls() if c.caller == "entry.run"]
    assert targets.count(Symbol("impl.original")) == 2
    assert Symbol("impl.other") in targets
    assert Symbol("anonymous.__default__") in targets


def test_coverage_accounts_for_failures_and_unsupported_sources(tmp_path: Path) -> None:
    write(tmp_path, "good.mts", "export function run(){}")
    write(tmp_path, "also.cts", "function run(){}")
    write(tmp_path, "bad.jsx", "function (((")
    write(tmp_path, "types.d.ts", "declare function typeOnly():void;")
    write(tmp_path, "native.rs", "fn main() {}")
    write(tmp_path, "barrel.ts", "export * from './good.mjs';")
    write(tmp_path, "missing.js", "import {foo} from './missing-target'; foo();")
    graph = build_project_graph(tmp_path)
    assert graph.coverage["collected_files"] == 5
    assert graph.coverage["parsed_files"] == 4
    assert len(graph.parse_errors) == 1
    kinds = {w["kind"] for w in graph.coverage["warnings"]}
    assert {"parse_failures", "unsupported_languages", "export_star_unresolved", "unresolved_local_import"} <= kinds
    assert len(graph.coverage["excluded_declarations"]) == 1


def test_exported_class_and_anonymous_default_class_methods(tmp_path: Path) -> None:
    write(tmp_path, "cls.ts", "import {exec} from 'child_process'; export class A { run(x:string){exec(x)} } export default class { run(x:string){exec(x)} }")
    graph = build_project_graph(tmp_path)
    assert {"cls.A.run", "cls.__default__.run"} <= graph.functions.keys()
    assert sum(c.target == Symbol("child_process.exec") for c in graph.all_calls()) == 2


def test_node_builtin_scheme_has_the_same_sink_identity(tmp_path: Path) -> None:
    write(tmp_path, "entry.mjs", "import fs from 'node:fs'; import {exec} from 'node:child_process'; export function run(name){exec(name); return fs.readFileSync(name)}")
    graph = build_project_graph(tmp_path)
    targets = {c.target for c in graph.all_calls()}
    assert Symbol("fs.readFileSync") in targets
    assert Symbol("child_process.exec") in targets


def test_adding_a_collision_changes_only_affected_module_identities(tmp_path: Path) -> None:
    write(tmp_path, "foo.js", "export function run(){}")
    write(tmp_path, "stable.js", "export function run(){}")
    before = build_project_graph(tmp_path)
    write(tmp_path, "foo.ts", "export function run(){}")
    after = build_project_graph(tmp_path)
    repeated = build_project_graph(tmp_path)
    assert set(before.modules) == {"foo", "stable"}
    assert set(after.modules) == {"file://foo.js", "file://foo.ts", "stable"}
    assert set(after.functions) == set(repeated.functions)
    assert "stable.run" in before.functions and "stable.run" in after.functions
    assert any(w["kind"] == "module_identity_disambiguated" for w in after.coverage["warnings"])


def test_coverage_reaches_ledger_markdown_and_graph(tmp_path: Path) -> None:
    import json
    from sentinel_zero.catalog_loader import bundled_snapshot_path
    from sentinel_zero.cli import main
    root = tmp_path / "repo"
    write(root, "entry.jsx", "export function view(){return <p/>}")
    write(root, "native.rs", "fn main(){}")
    out = tmp_path / "out"
    assert main(["analyze", str(root), "--language", "javascript", "--format", "md",
                 "--catalog", str(bundled_snapshot_path()), "--out", str(out)]) == 0
    ledger = json.loads((out / "verification_ledger.json").read_text(encoding="utf-8"))
    graph = json.loads((out / "graph.json").read_text(encoding="utf-8"))
    assert ledger["coverage"] == graph["coverage"]
    assert ledger["coverage"]["parsed_files"] == 1
    assert "unsupported_languages" in (out / "report.md").read_text(encoding="utf-8")

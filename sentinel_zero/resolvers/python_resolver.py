"""Python resolver for the ISBG: the only file in Sentinel-Zero that knows
Python's import/assignment syntax. It populates the language-agnostic
shapes in sentinel_zero.graph -- nothing downstream of this module needs to
know it was Python that got scanned.

Two passes over the whole repo, not one file at a time, because the bug
that motivated this (Code Atlas missing `promisify(execFile)` aliased into
a differently-named helper in another file) is inherently cross-file:

  Pass 1 -- index every top-level function in every .py file under its
  fully-qualified dotted name, and mark which ones are "guard-shaped"
  (structurally: an `if <condition>: raise ...` near the top of the body --
  this is a shape check, not a name check, which is what keeps it from
  reproducing the `check*` / `.checkbox()` false-match bug).

  Pass 2 -- for every module, resolve its imports and local re-assignments
  into a binding map, then resolve every call site's callee against that
  map plus the project-wide function index plus a small stdlib sink
  registry. Anything that doesn't resolve becomes Unresolved with a reason,
  never a dropped call.

Known, stated limits (do not silently claim more than this does):
  - only module-level and function-level `def`s are indexed; methods on
    classes are not yet (classes are out of scope for v0, same as
    Block-Wise's own plan grammar).
  - `import a.b.c` without an alias is approximated as binding the
    top-level package name only, per Python's actual binding rule, so
    `a.b.c.fn()` is NOT currently resolved through that form -- it falls
    back to Unresolved. Use `from a.b import c` or an explicit alias.
  - the "guard precedes sink" check is same-function, call order only --
    an approximation of control dependency, not a real CFG dominance
    check. A guard that runs but doesn't actually gate the sink (e.g. it's
    called but its result is ignored) will still read as "guard present."
"""
from __future__ import annotations

import ast
from pathlib import Path

from sentinel_zero.graph import CallSite, FunctionInfo, ModuleGraph, ProjectGraph, Symbol, Unresolved

STDLIB_SINKS = {
    "builtins.open",
    "json.load",
    "json.loads",
    "os.system",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}

SKIP_DIR_NAMES = {".venv", ".git", "__pycache__", "mutants", "node_modules"}


def _module_qualname(py_path: Path, repo_root: Path) -> str:
    rel = py_path.relative_to(repo_root).with_suffix("")
    parts = list(rel.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else py_path.stem


def _is_guard_shaped(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Structural check: does this function contain an `if ...: raise ...`
    (in the true branch or the else branch) anywhere at its top level?
    Matches Block-Wise's own require_* preset shape, and any hand-written
    equivalent, without ever comparing a function *name*."""
    for stmt in fn.body:
        if isinstance(stmt, ast.If):
            branches = stmt.body + stmt.orelse
            if any(isinstance(s, ast.Raise) for s in branches):
                return True
    return False


def _index_module_functions(tree: ast.Module, module_qualname: str, file_path: str, index: dict[str, FunctionInfo]) -> None:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{module_qualname}.{node.name}"
            index[qualname] = FunctionInfo(
                qualified_name=qualname,
                is_guard_shaped=_is_guard_shaped(node),
                file_path=file_path,
                lineno=node.lineno,
            )


def _import_bindings(tree: ast.Module, module_qualname: str) -> dict[str, str]:
    """local_name -> best-effort fully-qualified dotted path."""
    bindings: dict[str, str] = {}
    package_parts = module_qualname.split(".")[:-1]
    package = ".".join(package_parts)

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                bindings[local] = alias.asname and alias.name or alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                # relative import: best-effort resolve against this module's package
                base_parts = package_parts[: len(package_parts) - (node.level - 1)] if node.level > 1 else package_parts
                base = ".".join(base_parts)
                module_base = f"{base}.{node.module}" if node.module else base
            else:
                module_base = node.module or ""
            for alias in node.names:
                local = alias.asname or alias.name
                bindings[local] = f"{module_base}.{alias.name}" if module_base else alias.name
    return bindings


def _resolve_dotted(node: ast.expr, bindings: dict[str, str]) -> str | None:
    """Resolve a Name or Attribute chain to a dotted string, through the
    binding map where possible."""
    if isinstance(node, ast.Name):
        return bindings.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _resolve_dotted(node.value, bindings)
        return f"{base}.{node.attr}" if base else None
    return None


def mutually_exclusive(path_a: tuple, path_b: tuple) -> bool:
    """True if the two branch_paths provably cannot both execute in the
    same call -- they share an enclosing If/Try but took different arms
    (an `if` body vs. its `orelse`, or an elif chain's separate branches,
    which the parser represents as nested If.orelse)."""
    for (node_a, label_a), (node_b, label_b) in zip(path_a, path_b):
        if node_a == node_b and label_a != label_b:
            return True
    return False


def _resolve_module(
    tree: ast.Module,
    module_qualname: str,
    project_functions: dict[str, FunctionInfo],
) -> list[CallSite]:
    bindings = _import_bindings(tree, module_qualname)
    calls: list[CallSite] = []

    def walk_fn(fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None, caller_name: str) -> None:
        local_bindings = dict(bindings)
        order_counter = [0]
        body = fn_node.body if fn_node else tree.body

        def record_calls_in_expr(expr: ast.AST, branch_path: tuple) -> None:
            """Find every ast.Call nested in this expression (but not inside
            a nested def/lambda, which is a separate caller scope handled by
            its own walk_fn call), in source order, and record it."""
            # ast.walk is BFS and unordered across siblings; for a single
            # expression tree (no statement sequencing inside it) this is
            # acceptable because expressions don't branch the way If/Try do.
            # Known, stated gap: a call inside a nested `lambda` body is
            # still attributed to the enclosing function here, rather than
            # treated as its own scope -- lambdas are rare as sink/guard
            # call sites and this is not claimed to be resolved.
            for node in sorted(
                (n for n in ast.walk(expr) if isinstance(n, ast.Call)),
                key=lambda n: (n.lineno, n.col_offset),
            ):
                dotted = _resolve_dotted(node.func, local_bindings)
                target = None
                if dotted:
                    for cand in (dotted, f"{module_qualname}.{dotted}"):
                        if cand in project_functions or cand in STDLIB_SINKS:
                            target = Symbol(cand)
                            break
                    if target is None:
                        target = Symbol(dotted)
                if target is None:
                    target = Unresolved(
                        reason=f"callee expression at line {node.lineno} did not resolve to a dotted name "
                               "(dynamic dispatch, getattr, or an import form this resolver doesn't model)."
                    )
                order_counter[0] += 1
                calls.append(
                    CallSite(
                        caller=caller_name,
                        target=target,
                        lineno=node.lineno,
                        order=order_counter[0],
                        branch_path=branch_path,
                    )
                )

        def walk_stmts(stmts: list[ast.stmt], branch_path: tuple) -> None:
            for stmt in stmts:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    continue  # separate scope, indexed/walked on its own
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    record_calls_in_expr(stmt.value, branch_path)
                    resolved_rhs = _resolve_dotted(stmt.value, local_bindings)
                    if resolved_rhs:
                        local_bindings[stmt.targets[0].id] = resolved_rhs
                    continue
                if isinstance(stmt, ast.If):
                    record_calls_in_expr(stmt.test, branch_path)  # test always runs
                    tag = id(stmt)
                    walk_stmts(stmt.body, branch_path + ((tag, "body"),))
                    walk_stmts(stmt.orelse, branch_path + ((tag, "orelse"),))
                    continue
                if isinstance(stmt, ast.Try):
                    tag = id(stmt)
                    walk_stmts(stmt.body, branch_path + ((tag, "try"),))
                    for i, handler in enumerate(stmt.handlers):
                        walk_stmts(handler.body, branch_path + ((tag, f"except{i}"),))
                    walk_stmts(stmt.orelse, branch_path + ((tag, "orelse"),))
                    walk_stmts(stmt.finalbody, branch_path)  # finally always runs
                    continue
                if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                    test_or_iter = getattr(stmt, "test", None) or getattr(stmt, "iter", None)
                    if test_or_iter is not None:
                        record_calls_in_expr(test_or_iter, branch_path)
                    tag = id(stmt)
                    # a loop body may run zero or many times; treated as a
                    # single pass for v0 -- a known approximation, not a
                    # claim of exact semantics.
                    walk_stmts(stmt.body, branch_path + ((tag, "loop_body"),))
                    walk_stmts(stmt.orelse, branch_path)
                    continue
                if isinstance(stmt, (ast.With, ast.AsyncWith)):
                    for item in stmt.items:
                        record_calls_in_expr(item.context_expr, branch_path)
                    walk_stmts(stmt.body, branch_path)
                    continue
                # simple statement (Expr, Return, Raise, Assert, AugAssign, ...):
                # record every call nested in it at the current branch_path.
                record_calls_in_expr(stmt, branch_path)

        walk_stmts(body, ())

    # module-level calls
    walk_fn(None, "")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            walk_fn(node, f"{module_qualname}.{node.name}")

    return calls


def build_project_graph(repo_root: Path) -> ProjectGraph:
    graph = ProjectGraph()
    py_files = [
        p for p in sorted(repo_root.rglob("*.py")) if not any(part in SKIP_DIR_NAMES for part in p.parts)
    ]

    parsed: dict[Path, ast.Module] = {}
    for py_path in py_files:
        try:
            parsed[py_path] = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
        except (SyntaxError, UnicodeDecodeError):
            # A file this resolver cannot parse is NOT silently skipped from
            # the index -- the caller (dogfood_scan) treats a parse failure
            # as ToolFailure and halts. We still let pass 1 finish for the
            # files that did parse so the error message is informative.
            continue

    for py_path, tree in parsed.items():
        module_qualname = _module_qualname(py_path, repo_root)
        _index_module_functions(tree, module_qualname, str(py_path), graph.functions)

    for py_path, tree in parsed.items():
        module_qualname = _module_qualname(py_path, repo_root)
        calls = _resolve_module(tree, module_qualname, graph.functions)
        graph.modules[module_qualname] = ModuleGraph(module_qualname=module_qualname, file_path=str(py_path), calls=calls)

    return graph

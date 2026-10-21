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
  - Milestone 11: class method bodies ARE walked for call-site recording
    (not just indexed). Milestone 12 extended this to bind both `self`
    AND `cls` to the owning class's qualname for that walk, so both
    `self.foo()` and `cls.foo()` (classmethod dispatch) resolve to the
    real indexed method, the same way an import binding resolves a
    module alias. Not modeled: a method called on a SUBCLASS resolves to
    the DEFINING class's method, not the subclass's override, the same
    way `self` already approximates -- real dynamic dispatch through
    inheritance is a different, harder question, not claimed here.
  - `import a.b.c` without an alias is approximated as binding the
    top-level package name only, per Python's actual binding rule, so
    `a.b.c.fn()` is NOT currently resolved through that form -- it falls
    back to Unresolved. Use `from a.b import c` or an explicit alias.
  - the "guard precedes sink" check is same-function, call order only --
    an approximation of control dependency, not a real CFG dominance
    check. A guard that runs but doesn't actually gate the sink (e.g. it's
    called but its result is ignored) will still read as "guard present."
  - Milestone 12 tightened WHICH structural shape counts as blocking a
    DELEGATE's caller: callgraph.transitively_guard_shaped now requires
    FunctionInfo.raises_on_guard (an actual `raise`), not the broader
    is_guard_shaped (raise-OR-return), for exactly this reason -- a
    `return` inside a called-as-a-delegate function only ends that
    function's own body, never the caller's, so it was never real
    evidence that the caller's next statement (the sink) is blocked. See
    graph.py's FunctionInfo.raises_on_guard docstring for the full
    reasoning. is_guard_shaped (raise-OR-return) is still correct for the
    SAME-function dispatch shape (a wrapper's own __call__/__init__
    checking itself before forwarding) -- unchanged, not affected by this.
"""
from __future__ import annotations

import ast
from pathlib import Path

import sys

from sentinel_zero.callgraph import find_wrap_constructions
from sentinel_zero.graph import (
    CallSite,
    ExternalReference,
    FunctionInfo,
    ModuleGraph,
    ProjectGraph,
    Symbol,
    Unresolved,
    WrapperClass,
)

try:
    _STDLIB_MODULE_NAMES = set(sys.stdlib_module_names)  # Python >= 3.10
except AttributeError:  # pragma: no cover - older Python fallback
    _STDLIB_MODULE_NAMES = set(sys.builtin_module_names)
_STDLIB_MODULE_NAMES.add("builtins")

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
    """Structural check: does this function contain a top-level `if` whose
    true or else branch ends in an early exit (`raise` or `return`)?

    Broadened from Milestone 2's raise-only check specifically because of
    Horos's real BearerAuthMiddleware.__call__:

        if not self._authorized(scope):
            await self._reject(send)
            return
        await self._app(scope, receive, send)

    That is a guard -- it's the exact pattern this whole effort traces
    back to -- but it has no `raise` anywhere, only an early `return`.
    Matches Block-Wise's require_* preset shape too (which does raise),
    and any hand-written equivalent of either -- never a function *name*.
    """
    for stmt in fn.body:
        if isinstance(stmt, ast.If):
            branches = stmt.body + stmt.orelse
            if any(isinstance(s, (ast.Raise, ast.Return)) for s in branches):
                return True
    return False


def _is_raise_guard_shaped(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Stricter sibling of _is_guard_shaped, used only for the DELEGATION
    case -- another function calling `fn` and trusting its shape to
    protect that CALLER's own control flow (see FunctionInfo.raises_on_guard
    in graph.py for the full reasoning). Requires a `raise`, not a plain
    `return`, in the early-exit branch: a `return` inside `fn` only ends
    `fn`'s own execution, never the caller's -- the caller's next statement
    runs regardless unless it checks `fn`'s return value, which this
    resolver does not model. A `raise` genuinely propagates into the
    caller (absent an enclosing try/except, also not modeled, same
    approximation `transitively_guard_shaped`'s docstring already states).

    is_guard_shaped (raise-OR-return) remains the right check for the
    SAME-function dispatch case (Milestone 4/9/10's wrapper detection,
    e.g. Horos's own `__call__`): there, a `return` really does stop that
    same function's next statement, because it's the SAME execution."""
    for stmt in fn.body:
        if isinstance(stmt, ast.If):
            branches = stmt.body + stmt.orelse
            if any(isinstance(s, ast.Raise) for s in branches):
                return True
    return False


def _init_wrapped_param_index(init_fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[int, str] | None:
    """If __init__ stores one of its own (non-self) parameters directly
    onto an attribute (`self._app = app`), return (that parameter's
    position among non-self params, the attribute name). This is the
    generic shape of "a wrapper that holds onto the thing it wraps" --
    no attribute or parameter name is hardcoded."""
    params = [a.arg for a in init_fn.args.args if a.arg != "self"]
    for stmt in ast.walk(init_fn):
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Attribute)
            and isinstance(stmt.targets[0].value, ast.Name)
            and stmt.targets[0].value.id == "self"
            and isinstance(stmt.value, ast.Name)
            and stmt.value.id in params
        ):
            return params.index(stmt.value.id), stmt.targets[0].attr
    return None


def _dispatch_forwards_to(method: ast.FunctionDef | ast.AsyncFunctionDef, wrapped_attr: str) -> bool:
    """Does this method, anywhere in its body, call self.<wrapped_attr>(...)?"""
    for node in ast.walk(method):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == wrapped_attr
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
        ):
            return True
    return False


def _index_module_functions(
    tree: ast.Module,
    module_qualname: str,
    file_path: str,
    index: dict[str, FunctionInfo],
    wrapper_classes: dict[str, WrapperClass],
) -> None:
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualname = f"{module_qualname}.{node.name}"
            index[qualname] = FunctionInfo(
                qualified_name=qualname,
                is_guard_shaped=_is_guard_shaped(node),
                raises_on_guard=_is_raise_guard_shaped(node),
                file_path=file_path,
                lineno=node.lineno,
            )
        elif isinstance(node, ast.ClassDef):
            class_qualname = f"{module_qualname}.{node.name}"
            init_fn = call_fn = None
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    member_qualname = f"{class_qualname}.{member.name}"
                    index[member_qualname] = FunctionInfo(
                        qualified_name=member_qualname,
                        is_guard_shaped=_is_guard_shaped(member),
                        raises_on_guard=_is_raise_guard_shaped(member),
                        file_path=file_path,
                        lineno=member.lineno,
                    )
                    if member.name == "__init__":
                        init_fn = member
                    elif member.name == "__call__":
                        call_fn = member
            if init_fn is not None and call_fn is not None:
                wrapped = _init_wrapped_param_index(init_fn)
                if wrapped is not None:
                    param_index, attr = wrapped
                    if _dispatch_forwards_to(call_fn, attr):
                        wrapper_classes[class_qualname] = WrapperClass(
                            qualified_name=class_qualname,
                            wrapped_param_index=param_index,
                            dispatch_method=f"{class_qualname}.__call__",
                            dispatch_is_guarded=_is_guard_shaped(call_fn),
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


def _root_name_is_bound(node: ast.expr, bindings: dict[str, str]) -> bool:
    """True only if the leftmost name in an attribute chain (`x` in
    `x.y.z`) is something we can actually prove came from an import or a
    resolved re-assignment -- not a bare fallback. Needed because
    `_resolve_dotted` deliberately falls back to returning an unbound bare
    name verbatim (required so a same-module call like `handle(req)`
    still resolves against the project function index), but that same
    fallback would otherwise make an ordinary method call on a local
    variable (`lines.append(x)`) indistinguishable from a real
    `module.function()` reference -- confirmed as a real false-positive
    generator (local names like 'lines', 'text', 'row' were showing up as
    'external dependencies') before this check was added."""
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name) and node.id in bindings


def _resolve_dotted(node: ast.expr, bindings: dict[str, str]) -> str | None:
    """Resolve a Name or Attribute chain to a dotted string, through the
    binding map where possible."""
    if isinstance(node, ast.Name):
        return bindings.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _resolve_dotted(node.value, bindings)
        return f"{base}.{node.attr}" if base else None
    return None


def _alias_rhs_is_trustworthy(
    value_node: ast.expr,
    resolved_rhs: str,
    bindings: dict[str, str],
    project_functions: dict[str, "FunctionInfo"],
    module_qualname: str,
) -> bool:
    """Decides whether `alias = <value_node>` is safe to record in the
    binding map as `alias -> resolved_rhs`.

    `_resolve_dotted`'s unbound-Name fallback (it returns the bare name
    itself when there's no binding) is deliberate and needed elsewhere --
    without it, a same-module call like `handle(req)` couldn't resolve
    against the project function index. But that same fallback makes
    `_resolve_dotted` return a *string that looks resolved* even for a
    plain local variable (`add = lines.append` resolves to the string
    "lines.append" even though `lines` is a local list). This helper is
    the one place that decides whether to actually trust that string
    enough to propagate it as an alias, rather than just using it for the
    one expression it came from.

    Trusted in exactly two cases, both genuinely resolved rather than bare
    fallback: the RHS's root name is already bound (an import or a
    previously-trusted alias -- `_root_name_is_bound` covers Attribute
    chains; the plain-Name case is checked directly below), or the RHS
    names a real project function (so `handle = some_helper` keeps working
    for call-target resolution). Anything else -- in particular a bare,
    never-bound local variable name surviving only via the fallback --
    is rejected.

    Found for real while dogfooding vibe-explainer: `metadata = meta_payload`
    (where meta_payload is a local variable, never imported) let `metadata`
    inherit the bare string "meta_payload", and a later `metadata.get(...)`
    call then passed the root-bound check on `metadata` itself -- reporting
    a fake dependency on a package named "meta_payload". Confirmed this is
    a different call site, caught by a second round of dogfooding after the
    first alias fix (`add = lines.append`) was already in place.
    """
    if isinstance(value_node, ast.Name):
        if value_node.id in bindings:
            return True  # chains to something already trusted
    elif _root_name_is_bound(value_node, bindings):
        return True  # Attribute chain rooted in something already trusted
    return resolved_rhs in project_functions or f"{module_qualname}.{resolved_rhs}" in project_functions


def _param_names(fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None) -> frozenset[str]:
    if fn_node is None:
        return frozenset()
    args = fn_node.args
    names = {a.arg for a in args.posonlyargs + args.args + args.kwonlyargs}
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return frozenset(names)


def _combine_taint(classifications: list[str]) -> str:
    """parameter beats unknown beats literal: if any piece of a composite
    expression (an f-string, a list literal, a `+` concatenation) traces to
    a parameter, the whole thing does; otherwise if any piece can't be
    classified, the whole thing can't either -- only an expression built
    ENTIRELY from literals is reported as a literal."""
    if not classifications:
        return "literal"  # an empty list/tuple literal has nothing to taint
    if "parameter" in classifications:
        return "parameter"
    if "unknown" in classifications:
        return "unknown"
    return "literal"


def _classify_arg_taint(node: ast.expr, param_names: frozenset[str]) -> str:
    """Classifies one call argument expression by real AST structure --
    never by re-parsing source text. See graph.py's CallSite.arg_taint for
    the full contract and its stated bound (this is not interprocedural
    taint tracking)."""
    if isinstance(node, ast.Constant):
        return "literal"
    if isinstance(node, ast.JoinedStr):  # f-string
        return _combine_taint([_classify_arg_taint(v, param_names) for v in node.values])
    if isinstance(node, ast.FormattedValue):
        return _classify_arg_taint(node.value, param_names)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _combine_taint([_classify_arg_taint(e, param_names) for e in node.elts])
    if isinstance(node, ast.Dict):
        parts = [v for v in node.values if v is not None] + [k for k in node.keys if k is not None]
        return _combine_taint([_classify_arg_taint(p, param_names) for p in parts])
    if isinstance(node, ast.BinOp):  # e.g. string concatenation with `+`
        return _combine_taint([
            _classify_arg_taint(node.left, param_names),
            _classify_arg_taint(node.right, param_names),
        ])
    if isinstance(node, ast.UnaryOp):
        return _classify_arg_taint(node.operand, param_names)
    if isinstance(node, ast.Name):
        return "parameter" if node.id in param_names else "unknown"
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        base = node.value
        while isinstance(base, (ast.Attribute, ast.Subscript)):
            base = base.value
        if isinstance(base, ast.Name):
            return "parameter" if base.id in param_names else "unknown"
        return "unknown"
    return "unknown"  # a call result, comprehension, lambda, walrus, ... -- not modeled


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
    project_top_level_names: set[str],
    file_path: str,
    external_refs: list[ExternalReference],
) -> list[CallSite]:
    bindings = _import_bindings(tree, module_qualname)
    calls: list[CallSite] = []

    def walk_fn(
        fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None,
        caller_name: str,
        extra_bindings: dict[str, str] | None = None,
    ) -> None:
        local_bindings = dict(bindings)
        if extra_bindings:
            local_bindings.update(extra_bindings)
        order_counter = [0]
        body = fn_node.body if fn_node else tree.body
        param_names = _param_names(fn_node)

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
                elif isinstance(target, Symbol) and "." in target.qualified_name:
                    top_level = target.qualified_name.split(".", 1)[0]
                    if (
                        target.qualified_name not in project_functions
                        and top_level not in project_top_level_names
                        and top_level not in _STDLIB_MODULE_NAMES
                        and _root_name_is_bound(node.func, local_bindings)
                    ):
                        external_refs.append(
                            ExternalReference(
                                caller=caller_name,
                                package=top_level,
                                qualified_name=target.qualified_name,
                                file_path=file_path,
                                lineno=node.lineno,
                            )
                        )
                try:
                    arg_texts = tuple(ast.unparse(a) for a in node.args)
                except Exception:
                    arg_texts = ()
                arg_taint = tuple(_classify_arg_taint(a, param_names) for a in node.args)
                order_counter[0] += 1
                calls.append(
                    CallSite(
                        caller=caller_name,
                        target=target,
                        lineno=node.lineno,
                        order=order_counter[0],
                        args=arg_texts,
                        arg_taint=arg_taint,
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
                    # Only propagate the alias when it's actually trustworthy
                    # -- see _alias_rhs_is_trustworthy's docstring for the two
                    # real false-positives (`add = lines.append` and
                    # `metadata = meta_payload`) this gate exists to block.
                    if resolved_rhs and _alias_rhs_is_trustworthy(
                        stmt.value, resolved_rhs, local_bindings, project_functions, module_qualname
                    ):
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
        elif isinstance(node, ast.ClassDef):
            # Milestone 11: class method bodies are walked for CallSite
            # recording too -- the pre-existing gap logged in Milestone 6's
            # commit and pinned by
            # test_class_method_sink_is_not_probed_and_is_not_even_a_finding_yet
            # (a sink call inside ANY method produced zero finding plans,
            # not even UNRESOLVED_INCONCLUSIVE). `self` is bound to the
            # owning class's qualname for the duration of this one method's
            # walk, so `self.foo(...)` resolves to the exact qualname
            # _index_module_functions already indexed it under
            # ("module.Class.foo"), the same way an import binds a module
            # alias -- no new resolution mechanism, just one more binding.
            #
            # Milestone 12: `cls` is bound the same way, closing the
            # `cls.foo()` (classmethod dispatch) gap this file used to
            # document as explicitly deferred. Both names are bound
            # unconditionally, regardless of which the method actually
            # declares (a plain instance method never has a `cls` in its
            # body to collide with, and vice versa) -- harmless, and
            # avoids having to detect the @classmethod decorator to know
            # which one applies. Same approximation `self` already makes:
            # this resolves to the DEFINING class, not whatever subclass
            # the method might actually be called on at runtime through
            # inheritance -- a real dynamic-dispatch nuance, not modeled,
            # same bound this resolver already states for self.
            class_qualname = f"{module_qualname}.{node.name}"
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    walk_fn(
                        member,
                        f"{class_qualname}.{member.name}",
                        extra_bindings={"self": class_qualname, "cls": class_qualname},
                    )

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
        except (SyntaxError, UnicodeDecodeError) as exc:
            # A file this resolver cannot parse is NOT silently dropped from
            # the run -- recorded on the graph (mirrors js_resolver.py's
            # per-file errors; graph.py's own stated rule is that an
            # unresolved/unparseable thing must surface, never vanish).
            # Found while adding the JS resolver: this `except` used to just
            # `continue` with a comment claiming the caller halted on it --
            # it never did. The rest of the project proceeds with the files
            # that did parse; that choice is now a visible fact, not a
            # silent one.
            graph.parse_errors.append({"file_path": str(py_path), "error": f"{type(exc).__name__}: {exc}"})
            continue

    for py_path, tree in parsed.items():
        module_qualname = _module_qualname(py_path, repo_root)
        _index_module_functions(tree, module_qualname, str(py_path), graph.functions, graph.wrapper_classes)

    project_top_level_names = {_module_qualname(p, repo_root).split(".", 1)[0] for p in parsed}

    for py_path, tree in parsed.items():
        module_qualname = _module_qualname(py_path, repo_root)
        calls = _resolve_module(
            tree, module_qualname, graph.functions, project_top_level_names, str(py_path), graph.external_references
        )
        graph.modules[module_qualname] = ModuleGraph(module_qualname=module_qualname, file_path=str(py_path), calls=calls)

    # Pass 3: anywhere a known WrapperClass is instantiated, record what it
    # wrapped. Shared with js_resolver.py -- see callgraph.find_wrap_constructions
    # for why this moved out of here (it was always language-agnostic).
    graph.wrap_constructions = find_wrap_constructions(graph)

    return graph

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
  - the "guard precedes sink" check (Milestone 19) is real CFG dominance
    for If/Try nesting -- see dominates()'s own docstring -- not just an
    approximation of control dependency anymore. Still bounded: a loop
    body is one undifferentiated branch tag regardless of iteration count
    (zero-or-many semantics not modeled), and a guard that runs but
    doesn't actually gate the sink in a way this resolver can see (e.g.
    it's called but its boolean result is read and ignored, rather than
    the guard itself raising) will still read as "guard present" if it
    structurally raises on an early-exit condition -- dominance proves the
    CALL happens, not that its condition ties to attacker-controlled
    input.
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
    "os.open",
    "codecs.open",
    "io.open",
    "builtins.eval",
    "builtins.exec",
    "json.load",
    "json.loads",
    "pickle.load",
    "pickle.loads",
    "yaml.load",
    "os.system",
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
}

# Milestone 15: the bare names of Python builtins this tool treats as
# sinks. A bare call to one of these (`open(...)`, `eval(...)`, `exec(...)`)
# has NO import statement to bind it -- it is simply a global name that was
# never rebound in this module -- so `_resolve_dotted`'s unbound-Name
# fallback (see its own docstring) correctly returns the bare string
# "open", never "builtins.open". Before this set existed, that meant
# "builtins.open" in STDLIB_SINKS was dead data: nothing a bare `open(...)`
# call ever produced could match it, and there was no test that caught
# this (confirmed by grepping tests/ for "builtins.open" -- zero hits).
# record_calls_in_expr below checks this set, for exactly the bare-Name
# case where _resolve_dotted's fallback fired (the name is not in this
# function's own binding map), to re-resolve to the builtin's real
# qualified identity before falling through to the plain bare-name Symbol.
_BUILTIN_SINK_NAMES = {"open", "eval", "exec"}

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


def _ends_in_exit(stmts: list[ast.stmt]) -> bool:
    """True when a branch unconditionally leaves the code that follows the
    `if`: its last statement is raise/return (leaves the function) or
    continue/break (leaves this loop iteration or the loop). Used for the
    caller-side guard shape `if not valid(x): raise`, where the predicate
    itself only returns a bool and so is not guard-shaped on its own."""
    return bool(stmts) and isinstance(stmts[-1], (ast.Raise, ast.Return, ast.Continue, ast.Break))


def _decisive_guard_calls(test: ast.expr, exiting: str) -> frozenset:
    """ids of the calls in an `if` test that always run and whose result
    alone can trigger the exit, so execution continuing past the `if`
    proves each one returned the passing value.

    Exit in the body: the test is a call, `not call`, or an `or` of those
    (continuing means every disjunct was evaluated and was false). Exit in
    the else: a call, `not call`, or an `and` of those. Anything else --
    `strict and not ok(p)`, nested boolean logic, a call buried in an
    argument -- yields nothing, because the call may be skipped or may not
    decide the exit (`if strict and not ok(p): return` does not validate p
    when strict is false)."""
    def atom(expr: ast.expr) -> int | None:
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            expr = expr.operand
        return id(expr) if isinstance(expr, ast.Call) else None

    if not exiting:
        return frozenset()
    if isinstance(test, ast.BoolOp):
        if not isinstance(test.op, ast.Or if exiting == "body" else ast.And):
            return frozenset()
        return frozenset(i for i in (atom(v) for v in test.values) if i is not None)
    single = atom(test)
    return frozenset({single}) if single is not None else frozenset()


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


def _direct_nested_function_defs(
    stmts: list[ast.stmt],
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Function defs that belong to THIS scope -- found by walking through
    control-flow constructs (if/try/for/while/with) exactly the way
    _resolve_module's own walk_stmts does for CallSites, but collecting
    FunctionDef/AsyncFunctionDef nodes instead. Stops at a nested
    FunctionDef/AsyncFunctionDef/ClassDef boundary without descending into
    it -- each of those is a separate scope, indexed by its own recursive
    call in _index_function_and_nested below, never flattened into this
    one's result."""
    found: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.append(stmt)
        elif isinstance(stmt, ast.ClassDef):
            continue  # a nested class remains out of scope for this pass
        elif isinstance(stmt, ast.If):
            found += _direct_nested_function_defs(stmt.body)
            found += _direct_nested_function_defs(stmt.orelse)
        elif isinstance(stmt, ast.Try):
            found += _direct_nested_function_defs(stmt.body)
            for handler in stmt.handlers:
                found += _direct_nested_function_defs(handler.body)
            found += _direct_nested_function_defs(stmt.orelse)
            found += _direct_nested_function_defs(stmt.finalbody)
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            found += _direct_nested_function_defs(stmt.body)
            found += _direct_nested_function_defs(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            found += _direct_nested_function_defs(stmt.body)
        elif isinstance(stmt, ast.Match):
            # Codex review, PR #7: `match value: case ...: def inner():
            # ...` is real, supported Python 3.10+ syntax -- a case body is
            # just another list of statements, same as an If branch, and a
            # function def inside one still belongs to the enclosing
            # scope, not a separate one.
            for case in stmt.cases:
                found += _direct_nested_function_defs(case.body)
    return found


def _index_function_and_nested(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    qualname: str,
    file_path: str,
    index: dict[str, FunctionInfo],
) -> None:
    """Milestone (remediation item 5, VERIFICATION_LEDGER.md
    sz-2026-10-21-05): indexes `node` itself, then recurses into any
    function nested inside it -- at any depth, inside any control-flow
    construct -- giving each one a qualname of its own that mirrors
    Python's own __qualname__ convention for a nested function
    (`module.outer.<locals>.inner`). Before this, a nested function had
    NO entry in `project_functions` at all, so a sink call inside one
    could never resolve to a real caller -- it simply vanished, producing
    zero finding plans, not even UNRESOLVED_INCONCLUSIVE."""
    index[qualname] = FunctionInfo(
        qualified_name=qualname,
        is_guard_shaped=_is_guard_shaped(node),
        raises_on_guard=_is_raise_guard_shaped(node),
        file_path=file_path,
        lineno=node.lineno,
    )
    for nested in _direct_nested_function_defs(node.body):
        _index_function_and_nested(nested, f"{qualname}.<locals>.{nested.name}", file_path, index)


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
            _index_function_and_nested(node, qualname, file_path, index)
        elif isinstance(node, ast.ClassDef):
            class_qualname = f"{module_qualname}.{node.name}"
            init_fn = call_fn = None
            for member in node.body:
                if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    member_qualname = f"{class_qualname}.{member.name}"
                    _index_function_and_nested(member, member_qualname, file_path, index)
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

    for node in _scope_nodes(tree.body):
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


def _scope_nodes(body: list[ast.stmt]):
    """Walk one lexical scope, excluding bodies of child scopes."""
    def visit(node):
        yield node
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            return
        for child in ast.iter_child_nodes(node):
            yield from visit(child)
    for stmt in body:
        yield from visit(stmt)


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
    """parameter beats traced:parameter beats unknown beats traced:literal
    beats literal (the same five-tier order _taint_note documents in
    dogfood_scan.py): if any piece of a composite expression (an f-string,
    a list literal, a `+` concatenation) traces to a parameter, the whole
    thing does; a one-hop traced parameter is the next-strongest signal;
    otherwise if any piece can't be classified, the whole thing can't
    either; a one-hop traced literal is weaker evidence than that but
    still stronger than nothing; only an expression built ENTIRELY from
    literals is reported as a literal. Without this, a composite wrapping
    a traced:parameter/traced:literal constituent (e.g.
    `subprocess.run([sanitize(cmd)])` where `cmd` is a parameter) would
    fall through every explicit check and silently report as the weakest
    possible "literal" -- found by Codex review on the PR that introduced
    traced:parameter/traced:literal, confirmed real against this exact
    case."""
    if not classifications:
        return "literal"  # an empty list/tuple literal has nothing to taint
    if "parameter" in classifications:
        return "parameter"
    if "traced:parameter" in classifications:
        return "traced:parameter"
    if "unknown" in classifications:
        return "unknown"
    if "traced:literal" in classifications:
        return "traced:literal"
    return "literal"


def _is_immutable_constant(node: ast.expr) -> bool:
    """A value built only from immutable constants (str, bytes, numbers,
    None, f-strings and tuples of them). A literal list, set or dict can be
    mutated in place without rebinding its name (`cmd.append(x)`), so it
    never counts."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return all(_is_immutable_constant(v) for v in node.values)
    if isinstance(node, ast.FormattedValue):
        return _is_immutable_constant(node.value)
    if isinstance(node, ast.Tuple):
        return all(_is_immutable_constant(e) for e in node.elts)
    if isinstance(node, ast.BinOp):
        return _is_immutable_constant(node.left) and _is_immutable_constant(node.right)
    if isinstance(node, ast.UnaryOp):
        return _is_immutable_constant(node.operand)
    return False


def _constant_locals(fn_node: ast.FunctionDef | ast.AsyncFunctionDef, param_names: frozenset[str]) -> frozenset[str]:
    """Local names that hold the same constant wherever they are read: every
    binding of the name in this scope is a plain `name = <constant>` (or an
    annotated one) with an immutable value, it is not a parameter, and nothing declares it global or
    nonlocal, here or in a nested scope. Any other binding (augmented, loop,
    `with ... as`, walrus, import, def, except, match capture) disqualifies it,
    so a constant on only some paths never counts. Module-level constants are
    not covered (a separate, known gap)."""
    nodes = list(_scope_nodes(fn_node.body))
    literal_stores: dict[str, int] = {}
    for node in nodes:
        target = value = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        if isinstance(target, ast.Name) and value is not None and _is_immutable_constant(value):
            literal_stores[target.id] = literal_stores.get(target.id, 0) + 1
    stores: dict[str, int] = {}
    other: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            stores[node.id] = stores.get(node.id, 0) + 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not fn_node:
            other.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            other.update((a.asname or a.name).split(".")[0] for a in node.names)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            other.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            other.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            other.add(node.rest)
    for node in ast.walk(fn_node):  # nested scopes too: `nonlocal x` rebinds ours
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            other.update(node.names)
        # A walrus inside a comprehension binds the enclosing function's name,
        # and _scope_nodes skips comprehension bodies. Any walrus target,
        # wherever it sits, disqualifies the name (conservative).
        elif isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
            other.add(node.target.id)
    return frozenset(name for name, count in literal_stores.items()
                     if stores.get(name) == count and name not in other and name not in param_names)


def _classify_arg_taint(
    node: ast.expr, param_names: frozenset[str], *, allow_call_unwrap: bool = True,
    constants: frozenset[str] = frozenset(),
) -> str:
    """Classifies one call argument expression by real AST structure --
    never by re-parsing source text. See graph.py's CallSite.arg_taint for
    the full contract and its stated bound (this is not interprocedural
    taint tracking).

    `allow_call_unwrap` gates the one-hop widening added for
    .spec/arg-taint-one-hop-widening.md: when the argument expression
    itself IS a call (e.g. `json.loads(path.read_text())` -- the inner
    call written inline as the argument, not a prior assignment the
    classifier would have to trace backward through a function body to
    find), look at what THAT call's own receiver/arguments resolve to,
    one hop, via _classify_call_result_taint. That helper always recurses
    with allow_call_unwrap=False, so a receiver/argument that is itself
    another call result lands on the "unknown" catch-all below rather
    than being unwrapped a second time -- the explicit, stated bound this
    spec requires. Deliberately NOT inline/immediate-assignment dataflow
    either: `data = path.read_text(); json.loads(data)` still classifies
    `data` as a bare ast.Name ("parameter" if it happens to be one,
    "unknown" otherwise) exactly as before -- this widening only reaches
    the inline-nested-call shape, not a prior statement's binding."""
    if isinstance(node, ast.Constant):
        return "literal"
    if isinstance(node, ast.JoinedStr):  # f-string
        return _combine_taint([_classify_arg_taint(v, param_names, constants=constants) for v in node.values])
    if isinstance(node, ast.FormattedValue):
        return _classify_arg_taint(node.value, param_names, constants=constants)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _combine_taint([_classify_arg_taint(e, param_names, constants=constants) for e in node.elts])
    if isinstance(node, ast.Dict):
        parts = [v for v in node.values if v is not None] + [k for k in node.keys if k is not None]
        return _combine_taint([_classify_arg_taint(p, param_names, constants=constants) for p in parts])
    if isinstance(node, ast.BinOp):  # e.g. string concatenation with `+`
        return _combine_taint([
            _classify_arg_taint(node.left, param_names, constants=constants),
            _classify_arg_taint(node.right, param_names, constants=constants),
        ])
    if isinstance(node, ast.UnaryOp):
        return _classify_arg_taint(node.operand, param_names, constants=constants)
    if isinstance(node, ast.Name):
        if node.id in param_names:
            return "parameter"
        return "literal" if node.id in constants else "unknown"
    if isinstance(node, (ast.Attribute, ast.Subscript)):
        base = node.value
        while isinstance(base, (ast.Attribute, ast.Subscript)):
            base = base.value
        if isinstance(base, ast.Name):
            return "parameter" if base.id in param_names else "unknown"
        return "unknown"
    if isinstance(node, ast.Call) and allow_call_unwrap:
        return _classify_call_result_taint(node, param_names, constants)
    return "unknown"  # a call result (already unwrapped once, or unwrap disallowed), comprehension, lambda, walrus, ... -- not modeled


def _classify_call_result_taint(node: ast.Call, param_names: frozenset[str], constants: frozenset[str] = frozenset()) -> str:
    """The one-hop widening itself: classifies the result of a call used
    directly AS an argument expression, by looking at what that inner
    call's own receiver AND arguments (`receiver.method(arg, ...)`) or,
    for a plain function call, just its arguments (`func(arg, ...)`)
    resolve to -- with allow_call_unwrap=False on that lookup, so a
    receiver/argument that is itself a call result stays "unknown" rather
    than recursing past one hop. A method call's own arguments are
    inspected alongside its receiver (not receiver-only) because the
    taint-carrying value is routinely the argument, not the receiver --
    `json.loads(base64.b64decode(request))`'s `request` is exactly this
    shape, and receiver-only missed it (found by Codex review on the PR
    that introduced this function, confirmed real against that exact
    example).

    Priority among the constituents mirrors _combine_taint's own real
    order (parameter > unknown > literal, not literal before unknown):
    `parameter` -> `traced:parameter`; else any `unknown` constituent
    -> plain `unknown` (not every constituent is provably literal, so
    this must not be reported as the weaker `traced:literal`); only when
    every constituent is literal -> `traced:literal`. The original
    (literal-checked-before-unknown) version wrongly reported
    `json.loads(build(GLOBAL_VALUE, "suffix"))` as `traced:literal` even
    though `GLOBAL_VALUE` is unresolved -- also found by Codex review,
    confirmed real against that exact example."""
    if isinstance(node.func, ast.Attribute):
        constituents = [node.func.value, *node.args]
    elif isinstance(node.func, ast.Name):
        constituents = list(node.args)
    else:
        return "unknown"  # e.g. a call on another call's own result, (f())() -- not modeled
    if not constituents:
        return "unknown"  # a zero-arg plain function call, e.g. get_path() -- nothing to trace
    classifications = [_classify_arg_taint(c, param_names, allow_call_unwrap=False, constants=constants) for c in constituents]
    if "parameter" in classifications:
        return "traced:parameter"
    if "unknown" in classifications:
        return "unknown"
    return "traced:literal"


def dominates(guard_path: tuple, sink_path: tuple) -> bool:
    """Milestone 19: real CFG dominance for the guard-precedes-sink check,
    replacing the old order+mutually_exclusive heuristic entirely (that
    function is gone -- this one subsumes everything it caught, plus the
    real gap it missed; see below).

    branch_path (graph.py's CallSite.branch_path) is already a root-to-leaf
    chain of (If/Try node id, branch label) pairs, built by walk_stmts via
    strict recursive descent -- outermost ancestor first, innermost branch
    last. Because of that, "does every control-flow path that can reach
    the sink call also pass through the guard call" reduces to a simple,
    exact structural test for If/Try nesting (loops are a separate, already
    -stated approximation -- see module docstring): `guard_path` dominates
    `sink_path` iff `guard_path` is a literal PREFIX of `sink_path` --
    i.e. every (node, label) pair the guard call had to pass through to be
    reached is ALSO on the sink call's own path. An empty guard_path (a
    top-level, unconditional statement) is trivially a prefix of anything,
    which is correct: an unconditional statement really does run before
    any nested one that follows it. The CALLER is still responsible for
    also checking call ORDER (`earlier.order < call.order`) -- this
    function only answers "is guard_path a real ancestor scope of
    sink_path," not "did the guard call happen first" (two calls at
    exactly the same branch_path, i.e. sequential siblings, still need the
    order check to tell which ran first).

    This is a strictly more accurate replacement for the bug the old
    `mutually_exclusive` + order check actually had: `mutually_exclusive`
    only caught two paths that shared an ancestor node but took DIFFERENT
    arms (an `if` vs. its `orelse`) -- it said nothing about a guard that
    is simply MORE nested (less certain to run) than the sink. Confirmed
    directly before this was written:

        def f(x):
            if x:
                require_admin(x)     # branch_path = [(if_node, "body")]
            sink(x)                   # branch_path = ()

    The old check: `earlier.order < call.order` is True (guard comes
    first in source), and `mutually_exclusive((if_node,"body"), ())` is
    False (the zip over mismatched-length tuples never finds a shared
    node to diverge on) -- so the old code wrongly read this as "guard
    precedes sink," even though `sink(x)` runs unconditionally and
    `require_admin` only runs when `x` is truthy. `dominates` correctly
    returns False here: `()[: len([(if_node,"body")])]` is `()`, which is
    not equal to `[(if_node,"body")]`, so the guard's path is not a prefix
    of the sink's path, and the guard is (correctly) not credited with
    protecting this sink.

    The symmetric, correctly-still-passing case:

        def f(x):
            require_admin(x)          # branch_path = ()
            if y:
                sink(x)                # branch_path = [(if_node, "body")]

    `dominates((), [(if_node,"body")])`: `[(if_node,"body")][:0] == ()` --
    True. `require_admin` really does run on every path that can reach
    `sink`, so this still, correctly, reads as a guard hit.

    Still bounded, still stated plainly: this proves the guard CALL
    genuinely executes before the sink on every path -- it does not (and
    cannot, from static structure alone) prove the guard's own internal
    condition corresponds to attacker-controlled input, which is exactly
    why a dominance hit still only promotes to UNRESOLVED_INCONCLUSIVE,
    never VERIFIED_FALSE (see dogfood_scan.py's guard_hit reason text).
    Loop bodies still get one undifferentiated `loop_body` branch tag
    (zero-or-many-iterations semantics not modeled, per the module
    docstring's existing stated bound) -- a guard inside a loop and a
    sink after it are handled the same, approximate way as before.
    """
    return sink_path[: len(guard_path)] == guard_path


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
        enclosing_param_names: frozenset[str] = frozenset(),
    ) -> None:
        local_bindings = dict(bindings)
        if extra_bindings:
            local_bindings.update(extra_bindings)
        order_counter = [0]
        nested_bodies = []
        body = fn_node.body if fn_node else tree.body
        if fn_node is not None:
            nodes = list(_scope_nodes(body))
            declared_global = {name for node in nodes if isinstance(node, ast.Global) for name in node.names}
            declared_nonlocal = {name for node in nodes if isinstance(node, ast.Nonlocal) for name in node.names}
            # Python locals shadow closure/module bindings throughout the
            # scope, even before an assignment executes. Empty bindings
            # deliberately resolve to Unresolved rather than a false edge.
            local_names = _param_names(fn_node) | {
                node.id for node in nodes if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
            }
            for name in local_names - declared_global - declared_nonlocal:
                local_bindings[name] = ""
            for name in declared_global:
                local_bindings[name] = bindings.get(name, f"{module_qualname}.{name}")
            local_bindings.update(_import_bindings(ast.Module(body=body, type_ignores=[]), module_qualname))
            # Bind every sibling before entering any child body, including
            # definitions inside control-flow suites. This is lexical
            # resolution, not proof a conditional def executes at runtime.
            for nested in _direct_nested_function_defs(body):
                local_bindings[nested.name] = (
                    "" if nested.name in declared_global | declared_nonlocal
                    else f"{caller_name}.<locals>.{nested.name}"
                )
            # The dedicated method walk explicitly supplies these identities.
            if "<locals>" not in caller_name and extra_bindings:
                local_bindings.update(extra_bindings)
        # Milestone (remediation item 5, VERIFICATION_LEDGER.md
        # sz-2026-10-21-05): a nested function's own parameters are joined
        # with every ENCLOSING function's parameters, not just its own --
        # a closure that references its outer function's parameter must
        # still classify that reference as "parameter" taint, not
        # "unknown", or the exact case this fix targets would silently
        # regress to the wrong (weaker) classification one call deeper.
        param_names = _param_names(fn_node) | enclosing_param_names
        constant_locals = _constant_locals(fn_node, param_names) if fn_node is not None else frozenset()
        # name -> names its latest assigned value read, and how many times
        # the name has been assigned so far. Names are compared with their
        # version, so `if not ok(p): raise; p = q; open(p)` does not credit
        # ok() -- the sink reads a new p. Branches are walked in order and the
        # last assignment wins, which can only withhold credit, never add it.
        derived: dict[str, set[str]] = {}
        versions: dict[str, int] = {}

        def names_read(nodes: list[ast.AST]) -> frozenset:
            direct = {n.id for node in nodes for n in ast.walk(node) if isinstance(n, ast.Name)}
            seen: set[str] = set()
            pending = list(direct)
            while pending:
                name = pending.pop()
                if name in seen:
                    continue
                seen.add(name)
                pending.extend(derived.get(name, ()))
            return frozenset((name, versions.get(name, 0)) for name in seen - {"self", "cls"})

        def note_assignment(target: ast.AST, value: ast.AST | None) -> None:
            read = {n.id for n in ast.walk(value) if isinstance(n, ast.Name)} if value is not None else set()
            for node in ast.walk(target):
                if isinstance(node, ast.Name):
                    versions[node.id] = versions.get(node.id, 0) + 1
                    derived[node.id] = read - {node.id}

        def bound_names(target: ast.AST) -> list[str]:
            """Plain names bound by an assignment target, through tuple/list
            unpacking; `obj.attr` and `d[k]` targets bind no local name."""
            if isinstance(target, ast.Name):
                return [target.id]
            if isinstance(target, ast.Starred):
                return bound_names(target.value)
            if isinstance(target, (ast.Tuple, ast.List)):
                return [n for elt in target.elts for n in bound_names(elt)]
            return []

        def mark_results(first_call: int, targets: list[ast.expr]) -> None:
            """Record, on the calls made since index `first_call`, the
            just-assigned names their results flow into."""
            names = frozenset((n, versions[n]) for t in targets for n in bound_names(t))
            for site in calls[first_call:]:
                site.result_names = names

        def note_walrus(expr: ast.AST) -> None:
            for node in ast.walk(expr):
                if isinstance(node, ast.NamedExpr):
                    note_assignment(node.target, node.value)

        def record_calls_in_expr(
            expr: ast.AST, branch_path: tuple, exit_guard: tuple = (), guard_call_ids: frozenset = frozenset()
        ) -> None:
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
                target: Symbol | Unresolved | None = None
                if dotted:
                    for cand in (dotted, f"{module_qualname}.{dotted}"):
                        if cand in project_functions or cand in STDLIB_SINKS:
                            target = Symbol(cand)
                            break
                    if (
                        target is None
                        and isinstance(node.func, ast.Name)
                        and node.func.id not in local_bindings
                        and node.func.id in _BUILTIN_SINK_NAMES
                    ):
                        # See _BUILTIN_SINK_NAMES's docstring: a bare, never-
                        # rebound reference to a sink builtin (open/eval/exec)
                        # must resolve to its real "builtins.X" identity, or
                        # it can never match STDLIB_SINKS at all.
                        target = Symbol(f"builtins.{node.func.id}")
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
                arg_taint = tuple(_classify_arg_taint(a, param_names, constants=constant_locals) for a in node.args)
                kwarg_taint = tuple(
                    _classify_arg_taint(k.value, param_names, constants=constant_locals) for k in node.keywords
                )
                order_counter[0] += 1
                calls.append(
                    CallSite(
                        caller=caller_name,
                        target=target,
                        lineno=node.lineno,
                        order=order_counter[0],
                        args=arg_texts,
                        arg_taint=arg_taint,
                        kwarg_taint=kwarg_taint,
                        branch_path=branch_path,
                        # Only a project-defined check counts: stdlib/external
                        # predicates (os.path.exists, isinstance) gate
                        # behavior, not trust, and would credit almost
                        # every `if ...: return` as a security guard.
                        exit_guard=exit_guard if (
                            id(node) in guard_call_ids
                            and isinstance(target, Symbol) and target.qualified_name in project_functions
                        ) else (),
                        arg_names=names_read([*node.args, *(k.value for k in node.keywords)]),
                    )
                )

        def walk_stmts(stmts: list[ast.stmt], branch_path: tuple) -> None:
            for stmt in stmts:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Milestone (remediation item 5, VERIFICATION_LEDGER.md
                    # sz-2026-10-21-05): a nested function is a separate
                    # scope -- its own qualname, its own order_counter,
                    # its own CallSite caller identity -- but, unlike the
                    # old behavior, it IS walked, right here, recursively.
                    # Qualname mirrors Python's own __qualname__ convention
                    # for a nested function (module.outer.<locals>.inner),
                    # so a sink call inside it resolves to a real,
                    # addressable caller instead of vanishing entirely.
                    # Child bodies are deferred until this scope's bindings
                    # are complete, so later siblings and rebindings apply.
                    #
                    # Guarded on `fn_node is not None`: this walk_stmts can
                    # also be the TOP-level module scope's own walk
                    # (walk_fn(None, "") below), whose body is `tree.body`
                    # -- and tree.body's own top-level FunctionDefs are
                    # already walked by the dedicated loop right after that
                    # call, with the correct `module.name` qualname. Without
                    # this guard, every top-level function got walked
                    # TWICE: once correctly by that loop, once more here
                    # under a bogus `.<locals>.name` qualname with no
                    # module prefix -- a real duplicate-CallSite regression
                    # caught by the existing test suite, not a hypothetical.
                    if fn_node is not None:
                        nested_qualname = f"{caller_name}.<locals>.{stmt.name}"
                        nested_bodies.append((stmt, nested_qualname))
                    continue
                if isinstance(stmt, ast.ClassDef):
                    local_bindings[stmt.name] = ""
                    continue  # a nested class remains out of scope for this pass
                if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                    local_bindings.update(_import_bindings(ast.Module(body=[stmt], type_ignores=[]), module_qualname))
                    continue
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    first_call = len(calls)
                    record_calls_in_expr(stmt.value, branch_path)
                    note_walrus(stmt.value)
                    note_assignment(stmt.targets[0], stmt.value)  # after the RHS runs
                    mark_results(first_call, stmt.targets)
                    resolved_rhs = _resolve_dotted(stmt.value, local_bindings)
                    # Only propagate the alias when it's actually trustworthy
                    # -- see _alias_rhs_is_trustworthy's docstring for the two
                    # real false-positives (`add = lines.append` and
                    # `metadata = meta_payload`) this gate exists to block.
                    if resolved_rhs and _alias_rhs_is_trustworthy(
                        stmt.value, resolved_rhs, local_bindings, project_functions, module_qualname
                    ):
                        local_bindings[stmt.targets[0].id] = resolved_rhs
                    else:
                        local_bindings[stmt.targets[0].id] = ""
                    continue
                if isinstance(stmt, ast.If):
                    tag = id(stmt)
                    exiting = "body" if _ends_in_exit(stmt.body) else ("orelse" if _ends_in_exit(stmt.orelse) else "")
                    # test always runs; only its decisive calls can guard
                    record_calls_in_expr(
                        stmt.test, branch_path, (tag, exiting) if exiting else (),
                        _decisive_guard_calls(stmt.test, exiting),
                    )
                    note_walrus(stmt.test)
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
                        note_walrus(test_or_iter)
                    if isinstance(stmt, (ast.For, ast.AsyncFor)):
                        note_assignment(stmt.target, stmt.iter)
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
                        note_walrus(item.context_expr)
                        if item.optional_vars is not None:
                            note_assignment(item.optional_vars, item.context_expr)
                    walk_stmts(stmt.body, branch_path)
                    continue
                if isinstance(stmt, ast.Match):
                    # Codex review, PR #7: mirrors the If/Try/For treatment
                    # above -- without this branch, a Match statement fell
                    # through to the generic record_calls_in_expr(stmt, ...)
                    # case below, which calls plain ast.walk(stmt) and
                    # attributes every call inside every case body to THIS
                    # scope directly, bypassing the FunctionDef branch at
                    # the top of this loop entirely -- so a function nested
                    # inside a case body was never recursed into as its own
                    # scope, and calls made from inside it were silently
                    # misattributed to the enclosing function instead.
                    record_calls_in_expr(stmt.subject, branch_path)  # the matched subject always evaluates
                    tag = id(stmt)
                    for i, case in enumerate(stmt.cases):
                        if case.guard is not None:
                            record_calls_in_expr(case.guard, branch_path + ((tag, f"case{i}"),))
                        walk_stmts(case.body, branch_path + ((tag, f"case{i}"),))
                    continue
                # simple statement (Expr, Return, Raise, Assert, AugAssign, ...):
                # record every call nested in it at the current branch_path.
                first_call = len(calls)
                record_calls_in_expr(stmt, branch_path)
                note_walrus(stmt)
                if isinstance(stmt, ast.Assign):
                    for assigned in stmt.targets:
                        note_assignment(assigned, stmt.value)
                    mark_results(first_call, stmt.targets)
                elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
                    note_assignment(stmt.target, stmt.value)
                    mark_results(first_call, [stmt.target])

        walk_stmts(body, ())
        # Closures see the enclosing scope's completed lexical bindings,
        # rather than a snapshot taken at each def statement. Execution
        # timing and conditional rebinding remain outside this static model.
        for nested, nested_qualname in nested_bodies:
            walk_fn(nested, nested_qualname, extra_bindings=local_bindings,
                    enclosing_param_names=param_names)

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

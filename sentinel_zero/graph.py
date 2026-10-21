"""The language-agnostic Interprocedural Symbol & Binding Graph (ISBG) IR.

Nothing in this file knows Python syntax. A language resolver (see
resolvers/python_resolver.py) walks that language's AST and populates these
same shapes. That split is deliberate: the user's standing concern is that
this portfolio's tools keep getting calibrated to one repo, or one
language, instead of staying general. Putting the graph shapes here, with
no Python (or JS) import anywhere in this file, is how that concern gets
enforced in code rather than promised in prose -- a resolver that tries to
sneak language-specific logic in here has nowhere to put it.

Core idea: a call site is only meaningful once its callee has been resolved
to a SYMBOL -- a canonical, fully-qualified identity -- rather than left as
a bare name string. Two consequences follow directly:

  - sink/guard matching is by resolved identity, never by name prefix. This
    is the structural fix for the earlier `check*` wildcard bug, where a
    guard name heuristic matched an unrelated `.checkbox()` call: that bug
    is a category of error (name-string matching) this graph cannot
    reproduce, because nothing here ever compares raw name strings for
    sink/guard purposes.
  - a binding that cannot be resolved statically is recorded as UNRESOLVED,
    never silently dropped. An unresolved binding on a path to a sink must
    surface as UNRESOLVED_INCONCLUSIVE in the disposition engine -- never
    as a clean pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SinkKind(str, Enum):
    FILE_IO = "FILE_IO"
    DESERIALIZATION = "DESERIALIZATION"
    PROCESS_EXEC = "PROCESS_EXEC"


@dataclass(frozen=True)
class Symbol:
    """A fully-qualified identity: 'os.system', 'myproject.auth.require_role',
    or a module-local function's dotted path. Two call sites that resolve to
    the same Symbol are the same callee, regardless of what local alias or
    import name was used to reach it."""

    qualified_name: str


@dataclass(frozen=True)
class Unresolved:
    """Marks a binding the resolver could not pin down statically (a
    dynamic import, getattr-based dispatch, a wrap this language resolver
    doesn't model yet). Carries a reason so the disposition engine can
    explain *why* something is UNRESOLVED_INCONCLUSIVE instead of just
    saying so."""

    reason: str


Target = Symbol | Unresolved


@dataclass
class CallSite:
    """One call expression, with its callee already resolved."""

    caller: str  # qualified name of the enclosing function ("" if module scope)
    target: Target
    lineno: int
    order: int  # position among calls in `caller`, for the bounded same-function
    # "guard precedes sink" check -- an approximation of control
    # dependency, not full CFG dominance. See docs/isbg-limits.md.
    args: tuple = ()  # best-effort source text of each positional argument, for
    # the wrapper-construction detector below -- not used for further
    # resolution, only for reporting *what* was passed where.
    arg_taint: tuple = ()  # Milestone 15: one classification per positional
    # argument -- "literal" (a constant, or built entirely from constants),
    # "parameter" (derives from the enclosing function's own parameter,
    # directly or through a simple attribute/subscript/concatenation chain),
    # or "unknown" (anything else -- a global, another call's result, a
    # comprehension). Computed from the real AST node at the call site,
    # never from re-parsing `args`' source text -- this graph's one rule is
    # that identity/classification comes from resolved structure, not
    # strings. Bounded on purpose: this is NOT interprocedural taint
    # tracking. "parameter" only says the sink's argument traces to a
    # parameter of the function it's called FROM -- whether that parameter
    # is itself reachable from real attacker-controlled input (an HTTP
    # request, argv, stdin) is a separate question this does not answer.
    # A parameter-derived argument several layers of wrapping away from any
    # real entry point will still read as "parameter", same as one that
    # comes straight from a request body -- it narrows "is this worth a
    # human's time" without claiming to resolve exploitability.
    branch_path: tuple = ()  # sequence of (enclosing If/Try node id, branch label)
    # from the function root down to this call -- lets the "guard precedes
    # sink" check tell an elif/else sibling (mutually exclusive, can never
    # run in the same call) from a statement that actually executes
    # earlier in the same path. Confirmed necessary: Block-Wise's cli.py
    # dispatches subcommands via one big if/elif in a single function, and
    # without this, a guard call in the `show` branch was wrongly read as
    # "preceding" a sink in the unrelated `security-review` branch.


@dataclass
class FunctionInfo:
    qualified_name: str
    is_guard_shaped: bool  # structural: has an early raise- or return-on-condition pattern
    # Stricter than is_guard_shaped, and the field callgraph.transitively_guard_shaped
    # actually checks for the DELEGATION case (calling this function and trusting its
    # shape to protect the CALLER's control flow): True only if the early exit is a
    # `raise`, not a plain `return`. A `return` inside this function only exits this
    # function's own body -- it does nothing to stop the caller's next statement from
    # running, unless the caller checks a returned value (not modeled). A `raise`
    # propagates as an exception into the caller too, so it genuinely can prevent a
    # later statement in the caller from executing. is_guard_shaped (raise-OR-return)
    # stays correct for the SAME-function dispatch case (a wrapper's __call__ checking
    # itself before forwarding, e.g. Horos's BearerAuthMiddleware) -- there, a `return`
    # really does stop that same function's own next statement. Confirmed via dogfooding
    # before this field existed: a return-shaped delegate was read as "protecting" a
    # sink in a caller that never actually checked its return value.
    raises_on_guard: bool
    file_path: str
    lineno: int


@dataclass(frozen=True)
class WrapperClass:
    """A class that structurally behaves like middleware: its constructor
    stores a passed-in object, and its dispatch method checks something
    before forwarding to that stored object. Framework-agnostic on purpose
    -- this is how Horos's real BearerAuthMiddleware looks (a plain ASGI
    callable, not a Django/Flask-specific base class), and the detector
    below never names Starlette, ASGI, or Horos anywhere."""

    qualified_name: str
    wrapped_param_index: int  # position of the wrapped-object parameter in __init__ (0 = first non-self arg)
    dispatch_method: str  # qualified name of the guarding dispatch method, e.g. "...BearerAuthMiddleware.__call__"
    dispatch_is_guarded: bool


@dataclass(frozen=True)
class ExternalReference:
    """One call that leaves the project entirely -- resolves to a dotted
    name whose top-level component is neither one of this project's own
    modules nor the standard library. This is the queued dependency-
    mapping feature: it answers 'what does this function/route reach
    outside the project' using data the resolver already produces, rather
    than a new analysis pass."""

    caller: str
    package: str  # the top-level package name, e.g. "requests" from "requests.get"
    qualified_name: str
    file_path: str
    lineno: int


@dataclass(frozen=True)
class WrapConstruction:
    """One place in the project where a WrapperClass is instantiated,
    wrapping some expression. Does not yet trace which specific handler
    functions sit behind the wrapped expression -- that hop is framework-
    specific route/middleware registration and is explicitly not claimed
    here."""

    wrapper_qualified_name: str
    wrapped_expr: str  # best-effort source text of the wrapped argument
    file_path: str
    lineno: int


@dataclass
class ModuleGraph:
    module_qualname: str
    file_path: str
    calls: list[CallSite] = field(default_factory=list)


@dataclass
class ProjectGraph:
    """The whole-repo graph: every module's calls, plus a project-wide index
    of functions by qualified name so a call in one file can resolve to a
    definition in another."""

    modules: dict[str, ModuleGraph] = field(default_factory=dict)
    functions: dict[str, FunctionInfo] = field(default_factory=dict)
    wrapper_classes: dict[str, WrapperClass] = field(default_factory=dict)
    wrap_constructions: list[WrapConstruction] = field(default_factory=list)
    external_references: list[ExternalReference] = field(default_factory=list)
    parse_errors: list[dict] = field(default_factory=list)
    # A file this resolver's language parser could not handle at all (real
    # syntax it doesn't support, a decode error, ...). Language-agnostic by
    # design, like every other field here: any resolver can hit a file it
    # can't parse, and per graph.py's own rule above, that must surface as
    # a reported fact ({"file_path": ..., "error": ...}), never a file that
    # silently vanishes from the scan with nothing to show for it.

    def all_calls(self) -> list[CallSite]:
        return [c for m in self.modules.values() for c in m.calls]

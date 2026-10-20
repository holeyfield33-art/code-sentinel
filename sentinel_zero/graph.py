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
    is_guard_shaped: bool  # structural: has an early raise-on-condition pattern
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

    def all_calls(self) -> list[CallSite]:
        return [c for m in self.modules.values() for c in m.calls]

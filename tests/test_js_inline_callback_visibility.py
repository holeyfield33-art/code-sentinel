"""VERIFICATION_LEDGER.md sz-2026-10-21-06, docs/REMEDIATION_PLAN.md item 6
(the JS mirror of item 5's nested-Python-function fix, and per the plan's
own note "the highest real-world-impact item in the whole list"): an
inline anonymous function literal passed directly as a call argument --
the `app.get('/x', (req, res) => { ... })` shape -- was completely
invisible to extract_graph.js. findCallsInExpr correctly never descends
into a FunctionExpression/ArrowFunctionExpression's own body (that's a
separate scope), but nothing ever walked that separate scope either, so a
sink call inside one produced ZERO CallSites, not even an Unresolved one.

The fix gives every such inline callback a real, derived qualname
(`<enclosing>.<callback:L<line>C<col>>`) and walks it as a genuine scope
of its own, with parameter-taint classification that accumulates every
enclosing scope's own parameters too (closure-correct, mirroring item 5's
enclosing_param_names on the Python side).
"""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.graph import Symbol
from sentinel_zero.resolvers.js_resolver import build_project_graph

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("node") is None, reason="Node.js not available in this environment"
)


def test_sink_call_inside_an_inline_arrow_callback_is_no_longer_invisible():
    """The core regression, in the plan's own Express shape: before the
    fix this produced ZERO CallSites for the sink call -- the worst
    possible outcome, worse than Unresolved, since it never even
    surfaced as something to triage."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "routes.js").write_text(
            "const { exec } = require('child_process');\n"
            "function registerRoutes(app) {\n"
            "  app.get('/x', (req, res) => {\n"
            "    exec(req.query.cmd);\n"
            "  });\n"
            "}\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "routes.registerRoutes.<callback:L3C16>"


def test_closure_over_an_enclosing_parameter_classifies_as_parameter_taint():
    """The real correctness boundary, mirroring item 5's own: a callback's
    sink argument that is actually the ENCLOSING function's own
    parameter, captured by closure, must classify as 'parameter' taint,
    not 'unknown'."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function runLater(cmd) {\n"
            "  setTimeout(() => {\n"
            "    exec(cmd);\n"
            "  }, 1000);\n"
            "}\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].arg_taint == ("parameter",)


def test_a_second_more_realistic_express_app_shape_with_multiple_routes():
    """Verifier method hint from the plan: a more realistic fixture with
    several routes, only one of which has a sink in its inline handler,
    to catch an over-narrow fix that only handles a single-argument
    pattern or a single route."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.js").write_text(
            "const { exec } = require('child_process');\n"
            "function registerRoutes(app) {\n"
            "  app.get('/health', (req, res) => {\n"
            "    res.send('ok');\n"
            "  });\n"
            "  app.post('/run', (req, res) => {\n"
            "    exec(req.body.cmd);\n"
            "  });\n"
            "  app.get('/status', (req, res) => {\n"
            "    res.send('up');\n"
            "  });\n"
            "}\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "app.registerRoutes.<callback:L6C19>"
        assert sink_calls[0].arg_taint == ("parameter",)


def test_a_callback_nested_inside_a_callback_is_discovered_at_any_depth():
    """`.then(x => { arr.map(y => { sink(y) }) })` -- a callback inside a
    callback -- must still be found, not just one level of nesting."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function run(promise) {\n"
            "  promise.then((results) => {\n"
            "    results.forEach((cmd) => {\n"
            "      exec(cmd);\n"
            "    });\n"
            "  });\n"
            "}\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "mod.run.<callback:L3C15>.<callback:L4C20>"
        assert sink_calls[0].arg_taint == ("parameter",)


def test_callback_at_bare_module_scope_is_also_discovered():
    """A callback doesn't have to live inside any named function at all --
    directly at module scope must work too."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\nsetTimeout(() => {\n  exec('echo hi');\n}, 1000);\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "mod.<callback:L2C11>"


def test_inline_callback_inside_a_class_method_resolves_this_from_the_class():
    """A callback nested inside a class method still resolves `this.foo()`
    through the owning class, the same way the method's own body does."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "class Runner {\n"
            "  constructor() {\n"
            "    this.cmd = 'echo hi';\n"
            "  }\n"
            "  schedule() {\n"
            "    setTimeout(() => {\n"
            "      this.execute();\n"
            "    }, 1000);\n"
            "  }\n"
            "  execute() {\n"
            "    require('child_process').exec(this.cmd);\n"
            "  }\n"
            "}\n"
            "module.exports = { Runner };\n"
        )
        graph = build_project_graph(root)
        callback_calls = [c for c in graph.all_calls() if c.caller.startswith("mod.Runner.schedule.<callback")]
        assert len(callback_calls) == 1
        assert callback_calls[0].target == Symbol("mod.Runner.execute")


def test_arrow_function_with_a_concise_expression_body_is_still_walked():
    """`x => sink(x)` (no braces, implicit return) has no statement list --
    the walk path for this shape differs internally from a normal
    block-bodied callback and must be exercised directly, not assumed to
    work because the block-bodied case does."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function runAll(cmds) {\n"
            "  cmds.forEach((cmd) => exec(cmd));\n"
            "}\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].arg_taint == ("parameter",)


def test_named_top_level_const_arrow_function_is_not_mistaken_for_inline():
    """Regression guard: a top-level `const handler = (req, res) => {...}`
    is a NAMED scope (already indexed as `mod.handler`), not an inline
    callback -- it must not be double-indexed under a synthetic
    `<callback:...>` qualname too."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "const handler = (req, res) => {\n"
            "  exec(req.query.cmd);\n"
            "};\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "mod.handler"
        assert "<callback" not in sink_calls[0].caller
        assert "mod.handler" in graph.functions
        assert not any(name.startswith("mod.handler.<callback") for name in graph.functions)


def test_inline_function_as_an_object_literal_property_value_is_also_discovered():
    """collectInlineFunctionNodes is a fully generic tree walk, not limited
    to call-argument position -- a function literal assigned as an
    object-literal property's value (not passed as a call argument at
    all) must be discovered too, wider than the plan's own acceptance
    claim strictly asked for."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "function build(cmd) {\n"
            "  const handlers = {\n"
            "    run: () => {\n"
            "      exec(cmd);\n"
            "    },\n"
            "  };\n"
            "  return handlers;\n"
            "}\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "mod.build.<callback:L4C9>"
        assert sink_calls[0].arg_taint == ("parameter",)


def test_a_callback_nested_inside_a_named_concise_body_arrow_is_still_walked():
    """Codex review, PR #8 (P1): a NAMED top-level `const x = () => expr`
    with a concise (brace-less) expression body was gated entirely out
    of the caller-functions walk loop (it only ran for a BlockStatement
    body). Pass 1 (indexFile) discovers and indexes a callback nested
    inside that expression unconditionally -- it never gated on
    BlockStatement -- so before this fix the callback showed up in
    `functions` looking like a real, checked scope while pass 2 silently
    walked zero calls from it. Worse than before item 6 existed at all:
    an indexed-but-empty scope reads as "checked, no sink calls" rather
    than "never walked", the exact shape Codex's own repro
    (`const register = app => app.get('/x', req => exec(req.cmd));`)
    demonstrated."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\n"
            "const register = (app) => app.get('/x', (req) => exec(req.cmd));\n"
        )
        graph = build_project_graph(root)
        assert "mod.register" in graph.functions
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller.startswith("mod.register.<callback")
        assert sink_calls[0].arg_taint == ("parameter",)


def test_a_named_concise_body_arrows_own_direct_sink_call_is_also_recorded():
    """The other half of the same fix: a named top-level concise-body
    arrow's OWN direct call (not routed through any nested callback at
    all) must also be recorded now, not just a callback nested inside
    it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "mod.js").write_text(
            "const { exec } = require('child_process');\nconst runIt = (cmd) => exec(cmd);\n"
        )
        graph = build_project_graph(root)
        sink_calls = [c for c in graph.all_calls() if c.target == Symbol("child_process.exec")]
        assert len(sink_calls) == 1
        assert sink_calls[0].caller == "mod.runIt"
        assert sink_calls[0].arg_taint == ("parameter",)

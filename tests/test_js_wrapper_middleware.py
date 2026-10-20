"""JS/TS Milestone 9: wrapper-middleware detection. Mirrors
tests/test_wrapper_middleware.py's Python coverage exactly -- same shapes,
JS syntax, no __call__ convention assumed (JS has none, so the dispatch
method is found by its forwarding SHAPE, not a hardcoded name)."""
import tempfile
from pathlib import Path

import pytest

from sentinel_zero.resolvers.js_resolver import build_project_graph

pytestmark = pytest.mark.skipif(
    __import__("shutil").which("node") is None, reason="Node.js not available in this environment"
)


def test_wrapper_class_detected_and_construction_recorded_same_file():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "gatekeeper.js").write_text(
            "class TokenWall {\n"
            "  constructor(innerApp, token) {\n"
            "    this.inner = innerApp;\n"
            "    this.token = token;\n"
            "  }\n"
            "  handle(request) {\n"
            "    if (request.headers.authorization !== this.token) {\n"
            "      return reject(request);\n"
            "    }\n"
            "    return this.inner(request);\n"
            "  }\n"
            "}\n"
            "function build() {\n"
            "  const coreApp = makeCoreApp();\n"
            "  return new TokenWall(coreApp, SECRET);\n"
            "}\n"
            "module.exports = { TokenWall, build };\n"
        )

        graph = build_project_graph(root)

        wrapper = graph.wrapper_classes.get("gatekeeper.TokenWall")
        assert wrapper is not None, "TokenWall must be recognized as a wrapper class"
        assert wrapper.wrapped_param_index == 0, "innerApp is the first ctor param"
        assert wrapper.dispatch_method == "gatekeeper.TokenWall.handle"
        assert wrapper.dispatch_is_guarded, "handle() has an early-return guard"

        assert len(graph.wrap_constructions) == 1, "exactly one construction site: build()"
        wc = graph.wrap_constructions[0]
        assert wc.wrapper_qualified_name == "gatekeeper.TokenWall"
        assert wc.wrapped_expr == "coreApp", "must identify WHAT was wrapped, not just that something was"


def test_wrapper_construction_recorded_across_files():
    """The real-world case (Horos's own BearerAuthMiddleware): the wrapper
    class is defined in one file and constructed in another. Same-module
    sibling resolution was the actual bug fixed to make this milestone
    possible at all -- this is the test that would have caught it."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "middleware.js").write_text(
            "class AuthMiddleware {\n"
            "  constructor(app, secret) {\n"
            "    this.app = app;\n"
            "    this.secret = secret;\n"
            "  }\n"
            "  dispatch(req) {\n"
            "    if (req.token !== this.secret) {\n"
            "      throw new Error('forbidden');\n"
            "    }\n"
            "    return this.app(req);\n"
            "  }\n"
            "}\n"
            "module.exports = { AuthMiddleware };\n"
        )
        (root / "server.js").write_text(
            "const { AuthMiddleware } = require('./middleware');\n"
            "function build(coreApp) {\n"
            "  return new AuthMiddleware(coreApp, process.env.SECRET);\n"
            "}\n"
        )
        graph = build_project_graph(root)
        wrapper = graph.wrapper_classes.get("middleware.AuthMiddleware")
        assert wrapper is not None
        assert wrapper.dispatch_is_guarded

        assert len(graph.wrap_constructions) == 1
        wc = graph.wrap_constructions[0]
        assert wc.wrapper_qualified_name == "middleware.AuthMiddleware"
        assert wc.wrapped_expr == "coreApp"


def test_non_guarding_wrapper_is_not_flagged_as_guarded():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "logging_wrap.js").write_text(
            "class LoggingWrapper {\n"
            "  constructor(innerApp) {\n"
            "    this.inner = innerApp;\n"
            "  }\n"
            "  handle(request) {\n"
            "    log(request);\n"
            "    return this.inner(request);\n"
            "  }\n"
            "}\n"
            "module.exports = { LoggingWrapper };\n"
        )
        graph = build_project_graph(root)
        wrapper = graph.wrapper_classes.get("logging_wrap.LoggingWrapper")
        assert wrapper is not None, "it's still structurally a wrapper (stores + forwards)"
        assert not wrapper.dispatch_is_guarded, "but it never conditionally exits, so it is not a guard"

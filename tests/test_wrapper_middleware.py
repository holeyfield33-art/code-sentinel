"""Proves the generic wrapper-middleware detector before trusting it
against Horos's real BearerAuthMiddleware -- synthetic fixture, same
shape, different names, no copied code."""
import tempfile
from pathlib import Path

from sentinel_zero.resolvers.python_resolver import build_project_graph


def test_wrapper_class_detected_and_construction_recorded():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "gatekeeper.py").write_text(
            "class TokenWall:\n"
            "    def __init__(self, inner_app, token):\n"
            "        self._inner = inner_app\n"
            "        self._token = token\n"
            "\n"
            "    def __call__(self, request):\n"
            "        if request.headers.get('Authorization') != self._token:\n"
            "            return reject(request)\n"
            "        return self._inner(request)\n"
        )
        (root / "main.py").write_text(
            "from gatekeeper import TokenWall\n"
            "def build():\n"
            "    core_app = make_core_app()\n"
            "    return TokenWall(core_app, SECRET)\n"
        )

        graph = build_project_graph(root)

        wrapper = graph.wrapper_classes.get("gatekeeper.TokenWall")
        assert wrapper is not None, "TokenWall must be recognized as a wrapper class"
        assert wrapper.wrapped_param_index == 0, "inner_app is the first non-self param"
        assert wrapper.dispatch_is_guarded, "__call__ has an early-return guard"

        assert len(graph.wrap_constructions) == 1, "exactly one construction site: main.build()"
        wc = graph.wrap_constructions[0]
        assert wc.wrapper_qualified_name == "gatekeeper.TokenWall"
        assert wc.wrapped_expr == "core_app", "must identify WHAT was wrapped, not just that something was"


def test_non_guarding_wrapper_is_not_flagged_as_guarded():
    """A class with the same wrap-and-forward shape but no conditional
    early exit (e.g. a logging wrapper) must not be reported as guarded --
    the point is distinguishing middleware that actually gates something
    from one that doesn't."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "logging_wrap.py").write_text(
            "class LoggingWrapper:\n"
            "    def __init__(self, inner_app):\n"
            "        self._inner = inner_app\n"
            "\n"
            "    def __call__(self, request):\n"
            "        log(request)\n"
            "        return self._inner(request)\n"
        )
        graph = build_project_graph(root)
        wrapper = graph.wrapper_classes.get("logging_wrap.LoggingWrapper")
        assert wrapper is not None, "it's still structurally a wrapper (stores + forwards)"
        assert not wrapper.dispatch_is_guarded, "but it never conditionally exits, so it is not a guard"

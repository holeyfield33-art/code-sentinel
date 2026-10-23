"""Local stdio MCP transport for source-code security triage.

`analyze_repository` shares the CLI's scan pipeline and returns its ledger.
Static mode does not execute target code. Optional Docker diagnostics
record target-controlled observations and cannot authorize verified states.
Temporary server-side artifacts are removed after the request; use the CLI
to retain graph exports or Markdown reports.

Run `sentinel-zero-mcp` or `python -m sentinel_zero.mcp_server` in the
installed environment. Client setup and result interpretation: USAGE.md.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

from sentinel_zero.catalog_loader import bundled_snapshot_path
from sentinel_zero.disposition import ToolFailure
from sentinel_zero.dogfood_scan import run as run_scan
from sentinel_zero.repo_detect import detect_language, js_deps_installed

server = MCPServer(
    name="sentinel-zero",
    version="0.1.0",
    instructions=(
        "Source-code security triage for Python, JavaScript, and TypeScript repositories. "
        "Call analyze_repository with an absolute local repo path to obtain a ledger of "
        "supported, resolved sink calls and bounded structural evidence. Static mode is the default. "
        "Diagnostic mode requires Docker and records untrusted reports; current scans cannot "
        "authorize VERIFIED_TRUE or VERIFIED_FALSE. Treat UNRESOLVED_INCONCLUSIVE as requiring "
        "review. Inspect parse_errors, unresolved_call_sites, and diagnostic failures; zero "
        "plans or a completed command does not establish repository safety."
    ),
)


@server.tool()
def analyze_repository(
    repo_path: str,
    language: str | None = None,
    catalog_path: str | None = None,
    probe_mode: str = "static",
) -> dict[str, Any]:
    """Run a Sentinel-Zero scan against a repository and return its verification ledger.

    Args:
        repo_path: absolute path to the repository to analyze (not this server's own repo).
        language: "python" or "javascript". Omit to auto-detect by counting source files.
        catalog_path: path to a live asi-catalog.json export. Omit to use the catalog
            snapshot bundled with this install -- the returned ledger's "catalog" block
            always says which one was actually used, and its version/generatedAt, so this
            is never silently treated as equivalent to a freshly-fetched taxonomy.

        probe_mode: static (default) never executes target code. diagnostic requires
            Docker isolation and records untrusted reports, never VERIFIED_TRUE.

    Returns:
        The same ledger dict `sentinel-zero analyze --format json` writes to disk:
        target_repository, modules_scanned, functions_indexed, unresolved_call_sites,
        plan_count, plans (each a full Finding Plan with a disposition), catalog,
        wrapper_middleware_detected, wrapper_construction_sites, external_dependencies,
        parse_errors. On any internal failure this raises -- MCP surfaces that as a tool
        error back to the calling agent, never a quiet empty result.
    """
    repo_root = Path(repo_path).resolve()
    if not repo_root.is_dir():
        raise ToolFailure(f"{repo_root} is not a directory")

    resolved_language = language or detect_language(repo_root)
    if resolved_language == "javascript" and not js_deps_installed():
        raise ToolFailure(
            "the JS/TS resolver's dependencies are not installed on this host -- "
            "run `sentinel-zero install-js-deps` once before calling this tool for a JS/TS target."
        )

    is_bundled = catalog_path is None
    resolved_catalog_path = catalog_path or str(bundled_snapshot_path())

    with tempfile.TemporaryDirectory(prefix="sentinel-zero-mcp-") as tmp:
        out_dir = Path(tmp)
        # Propagates ToolFailure/UnknownAttackClass uncaught -- the MCP
        # framework turns an uncaught exception into a tool error result,
        # which is the hard-failure behavior invariant #1 requires. This
        # function must never catch either exception type and return a
        # softened result instead.
        run_scan(
            repo_root,
            resolved_catalog_path,
            out_dir,
            resolved_language,
            is_bundled_snapshot_catalog=is_bundled,
            probe_mode=probe_mode,
        )
        return json.loads((out_dir / "verification_ledger.json").read_text(encoding="utf-8"))


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()

"""REMEDIATION_PLAN.md item 8 / VERIFICATION_LEDGER.md sz-2026-10-22-02:
the distributed wheel omitted `probes/js/_sink_reachability_harness.js` --
`pyproject.toml`'s `[tool.setuptools.package-data]` list for `sentinel_zero`
covered `resolvers/js/*.js` but not `probes/js/*.js`, so an installed
package's `run_js_sink_reachability_probe()` raised `FileNotFoundError` the
moment a JS/TS target actually reached that probe, even though the exact
same file is present and used fine from a source checkout.

Two layers of regression guard, cheapest-and-always-on first:

  1. A fast, no-build test that walks every file each probe module's own
     `_HARNESS_PATH` constant points at, and asserts it is covered by at
     least one glob in pyproject.toml's declared package-data list. This
     is the one that would have caught the original bug instantly, and
     it stays fast enough to run every time.
  2. A slower, skippable test that actually builds the real wheel with
     `python -m build` and inspects its real file list -- the same
     reproduction method used to confirm this bug for real before any
     fix was written. Skipped when the `build` package isn't installed,
     since CI environments vary, but exercised here to lock in the one
     true end-to-end check.
"""
from __future__ import annotations

import fnmatch
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "sentinel_zero"


def _load_pyproject() -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover -- py<3.11 fallback
        import tomli as tomllib  # type: ignore[no-redef]
    with open(REPO_ROOT / "pyproject.toml", "rb") as f:
        return tomllib.load(f)


def _declared_package_data_globs() -> list[str]:
    data = _load_pyproject()
    return data["tool"]["setuptools"]["package-data"]["sentinel_zero"]


def _required_runtime_assets() -> list[Path]:
    """Every file a probe module's own `_HARNESS_PATH`-style constant
    points at -- derived from the actual running source, not hand-copied
    paths that could drift out of sync with it."""
    import sentinel_zero.probes.js_sink_reachability_probe as js_probe
    import sentinel_zero.probes.sink_reachability_probe as py_probe

    paths = [js_probe._HARNESS_PATH, py_probe._HARNESS_PATH]
    for path in paths:
        assert path.is_file(), f"{path} must exist in the source checkout for this test to mean anything"
    return paths


def test_every_probe_harness_file_is_covered_by_a_declared_package_data_glob():
    """`.py` harness files (the Python-side probe) ship automatically as
    package source via `[tool.setuptools.packages.find]` -- only
    non-Python runtime assets (the JS harness) depend on being named in
    `package-data`, so only those need checking here."""
    globs = _declared_package_data_globs()
    for harness_path in _required_runtime_assets():
        if harness_path.suffix == ".py":
            continue
        relative = harness_path.relative_to(PACKAGE_ROOT).as_posix()
        covered = any(fnmatch.fnmatch(relative, pattern) for pattern in globs)
        assert covered, (
            f"{relative} is required at runtime (see its module's _HARNESS_PATH) but is not "
            f"covered by any of pyproject.toml's package-data globs {globs} -- an installed "
            f"wheel would be missing it, exactly like sz-2026-10-21-08 claim 2."
        )


_BUILD_ARTIFACT_DIR_NAMES = {"build", "dist", "__pycache__", ".git", "node_modules", ".pytest_cache"}


def _is_stale_build_metadata_dir(name: str) -> bool:
    """`*.egg-info` directories (setuptools' own package-metadata cache,
    e.g. `sentinel_zero.egg-info/SOURCES.txt`) turned out to be just as
    load-bearing a leak as `build/` itself: confirmed while fixing this
    very Codex finding -- excluding only `build/` from the copy was NOT
    enough, because setuptools used a leftover `sentinel_zero.egg-info`
    in the copy to decide the wheel's file list instead of re-deriving it
    from `pyproject.toml`, and the "clean copy" test kept passing anyway.
    Only excluding both made the test actually fail against a broken
    pyproject.toml, which is the whole point of this test existing."""
    return name.endswith(".egg-info")


def _copy_clean_source_tree(dest: Path) -> Path:
    """VERIFICATION_LEDGER.md sz-2026-10-22-04 (Codex P2 on PR #10): this
    test must build from a source tree with no leftover build artifacts
    of its own, never from `REPO_ROOT` directly. setuptools' incremental
    build cache (`build/lib`) and its package-metadata cache
    (`*.egg-info`) both live inside the source tree `python -m build` is
    pointed at, and both are keyed by file identity rather than by the
    current package-data declaration -- so either one left over from an
    earlier, correctly-configured build can silently carry a
    since-removed asset into a *new* wheel built against a now-broken
    pyproject.toml, letting this exact test pass even though the real,
    fresh-checkout build would fail. This happened for real, twice, while
    fixing item 8 and then this very finding in this session (see the
    sz-2026-10-22-02 stash-confirmation note, and
    `_is_stale_build_metadata_dir`'s docstring for the second one this
    test's own first draft missed). Copying into an isolated temp
    directory first (excluding both kinds, belt-and-suspenders in case
    REPO_ROOT itself has stale ones) guarantees setuptools has nothing to
    find and reuse."""
    def _ignore(_dir: str, names: list[str]) -> set[str]:
        return {n for n in names if n in _BUILD_ARTIFACT_DIR_NAMES or _is_stale_build_metadata_dir(n)}

    shutil.copytree(REPO_ROOT, dest, ignore=_ignore, dirs_exist_ok=True)
    return dest


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("build") is None,
    reason="the 'build' package is not installed in this environment",
)
def test_a_real_built_wheel_actually_contains_the_js_probe_harness():
    """The strongest check: build the actual artifact end users install
    and look inside it, rather than trusting the glob declaration alone.
    Builds from an isolated copy of the source tree, not REPO_ROOT
    directly -- see `_copy_clean_source_tree` for why that distinction is
    load-bearing, not cosmetic."""
    with tempfile.TemporaryDirectory() as tmp:
        clean_source = _copy_clean_source_tree(Path(tmp) / "src")
        assert not (clean_source / "build").exists(), "the copy must start with no build/ directory"
        assert not any(clean_source.glob("*.egg-info")), (
            "the copy must start with no leftover *.egg-info metadata directory either"
        )

        dist_dir = Path(tmp) / "dist"
        result = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "-o", str(dist_dir), str(clean_source)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"wheel build failed:\n{result.stdout}\n{result.stderr}"

        wheels = list(dist_dir.glob("*.whl"))
        assert len(wheels) == 1, f"expected exactly one wheel, found {wheels}"

        with zipfile.ZipFile(wheels[0]) as zf:
            names = zf.namelist()
            assert "sentinel_zero/probes/js/_sink_reachability_harness.js" in names, (
                "the built wheel is missing the JS probe harness -- an installed package would "
                f"raise FileNotFoundError the moment a JS/TS scan reached the probe. Wheel contents: {names}"
            )

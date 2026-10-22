"""Build and scan with an isolated installed wheel, outside the checkout.

Used by CI on Windows and Linux. --docker also checks both installed
diagnostic harnesses against a real daemon; static scans never require it.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv


def checked(args, *, cwd, timeout=180):
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--docker", action="store_true")
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="sentinel-wheel-") as directory:
        work = Path(directory)
        source = work / "source"
        source.mkdir()
        shutil.copytree(root / "sentinel_zero", source / "sentinel_zero",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "node_modules"))
        for name in ("pyproject.toml", "README.md"):
            shutil.copy2(root / name, source / name)
        dist = work / "dist"
        checked([sys.executable, "-I", "-m", "build", "--wheel", "--outdir", dist, source], cwd=work)
        wheels = list(dist.glob("*.whl"))
        assert len(wheels) == 1
        environment = work / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        checked([python, "-I", "-m", "pip", "install", wheels[0]], cwd=work)
        installed = Path(checked([python, "-I", "-c",
                                  "import pathlib,sentinel_zero;print(pathlib.Path(sentinel_zero.__file__).parent)"], cwd=work))
        assert installed.resolve().is_relative_to(environment.resolve()), "smoke test imported the source checkout"
        npm = shutil.which("npm")
        if npm is None:
            raise RuntimeError("npm is required for the installed JS parser smoke test")
        checked([npm, "ci", "--prefix", installed / "resolvers/js"], cwd=work)
        for language, filename, content in (
            ("python", "app.py", "import os\ndef run_it():\n    os.open('positive-control', os.O_RDONLY)\n"),
            ("javascript", "app.cjs", "const cp=require('child_process');function run_it(){cp.exec('positive-control');}module.exports={run_it};"),
        ):
            fixture = work / language
            fixture.mkdir()
            fixture.chmod(0o755)
            (fixture / filename).write_text(content, encoding="utf-8")
            for mode in (["static", "diagnostic"] if options.docker else ["static"]):
                output = work / f"{language}-{mode}"
                checked([python, "-I", "-m", "sentinel_zero.cli", "analyze", fixture,
                         "--language", language, "--probe-mode", mode, "--out", output], cwd=work)
                ledger = json.loads((output / "verification_ledger.json").read_text(encoding="utf-8"))
                assert ledger["catalog"]["is_bundled_snapshot"] is True
                assert ledger["plan_count"] == 1 and not ledger["parse_errors"]
                plan = ledger["plans"][0]
                assert plan["disposition"]["status"] == "UNRESOLVED_INCONCLUSIVE"
                if mode == "diagnostic":
                    report = plan["verification_method"]["probe_observation"]["report"]
                    assert report["status"] == "sink_reached", report
                print(f"installed wheel: {language} {mode} passed")


if __name__ == "__main__":
    main()

"""Calibration gate: triage must not regress on the labeled fixtures.

Runs calibration/calibrate.py against calibration/baseline.json. A case that
was correct must stay correct, and the headline rates must not fall. After an
intended change, review the diff and run
`python calibration/calibrate.py --update-baseline`.
"""
import contextlib
import importlib.util
import io
from pathlib import Path

CALIBRATE = Path(__file__).resolve().parents[1] / "calibration" / "calibrate.py"


def test_baseline_is_recorded():
    # Without a baseline the gate below would pass vacuously.
    assert (CALIBRATE.parent / "baseline.json").is_file()
    assert (CALIBRATE.parent / "manifest.json").is_file()


def test_triage_calibration_has_no_regressions():
    spec = importlib.util.spec_from_file_location("calibrate", CALIBRATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = module.main([])
    assert code == 0, out.getvalue()[-3000:]

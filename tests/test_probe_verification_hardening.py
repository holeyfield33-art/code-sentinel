"""VERIFICATION_LEDGER.md sz-2026-10-21-02/03, docs/REMEDIATION_PLAN.md
items 1-2: regression tests for the forgery and sandbox-escape gaps an
independent audit confirmed in the previous version of the dynamic
reachability probe.

These are deliberately adversarial fixtures -- not "does the probe work on
normal code" (tests/test_sandbox_probe.py and
tests/test_sink_probe_widening.py already cover that), but "does a target
that is actively trying to defeat the probe succeed." A fix here is only
real if these fail BEFORE the fix and pass AFTER it -- which is exactly
what was confirmed by hand before this file was written (reverting
sink_reachability_probe.py/_sink_reachability_harness.py and re-running
reproduces failures matching the ledger's sz-2026-10-21-02/03 entries).
"""
import os
import tempfile
from pathlib import Path

from sentinel_zero.probes.sink_reachability_probe import run_sink_reachability_probe


def test_target_cannot_forge_sink_reached_by_printing_a_matching_line():
    """The core of sz-2026-10-21-02: a target module whose import-time code
    prints a plausible-looking {"status": "sink_reached", ...} line and
    exits before the real function can even be called must NOT cause a
    false VERIFIED_TRUE -- the probe has no nonce to include, so the parent
    must discard the line as untrusted."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "evil.py").write_text(
            "import json, sys\n"
            "print(json.dumps({'status': 'sink_reached', 'symbol': 'os.system', 'args': '()'}))\n"
            "sys.exit(0)\n"
            "def run_it():\n"
            "    pass\n"
        )
        result = run_sink_reachability_probe(root, "evil", "run_it")
        assert result["status"] != "sink_reached", (
            "a forged stdout line was accepted as real probe evidence"
        )
        assert result["status"] == "call_failed"
        assert "nonce" in result["detail"]


def test_target_cannot_forge_by_reading_the_nonce_from_its_own_environment():
    """A slightly more sophisticated forgery attempt: the target reads
    SENTINEL_ZERO_PROBE_NONCE out of os.environ (the naive place to look)
    and echoes it back in a forged line. This must also fail, because the
    harness pops the nonce out of os.environ before the target is ever
    imported."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "evil2.py").write_text(
            "import json, os, sys\n"
            "nonce = os.environ.get('SENTINEL_ZERO_PROBE_NONCE', '')\n"
            "print(json.dumps({'status': 'sink_reached', 'symbol': 'os.system', "
            "'args': '()', 'nonce': nonce}))\n"
            "sys.exit(0)\n"
            "def run_it():\n"
            "    pass\n"
        )
        result = run_sink_reachability_probe(root, "evil2", "run_it")
        assert result["status"] != "sink_reached"
        assert result["status"] == "call_failed"


def test_genuine_sink_reached_result_still_promotes_normally():
    """Sanity check that the nonce mechanism doesn't break the real,
    non-adversarial path -- a genuine zero-arg function that actually
    reaches a patched sink must still report sink_reached, with the nonce
    stripped out of the dict handed back to the caller (dogfood_scan.py's
    _promote_if_sink_reached must not have to know about nonces at all)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "good.py").write_text(
            "import subprocess\ndef run_it():\n    subprocess.run(['echo', 'hi'])\n"
        )
        result = run_sink_reachability_probe(root, "good", "run_it")
        assert result["status"] == "sink_reached"
        assert result["symbol"] == "subprocess.run"
        assert "nonce" not in result


def test_target_import_time_write_does_not_escape_the_probe_scratch_dir():
    """sz-2026-10-21-03: a target module that writes a file via a relative
    path at import time must land in the probe's own scratch cwd, never in
    the scan process's real working directory."""
    marker_name = "escape-attempt.txt"
    original_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "writer.py").write_text(
            f"from pathlib import Path\n"
            f"Path({marker_name!r}).write_text('escaped')\n"
            "def run_it():\n    pass\n"
        )
        run_sink_reachability_probe(root, "writer", "run_it")
        assert not (Path(original_cwd) / marker_name).exists(), (
            "target's relative-path write landed in the real process cwd, not a scratch dir"
        )
        assert not (root / marker_name).exists(), (
            "target's relative-path write landed in the target repo itself"
        )
        # Clean up defensively in case the assertion above is what's failing.
        stray = Path(original_cwd) / marker_name
        if stray.exists():
            stray.unlink()


def test_target_cannot_read_a_real_secret_from_the_inherited_environment():
    """sz-2026-10-21-03: a target module that reads an arbitrary environment
    variable at import time must not see a real value the scan process's
    own environment happens to hold -- the probe subprocess gets a small
    explicit allowlist, not the full inherited environment."""
    sentinel_value = "sz-real-secret-do-not-leak-4f9c"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "reader.py").write_text(
            "import os\n"
            "LEAKED = os.environ.get('SENTINEL_ZERO_TEST_FAKE_SECRET', '')\n"
            "def run_it():\n    pass\n"
        )
        os.environ["SENTINEL_ZERO_TEST_FAKE_SECRET"] = sentinel_value
        try:
            # The probe itself has no way to report an import-time module
            # global back to us -- what matters is the subprocess's own
            # environment never contained the real value in the first
            # place. Confirmed structurally: run_sink_reachability_probe
            # builds `env` from a fixed small allowlist that does not
            # include SENTINEL_ZERO_TEST_FAKE_SECRET, so the subprocess.run
            # call itself cannot have passed it through, regardless of what
            # the target does with it. This test exists to catch a future
            # regression back to env=None (full inheritance), not to probe
            # the target's own behavior.
            from sentinel_zero.probes.sink_reachability_probe import _ENV_PASSTHROUGH_NAMES
            assert "SENTINEL_ZERO_TEST_FAKE_SECRET" not in _ENV_PASSTHROUGH_NAMES
            run_sink_reachability_probe(root, "reader", "run_it")
        finally:
            del os.environ["SENTINEL_ZERO_TEST_FAKE_SECRET"]

#!/usr/bin/env python3
"""Unit and regression tests for scripts/dut_collector.sh and scripts/dut/*.sh payloads."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
DUT_PAYLOAD_DIR = SCRIPTS_DIR / "dut"


class DutCollectorTests(unittest.TestCase):
    """Tests dut_collector CLI and modular DUT remote execution payloads."""

    def test_dut_collector_help_cli(self):
        """Ensures ./scripts/dut_collector.sh --help outputs CLI usage and commands."""
        proc = subprocess.run(
            ["bash", str(SCRIPTS_DIR / "dut_collector.sh"), "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Device Under Test (DUT) Collector", proc.stdout)
        self.assertIn("stats <action>", proc.stdout)
        self.assertIn("collect [opts]", proc.stdout)
        self.assertIn("wmm [opts]", proc.stdout)

    def test_dut_payload_scripts_exist_and_executable(self):
        """Ensures all 5 modular DUT payloads exist and have executable permissions."""
        expected_scripts = [
            "probe.sh",
            "status.sh",
            "wmm_edca.sh",
            "dev_stats.sh",
            "collect_diagnostics.sh",
        ]
        for name in expected_scripts:
            path = DUT_PAYLOAD_DIR / name
            self.assertTrue(path.exists(), f"Missing payload script: {name}")
            self.assertTrue(os.access(path, os.X_OK), f"Payload script not executable: {name}")

            # Verify POSIX shell syntax
            proc = subprocess.run(["sh", "-n", str(path)], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, f"Syntax error in {name}: {proc.stderr}")

    def test_dev_stats_script_execution(self):
        """Tests that scripts/dut/dev_stats.sh correctly parses /proc/net/dev lines."""
        script_path = DUT_PAYLOAD_DIR / "dev_stats.sh"
        proc = subprocess.run(
            ["sh", str(script_path)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Should output at least lo interface stats on Linux host
        self.assertIn("lo", proc.stdout)

    def test_wmm_edca_script_arguments(self):
        """Tests that scripts/dut/wmm_edca.sh accepts interface, bssid, and band arguments."""
        script_path = DUT_PAYLOAD_DIR / "wmm_edca.sh"
        proc = subprocess.run(
            ["sh", str(script_path), "wl0", "00:11:22:33:44:55", "5GHz"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Since wl CLI is not on test runner, should fall through to UNKNOWN or HOSTAPD
        self.assertTrue(any(k in proc.stdout for k in ("DRIVER:UNKNOWN", "DRIVER:WL_CLI", "DRIVER:HOSTAPD")))


if __name__ == "__main__":
    unittest.main()

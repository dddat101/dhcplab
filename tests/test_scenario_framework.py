#!/usr/bin/env python3
"""Unit and integration regression tests for the nwlab scenario framework."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ScenarioFrameworkTests(unittest.TestCase):
    """Tests scenario registration, resolution, listing, and execution."""

    def test_scenario_list_cli(self):
        """Ensures ./scripts/scenario.sh list outputs registered scenarios."""
        proc = subprocess.run(
            ["bash", "scripts/scenario.sh", "list"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("template", proc.stdout)
        self.assertIn("Throughput & Loss Benchmark", proc.stdout)

    def test_scenario_help_cli(self):
        """Ensures ./scripts/scenario.sh -h <scenario> displays scenario usage."""
        proc = subprocess.run(
            ["bash", "scripts/scenario.sh", "-h", "template"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("[TEMPLATE] CANONICAL THROUGHPUT", proc.stdout)
        self.assertIn("--bitrate", proc.stdout)
        self.assertIn("--duration", proc.stdout)

    def test_scenario_dry_run_execution(self):
        """Ensures ./scripts/scenario.sh --dry-run template completes cleanly without errors."""
        proc = subprocess.run(
            ["bash", "scripts/scenario.sh", "--dry-run", "template", "--bitrate", "200M"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Executing Scenario: [template]", proc.stdout)
        self.assertIn("[DRY-RUN] Would start iperf3 server", proc.stdout)

    def test_scenario_verify_compliance_cli(self):
        """Ensures ./scripts/verify_compliance.sh template works in standalone mode."""
        proc = subprocess.run(
            ["bash", "scripts/verify_compliance.sh", "template"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("COMPLIANCE VERIFICATION REPORT", proc.stdout)
        self.assertIn("[template]", proc.stdout)

    def test_custom_scenario_registration_and_alias_resolution(self):
        """Tests declarative registration and alias resolution in a bash subshell."""
        script = """set -Eeuo pipefail
source scripts/lib/common.sh
source scripts/lib/scenario_framework.sh

dummy_run() { echo "running dummy"; }
dummy_help() { echo "help dummy"; }

scenario_register \
    --id "custom_latency" \
    --name "Custom Latency Test" \
    --desc "Validates round trip latency" \
    --aliases "latency,lat01" \
    --lan-ns "ns-test" \
    --bpf "icmp" \
    --duration 5 \
    --run-fn "dummy_run" \
    --help-fn "dummy_help"

res1="$(scenario_resolve 'custom_latency')"
res2="$(scenario_resolve 'latency')"
res3="$(scenario_resolve 'lat01')"

echo "R1:${res1}"
echo "R2:${res2}"
echo "R3:${res3}"
"""
        proc = subprocess.run(
            ["bash", "-c", script],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("R1:custom_latency", proc.stdout)
        self.assertIn("R2:custom_latency", proc.stdout)
        self.assertIn("R3:custom_latency", proc.stdout)

    def test_orchestrator_mode_plan_cli(self):
        """Ensures ./scripts/scenario.sh plan displays the execution plan."""
        proc = subprocess.run(
            ["bash", "scripts/scenario.sh", "plan", "template"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Execution Plan for [template]:", proc.stdout)
        self.assertIn("Topology Mode", proc.stdout)
        self.assertIn("Canonical Mode", proc.stdout)

    def test_orchestrator_execution_plan_in_scenario_run(self):
        """Ensures scenario execution displays Execution Plan via orchestrator_mode."""
        proc = subprocess.run(
            ["bash", "scripts/scenario.sh", "--dry-run", "template"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Execution Plan for [Throughput & Loss Benchmark]:", proc.stdout)
        self.assertIn("Virtual Emulated : YES", proc.stdout)


if __name__ == "__main__":
    unittest.main()


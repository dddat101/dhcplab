#!/usr/bin/env python3
"""
tests/test_traffic_orchestrator.py - Unit Tests for Traffic Process Supervisor

Validates background process lifecycle orchestration, process registry tracking,
namespace fallback execution, timeout escalation, and clean child process reaping
defined in scripts/lib/traffic_orchestrator.sh.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ORCHESTRATOR_PATH = ROOT / "scripts" / "lib" / "traffic_orchestrator.sh"


class TrafficOrchestratorTests(unittest.TestCase):
    """Test suite for Bash-based Traffic Process Supervisor."""

    def setUp(self):
        self.assertTrue(
            ORCHESTRATOR_PATH.is_file(),
            f"Missing orchestrator script: {ORCHESTRATOR_PATH}",
        )

    def _run_bash(self, commands: str, timeout: int = 15) -> subprocess.CompletedProcess:
        """Run bash snippet sourcing the traffic orchestrator library."""
        full_script = f"""
        set -Eeuo pipefail
        source "{ORCHESTRATOR_PATH}"
        {commands}
        """
        return subprocess.run(
            ["bash", "-c", full_script],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def test_run_bg_registration_and_status(self):
        """Test process launching, registry tracking, and status querying."""
        script = """
        traffic_run_bg --job test_job sleep 2
        pid=$(traffic_get_pid test_job)
        [[ -n "${pid}" ]] || exit 10
        status=$(traffic_get_status test_job)
        echo "STATUS:${status}"
        echo "ACTIVE:${#ACTIVE_BG_PIDS[@]}"
        traffic_stop_group test_job
        after_status=$(traffic_get_status test_job || true)
        echo "AFTER:${after_status}"
        echo "ACTIVE_AFTER:${#ACTIVE_BG_PIDS[@]}"
        """
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
        self.assertIn("STATUS:RUNNING", res.stdout)
        self.assertIn("ACTIVE:1", res.stdout)
        self.assertIn("ACTIVE_AFTER:0", res.stdout)

    def test_run_bg_output_redirection(self):
        """Test that stdout and stderr are properly redirected to output log file."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            script = f"""
            traffic_run_bg --job echo_job --out "{tmp_path}" bash -c 'echo "traffic orchestrator output"'
            traffic_wait_all echo_job
            """
            res = self._run_bash(script)
            self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("traffic orchestrator output", content)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_wait_all_clean_exit_and_reap(self):
        """Test traffic_wait_all waiting for multiple parallel jobs and reaping cleanly."""
        script = """
        traffic_run_bg --job job_a sleep 0.2
        traffic_run_bg --job job_b sleep 0.3
        echo "BEFORE:${#ACTIVE_BG_PIDS[@]}"
        traffic_wait_all job_a job_b
        echo "AFTER:${#ACTIVE_BG_PIDS[@]}"
        """
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
        self.assertIn("BEFORE:2", res.stdout)
        self.assertIn("AFTER:0", res.stdout)

    def test_stop_group_graceful_termination(self):
        """Test traffic_stop_group stops lingering processes and cleans registry."""
        script = """
        traffic_run_bg --job slow_1 sleep 30
        traffic_run_bg --job slow_2 sleep 30
        pid1=$(traffic_get_pid slow_1)
        pid2=$(traffic_get_pid slow_2)
        kill -0 "${pid1}" || exit 11
        kill -0 "${pid2}" || exit 12
        traffic_stop_group slow_1 slow_2
        # Verify processes are terminated
        kill -0 "${pid1}" 2>/dev/null && exit 13 || true
        kill -0 "${pid2}" 2>/dev/null && exit 14 || true
        echo "TERMINATED_CLEANLY"
        echo "ACTIVE:${#ACTIVE_BG_PIDS[@]}"
        """
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
        self.assertIn("TERMINATED_CLEANLY", res.stdout)
        self.assertIn("ACTIVE:0", res.stdout)

    def test_wait_all_timeout_escalation(self):
        """Test traffic_wait_all with --timeout terminates stubborn lingering jobs."""
        script = """
        traffic_run_bg --job hung_job sleep 30
        pid=$(traffic_get_pid hung_job)
        set +e
        traffic_wait_all --timeout 1 hung_job
        rc=$?
        set -e
        echo "RC:${rc}"
        # Verify hung process was killed by timeout handler
        kill -0 "${pid}" 2>/dev/null && exit 15 || true
        echo "KILLED_AFTER_TIMEOUT"
        echo "ACTIVE:${#ACTIVE_BG_PIDS[@]}"
        """
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
        self.assertIn("RC:124", res.stdout)
        self.assertIn("KILLED_AFTER_TIMEOUT", res.stdout)
        self.assertIn("ACTIVE:0", res.stdout)

    def test_netns_fallback_on_host(self):
        """Test fallback to host execution when namespace is absent or unprivileged."""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            script = f"""
            traffic_run_bg --job fallback_test --netns "nonexistent_fake_ns_xyz" --out "{tmp_path}" bash -c 'echo "fallback_ok"'
            traffic_wait_all fallback_test
            """
            res = self._run_bash(script)
            self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
            with open(tmp_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("fallback_ok", content)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_clean_stale_processes(self):
        """Test traffic_clean_stale terminates processes matching specific pattern."""
        script = """
        # Spawn unique background command
        bash -c 'exec -a dhcplab_stale_test_proc sleep 25' &
        stale_pid=$!
        sleep 0.1
        kill -0 "${stale_pid}" || exit 20

        traffic_clean_stale "dhcplab_stale_test_proc"
        sleep 0.2

        if kill -0 "${stale_pid}" 2>/dev/null; then
            kill -KILL "${stale_pid}" 2>/dev/null || true
            exit 21
        fi
        echo "STALE_CLEANED"
        """
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
        self.assertIn("STALE_CLEANED", res.stdout)

    def test_reset_registry(self):
        """Test traffic_reset_registry clears all internal tracking state."""
        script = """
        traffic_run_bg --job reg_test sleep 1
        echo "COUNT_BEFORE:${#TRAFFIC_JOB_PID[@]}"
        traffic_reset_registry
        echo "COUNT_AFTER:${#TRAFFIC_JOB_PID[@]}"
        """
        res = self._run_bash(script)
        self.assertEqual(res.returncode, 0, f"Stderr: {res.stderr}")
        self.assertIn("COUNT_BEFORE:1", res.stdout)
        self.assertIn("COUNT_AFTER:0", res.stdout)


if __name__ == "__main__":
    unittest.main()

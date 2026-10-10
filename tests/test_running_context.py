#!/usr/bin/env python3
"""
Unit tests for tools/running_context.py (RunningContextResolver)
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from running_context import (
    ExecutionMode,
    ExecutionPlan,
    RunningContextResolver,
    TopologyMode,
)


class TestRunningContextResolver(unittest.TestCase):

    def test_virtual_topology_strictly_emulated_by_default(self):
        """Invariant 1: Virtual topology MUST strictly resolve to emulated_virtual by default."""
        plan = RunningContextResolver.resolve(
            topology_mode="virtual",
            config_wifi_mode="real_single_band",  # Even with config specifying real card
            wifi_card_count=1,
            detected_wifi_if="wlp3s0",
            detected_wifi_ssid="DUT_5G",
        )
        self.assertEqual(plan.topology_mode, "virtual")
        self.assertEqual(plan.execution_mode, ExecutionMode.EMULATED_VIRTUAL.value)
        self.assertTrue(plan.is_virtual)
        self.assertFalse(plan.requires_host_route)
        self.assertFalse(plan.requires_remote_client)
        self.assertFalse(plan.requires_iptables_mangle)
        self.assertEqual(plan.primary_wifi_ns, "ns-wlan5g")
        self.assertEqual(plan.legacy_sim_mode(), "emulated")
        self.assertEqual(plan.legacy_voip_mode(), "virtual")
        self.assertEqual(plan.legacy_wqos_mode(), "virtual")

    def test_virtual_topology_with_forced_cli_override(self):
        """User can explicitly force physical Wi-Fi in virtual topology via CLI flag."""
        plan = RunningContextResolver.resolve(
            topology_mode="virtual",
            cli_wifi_mode="real_single_band",
            detected_wifi_if="wlp3s0",
            detected_wifi_ssid="DUT_5G",
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.LOCAL_PHYSICAL_SINGLE.value)
        self.assertFalse(plan.is_virtual)
        self.assertTrue(plan.requires_host_route)
        self.assertTrue(plan.is_forced_override)
        self.assertEqual(plan.legacy_sim_mode(), "real_single_band")

    def test_physical_topology_auto_zero_cards_fallback(self):
        """Physical topology with 0 cards and no remote station falls back to emulated."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            wifi_card_count=0,
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.EMULATED_VIRTUAL.value)
        self.assertTrue(plan.is_virtual)
        self.assertFalse(plan.requires_host_route)

    def test_physical_topology_auto_zero_cards_with_remote_client(self):
        """Physical topology with 0 cards but active remote station resolves to remote_physical_only."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            wifi_card_count=0,
            remote_client_host="192.168.1.200",
            remote_wifi_ok=True,
            remote_wifi_if="wlan0",
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.REMOTE_PHYSICAL_ONLY.value)
        self.assertFalse(plan.is_virtual)
        self.assertTrue(plan.requires_remote_client)
        self.assertEqual(plan.primary_wifi_if, "wlan0")
        self.assertEqual(plan.legacy_sim_mode(), "remote")
        self.assertEqual(plan.legacy_voip_mode(), "remote_only")

    def test_physical_topology_auto_single_connected_card(self):
        """Physical topology with 1 connected card resolves to local_physical_single."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            wifi_card_count=1,
            detected_wifi_if="wlp3s0",
            detected_wifi_ssid="DUT_5G",
            detected_wifi_band="5GHz",
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.LOCAL_PHYSICAL_SINGLE.value)
        self.assertFalse(plan.is_virtual)
        self.assertTrue(plan.requires_host_route)
        self.assertTrue(plan.requires_iptables_mangle)
        self.assertEqual(plan.primary_wifi_if, "wlp3s0")
        self.assertEqual(plan.legacy_sim_mode(), "real_single_band")
        self.assertEqual(plan.legacy_voip_mode(), "physical_single")
        self.assertEqual(plan.legacy_wqos_mode(), "physical_single")

    def test_physical_topology_auto_single_disconnected_card(self):
        """Physical topology with 1 card that is NOT connected to SSID falls back to emulated."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            wifi_card_count=1,
            detected_wifi_if="wlp3s0",
            detected_wifi_ssid="",  # Disconnected
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.EMULATED_VIRTUAL.value)
        self.assertTrue(plan.is_virtual)

    def test_physical_topology_explicit_sequential(self):
        """Explicit sequential multiband mode resolution."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            cli_wifi_mode="sequential",
            detected_wifi_if="wlp3s0",
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.SEQUENTIAL_MULTIBAND.value)
        self.assertTrue(plan.requires_host_route)
        self.assertEqual(plan.legacy_sim_mode(), "sequential")

    def test_physical_topology_explicit_tri_station(self):
        """Explicit 3-way concurrent distributed benchmark resolution."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            cli_wifi_mode="tri_station",
            detected_wifi_if="wlp3s0",
            remote_client_host="remote_pc",
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.CONCURRENT_DISTRIBUTED.value)
        self.assertTrue(plan.requires_host_route)
        self.assertTrue(plan.requires_remote_client)
        self.assertEqual(plan.legacy_sim_mode(), "tri_station")
        self.assertEqual(plan.legacy_voip_mode(), "distributed")

    def test_physical_topology_hybrid_mode(self):
        """Explicit hybrid execution mode resolution."""
        plan = RunningContextResolver.resolve(
            topology_mode="physical",
            cli_wifi_mode="hybrid",
            detected_wifi_if="wlp3s0",
        )
        self.assertEqual(plan.execution_mode, ExecutionMode.HYBRID.value)
        self.assertTrue(plan.requires_host_route)
        self.assertEqual(plan.legacy_sim_mode(), "hybrid")

    def test_alias_normalization(self):
        """Verify all historical aliases map to canonical ExecutionMode enums."""
        self.assertEqual(RunningContextResolver.normalize_mode("virtual"), ExecutionMode.EMULATED_VIRTUAL)
        self.assertEqual(RunningContextResolver.normalize_mode("emulated"), ExecutionMode.EMULATED_VIRTUAL)
        self.assertEqual(RunningContextResolver.normalize_mode("real_single"), ExecutionMode.LOCAL_PHYSICAL_SINGLE)
        self.assertEqual(RunningContextResolver.normalize_mode("real_single_band"), ExecutionMode.LOCAL_PHYSICAL_SINGLE)
        self.assertEqual(RunningContextResolver.normalize_mode("physical_single"), ExecutionMode.LOCAL_PHYSICAL_SINGLE)
        self.assertEqual(RunningContextResolver.normalize_mode("remote"), ExecutionMode.REMOTE_PHYSICAL_ONLY)
        self.assertEqual(RunningContextResolver.normalize_mode("remote_only"), ExecutionMode.REMOTE_PHYSICAL_ONLY)
        self.assertEqual(RunningContextResolver.normalize_mode("tri_station"), ExecutionMode.CONCURRENT_DISTRIBUTED)
        self.assertEqual(RunningContextResolver.normalize_mode("distributed"), ExecutionMode.CONCURRENT_DISTRIBUTED)
        self.assertEqual(RunningContextResolver.normalize_mode("sequential"), ExecutionMode.SEQUENTIAL_MULTIBAND)
        self.assertEqual(RunningContextResolver.normalize_mode("multiband"), ExecutionMode.SEQUENTIAL_MULTIBAND)
        self.assertIsNone(RunningContextResolver.normalize_mode("auto"))
        self.assertIsNone(RunningContextResolver.normalize_mode(""))

    def test_env_export_structure(self):
        """Verify shell environment variable generation for Bash evaluation."""
        plan = RunningContextResolver.resolve(
            topology_mode="virtual",
        )
        env_str = plan.to_env(prefix="TEST_PLAN_")
        self.assertIn('TEST_PLAN_TOPOLOGY_MODE="virtual"', env_str)
        self.assertIn('TEST_PLAN_EXECUTION_MODE="emulated_virtual"', env_str)
        self.assertIn('TEST_PLAN_IS_VIRTUAL="1"', env_str)
        self.assertIn('TEST_PLAN_REQUIRES_HOST_ROUTE="0"', env_str)
        self.assertIn('TEST_PLAN_SIM_MODE="emulated"', env_str)
        self.assertIn('TEST_PLAN_VOIP_MODE="virtual"', env_str)

    def test_json_export_structure(self):
        """Verify JSON serialization round-trip."""
        plan = RunningContextResolver.resolve(topology_mode="virtual")
        data = json.loads(plan.to_json())
        self.assertEqual(data["topology_mode"], "virtual")
        self.assertEqual(data["execution_mode"], "emulated_virtual")
        self.assertTrue(data["is_virtual"])


if __name__ == "__main__":
    unittest.main()

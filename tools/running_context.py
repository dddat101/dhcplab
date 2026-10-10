#!/usr/bin/env python3
"""
running_context.py - Unified Running Context Resolver

Deep domain module responsible for resolving the laboratory execution mode,
validating topology constraints, enforcing virtual/physical isolation invariants,
and exporting an immutable Execution Plan to scenario runners.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class TopologyMode(str, Enum):
    VIRTUAL = "virtual"
    PHYSICAL = "physical"


class ExecutionMode(str, Enum):
    EMULATED_VIRTUAL = "emulated_virtual"
    LOCAL_PHYSICAL_SINGLE = "local_physical_single"
    REMOTE_PHYSICAL_ONLY = "remote_physical_only"
    CONCURRENT_DISTRIBUTED = "concurrent_distributed"
    SEQUENTIAL_MULTIBAND = "sequential_multiband"
    HYBRID = "hybrid"


@dataclass(frozen=True)
class ExecutionPlan:
    """Immutable execution configuration for scenario execution."""
    topology_mode: str
    execution_mode: str
    is_virtual: bool
    requires_host_route: bool
    requires_remote_client: bool
    requires_iptables_mangle: bool
    primary_wifi_if: str
    primary_wifi_ns: str
    primary_wifi_ip: str
    primary_wifi_ssid: str
    primary_wifi_band: str
    reason: str
    is_forced_override: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_env(self, prefix: str = "PLAN_") -> str:
        """Export as shell environment variables for Bash eval."""
        lines = [
            f'{prefix}TOPOLOGY_MODE="{self.topology_mode}"',
            f'{prefix}EXECUTION_MODE="{self.execution_mode}"',
            f'{prefix}IS_VIRTUAL="{"1" if self.is_virtual else "0"}"',
            f'{prefix}REQUIRES_HOST_ROUTE="{"1" if self.requires_host_route else "0"}"',
            f'{prefix}REQUIRES_REMOTE_CLIENT="{"1" if self.requires_remote_client else "0"}"',
            f'{prefix}REQUIRES_IPTABLES_MANGLE="{"1" if self.requires_iptables_mangle else "0"}"',
            f'{prefix}PRIMARY_WIFI_IF="{self.primary_wifi_if}"',
            f'{prefix}PRIMARY_WIFI_NS="{self.primary_wifi_ns}"',
            f'{prefix}PRIMARY_WIFI_IP="{self.primary_wifi_ip}"',
            f'{prefix}PRIMARY_WIFI_SSID="{self.primary_wifi_ssid}"',
            f'{prefix}PRIMARY_WIFI_BAND="{self.primary_wifi_band}"',
            f'{prefix}REASON="{self.reason}"',
            f'{prefix}IS_FORCED_OVERRIDE="{"1" if self.is_forced_override else "0"}"',
            # Scenario-specific backward-compatible aliases
            f'{prefix}SIM_MODE="{self.legacy_sim_mode()}"',
            f'{prefix}VOIP_MODE="{self.legacy_voip_mode()}"',
            f'{prefix}WQOS_MODE="{self.legacy_wqos_mode()}"',
        ]
        return "\n".join(lines)

    def legacy_sim_mode(self) -> str:
        """Map canonical execution mode to scenario 04 simultaneous terminology."""
        mapping = {
            ExecutionMode.EMULATED_VIRTUAL.value: "emulated",
            ExecutionMode.LOCAL_PHYSICAL_SINGLE.value: "real_single_band",
            ExecutionMode.REMOTE_PHYSICAL_ONLY.value: "remote",
            ExecutionMode.CONCURRENT_DISTRIBUTED.value: "tri_station",
            ExecutionMode.SEQUENTIAL_MULTIBAND.value: "sequential",
            ExecutionMode.HYBRID.value: "hybrid",
        }
        return mapping.get(self.execution_mode, "emulated")

    def legacy_voip_mode(self) -> str:
        """Map canonical execution mode to scenario 05 VoIP QoS terminology."""
        mapping = {
            ExecutionMode.EMULATED_VIRTUAL.value: "virtual",
            ExecutionMode.LOCAL_PHYSICAL_SINGLE.value: "physical_single",
            ExecutionMode.REMOTE_PHYSICAL_ONLY.value: "remote_only",
            ExecutionMode.CONCURRENT_DISTRIBUTED.value: "distributed",
            ExecutionMode.SEQUENTIAL_MULTIBAND.value: "physical_single",
            ExecutionMode.HYBRID.value: "physical_single",
        }
        return mapping.get(self.execution_mode, "virtual")

    def legacy_wqos_mode(self) -> str:
        """Map canonical execution mode to scenario 06 Wireless QoS terminology."""
        mapping = {
            ExecutionMode.EMULATED_VIRTUAL.value: "virtual",
            ExecutionMode.LOCAL_PHYSICAL_SINGLE.value: "physical_single",
            ExecutionMode.REMOTE_PHYSICAL_ONLY.value: "remote_only",
            ExecutionMode.CONCURRENT_DISTRIBUTED.value: "physical_single",
            ExecutionMode.SEQUENTIAL_MULTIBAND.value: "physical_single",
            ExecutionMode.HYBRID.value: "physical_single",
        }
        return mapping.get(self.execution_mode, "virtual")


class RunningContextResolver:
    """
    Centralized domain service that inspects lab topology constraints,
    hardware discovery findings, and user overrides to construct an ExecutionPlan.
    """

    ALIASES = {
        "emulated": ExecutionMode.EMULATED_VIRTUAL,
        "virtual": ExecutionMode.EMULATED_VIRTUAL,
        "emulated_virtual": ExecutionMode.EMULATED_VIRTUAL,
        "real_single": ExecutionMode.LOCAL_PHYSICAL_SINGLE,
        "real_single_band": ExecutionMode.LOCAL_PHYSICAL_SINGLE,
        "physical_single": ExecutionMode.LOCAL_PHYSICAL_SINGLE,
        "local_physical_single": ExecutionMode.LOCAL_PHYSICAL_SINGLE,
        "remote": ExecutionMode.REMOTE_PHYSICAL_ONLY,
        "remote_only": ExecutionMode.REMOTE_PHYSICAL_ONLY,
        "remote_client": ExecutionMode.REMOTE_PHYSICAL_ONLY,
        "remote_physical_only": ExecutionMode.REMOTE_PHYSICAL_ONLY,
        "tri_station": ExecutionMode.CONCURRENT_DISTRIBUTED,
        "tri_stream": ExecutionMode.CONCURRENT_DISTRIBUTED,
        "concurrent": ExecutionMode.CONCURRENT_DISTRIBUTED,
        "distributed": ExecutionMode.CONCURRENT_DISTRIBUTED,
        "distributed_3way": ExecutionMode.CONCURRENT_DISTRIBUTED,
        "concurrent_distributed": ExecutionMode.CONCURRENT_DISTRIBUTED,
        "sequential": ExecutionMode.SEQUENTIAL_MULTIBAND,
        "sequential_bands": ExecutionMode.SEQUENTIAL_MULTIBAND,
        "multiband": ExecutionMode.SEQUENTIAL_MULTIBAND,
        "sequential_multiband": ExecutionMode.SEQUENTIAL_MULTIBAND,
        "hybrid": ExecutionMode.HYBRID,
    }

    @classmethod
    def normalize_mode(cls, raw_mode: Optional[str]) -> Optional[ExecutionMode]:
        if not raw_mode:
            return None
        key = raw_mode.strip().lower()
        if key == "auto":
            return None
        return cls.ALIASES.get(key)

    @classmethod
    def resolve(
        cls,
        topology_mode: str = "virtual",
        cli_wifi_mode: Optional[str] = None,
        config_wifi_mode: Optional[str] = None,
        wifi_card_count: int = 0,
        detected_wifi_if: str = "",
        detected_wifi_ssid: str = "",
        detected_wifi_band: str = "",
        detected_wifi_ip: str = "",
        remote_client_host: str = "",
        remote_wifi_ok: bool = False,
        remote_wifi_if: str = "",
        remote_wifi_ip: str = "",
        remote_wifi_ssid: str = "",
        remote_wifi_band: str = "",
        force_cli_override: bool = False
    ) -> ExecutionPlan:
        """
        Evaluate inputs and produce an immutable ExecutionPlan following strict invariants.
        """
        topo = TopologyMode.PHYSICAL if topology_mode.strip().lower() == "physical" else TopologyMode.VIRTUAL
        cli_target = cls.normalize_mode(cli_wifi_mode)
        cfg_target = cls.normalize_mode(config_wifi_mode)

        # ----------------------------------------------------------------------
        # Case A: Pure Software Virtual Topology (ns-dut, ns-wan, ns-pc, ns-wlan*)
        # ----------------------------------------------------------------------
        if topo == TopologyMode.VIRTUAL:
            # If user explicitly forced a physical mode via CLI flag, honor it with warning
            if cli_target and cli_target != ExecutionMode.EMULATED_VIRTUAL:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=cli_target.value,
                    is_virtual=False,
                    requires_host_route=True,
                    requires_remote_client=(cli_target in (ExecutionMode.REMOTE_PHYSICAL_ONLY, ExecutionMode.CONCURRENT_DISTRIBUTED)),
                    requires_iptables_mangle=True,
                    primary_wifi_if=detected_wifi_if or "wlp3s0",
                    primary_wifi_ns="",
                    primary_wifi_ip=detected_wifi_ip,
                    primary_wifi_ssid=detected_wifi_ssid,
                    primary_wifi_band=detected_wifi_band,
                    reason=f"Forced CLI override '{cli_wifi_mode}' in virtual topology",
                    is_forced_override=True
                )

            # Invariant: Virtual topology strictly uses software namespaces by default
            return ExecutionPlan(
                topology_mode=topo.value,
                execution_mode=ExecutionMode.EMULATED_VIRTUAL.value,
                is_virtual=True,
                requires_host_route=False,
                requires_remote_client=False,
                requires_iptables_mangle=False,
                primary_wifi_if="eth0",
                primary_wifi_ns="ns-wlan5g",
                primary_wifi_ip="192.168.1.32",
                primary_wifi_ssid="virtual-ssid-5g",
                primary_wifi_band="5GHz",
                reason="Virtual topology active; isolated Linux network namespaces engaged"
            )

        # ----------------------------------------------------------------------
        # Case B: Physical Hardware Testbed (Connected to physical DUT)
        # ----------------------------------------------------------------------
        desired_mode = cli_target or cfg_target

        if desired_mode is not None:
            # Explicit physical mode requested
            if desired_mode == ExecutionMode.EMULATED_VIRTUAL:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.EMULATED_VIRTUAL.value,
                    is_virtual=True,
                    requires_host_route=False,
                    requires_remote_client=False,
                    requires_iptables_mangle=False,
                    primary_wifi_if="eth0",
                    primary_wifi_ns="ns-wlan5g",
                    primary_wifi_ip="192.168.1.32",
                    primary_wifi_ssid="emulated",
                    primary_wifi_band="5GHz",
                    reason="Emulated virtual namespaces explicitly requested in physical topology"
                )

            if desired_mode == ExecutionMode.REMOTE_PHYSICAL_ONLY:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.REMOTE_PHYSICAL_ONLY.value,
                    is_virtual=False,
                    requires_host_route=False,
                    requires_remote_client=True,
                    requires_iptables_mangle=False,
                    primary_wifi_if=remote_wifi_if or "wlan0",
                    primary_wifi_ns="",
                    primary_wifi_ip=remote_wifi_ip,
                    primary_wifi_ssid=remote_wifi_ssid,
                    primary_wifi_band=remote_wifi_band or "Remote-WiFi",
                    reason=f"Remote physical station on {remote_client_host or 'remote_host'} engaged"
                )

            if desired_mode == ExecutionMode.CONCURRENT_DISTRIBUTED:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.CONCURRENT_DISTRIBUTED.value,
                    is_virtual=False,
                    requires_host_route=True,
                    requires_remote_client=True,
                    requires_iptables_mangle=True,
                    primary_wifi_if=detected_wifi_if or "wlp3s0",
                    primary_wifi_ns="",
                    primary_wifi_ip=detected_wifi_ip,
                    primary_wifi_ssid=detected_wifi_ssid,
                    primary_wifi_band=detected_wifi_band,
                    reason="Concurrent distributed 3-way benchmark (local wired + local 5G + remote 2.4G) engaged"
                )

            if desired_mode == ExecutionMode.SEQUENTIAL_MULTIBAND:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.SEQUENTIAL_MULTIBAND.value,
                    is_virtual=False,
                    requires_host_route=True,
                    requires_remote_client=False,
                    requires_iptables_mangle=True,
                    primary_wifi_if=detected_wifi_if or "wlp3s0",
                    primary_wifi_ns="",
                    primary_wifi_ip=detected_wifi_ip,
                    primary_wifi_ssid=detected_wifi_ssid,
                    primary_wifi_band=detected_wifi_band,
                    reason="Sequential multi-band testing (5GHz -> 2.4GHz) on local physical card engaged"
                )

            if desired_mode == ExecutionMode.HYBRID:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.HYBRID.value,
                    is_virtual=False,
                    requires_host_route=True,
                    requires_remote_client=False,
                    requires_iptables_mangle=True,
                    primary_wifi_if=detected_wifi_if or "wlp3s0",
                    primary_wifi_ns="",
                    primary_wifi_ip=detected_wifi_ip,
                    primary_wifi_ssid=detected_wifi_ssid,
                    primary_wifi_band=detected_wifi_band,
                    reason="Hybrid execution (local physical active band + emulated namespaces) engaged"
                )

            # LOCAL_PHYSICAL_SINGLE
            return ExecutionPlan(
                topology_mode=topo.value,
                execution_mode=ExecutionMode.LOCAL_PHYSICAL_SINGLE.value,
                is_virtual=False,
                requires_host_route=True,
                requires_remote_client=False,
                requires_iptables_mangle=True,
                primary_wifi_if=detected_wifi_if or "wlp3s0",
                primary_wifi_ns="",
                primary_wifi_ip=detected_wifi_ip,
                primary_wifi_ssid=detected_wifi_ssid,
                primary_wifi_band=detected_wifi_band,
                reason="Single physical Wi-Fi over-the-air card engaged"
            )

        # ----------------------------------------------------------------------
        # Case C: Physical Hardware Topology with Auto-Discovery Mode
        # ----------------------------------------------------------------------
        if wifi_card_count == 0:
            if remote_client_host and remote_wifi_ok:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.REMOTE_PHYSICAL_ONLY.value,
                    is_virtual=False,
                    requires_host_route=False,
                    requires_remote_client=True,
                    requires_iptables_mangle=False,
                    primary_wifi_if=remote_wifi_if or "wlan0",
                    primary_wifi_ns="",
                    primary_wifi_ip=remote_wifi_ip,
                    primary_wifi_ssid=remote_wifi_ssid,
                    primary_wifi_band=remote_wifi_band or "Remote-WiFi",
                    reason="Auto-discovery: 0 local cards, fallback to connected remote station"
                )
            return ExecutionPlan(
                topology_mode=topo.value,
                execution_mode=ExecutionMode.EMULATED_VIRTUAL.value,
                is_virtual=True,
                requires_host_route=False,
                requires_remote_client=False,
                requires_iptables_mangle=False,
                primary_wifi_if="eth0",
                primary_wifi_ns="ns-wlan5g",
                primary_wifi_ip="192.168.1.32",
                primary_wifi_ssid="emulated",
                primary_wifi_band="5GHz",
                reason="Auto-discovery: 0 local cards detected, fallback to emulated namespaces"
            )

        if wifi_card_count == 1:
            if detected_wifi_ssid:
                if remote_client_host and remote_wifi_ok:
                    return ExecutionPlan(
                        topology_mode=topo.value,
                        execution_mode=ExecutionMode.CONCURRENT_DISTRIBUTED.value,
                        is_virtual=False,
                        requires_host_route=True,
                        requires_remote_client=True,
                        requires_iptables_mangle=True,
                        primary_wifi_if=detected_wifi_if or "wlp3s0",
                        primary_wifi_ns="",
                        primary_wifi_ip=detected_wifi_ip,
                        primary_wifi_ssid=detected_wifi_ssid,
                        primary_wifi_band=detected_wifi_band,
                        reason="Auto-discovery: 1 local card connected + active remote station -> distributed mode"
                    )
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.LOCAL_PHYSICAL_SINGLE.value,
                    is_virtual=False,
                    requires_host_route=True,
                    requires_remote_client=False,
                    requires_iptables_mangle=True,
                    primary_wifi_if=detected_wifi_if or "wlp3s0",
                    primary_wifi_ns="",
                    primary_wifi_ip=detected_wifi_ip,
                    primary_wifi_ssid=detected_wifi_ssid,
                    primary_wifi_band=detected_wifi_band,
                    reason=f"Auto-discovery: 1 local card connected to SSID '{detected_wifi_ssid}'"
                )
            # Local card present but disconnected from SSID
            if remote_client_host and remote_wifi_ok:
                return ExecutionPlan(
                    topology_mode=topo.value,
                    execution_mode=ExecutionMode.REMOTE_PHYSICAL_ONLY.value,
                    is_virtual=False,
                    requires_host_route=False,
                    requires_remote_client=True,
                    requires_iptables_mangle=False,
                    primary_wifi_if=remote_wifi_if or "wlan0",
                    primary_wifi_ns="",
                    primary_wifi_ip=remote_wifi_ip,
                    primary_wifi_ssid=remote_wifi_ssid,
                    primary_wifi_band=remote_wifi_band or "Remote-WiFi",
                    reason="Auto-discovery: local card disconnected, fallback to connected remote station"
                )
            return ExecutionPlan(
                topology_mode=topo.value,
                execution_mode=ExecutionMode.EMULATED_VIRTUAL.value,
                is_virtual=True,
                requires_host_route=False,
                requires_remote_client=False,
                requires_iptables_mangle=False,
                primary_wifi_if="eth0",
                primary_wifi_ns="ns-wlan5g",
                primary_wifi_ip="192.168.1.32",
                primary_wifi_ssid="emulated",
                primary_wifi_band="5GHz",
                reason="Auto-discovery: local card detected but not connected to SSID; fallback to emulated namespaces"
            )

        # 2 or more cards
        return ExecutionPlan(
            topology_mode=topo.value,
            execution_mode=ExecutionMode.CONCURRENT_DISTRIBUTED.value,
            is_virtual=False,
            requires_host_route=True,
            requires_remote_client=bool(remote_client_host),
            requires_iptables_mangle=True,
            primary_wifi_if=detected_wifi_if or "wlp3s0",
            primary_wifi_ns="",
            primary_wifi_ip=detected_wifi_ip,
            primary_wifi_ssid=detected_wifi_ssid,
            primary_wifi_band=detected_wifi_band,
            reason=f"Auto-discovery: {wifi_card_count} physical wireless cards detected"
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Running Context Resolver: Evaluates lab topology and generates an ExecutionPlan."
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    resolve_cmd = sub.add_parser("resolve", help="Resolve running mode and output plan.")
    export_cmd = sub.add_parser("export-env", help="Resolve running mode and output shell export statements.")

    for p in (resolve_cmd, export_cmd):
        p.add_argument("--topology-mode", default="virtual", help="Topology mode: 'virtual' or 'physical'")
        p.add_argument("--cli-wifi-mode", default="", help="User CLI override (--wifi-mode)")
        p.add_argument("--config-wifi-mode", default="auto", help="Config file setting (WIFI_TEST_MODE)")
        p.add_argument("--wifi-card-count", type=int, default=0, help="Detected Wi-Fi card count")
        p.add_argument("--wifi-if", default="", help="Detected physical Wi-Fi interface")
        p.add_argument("--wifi-ssid", default="", help="Connected Wi-Fi SSID")
        p.add_argument("--wifi-band", default="", help="Connected Wi-Fi band (e.g. 5GHz)")
        p.add_argument("--wifi-ip", default="", help="IP address on Wi-Fi interface")
        p.add_argument("--remote-host", default="", help="Remote PC client host")
        p.add_argument("--remote-wifi-ok", action="store_true", help="Remote PC Wi-Fi is reachable and verified")
        p.add_argument("--remote-wifi-if", default="", help="Remote Wi-Fi interface")
        p.add_argument("--remote-wifi-ip", default="", help="Remote Wi-Fi IP")
        p.add_argument("--remote-wifi-ssid", default="", help="Remote Wi-Fi SSID")
        p.add_argument("--remote-wifi-band", default="", help="Remote Wi-Fi band")

    resolve_cmd.add_argument("--json", action="store_true", help="Print plan as JSON")
    export_cmd.add_argument("--prefix", default="PLAN_", help="Prefix for exported shell variables")

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    plan = RunningContextResolver.resolve(
        topology_mode=args.topology_mode,
        cli_wifi_mode=args.cli_wifi_mode or None,
        config_wifi_mode=args.config_wifi_mode or None,
        wifi_card_count=args.wifi_card_count,
        detected_wifi_if=args.wifi_if,
        detected_wifi_ssid=args.wifi_ssid,
        detected_wifi_band=args.wifi_band,
        detected_wifi_ip=args.wifi_ip,
        remote_client_host=args.remote_host,
        remote_wifi_ok=args.remote_wifi_ok,
        remote_wifi_if=args.remote_wifi_if,
        remote_wifi_ip=args.remote_wifi_ip,
        remote_wifi_ssid=args.remote_wifi_ssid,
        remote_wifi_band=args.remote_wifi_band,
    )

    if args.subcommand == "export-env":
        print(plan.to_env(prefix=getattr(args, "prefix", "PLAN_")))
        return 0

    if getattr(args, "json", False):
        print(plan.to_json())
    else:
        print(f"=== Execution Plan ===")
        print(f"  Topology Mode       : {plan.topology_mode}")
        print(f"  Execution Mode      : {plan.execution_mode.upper()}")
        print(f"  Is Virtual          : {plan.is_virtual}")
        print(f"  Requires Host Route : {plan.requires_host_route}")
        print(f"  Requires Remote     : {plan.requires_remote_client}")
        print(f"  Primary Wi-Fi Dev   : {plan.primary_wifi_if} ({plan.primary_wifi_ns or 'host'})")
        print(f"  Reason              : {plan.reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

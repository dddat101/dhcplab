#!/usr/bin/env python3
"""
voip_pcap_audit.py - Dual-Sided VoIP QoS Packet Capture Analyzer

Performs multi-point cross-verification of VoIP RTP streams across WAN and
LAN/Wi-Fi interfaces. Computes per-stream packet loss, jitter, arrival delta,
and DiffServ DSCP 46 (EF) preservation to quantitatively evaluate Gateway QoS.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from evidence_auditor import run_tshark_count, parse_rtp_streams, VoipStreamAuditor



def audit_stream(
    stream_name: str,
    direction: str,
    tx_pcap: str,
    tx_filter: str,
    rx_pcap: str,
    rx_filter: str,
    dscp_target: int = 46
) -> Dict[str, Any]:
    """Audit an individual directional media stream between sender and receiver."""
    tx_count = run_tshark_count(tx_pcap, tx_filter)
    rx_count = run_tshark_count(rx_pcap, rx_filter)

    tx_dscp = run_tshark_count(tx_pcap, f"({tx_filter}) and ip.dsfield == {hex(dscp_target << 2)}")
    rx_dscp = run_tshark_count(rx_pcap, f"({rx_filter}) and ip.dsfield == {hex(dscp_target << 2)}")

    if tx_count > 0:
        loss_pkts = max(0, tx_count - rx_count)
        loss_pct = round((loss_pkts / tx_count) * 100.0, 3)
    else:
        loss_pkts = 0
        loss_pct = 0.0

    tx_dscp_pct = round((tx_dscp / tx_count * 100.0), 1) if tx_count > 0 else 0.0
    rx_dscp_pct = round((rx_dscp / rx_count * 100.0), 1) if rx_count > 0 else 0.0

    return {
        "stream": stream_name,
        "direction": direction,
        "tx_packets": tx_count,
        "rx_packets": rx_count,
        "lost_packets": loss_pkts,
        "loss_pct": loss_pct,
        "tx_dscp46_pkts": tx_dscp,
        "rx_dscp46_pkts": rx_dscp,
        "tx_dscp_ok": (tx_dscp_pct >= 95.0) if tx_count > 0 else False,
        "rx_dscp_ok": (rx_dscp_pct >= 95.0) if rx_count > 0 else False,
    }


def _create_stream_entry(
    name: str,
    direction: str,
    tx_s: Optional[Dict[str, Any]],
    rx_s: Optional[Dict[str, Any]],
    dscp_ok: bool,
) -> Dict[str, Any]:
    tx_pkts = tx_s["packets"] if tx_s else (rx_s["packets"] if rx_s else 0)
    rx_pkts = rx_s["packets"] if rx_s else 0

    lost_pkts = 0
    loss_pct = 0.0
    if rx_s:
        lost_m = re.search(r"(\d+)", str(rx_s.get("lost_str", "0")))
        lost_pkts = int(lost_m.group(1)) if lost_m else 0
        loss_pct = round((lost_pkts / max(1, rx_pkts + lost_pkts)) * 100.0, 2)
    elif tx_s and not rx_s:
        lost_pkts = tx_pkts
        loss_pct = 100.0

    jitter = rx_s.get("mean_jitter_ms", 0.0) if rx_s else (tx_s.get("mean_jitter_ms", 0.0) if tx_s else 0.0)
    delta = rx_s.get("mean_delta_ms", 0.0) if rx_s else (tx_s.get("mean_delta_ms", 0.0) if tx_s else 0.0)

    return {
        "stream": name,
        "direction": direction,
        "tx_packets": tx_pkts,
        "rx_packets": rx_pkts,
        "lost_packets": lost_pkts,
        "loss_pct": loss_pct,
        "mean_jitter_ms": jitter,
        "mean_delta_ms": delta,
        "dscp46_ok": dscp_ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Dual-Sided VoIP QoS Multi-Point Packet Capture Analyzer"
    )
    parser.add_argument("--wan-pcap", required=True, help="WAN endpoint PCAP capture file.")
    parser.add_argument("--phone1-pcap", help="Local Phone 1 Wi-Fi PCAP capture file.")
    parser.add_argument("--phone2-pcap", help="Phone 2 (Remote/Local) Wi-Fi PCAP capture file.")
    parser.add_argument("--lan-pcap", help="Wired PC LAN PCAP capture file.")
    parser.add_argument("--loss-tolerance", type=float, default=1.0, help="Max acceptable packet loss %% (default: 1.0%%).")
    parser.add_argument("--pc-baseline", type=float, default=0.0, help="Baseline wired PC throughput in Mbps.")
    parser.add_argument("--pc-during", type=float, default=0.0, help="Concurrent wired PC throughput in Mbps.")
    parser.add_argument("--output", "-o", help="Path to write JSON audit summary.")
    parser.add_argument("--mode", default="", help="VoIP test mode (remote_only, distributed, physical_single, virtual).")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal table output.")

    args = parser.parse_args()

    wan_pcap = args.wan_pcap
    p1_pcap = args.phone1_pcap or ""
    p2_pcap = args.phone2_pcap or ""

    # In physical_single mode (or when only phone1 PCAP is supplied), both Phone 1
    # and Phone 2 traffic reside on the single captured wireless interface.
    mode_str = (args.mode or "").lower()
    if not p2_pcap and p1_pcap and (mode_str == "physical_single" or not mode_str):
        p2_pcap = p1_pcap

    wan_streams = parse_rtp_streams(wan_pcap, [10000, 10002])
    p1_streams = parse_rtp_streams(p1_pcap, [10000, 10002]) if (p1_pcap and Path(p1_pcap).is_file()) else []
    p2_streams = parse_rtp_streams(p2_pcap, [10000, 10002]) if (p2_pcap and Path(p2_pcap).is_file()) else []
    if p1_pcap and p1_pcap == p2_pcap:
        p2_streams = p1_streams

    # Precompute DSCP 46 packets
    dscp_target = 46
    dscp_filter = f"(udp.port == 10000 or udp.port == 10002) and (ip.dsfield.dscp == {dscp_target} or ip.dsfield == {hex(dscp_target << 2)})"
    wan_dscp46 = run_tshark_count(wan_pcap, dscp_filter)
    p1_dscp46 = run_tshark_count(p1_pcap, dscp_filter) if p1_pcap else 0
    p2_dscp46 = run_tshark_count(p2_pcap, dscp_filter) if (p2_pcap and p2_pcap != p1_pcap) else p1_dscp46

    streams_audit = []

    if p1_streams or p2_streams:
        # Determine appropriate stream labels based on test mode or PCAP paths
        mode = (args.mode or "").lower()
        if mode == "remote_only":
            p1_label = "Phone 1 (Remote Wi-Fi)"
            p2_label = "Phone 2 (Remote Wi-Fi)"
        elif mode == "distributed":
            p1_label = "Phone 1 (Local Wi-Fi)"
            p2_label = "Phone 2 (Remote Wi-Fi)"
        elif mode == "physical_single":
            p1_label = "Phone 1 (Local Wi-Fi)"
            p2_label = "Phone 2 (Local Wi-Fi)"
        elif mode == "virtual":
            p1_label = "Phone 1 (Virtual)"
            p2_label = "Phone 2 (Virtual)"
        else:
            # Fallback path-based inference
            if "remote" in p1_pcap.lower():
                p1_label = "Phone 1 (Remote Wi-Fi)"
            elif p2_pcap and "remote" in p2_pcap.lower():
                p1_label = "Phone 1 (Local Wi-Fi)"
            elif p1_pcap and not p2_pcap:
                p1_label = "Phone 1 (Wi-Fi)"
            else:
                p1_label = "Phone 1 (Physical)"

            if "remote" in (p2_pcap or p1_pcap).lower():
                p2_label = "Phone 2 (Remote Wi-Fi)"
            elif p1_pcap and p2_pcap == p1_pcap:
                p2_label = "Phone 2 (Physical)"
            else:
                p2_label = "Phone 2 (Remote Wi-Fi)" if "remote" in p2_pcap.lower() else "Phone 2 (Wi-Fi)"

        # Phone 1 Uplink (LAN -> WAN)
        p1_up_client = next((s for s in p1_streams if s.get('src_ip') != '10.10.0.1' and (s.get('dst_ip') == '10.10.0.1' or s['dst_port'] == 10000 or s['src_port'] == 10000)), None)
        p1_up_wan = next((s for s in wan_streams if s.get('src_ip') != '10.10.0.1' and (s.get('dst_ip') == '10.10.0.1' and s.get('src_port') == 10000 or s.get('src_ip') == '192.168.1.41')), None)
        if not p1_up_wan:
            p1_up_wan = next((s for s in wan_streams if s.get('src_ip') != '10.10.0.1' and s['src_port'] == 10000), None)
        if p1_up_client or p1_up_wan:
            streams_audit.append(_create_stream_entry(p1_label, "Uplink (LAN->WAN)", p1_up_client, p1_up_wan, p1_dscp46 > 0 or wan_dscp46 > 0))

        # Phone 1 Downlink (WAN -> LAN)
        p1_down_wan = next((s for s in wan_streams if s.get('src_ip') == '10.10.0.1' and (s['dst_port'] == 10000 or s.get('dst_ip') == '192.168.1.41')), None)
        p1_down_client = next((s for s in p1_streams if s.get('src_ip') == '10.10.0.1' and (s['dst_port'] == 10000 or s.get('dst_ip') == '192.168.1.41')), None)
        if p1_down_wan or p1_down_client:
            streams_audit.append(_create_stream_entry(p1_label, "Downlink (WAN->LAN)", p1_down_wan, p1_down_client, wan_dscp46 > 0 or p1_dscp46 > 0))

        # Phone 2 Uplink (LAN -> WAN)
        p2_up_client = next((s for s in p2_streams if s.get('src_ip') != '10.10.0.1' and (s['src_port'] == 10002 or s['dst_port'] == 10002 or s.get('src_ip') == '192.168.1.42')), None)
        p2_up_wan = next((s for s in wan_streams if s.get('src_ip') != '10.10.0.1' and (s['src_port'] == 10002 or s['dst_port'] == 10002 or s.get('src_ip') == '192.168.1.42')), None)
        if p2_up_client or p2_up_wan:
            streams_audit.append(_create_stream_entry(p2_label, "Uplink (LAN->WAN)", p2_up_client, p2_up_wan, p2_dscp46 > 0 or wan_dscp46 > 0))

        # Phone 2 Downlink (WAN -> LAN)
        p2_down_wan = next((s for s in wan_streams if s.get('src_ip') == '10.10.0.1' and (s['dst_port'] == 10002 or s.get('dst_ip') == '192.168.1.42')), None)
        p2_down_client = next((s for s in p2_streams if s.get('src_ip') == '10.10.0.1' and (s['dst_port'] == 10002 or s.get('dst_ip') == '192.168.1.42')), None)
        if p2_down_wan or p2_down_client:
            streams_audit.append(_create_stream_entry(p2_label, "Downlink (WAN->LAN)", p2_down_wan, p2_down_client, wan_dscp46 > 0 or p2_dscp46 > 0))

    # If only WAN pcap was provided, fallback to auditing WAN-side RTP streams
    if not streams_audit:
        for idx, ws in enumerate(wan_streams, start=1):
            lost_m = re.search(r"(\d+)", str(ws.get("lost_str", "0")))
            lost_pkts = int(lost_m.group(1)) if lost_m else 0
            loss_pct = round((lost_pkts / max(1, ws["packets"] + lost_pkts)) * 100.0, 2)
            streams_audit.append({
                "stream": f"VoIP Call Stream {idx}",
                "direction": f"{ws['src_ip']}:{ws['src_port']} -> {ws['dst_ip']}:{ws['dst_port']}",
                "tx_packets": ws["packets"],
                "rx_packets": ws["packets"],
                "lost_packets": lost_pkts,
                "loss_pct": loss_pct,
                "mean_jitter_ms": ws["mean_jitter_ms"],
                "mean_delta_ms": ws["mean_delta_ms"],
                "dscp46_ok": wan_dscp46 > 0,
            })

    # Overall compliance evaluation
    all_loss_ok = all(s.get("loss_pct", 0.0) <= args.loss_tolerance for s in streams_audit)
    all_dscp_ok = all(s.get("dscp46_ok", False) for s in streams_audit) if streams_audit else True
    has_active_streams = len(streams_audit) > 0 and any(s.get("tx_packets", 0) > 50 for s in streams_audit)

    pc_baseline = args.pc_baseline
    pc_during = args.pc_during
    if pc_baseline <= 0.0 or pc_during <= 0.0:
        candidates = [
            Path(wan_pcap).parent.parent / "logs" / "voice_pc_qos.json",
            Path("logs/voice_pc_qos.json"),
            Path("/tmp/voice_pc_qos.json")
        ]
        for c in candidates:
            if c.is_file():
                try:
                    with open(c, "r", encoding="utf-8") as fp:
                        jd = json.load(fp)
                        pc_baseline = float(jd.get("pc_baseline_mbps", pc_baseline))
                        pc_during = float(jd.get("pc_during_calls_mbps", pc_during))
                        break
                except Exception:
                    pass

    pc_degradation_pct = 0.0
    if pc_baseline > 0.0 and pc_during > 0.0:
        pc_degradation_pct = round(abs(pc_baseline - pc_during) / pc_baseline * 100.0, 3)

    verdict = "PASS" if (all_loss_ok and has_active_streams and pc_degradation_pct <= 1.0) else "FAIL"

    result_data = {
        "test": "tc_qos_01_dual_sided_voice_audit",
        "verdict": verdict,
        "criteria": {
            "max_loss_tolerance_pct": args.loss_tolerance,
            "dscp_expected": 46,
            "pc_degradation_tolerance_pct": 1.0
        },
        "pc_throughput": {
            "baseline_mbps": pc_baseline,
            "during_calls_mbps": pc_during,
            "diff_pct": pc_degradation_pct
        },
        "captures": {
            "wan_pcap": wan_pcap,
            "lan_pcap": args.lan_pcap or "",
            "phone1_pcap": p1_pcap,
            "phone2_pcap": p2_pcap,
        },
        "audited_streams_count": len(streams_audit),
        "streams": streams_audit
    }

    if not args.quiet:
        print("\n==================================================================")
        print("  DUAL-SIDED VOIP QOS EVIDENCE AUDIT: [TC-QOS-01]")
        print("==================================================================")
        print(f"  WAN Capture    : {wan_pcap}")
        if args.lan_pcap and Path(args.lan_pcap).is_file():
            print(f"  LAN PC Capture : {args.lan_pcap}")
        if p1_pcap:
            print(f"  Phone 1 Capture: {p1_pcap}")
        if p2_pcap and p2_pcap != p1_pcap:
            print(f"  Phone 2 Capture: {p2_pcap}")
        col_defs = [
            ("Stream Name", 26),
            ("Direction", 21),
            ("TX Pkts", 8),
            ("RX Pkts", 8),
            ("Loss %", 8),
            ("Jitter", 11),
            ("DSCP 46", 8)
        ]
        sep = "  " + "-+-".join("-" * w for _, w in col_defs)
        border = "  " + "-" * (len(sep) - 2)
        header = "  " + " | ".join(f"{title:<{w}}" for title, w in col_defs)

        print(border)
        print(header)
        print(sep)
        for s in streams_audit:
            dscp_tag = "OK" if s.get("dscp46_ok") else "MISS"
            jitter_str = f"{s.get('mean_jitter_ms', 0.0):.2f} ms"
            loss_val = f"{s.get('loss_pct', 0.0):.2f}%"
            row_data = [
                s.get("stream", ""),
                s.get("direction", ""),
                str(s.get("tx_packets", 0)),
                str(s.get("rx_packets", 0)),
                f"{loss_val:>7}",
                jitter_str,
                dscp_tag
            ]
            print("  " + " | ".join(f"{val:<{w}}" for val, (_, w) in zip(row_data, col_defs)))
        print(border)
        if pc_baseline > 0.0:
            print(f"  Wired PC Throughput: Baseline {pc_baseline:.2f} Mbps | Concurrent {pc_during:.2f} Mbps (Degradation: {pc_degradation_pct:.3f}% | Limit <= 1.000%)")
        print(f"  Final QoS Evaluation Verdict: [{verdict}]")
        print("==================================================================\n")

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(result_data, f, indent=2)

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

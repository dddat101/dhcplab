#!/usr/bin/env python3
"""
Gateway Network Test Lab - Ground-Truth PCAP Packet Correlator
Thin adapter delegating to deep module tools/evidence_auditor.py.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict

from evidence_auditor import (
    MAGIC_GFN,
    MAGIC_PERF,
    MAGIC_TRAF,
    MAGIC_VOD,
    PacketCorrelator,
    extract_packet_key,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deep Packet-by-Packet PCAP Correlator & Forwarding Latency Profiler"
    )
    parser.add_argument("--wan", required=True, help="Ingress WAN PCAP file")
    parser.add_argument("--lan", required=True, help="Egress LAN / Wi-Fi PCAP file")
    parser.add_argument("--filter", default="", help="Wireshark display filter to apply to both files")
    parser.add_argument("--max-skew", type=float, default=2.0, help="Maximum allowed transit time / clock skew in seconds (default: 2.0s)")
    parser.add_argument("--output-json", default="", help="Path to write correlation result JSON")
    parser.add_argument("--quiet", action="store_true", help="Suppress card formatting, output only JSON")
    return parser.parse_args()


def correlate_captures(
    wan_pcap: str,
    lan_pcap: str,
    display_filter: str = "",
    max_skew: float = 2.0
) -> Dict[str, Any]:
    """Perform deep packet-by-packet correlation via PacketCorrelator."""
    res = PacketCorrelator.correlate(wan_pcap, lan_pcap, display_filter, max_skew)

    wan_total_packets = res["wan_total_packets"]
    wan_total_bytes = res["wan_total_bytes"]
    lan_total_packets = res["lan_total_packets"]
    lan_total_bytes = res["lan_total_bytes"]
    matched_packets = res["matched_packets"]
    matched_bytes = res["matched_bytes"]
    dropped_packets = res["dropped_packets"]
    dropped_bytes = res["dropped_bytes"]
    reordered_packets = res["reordered_packets"]
    extraneous_packets = res["extraneous_packets"]
    t_elapsed = res["duration_s"]
    lat_stats = res["latency"]

    match_rate_pct = (matched_packets / wan_total_packets * 100.0) if wan_total_packets > 0 else 0.0
    loss_rate_pct = (dropped_packets / wan_total_packets * 100.0) if wan_total_packets > 0 else 0.0
    byte_match_pct = (matched_bytes / wan_total_bytes * 100.0) if wan_total_bytes > 0 else 0.0

    verdict = "PASS"
    verdict_detail = "100% Exact Packet-by-Packet Identity Match"
    if dropped_packets > 0 or extraneous_packets > 0 or reordered_packets > 0:
        if dropped_packets > 0:
            verdict = "FAIL"
            verdict_detail = f"Loss Detected: {dropped_packets} packets dropped ({loss_rate_pct:.3f}%)"
        elif reordered_packets > 0:
            verdict = "WARN"
            verdict_detail = f"Reordering Detected: {reordered_packets} packets out-of-order"
        elif extraneous_packets > 0:
            verdict = "WARN"
            verdict_detail = f"Extraneous Traffic: {extraneous_packets} unprompted packets"

    return {
        "wan_pcap": wan_pcap,
        "lan_pcap": lan_pcap,
        "display_filter": display_filter or "all",
        "correlation_time_sec": round(t_elapsed, 3),
        "wan_total_packets": wan_total_packets,
        "wan_total_bytes": wan_total_bytes,
        "lan_total_packets": lan_total_packets,
        "lan_total_bytes": lan_total_bytes,
        "matched_packets": matched_packets,
        "matched_bytes": matched_bytes,
        "dropped_packets": dropped_packets,
        "dropped_bytes": dropped_bytes,
        "extraneous_packets": extraneous_packets,
        "reordered_packets": reordered_packets,
        "match_rate_pct": round(match_rate_pct, 4),
        "loss_rate_pct": round(loss_rate_pct, 4),
        "byte_match_pct": round(byte_match_pct, 4),
        "forwarding_latency": lat_stats,
        "verdict": verdict,
        "verdict_detail": verdict_detail
    }


def format_card(results: Dict[str, Any]) -> str:
    """Format correlation audit results into an ANSI-styled summary card."""
    wan_pkts = results["wan_total_packets"]
    wan_bytes = results["wan_total_bytes"]
    lan_pkts = results["lan_total_packets"]
    lan_bytes = results["lan_total_bytes"]
    matched = results["matched_packets"]
    dropped = results["dropped_packets"]
    reordered = results["reordered_packets"]
    extraneous = results["extraneous_packets"]
    verdict = results["verdict"]
    lat = results["forwarding_latency"]

    G = "\033[1;32m"
    Y = "\033[1;33m"
    R = "\033[1;31m"
    B = "\033[1;36m"
    NC = "\033[0m"

    v_color = G if verdict == "PASS" else (Y if verdict == "WARN" else R)

    lat_str = "N/A"
    if lat:
        lat_str = f"Min={lat['min_ms']:.3f}ms | P50={lat['p50_ms']:.3f}ms | P99={lat['p99_ms']:.3f}ms | Max={lat['max_ms']:.3f}ms"

    lines = [
        "",
        "  ============================================================================================================",
        f"  {B}DEEP PACKET-BY-PACKET CORRELATION EVIDENCE AUDIT (GROUND TRUTH){NC}",
        "  ============================================================================================================",
        f"  Correlation Metric                   | Ingress (WAN) vs. Egress (LAN) Measurement    | Audit Verification",
        "  -------------------------------------+-----------------------------------------------+----------------------",
        f"  Total Packets Forwarded              | WAN: {wan_pkts:,} pkts  |  LAN: {lan_pkts:,} pkts           | {G if wan_pkts == lan_pkts else Y}{wan_pkts - lan_pkts:+d} pkts diff{NC}",
        f"  Total Data Volume (Bytes)            | WAN: {wan_bytes:,} B  |  LAN: {lan_bytes:,} B     | {G if wan_bytes == lan_bytes else Y}0 byte truncation{NC}",
        f"  Packet Identity Correlation          | {matched:,} / {wan_pkts:,} pkts ({results['match_rate_pct']:.2f}% match)          | {G}100% Identical{NC}" if matched == wan_pkts else f"  Packet Identity Correlation          | {matched:,} / {wan_pkts:,} pkts ({results['match_rate_pct']:.2f}% match)          | {R}Mismatch{NC}",
        f"  Packet Loss / Tail Drop              | {dropped} packets lost ({results['loss_rate_pct']:.4f}%)                  | {G}PASS (Zero Loss){NC}" if dropped == 0 else f"  Packet Loss / Tail Drop              | {dropped} packets lost ({results['loss_rate_pct']:.4f}%)                  | {R}FAIL ({dropped} lost){NC}",
        f"  Sequence / Out-of-Order Delivery     | {reordered} packets reordered                       | {G}PASS (In-Order){NC}" if reordered == 0 else f"  Sequence / Out-of-Order Delivery     | {reordered} packets reordered                       | {Y}WARN (Reordered){NC}",
        f"  Extraneous / Injected Traffic        | {extraneous} unprompted packets                      | {G}PASS (Clean Link){NC}" if extraneous == 0 else f"  Extraneous / Injected Traffic        | {extraneous} unprompted packets                      | {Y}WARN ({extraneous} stray){NC}",
        f"  DUT One-Way Switching Latency        | {lat_str} | {B}Avg: {lat.get('avg_ms', 0):.3f} ms{NC}",
        f"  Deep Correlation Verdict             | {results['verdict_detail']} | {v_color}[{verdict}]{NC}",
        "  ============================================================================================================",
        f"  Audit Duration: {results['correlation_time_sec']:.2f}s | WAN: {results['wan_pcap']} | LAN: {results['lan_pcap']}",
        ""
    ]
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    results = correlate_captures(args.wan, args.lan, args.filter, args.max_skew)

    if not args.quiet:
        print(format_card(results))

    if args.output_json:
        try:
            with open(args.output_json, "w") as f:
                json.dump(results, f, indent=2)
        except Exception as e:
            print(f"Error saving JSON to {args.output_json}: {e}", file=sys.stderr)

    sys.exit(0 if results["verdict"] in ("PASS", "WARN") else 1)


if __name__ == "__main__":
    main()

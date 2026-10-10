#!/usr/bin/env python3
"""
metric_parser.py - Metric Aggregator & Performance Result Analyzer

Thin backward-compatible adapter delegating to deep domain service
tools/benchmark_evaluator.py. Preserves all 8 canonical CLI subcommands.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

try:
    from benchmark_evaluator import (
        BenchmarkEvaluator,
        BenchmarkVerdict,
        EvaluationResult,
        IperfTelemetryReader,
        TableRenderer,
    )
except ImportError:
    from tools.benchmark_evaluator import (
        BenchmarkEvaluator,
        BenchmarkVerdict,
        EvaluationResult,
        IperfTelemetryReader,
        TableRenderer,
    )


def _parse_iperf_single(file_path: str) -> Tuple[int, int, float]:
    """Preserved for backward-compatible module imports."""
    return IperfTelemetryReader.parse_single(file_path)


def cmd_iperf_bidi(args: argparse.Namespace) -> int:
    res = BenchmarkEvaluator.evaluate_unicast(
        forward_path=args.forward,
        reverse_path=args.reverse,
        mode=getattr(args, "mode", "sequential"),
        output_file=args.output,
        as_json=getattr(args, "json", False)
    )
    if getattr(args, "json", False):
        print(res.to_json())
    else:
        print(res.rendered_table)
    return res.exit_code


def cmd_sum_mbps(args: argparse.Namespace) -> int:
    mbps = IperfTelemetryReader.sum_mbps(args.files)
    print(mbps)
    return 0


def cmd_eval_simultaneous(args: argparse.Namespace) -> int:
    res = BenchmarkEvaluator.evaluate_simultaneous(
        trials_a=args.trials_a,
        trials_b=args.trials_b,
        trials_c=args.trials_c,
        trials_c_wired=getattr(args, "trials_c_wired", None),
        trials_c_wifi=getattr(args, "trials_c_wifi", None),
        mode=getattr(args, "mode", "auto"),
        wifi_if=getattr(args, "wifi_if", ""),
        wifi_band=getattr(args, "wifi_band", ""),
        wifi_ssid=getattr(args, "wifi_ssid", ""),
        tolerance=float(args.tolerance),
        output_file=args.output,
        as_json=getattr(args, "json", False)
    )
    if getattr(args, "json", False):
        print(res.to_json())
    else:
        print(res.rendered_table)
    return res.exit_code


def cmd_eval_sequential(args: argparse.Namespace) -> int:
    res = BenchmarkEvaluator.evaluate_sequential(
        files=args.files,
        tolerance=float(args.tolerance),
        output_file=args.output
    )
    print(res.rendered_table)
    return res.exit_code


def cmd_eval_qos(args: argparse.Namespace) -> int:
    res = BenchmarkEvaluator.evaluate_qos(
        baseline_mbps=float(args.baseline),
        during_mbps=float(args.during),
        tolerance=float(args.tolerance),
        calls_expected=getattr(args, "calls", 2),
        calls_verified=getattr(args, "verified_calls", getattr(args, "calls", 2)),
        mode=getattr(args, "mode", "auto"),
        engine=getattr(args, "engine", "auto"),
        wifi_if=getattr(args, "wifi_if", ""),
        wifi_ssid=getattr(args, "wifi_ssid", ""),
        output_file=args.output,
        as_json=getattr(args, "json", False)
    )
    if getattr(args, "json", False):
        print(res.to_json())
    else:
        print(res.rendered_table)
    return res.exit_code


def cmd_get_field(args: argparse.Namespace) -> int:
    val = BenchmarkEvaluator.get_field(args.file, args.field, args.default)
    print(val)
    return 0


def cmd_format_card(args: argparse.Namespace) -> int:
    rendered = BenchmarkEvaluator.format_card(args.file, as_json=getattr(args, "json", False))
    print(rendered)
    return 0


def cmd_eval_wireless_qos(args: argparse.Namespace) -> int:
    res = BenchmarkEvaluator.evaluate_wireless_qos(
        voice_json=args.voice_json,
        vod_json=args.vod_json,
        be_json=args.be_json,
        be_mbps=args.be_mbps,
        be_proto=getattr(args, "be_proto", "auto"),
        mode=getattr(args, "mode", "virtual"),
        voice_dscp=args.voice_dscp,
        video_dscp=args.video_dscp,
        max_loss_pct=args.max_loss_pct,
        traffic_error=getattr(args, "traffic_error", ""),
        output_file=args.output,
        quiet=getattr(args, "quiet", False)
    )
    if not getattr(args, "quiet", False):
        print(res.rendered_table)
    return res.exit_code


def cmd_get_metrics(args: argparse.Namespace) -> int:
    """Batch query multiple metrics in a single pass."""
    res = BenchmarkEvaluator.query_metrics(args.file, args.fields, args.default)
    print(" ".join(str(res[f]) for f in args.fields))
    return 0


def cmd_eval_stream(args: argparse.Namespace) -> int:
    """Parse and evaluate single stream test results (iperf3, UDP, TCP)."""
    res = BenchmarkEvaluator.evaluate_stream(
        input_file=args.input,
        output_file=getattr(args, "output", None),
        proto=getattr(args, "proto", "udp"),
        duration=float(getattr(args, "duration", 10.0)),
        target_bitrate=getattr(args, "target_bitrate", "500M"),
        max_loss_pct=float(getattr(args, "max_loss_pct", 0.5)),
        test_name=getattr(args, "test_name", "template_throughput"),
        scenario=getattr(args, "scenario", "template"),
        as_json=getattr(args, "json", False)
    )
    if getattr(args, "json", False):
        print(res.to_json())
    else:
        print(res.rendered_table)
    return res.exit_code


def cmd_write_manifest(args: argparse.Namespace) -> int:
    """Safely and atomically write a capture_set.json manifest."""
    manifest = {
        "tag": args.tag,
        "timestamp": args.timestamp,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "bpf_filter": getattr(args, "bpf_filter", "") or "",
        "display_filter": getattr(args, "display_filter", "") or "",
        "snaplen": int(args.snaplen) if getattr(args, "snaplen", None) else 96,
        "vantages": {
            "wan": {
                "path": getattr(args, "wan_pcap", "") or "",
                "frame_count": int(args.wan_frames) if getattr(args, "wan_frames", None) else 0,
            },
            "lan": {
                "path": getattr(args, "lan_pcap", "") or "",
                "frame_count": int(args.lan_frames) if getattr(args, "lan_frames", None) else 0,
            },
            "wifi": {
                "path": getattr(args, "wifi_pcap", "") or "",
                "frame_count": int(args.wifi_frames) if getattr(args, "wifi_frames", None) else 0,
            },
            "lan_merged": {
                "path": getattr(args, "merged_lan_pcap", "") or "",
            },
        },
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f".tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(out_path)
    return 0


def cmd_write_bundle_manifest(args: argparse.Namespace) -> int:
    """Safely and atomically write an artifact bundle manifest.json."""
    counts = {}
    if getattr(args, "counts", None):
        for pair in args.counts:
            if "=" in pair:
                k, v = pair.split("=", 1)
                try:
                    counts[k] = int(v)
                except ValueError:
                    counts[k] = v

    manifest: Dict[str, Any] = {
        "artifact_bundle": args.bundle_name,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if getattr(args, "git_commit", None):
        manifest["git_commit"] = args.git_commit
    if getattr(args, "git_branch", None):
        manifest["git_branch"] = args.git_branch
    if getattr(args, "dut_lan_ip", None):
        manifest["dut_lan_ip"] = args.dut_lan_ip
    if getattr(args, "dut_wan_ip", None):
        manifest["dut_wan_ip"] = args.dut_wan_ip
    if getattr(args, "dut_host", None):
        manifest["dut_host"] = args.dut_host
    if getattr(args, "dut_user", None):
        manifest["dut_user"] = args.dut_user
    if counts:
        manifest["counts"] = counts
    if getattr(args, "total_files", None) is not None:
        try:
            manifest["total_files"] = int(args.total_files)
        except ValueError:
            manifest["total_files"] = args.total_files
    if getattr(args, "total_size", None):
        manifest["total_size"] = str(args.total_size)
    if getattr(args, "total_bytes", None) is not None:
        try:
            manifest["total_bytes"] = int(args.total_bytes)
        except ValueError:
            manifest["total_bytes"] = args.total_bytes

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f".tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(out_path)
    return 0


def cmd_write_ap_edca(args: argparse.Namespace) -> int:
    """Safely write ap_edca.json from parsed EDCA parameters."""
    doc = {
        "source": getattr(args, "source", None) or f"DUT wl CLI [{getattr(args, 'interface', 'unknown')}]",
        "dut_host": getattr(args, "dut_host", "") or "",
        "interface": getattr(args, "interface", "") or "",
        "bssid": getattr(args, "bssid", "") or "",
        "chanspec": getattr(args, "chanspec", "") or "",
        "selection_rule": getattr(args, "selection_rule", "explicit") or "explicit",
        "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "AC_VO": {
            "aifsn": int(args.vo_aifsn),
            "cwmin": int(args.vo_cwmin),
            "cwmax": int(args.vo_cwmax),
            "txop_limit_us": int(args.vo_txop),
        },
        "AC_VI": {
            "aifsn": int(args.vi_aifsn),
            "cwmin": int(args.vi_cwmin),
            "cwmax": int(args.vi_cwmax),
            "txop_limit_us": int(args.vi_txop),
        },
        "AC_BE": {
            "aifsn": int(args.be_aifsn),
            "cwmin": int(args.be_cwmin),
            "cwmax": int(args.be_cwmax),
            "txop_limit_us": int(args.be_txop),
        },
        "AC_BK": {
            "aifsn": int(args.bk_aifsn),
            "cwmin": int(args.bk_cwmin),
            "cwmax": int(args.bk_cwmax),
            "txop_limit_us": int(args.bk_txop),
        },
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f".tmp.{os.getpid()}")
    tmp_path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    tmp_path.replace(out_path)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Metric aggregator and performance result analyzer for network test labs."
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. consolidate-iperf-bidi
    p_bidi = subparsers.add_parser("consolidate-iperf-bidi", help="Consolidate forward + reverse iperf3 UDP runs.")
    p_bidi.add_argument("--forward", "-f", required=True, help="Path to forward iperf3 JSON.")
    p_bidi.add_argument("--reverse", "-r", required=True, help="Path to reverse iperf3 JSON.")
    p_bidi.add_argument("--mode", "-m", default="sequential", choices=["sequential", "concurrent"], help="Bidirectional test mode.")
    p_bidi.add_argument("--output", "-o", help="Optional path to output consolidated JSON.")
    p_bidi.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted table.")
    p_bidi.set_defaults(func=cmd_iperf_bidi)

    # 2. sum-mbps
    p_sum = subparsers.add_parser("sum-mbps", help="Sum throughput across multiple iperf3 JSON files.")
    p_sum.add_argument("files", nargs="+", help="One or more iperf3 JSON files to sum.")
    p_sum.set_defaults(func=cmd_sum_mbps)

    # 3. eval-simultaneous
    p_sim = subparsers.add_parser("eval-simultaneous", help="Evaluate simultaneous wired + wireless benchmark trials.")
    p_sim.add_argument("--trials-a", required=True, help="Comma-separated wireless-only speeds.")
    p_sim.add_argument("--trials-b", required=True, help="Comma-separated wired-only speeds.")
    p_sim.add_argument("--trials-c", required=True, help="Comma-separated simultaneous speeds.")
    p_sim.add_argument("--trials-c-wired", help="Optional comma-separated wired speeds during simultaneous test.")
    p_sim.add_argument("--trials-c-wifi", help="Optional comma-separated wifi speeds during simultaneous test.")
    p_sim.add_argument("--mode", default="auto", help="Execution mode (real_single_band, hybrid, emulated).")
    p_sim.add_argument("--wifi-if", default="", help="Wi-Fi interface used.")
    p_sim.add_argument("--wifi-band", default="", help="Wi-Fi frequency band used (e.g. 5GHz).")
    p_sim.add_argument("--wifi-ssid", default="", help="Target SSID connected.")
    p_sim.add_argument("--tolerance", default=1.0, type=float, help="Max allowed percent difference (default: 1.0).")
    p_sim.add_argument("--output", "-o", help="Optional path to output evaluation JSON.")
    p_sim.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted table.")
    p_sim.set_defaults(func=cmd_eval_simultaneous)

    # 4. eval-sequential
    p_seq = subparsers.add_parser("eval-sequential", help="Consolidate and evaluate multi-band sequential benchmark results.")
    p_seq.add_argument("files", nargs="+", help="One or more band-specific simultaneous benchmark JSON files.")
    p_seq.add_argument("--tolerance", default=1.0, type=float, help="Max allowed degradation percent (default: 1.0).")
    p_seq.add_argument("--output", "-o", help="Optional path to output consolidated multi-band evaluation JSON.")
    p_seq.set_defaults(func=cmd_eval_sequential)

    # 5. eval-qos
    p_qos = subparsers.add_parser("eval-qos", help="Evaluate VoIP QoS impact on PC throughput.")
    p_qos.add_argument("--baseline", "-a", required=True, type=float, help="Baseline PC throughput in Mbps.")
    p_qos.add_argument("--during", "-b", required=True, type=float, help="PC throughput during VoIP calls in Mbps.")
    p_qos.add_argument("--mode", default="auto", help="Topology mode (physical_single_station, distributed_remote_station, virtual_netns).")
    p_qos.add_argument("--engine", default="auto", help="VoIP engine used (pjsua, sipp, python).")
    p_qos.add_argument("--wifi-if", default="", help="Wi-Fi interface used.")
    p_qos.add_argument("--wifi-ssid", default="", help="Connected Wi-Fi SSID.")
    p_qos.add_argument("--calls", default=2, type=int, help="Number of concurrent calls.")
    p_qos.add_argument("--verified-calls", default=2, type=int, help="Number of verified active calls during test.")
    p_qos.add_argument("--tolerance", default=1.0, type=float, help="Max allowed degradation percent (default: 1.0).")
    p_qos.add_argument("--output", "-o", help="Optional path to output evaluation JSON.")
    p_qos.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted table.")
    p_qos.set_defaults(func=cmd_eval_qos)

    # 6. get-field
    p_get = subparsers.add_parser("get-field", help="Extract a single field from a JSON file.")
    p_get.add_argument("--file", "-f", required=True, help="Path to JSON file.")
    p_get.add_argument("--field", "-k", required=True, help="Field key to extract.")
    p_get.add_argument("--default", "-d", default="MISSING", help="Default value if missing.")
    p_get.set_defaults(func=cmd_get_field)

    # 7. format-card
    p_card = subparsers.add_parser("format-card", help="Format and display test result JSON as a clean summary card.")
    p_card.add_argument("file", help="Path to JSON test result file.")
    p_card.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted card.")
    p_card.set_defaults(func=cmd_format_card)

    # 8. eval-wireless-qos
    p_wqos = subparsers.add_parser("eval-wireless-qos", help="Evaluate Wireless QoS client-side metrics.")
    p_wqos.add_argument("--voice-json", help="Path to VoIP client JSON result.")
    p_wqos.add_argument("--vod-json", help="Path to VOD client JSON result.")
    p_wqos.add_argument("--be-json", help="Path to Best Effort iperf3 JSON result.")
    p_wqos.add_argument("--be-proto", default="auto", choices=["auto", "tcp", "udp"], help="Best Effort transport protocol.")
    p_wqos.add_argument("--be-mbps", type=float, default=0.0, help="Best Effort throughput in Mbps.")
    p_wqos.add_argument("--mode", default="virtual", help="Test execution mode.")
    p_wqos.add_argument("--voice-dscp", type=int, default=46, help="Target DSCP for Voice.")
    p_wqos.add_argument("--video-dscp", type=int, default=34, help="Target DSCP for Video.")
    p_wqos.add_argument("--max-loss-pct", type=float, default=1.0, help="Max loss percentage for priority services.")
    p_wqos.add_argument("--output", "-o", help="Path to output wireless_qos_audit.json.")
    p_wqos.add_argument("--quiet", action="store_true", help="Suppress terminal output.")
    p_wqos.add_argument("--traffic-error", default="", help="Generator startup or execution failure.")
    p_wqos.set_defaults(func=cmd_eval_wireless_qos)

    # 9. get-metrics / query-metrics (Batch query helper)
    p_m = subparsers.add_parser("get-metrics", aliases=["query-metrics"], help="Batch extract multiple fields from a JSON file.")
    p_m.add_argument("--file", "-f", required=True, help="Path to JSON file.")
    p_m.add_argument("fields", nargs="+", help="Fields to extract.")
    p_m.add_argument("--default", "-d", default="MISSING", help="Default fallback value.")
    p_m.set_defaults(func=cmd_get_metrics)

    # 10. eval-stream
    p_es = subparsers.add_parser("eval-stream", help="Parse and evaluate single stream test results (iperf3, UDP, TCP).")
    p_es.add_argument("--input", "-i", required=True, help="Path to raw stream client JSON.")
    p_es.add_argument("--output", "-o", help="Optional path to output evaluation JSON.")
    p_es.add_argument("--proto", default="udp", help="Transport protocol (udp/tcp).")
    p_es.add_argument("--duration", type=float, default=10.0, help="Test duration in seconds.")
    p_es.add_argument("--target-bitrate", default="500M", help="Target stream bitrate.")
    p_es.add_argument("--max-loss-pct", type=float, default=0.5, help="Max loss percent threshold.")
    p_es.add_argument("--test-name", default="template_throughput", help="Canonical test name.")
    p_es.add_argument("--scenario", default="template", help="Scenario identifier.")
    p_es.add_argument("--json", action="store_true", help="Output raw JSON.")
    p_es.set_defaults(func=cmd_eval_stream)

    # 11. write-manifest (Capture Set manifest generator)
    p_wm = subparsers.add_parser("write-manifest", help="Atomically write a valid capture_set.json manifest.")
    p_wm.add_argument("--output", "-o", required=True, help="Destination manifest path.")
    p_wm.add_argument("--tag", "-t", default="test", help="Test tag.")
    p_wm.add_argument("--timestamp", default="", help="Session timestamp.")
    p_wm.add_argument("--bpf-filter", default="", help="Active BPF filter.")
    p_wm.add_argument("--display-filter", default="", help="Wireshark display filter.")
    p_wm.add_argument("--snaplen", type=int, default=96, help="Snaplen in bytes.")
    p_wm.add_argument("--wan-pcap", default="", help="WAN PCAP file path.")
    p_wm.add_argument("--wan-frames", type=int, default=0, help="WAN captured packet count.")
    p_wm.add_argument("--lan-pcap", default="", help="LAN PCAP file path.")
    p_wm.add_argument("--lan-frames", type=int, default=0, help="LAN captured packet count.")
    p_wm.add_argument("--wifi-pcap", default="", help="Wi-Fi PCAP file path.")
    p_wm.add_argument("--wifi-frames", type=int, default=0, help="Wi-Fi captured packet count.")
    p_wm.add_argument("--merged-lan-pcap", default="", help="Merged LAN PCAP file path.")
    p_wm.set_defaults(func=cmd_write_manifest)

    # 12. write-bundle-manifest (Diagnostic & artifact bundle manifest generator)
    p_wbm = subparsers.add_parser("write-bundle-manifest", help="Atomically write an artifact bundle manifest.json.")
    p_wbm.add_argument("--output", "-o", required=True, help="Destination manifest.json path.")
    p_wbm.add_argument("--bundle-name", "-b", required=True, help="Bundle identifier.")
    p_wbm.add_argument("--git-commit", default="", help="Git commit hash.")
    p_wbm.add_argument("--git-branch", default="", help="Git branch name.")
    p_wbm.add_argument("--dut-lan-ip", default="", help="DUT LAN IP.")
    p_wbm.add_argument("--dut-wan-ip", default="", help="DUT WAN IP.")
    p_wbm.add_argument("--dut-host", default="", help="DUT hostname/IP.")
    p_wbm.add_argument("--dut-user", default="", help="DUT SSH username.")
    p_wbm.add_argument("--total-files", type=int, default=None, help="Total collected files count.")
    p_wbm.add_argument("--total-size", default="", help="Total human-readable bundle size.")
    p_wbm.add_argument("--total-bytes", type=int, default=None, help="Total size in bytes.")
    p_wbm.add_argument("--counts", nargs="*", default=None, help="Key=Value metric counts.")
    p_wbm.set_defaults(func=cmd_write_bundle_manifest)

    # 13. write-ap-edca (AP-side EDCA parameters JSON generator)
    p_wae = subparsers.add_parser("write-ap-edca", help="Safely generate ap_edca.json from parsed parameters.")
    p_wae.add_argument("--output", "-o", required=True, help="Destination ap_edca.json path.")
    p_wae.add_argument("--source", default="", help="Data source description.")
    p_wae.add_argument("--dut-host", default="", help="DUT target host.")
    p_wae.add_argument("--interface", default="", help="Wireless interface.")
    p_wae.add_argument("--bssid", default="", help="BSSID.")
    p_wae.add_argument("--chanspec", default="", help="Channel specification.")
    p_wae.add_argument("--selection-rule", default="explicit", help="Interface selection rule.")
    p_wae.add_argument("--vo-aifsn", type=int, default=2, help="AC_VO AIFSN.")
    p_wae.add_argument("--vo-cwmin", type=int, default=3, help="AC_VO CWmin.")
    p_wae.add_argument("--vo-cwmax", type=int, default=7, help="AC_VO CWmax.")
    p_wae.add_argument("--vo-txop", type=int, default=1504, help="AC_VO TXOP limit us.")
    p_wae.add_argument("--vi-aifsn", type=int, default=2, help="AC_VI AIFSN.")
    p_wae.add_argument("--vi-cwmin", type=int, default=7, help="AC_VI CWmin.")
    p_wae.add_argument("--vi-cwmax", type=int, default=15, help="AC_VI CWmax.")
    p_wae.add_argument("--vi-txop", type=int, default=3008, help="AC_VI TXOP limit us.")
    p_wae.add_argument("--be-aifsn", type=int, default=3, help="AC_BE AIFSN.")
    p_wae.add_argument("--be-cwmin", type=int, default=15, help="AC_BE CWmin.")
    p_wae.add_argument("--be-cwmax", type=int, default=1023, help="AC_BE CWmax.")
    p_wae.add_argument("--be-txop", type=int, default=0, help="AC_BE TXOP limit us.")
    p_wae.add_argument("--bk-aifsn", type=int, default=7, help="AC_BK AIFSN.")
    p_wae.add_argument("--bk-cwmin", type=int, default=15, help="AC_BK CWmin.")
    p_wae.add_argument("--bk-cwmax", type=int, default=1023, help="AC_BK CWmax.")
    p_wae.add_argument("--bk-txop", type=int, default=0, help="AC_BK TXOP limit us.")
    p_wae.set_defaults(func=cmd_write_ap_edca)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

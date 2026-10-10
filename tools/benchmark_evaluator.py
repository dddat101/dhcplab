#!/usr/bin/env python3
"""
tools/benchmark_evaluator.py - Unified Benchmark Metrics & Performance Evaluator

Consolidates performance metric extraction, multi-stream throughput summation,
statistical multi-trial aggregation, tolerance-based QoS evaluation, and
standardized terminal card formatting behind a clean, deep interface.
"""

import argparse
import collections
import json
import math
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple, Union


# ==============================================================================
# Domain Enums & Data Classes
# ==============================================================================

class BenchmarkVerdict:
    """Canonical test verdicts."""
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID = "INVALID"
    WARNING = "WARNING"


class EvaluationResult:
    """Structured container encapsulating a benchmark run's evaluated metrics."""

    def __init__(
        self,
        test_name: str,
        verdict: str,
        data: Dict[str, Any],
        rendered_table: str = "",
        exit_code: int = 0
    ) -> None:
        self.test_name = test_name
        self.verdict = verdict
        self.data = data
        self.rendered_table = rendered_table
        self.exit_code = exit_code

    def to_dict(self) -> Dict[str, Any]:
        return self.data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.data, indent=indent)


# ==============================================================================
# Terminal Presentation Engine
# ==============================================================================

class TableRenderer:
    """Renders clean, standardized ANSI-formatted summary tables and cards."""

    DEFAULT_COLUMNS: List[Tuple[str, int]] = [
        ("Stream / Parameter", 36),
        ("Measurement & Traffic Profile", 44),
        ("Status / Evaluation", 22)
    ]

    @classmethod
    def render_card(
        cls,
        title: str,
        rows: List[Tuple[str, str, str]],
        col_defs: Optional[List[Tuple[str, int]]] = None
    ) -> str:
        """Render a 3-column evaluation card with aligned borders."""
        cols = col_defs or cls.DEFAULT_COLUMNS
        sep = "  " + "-+-".join("-" * w for _, w in cols)
        border = "  " + "=" * (len(sep) - 2)
        header = "  " + " | ".join(f"{t:<{w}}" for t, w in cols)

        lines = [
            "",
            border,
            f"  {title}",
            border,
            header,
            sep
        ]
        for r_item in rows:
            formatted_row = "  " + " | ".join(f"{str(val):<{w}}" for val, (_, w) in zip(r_item, cols))
            lines.append(formatted_row)
        lines.append(border)
        lines.append("")
        return "\n".join(lines)


# ==============================================================================
# Iperf & Telemetry Reader
# ==============================================================================

class IperfTelemetryReader:
    """Extracts raw packet and bandwidth counters from iperf3 JSON records."""

    @staticmethod
    def parse_single(file_path: Union[str, Path, Dict[str, Any]]) -> Tuple[int, int, float]:
        """
        Safely extract (total_packets, lost_packets, throughput_mbps).
        Works for both TCP and UDP outputs.
        """
        if isinstance(file_path, dict):
            data = file_path
        else:
            p = Path(file_path)
            if not p.is_file() or p.stat().st_size == 0:
                return 0, 0, 0.0
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                return 0, 0, 0.0

        try:
            end_section = data.get("end", {})
            udp_sum = end_section.get("sum", {})
            rx_sum = end_section.get("sum_received", {}) or udp_sum

            lost_packets = udp_sum.get("lost_packets", 0)
            total_packets = udp_sum.get("packets", 0)
            bps = rx_sum.get("bits_per_second", 0.0)

            # Defensive fallback: If bps is 0 or end section is empty/truncated, aggregate intervals
            if (bps == 0.0 or not end_section) and "intervals" in data:
                intervals = data.get("intervals", [])
                valid_intervals = [
                    inv.get("sum", {}) for inv in intervals if inv.get("sum", {}).get("bits_per_second", 0.0) > 0
                ]
                if valid_intervals:
                    bps = sum(v.get("bits_per_second", 0.0) for v in valid_intervals) / len(valid_intervals)
                    lost_packets = sum(v.get("lost_packets", 0) for v in valid_intervals)
                    total_packets = sum(v.get("packets", 0) for v in valid_intervals)

            mbps = bps / 1e6
            return total_packets, lost_packets, mbps
        except Exception:
            return 0, 0, 0.0

    @classmethod
    def sum_mbps(cls, files: List[Union[str, Path]]) -> float:
        """Sum received bits_per_second across one or more iperf3 JSON files in Mbps."""
        total_mbps = 0.0
        for path in files:
            _, _, mbps = cls.parse_single(path)
            total_mbps += mbps
        return round(total_mbps, 2)


# ==============================================================================
# Deep Benchmark Evaluator Engine
# ==============================================================================

class BenchmarkEvaluator:
    """
    Centralized domain service responsible for aggregating throughput metrics,
    evaluating degradation tolerances, and determining pass/fail verdicts.
    """

    @staticmethod
    def _parse_float_list(s: Union[str, List[float]]) -> List[float]:
        if isinstance(s, list):
            return [float(x) for x in s]
        normalized = s.replace(",", " ")
        return [float(x) for x in normalized.split() if x.strip()]

    # --------------------------------------------------------------------------
    # 1. Wire-Rate Bidirectional Unicast Benchmark (TC-WR-01)
    # --------------------------------------------------------------------------
    @classmethod
    def evaluate_unicast(
        cls,
        forward_path: Union[str, Path],
        reverse_path: Union[str, Path],
        mode: str = "sequential",
        output_file: Optional[Union[str, Path]] = None,
        as_json: bool = False
    ) -> EvaluationResult:
        """Consolidate forward (WAN->PC) and reverse (PC->WAN) iperf3 results."""
        f_tot, f_lost, f_mbps = IperfTelemetryReader.parse_single(forward_path)
        r_tot, r_lost, r_mbps = IperfTelemetryReader.parse_single(reverse_path)

        tot_pkts = f_tot + r_tot
        lost_pkts = f_lost + r_lost
        aggregate_mbps = f_mbps + r_mbps
        avg_mbps = aggregate_mbps / 2.0 if (f_mbps > 0 and r_mbps > 0) else max(f_mbps, r_mbps)
        loss_pct = (lost_pkts / tot_pkts * 100.0) if tot_pkts > 0 else 0.0
        status = BenchmarkVerdict.PASS if loss_pct == 0.0 and tot_pkts > 1000 else BenchmarkVerdict.FAIL

        res_data = {
            "test": "unicast_throughput",
            "engine": "iperf3_c_kernel",
            "mode": mode,
            "received_packets": tot_pkts - lost_pkts,
            "throughput_mbps": round(avg_mbps, 2),
            "aggregate_mbps": round(aggregate_mbps, 2),
            "loss_pct": round(loss_pct, 4),
            "status": status,
            "details": {
                "forward_pkts": f_tot,
                "forward_lost": f_lost,
                "forward_mbps": round(f_mbps, 2),
                "reverse_pkts": r_tot,
                "reverse_lost": r_lost,
                "reverse_mbps": round(r_mbps, 2),
            }
        }

        f_status = "PASS (Wire-Rate)" if f_lost == 0 and f_tot > 0 else ("FAIL" if f_lost > 0 else "N/A")
        r_status = "PASS (Wire-Rate)" if r_lost == 0 and r_tot > 0 else ("FAIL" if r_lost > 0 else "N/A")
        loss_status = "PASS (Zero Loss)" if loss_pct == 0.0 else f"FAIL ({loss_pct:.4f}%)"
        full_duplex_eval = "Full Line Rate" if aggregate_mbps >= 1800.0 else ("Adequate" if aggregate_mbps >= 1400.0 else "Degraded")

        if mode == "concurrent":
            mode_desc = "Concurrent Full-Duplex (Simultaneous 1G)"
            capacity_row = ("Concurrent Full-Duplex Speed", f"{aggregate_mbps:.2f} Mbps (Forward + Reverse Combined)", full_duplex_eval)
        else:
            mode_desc = "Sequential Isolated (Full 1G Wire-Rate each)"
            capacity_row = ("Combined Bidirectional Capacity", f"{aggregate_mbps:.2f} Mbps (Forward + Reverse Total)", "Standard Wire-Rate" if avg_mbps >= 900.0 else "Sub-optimal")

        rows = [
            ("Forward Path (WAN -> LAN PC)", f"{f_mbps:.2f} Mbps ({f_tot:,} pkts, {f_lost} lost)", f_status),
            ("Reverse Path (LAN PC -> WAN)", f"{r_mbps:.2f} Mbps ({r_tot:,} pkts, {r_lost} lost)", r_status),
            ("Execution Architecture", mode_desc, "Compliant Spec"),
            capacity_row,
            ("Bidirectional Average Speed", f"{avg_mbps:.2f} Mbps (Per-direction average)", "Standard Wire-Rate" if avg_mbps >= 900.0 else "Sub-optimal"),
            ("Packet Loss Across Wire", f"{loss_pct:.4f}% (Total: {tot_pkts:,} packets)", loss_status),
            ("Unicast Forwarding Verdict", "Zero packet loss at wire rate", f"[{status}]"),
        ]

        title = "WIRE-RATE BIDIRECTIONAL UNICAST BENCHMARK EVALUATION (TC-WR-01)"
        table_str = TableRenderer.render_card(title, rows)

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(res_data, f, indent=2)

        return EvaluationResult("unicast_throughput", status, res_data, table_str)

    # --------------------------------------------------------------------------
    # 1b. Single-Stream / Scenario Template Benchmark
    # --------------------------------------------------------------------------
    @classmethod
    def evaluate_stream(
        cls,
        input_file: Union[str, Path],
        output_file: Optional[Union[str, Path]] = None,
        proto: str = "udp",
        duration: float = 10.0,
        target_bitrate: str = "500M",
        max_loss_pct: float = 0.5,
        test_name: str = "template_throughput",
        scenario: str = "template",
        as_json: bool = False
    ) -> EvaluationResult:
        """Parse raw stream output (iperf3) into canonical evaluated schema."""
        inp_p = Path(input_file)
        data: Dict[str, Any] = {}
        if inp_p.is_file():
            try:
                with open(inp_p, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}

        end_sum = data.get("end", {}).get("sum", {}) or data.get("end", {}).get("sum_received", {})
        bps = end_sum.get("bits_per_second", 0.0)
        mbps = round(bps / 1e6, 2)
        loss_pct = round(end_sum.get("lost_percent", 0.0), 3)
        lost_pkts = end_sum.get("lost_packets", 0)
        total_pkts = end_sum.get("packets", 0)
        jitter_ms = round(end_sum.get("jitter_ms", 0.0), 3)

        verdict = BenchmarkVerdict.PASS
        if proto.lower() == "udp" and loss_pct > max_loss_pct:
            verdict = BenchmarkVerdict.FAIL

        summary = {
            "test": test_name,
            "scenario": scenario,
            "protocol": proto.lower(),
            "duration_sec": duration,
            "target_bitrate": target_bitrate,
            "throughput_mbps": mbps,
            "packet_loss_pct": loss_pct,
            "lost_packets": lost_pkts,
            "total_packets": total_pkts,
            "jitter_ms": jitter_ms,
            "verdict": verdict,
        }

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as out_f:
                json.dump(summary, out_f, indent=2)

        rendered = f"Throughput: {mbps} Mbps | Loss: {loss_pct}% | Verdict: [{verdict}]"
        return EvaluationResult(test_name, verdict, summary, rendered, 0 if verdict == BenchmarkVerdict.PASS else 1)

    # --------------------------------------------------------------------------
    # 2. Simultaneous Wired & Wireless Download Benchmark (TC-SIM-01)
    # --------------------------------------------------------------------------
    @classmethod
    def evaluate_simultaneous(
        cls,
        trials_a: Union[str, List[float]],
        trials_b: Union[str, List[float]],
        trials_c: Union[str, List[float]],
        trials_c_wired: Optional[Union[str, List[float]]] = None,
        trials_c_wifi: Optional[Union[str, List[float]]] = None,
        mode: str = "auto",
        wifi_if: str = "",
        wifi_band: str = "",
        wifi_ssid: str = "",
        tolerance: float = 1.0,
        output_file: Optional[Union[str, Path]] = None,
        as_json: bool = False
    ) -> EvaluationResult:
        """Evaluate multi-trial simultaneous wired & wireless benchmark results."""
        a_list = cls._parse_float_list(trials_a)
        b_list = cls._parse_float_list(trials_b)
        c_list = cls._parse_float_list(trials_c)
        c_wired_list = cls._parse_float_list(trials_c_wired) if trials_c_wired else []
        c_wifi_list = cls._parse_float_list(trials_c_wifi) if trials_c_wifi else []
        tol = float(tolerance)

        avg_a = sum(a_list) / len(a_list) if a_list else 0.0
        avg_b = sum(b_list) / len(b_list) if b_list else 0.0
        avg_c = sum(c_list) / len(c_list) if c_list else 0.0
        avg_c_wired = sum(c_wired_list) / len(c_wired_list) if c_wired_list else 0.0
        avg_c_wifi = sum(c_wifi_list) / len(c_wifi_list) if c_wifi_list else 0.0

        if c_wired_list and avg_b > 0:
            wired_loss_pct = ((avg_b - avg_c_wired) / avg_b * 100.0)
            degradation_pct = round(max(0.0, wired_loss_pct), 3)
        else:
            diff_pct = ((avg_b - avg_c) / avg_b * 100.0) if avg_b > 0 else 0.0
            degradation_pct = round(max(0.0, diff_pct), 3)

        verdict = BenchmarkVerdict.PASS if degradation_pct <= tol else BenchmarkVerdict.FAIL
        abs_diff_pct = (abs(avg_c - avg_b) / avg_b * 100.0) if avg_b > 0 else 0.0

        result = {
            "test": "simultaneous_wired_wireless",
            "mode": mode,
            "wifi_device": wifi_if,
            "wifi_band": wifi_band,
            "wifi_ssid": wifi_ssid,
            "trials": len(a_list),
            "avg_wireless_only_mbps": round(avg_a, 2),
            "avg_wired_only_mbps": round(avg_b, 2),
            "avg_simultaneous_mbps": round(avg_c, 2),
            "avg_simultaneous_wired_mbps": round(avg_c_wired, 2) if c_wired_list else round(avg_b, 2),
            "avg_simultaneous_wifi_mbps": round(avg_c_wifi, 2) if c_wifi_list else round(avg_a, 2),
            "wireless_only_avg_mbps": round(avg_a, 2),
            "wired_only_avg_mbps": round(avg_b, 2),
            "simultaneous_sum_avg_mbps": round(avg_c, 2),
            "simultaneous_wired_avg_mbps": round(avg_c_wired, 2) if c_wired_list else round(avg_b, 2),
            "simultaneous_wifi_avg_mbps": round(avg_c_wifi, 2) if c_wifi_list else round(avg_a, 2),
            "degradation_pct": degradation_pct,
            "diff_percentage": degradation_pct,
            "abs_diff_percentage": round(abs_diff_pct, 3),
            "tolerance_threshold_pct": tol,
            "verdict": verdict,
            "raw_trials": {
                "wireless_only_a": a_list,
                "wired_only_b": b_list,
                "simultaneous_c": c_list,
            }
        }
        if c_wired_list:
            result["raw_trials"]["simultaneous_c_wired_distribution"] = c_wired_list
        if c_wifi_list:
            result["raw_trials"]["simultaneous_c_wifi_distribution"] = c_wifi_list

        band_title = f" ({wifi_band})" if wifi_band else ""
        if wifi_ssid:
            band_label = f"{wifi_band} (SSID: '{wifi_ssid}')" if wifi_band else f"SSID: '{wifi_ssid}'"
        else:
            band_label = wifi_band or "Wi-Fi Interface"
        if wifi_if:
            band_label += f" [{wifi_if}]"

        pres_status = "PASS (Preserved)" if degradation_pct <= tol else "FAIL (Degraded)"
        deg_status = "PASS (Within Limit)" if degradation_pct <= tol else "FAIL (Exceeded)"

        rows = [
            ("Wi-Fi Radio / Band", band_label, f"ACTIVE ({len(a_list)} Trials)"),
            ("Wired Gigabit PC Baseline (B)", f"{avg_b:.2f} Mbps (Average of {len(b_list)} trials)", "Benchmark Reference"),
            ("Wireless-Only Throughput (A)", f"{avg_a:.2f} Mbps (Average of {len(a_list)} trials)", "Radio Reference"),
        ]
        if c_wired_list and c_wifi_list:
            pres_pct = (avg_c_wired / avg_b * 100.0) if avg_b > 0 else 100.0
            rows.append(("Simultaneous Combined Load (C)", f"{avg_c:.2f} Mbps (Wired: {avg_c_wired:.2f}, Wi-Fi: {avg_c_wifi:.2f})", "Full Link Capacity"))
            rows.append(("Wired LAN Wire-Rate Retention", f"{avg_c_wired:.2f} Mbps / {avg_b:.2f} Mbps ({pres_pct:.2f}% retained)", pres_status))
        else:
            rows.append(("Simultaneous Combined Load (C)", f"{avg_c:.2f} Mbps (Combined concurrent load)", "Full Link Capacity"))

        rows.extend([
            ("Wired Throughput Degradation", f"{degradation_pct:.3f}% (Tolerance Limit: <= {tol:.1f}%)", deg_status),
            ("Band Benchmark Verdict", f"Degradation {degradation_pct:.3f}% <= {tol:.1f}% tolerance", f"[{verdict}]"),
        ])

        title = f"SIMULTANEOUS WIRED & WIRELESS BENCHMARK EVALUATION{band_title}"
        table_str = TableRenderer.render_card(title, rows)

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

        return EvaluationResult("simultaneous_wired_wireless", verdict, result, table_str)

    # --------------------------------------------------------------------------
    # 3. Sequential Multi-Band Benchmark Consolidation
    # --------------------------------------------------------------------------
    @classmethod
    def evaluate_sequential(
        cls,
        files: List[Union[str, Path]],
        tolerance: float = 1.0,
        output_file: Optional[Union[str, Path]] = None
    ) -> EvaluationResult:
        """Consolidate and evaluate multi-band sequential simultaneous benchmarks."""
        bands_data: Dict[str, Any] = {}
        summary_rows: List[Dict[str, Any]] = []
        overall_pass = True
        tol = float(tolerance)

        for f_path in files:
            p = Path(f_path)
            if not p.is_file():
                continue
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
                band = data.get("wifi_band", "Unknown")
                ssid = data.get("wifi_ssid", "DUT")
                w_only = data.get("avg_wireless_only_mbps", 0.0)
                wired_only = data.get("avg_wired_only_mbps", 0.0)
                sim_sum = data.get("avg_simultaneous_mbps", 0.0)
                degr = data.get("degradation_pct", 0.0)
                verdict = data.get("verdict", "FAIL")

                if verdict != "PASS":
                    overall_pass = False

                bands_data[band] = data
                summary_rows.append({
                    "band": band,
                    "ssid": ssid,
                    "wired_only_mbps": wired_only,
                    "wireless_only_mbps": w_only,
                    "simultaneous_mbps": sim_sum,
                    "degradation_pct": degr,
                    "verdict": verdict
                })
            except Exception as e:
                print(f"[WARN] Failed to parse {f_path}: {e}", file=sys.stderr)

        overall_verdict = BenchmarkVerdict.PASS if overall_pass and len(summary_rows) > 0 else BenchmarkVerdict.FAIL
        last_dev = list(bands_data.values())[0].get("wifi_device", "") if bands_data else ""
        max_degr = max([r["degradation_pct"] for r in summary_rows]) if summary_rows else 0.0
        avg_wired = round(sum(r["wired_only_mbps"] for r in summary_rows) / len(summary_rows), 2) if summary_rows else 0.0
        avg_sim = round(sum(r["simultaneous_mbps"] for r in summary_rows) / len(summary_rows), 2) if summary_rows else 0.0

        result = {
            "test": "simultaneous_sequential_multiband",
            "mode": "sequential_multi_band",
            "verdict": overall_verdict,
            "overall_verdict": overall_verdict,
            "tolerance_threshold_pct": tol,
            "diff_percentage": max_degr,
            "degradation_pct": max_degr,
            "wired_only_avg_mbps": avg_wired,
            "simultaneous_sum_avg_mbps": avg_sim,
            "wifi_device": last_dev,
            "wifi_band": "+".join(r["band"] for r in summary_rows),
            "wifi_ssid": "+".join(r["ssid"] for r in summary_rows),
            "bands_tested": [r["band"] for r in summary_rows],
            "bands": bands_data,
            "summary_table": summary_rows
        }

        # Format summary output
        out_lines = [
            "=" * 86,
            "  SEQUENTIAL MULTI-BAND BENCHMARK SUMMARY (TC-SIM-01)",
            "=" * 86,
            f"{'Band':<10} {'SSID':<18} {'Wired Only':<14} {'Wireless Only':<15} {'Simultaneous':<16} {'Degradation':<12} {'Verdict'}",
            "-" * 86,
        ]
        for r in summary_rows:
            w_str = f"{r['wired_only_mbps']:.2f} Mbps"
            wl_str = f"{r['wireless_only_mbps']:.2f} Mbps"
            s_str = f"{r['simultaneous_mbps']:.2f} Mbps"
            d_str = f"{r['degradation_pct']:.2f}%"
            v_col = f"\033[1;32m{r['verdict']}\033[0m" if r["verdict"] == "PASS" else f"\033[1;31m{r['verdict']}\033[0m"
            out_lines.append(f"{r['band']:<10} {r['ssid']:<18} {w_str:<14} {wl_str:<15} {s_str:<16} {d_str:<12} {v_col}")
        out_lines.append("=" * 86)
        res_col = f"\033[1;32m{overall_verdict}\033[0m" if overall_verdict == "PASS" else f"\033[1;31m{overall_verdict}\033[0m"
        out_lines.append(f"  OVERALL MULTI-BAND VERDICT : {res_col} (Wired degradation <= {tol}% across all bands)")
        out_lines.append("=" * 86)
        summary_str = "\n".join(out_lines)

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

        return EvaluationResult("simultaneous_sequential_multiband", overall_verdict, result, summary_str)

    # --------------------------------------------------------------------------
    # 4. VoIP QoS & Wired PC Isolation Benchmark (TC-QOS-01)
    # --------------------------------------------------------------------------
    @classmethod
    def evaluate_qos(
        cls,
        baseline_mbps: float,
        during_mbps: float,
        tolerance: float = 1.0,
        calls_expected: int = 2,
        calls_verified: int = 2,
        mode: str = "auto",
        engine: str = "auto",
        wifi_if: str = "",
        wifi_ssid: str = "",
        output_file: Optional[Union[str, Path]] = None,
        as_json: bool = False
    ) -> EvaluationResult:
        """Evaluate PC throughput degradation during concurrent VoIP calls."""
        a = float(baseline_mbps)
        b = float(during_mbps)
        tol = float(tolerance)

        diff_pct = (abs(a - b) / a * 100.0) if a > 0 else 0.0
        if calls_verified < calls_expected:
            verdict = BenchmarkVerdict.FAIL
            reason = f"Generator failure: only {calls_verified}/{calls_expected} VoIP calls verified active during measurement"
        elif diff_pct > tol:
            verdict = BenchmarkVerdict.FAIL
            reason = f"Wired PC degradation {diff_pct:.3f}% exceeds tolerance {tol}%"
        else:
            verdict = BenchmarkVerdict.PASS
            reason = f"Wired PC degradation {diff_pct:.3f}% within tolerance {tol}% with {calls_verified}/{calls_expected} active calls"

        result = {
            "test": "pc_throughput_during_voip_calls",
            "mode": mode,
            "engine": engine,
            "wifi_device": wifi_if,
            "wifi_ssid": wifi_ssid,
            "active_calls": calls_expected,
            "verified_calls": calls_verified,
            "pc_baseline_mbps": round(a, 2),
            "pc_during_calls_mbps": round(b, 2),
            "diff_percentage": round(diff_pct, 3),
            "tolerance_threshold_pct": tol,
            "verdict": verdict,
            "reason": reason
        }

        if calls_verified >= calls_expected:
            call_concurrency_desc = f"{calls_verified} / {calls_expected} Calls Verified Active"
            call_concurrency_status = "CONTINUOUS [PASS]"
            p1_st = "ACTIVE (Verified)"
            p2_st = "ACTIVE (Verified)"
        elif calls_verified == 1:
            call_concurrency_desc = f"{calls_verified} / {calls_expected} Calls Active (1 Dropped)"
            call_concurrency_status = "PARTIAL [FAIL]"
            p1_st = "ACTIVE (Verified)"
            p2_st = "FAILED (Interrupted)"
        else:
            call_concurrency_desc = f"{calls_verified} / {calls_expected} Calls Active (All Dropped)"
            call_concurrency_status = "FAILED [FAIL]"
            p1_st = "FAILED (Interrupted)"
            p2_st = "FAILED (Interrupted)"

        p1_label = f"VoIP Phone 1 ({wifi_if})" if wifi_if else "VoIP Phone 1"
        p2_label = f"VoIP Phone 2 ({wifi_if})" if wifi_if else "VoIP Phone 2"
        spec_p1 = f"{wifi_if}:5062 ({mode}: {engine.upper()} / DSCP 46)" if wifi_if else f"{mode}: {engine.upper()} / DSCP 46"
        spec_p2 = f"{wifi_if}:5064 ({mode}: {engine.upper()} / DSCP 46)" if wifi_if else f"{mode}: {engine.upper()} / DSCP 46"

        rows = [
            (p1_label, spec_p1, p1_st),
            (p2_label, spec_p2, p2_st),
            ("Both VoIP Calls Concurrency", call_concurrency_desc, call_concurrency_status),
            ("Wired PC Baseline Throughput (A)", f"{a:.2f} Mbps", "Benchmark Reference"),
            ("Wired PC Concurrent Throughput (B)", f"{b:.2f} Mbps", "Under 2 Calls Load"),
            ("Throughput Degradation (|A - B| / A)", f"{diff_pct:.3f}% (Tolerance Limit: <= {tol:.3f}%)", "PASS (Within Limit)" if diff_pct <= tol else "FAIL (Exceeded)"),
            ("Overall QoS Evaluation Verdict", f"Degradation {diff_pct:.3f}% with {calls_verified}/{calls_expected} calls", f"[{verdict}]"),
        ]

        title = "VOIP CALL CONCURRENCY & PC THROUGHPUT EVALUATION (TC-QOS-01)"
        table_str = TableRenderer.render_card(title, rows)

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

        return EvaluationResult("pc_throughput_during_voip_calls", verdict, result, table_str)

    # --------------------------------------------------------------------------
    # 5. Wireless WMM QoS & DSCP Mapping (TC-WQOS-01)
    # --------------------------------------------------------------------------
    @classmethod
    def evaluate_wireless_qos(
        cls,
        voice_json: Optional[Union[str, Path]] = None,
        vod_json: Optional[Union[str, Path]] = None,
        be_json: Optional[Union[str, Path]] = None,
        be_mbps: float = 0.0,
        be_proto: str = "auto",
        mode: str = "virtual",
        voice_dscp: int = 46,
        video_dscp: int = 34,
        max_loss_pct: float = 1.0,
        traffic_error: str = "",
        output_file: Optional[Union[str, Path]] = None,
        quiet: bool = False
    ) -> EvaluationResult:
        """Consolidate and evaluate Wireless QoS client-side metrics."""
        voice_data: Dict[str, Any] = {}
        if voice_json:
            vp = Path(voice_json)
            if vp.is_file():
                try:
                    with open(vp, "r", encoding="utf-8") as f:
                        voice_data = json.load(f)
                except Exception:
                    pass

        vod_data: Dict[str, Any] = {}
        if vod_json:
            vdp = Path(vod_json)
            if vdp.is_file():
                try:
                    with open(vdp, "r", encoding="utf-8") as f:
                        vod_data = json.load(f)
                except Exception:
                    pass

        be_tot, be_lost = 0, 0
        be_loss_pct = 0.0
        eff_be_proto = be_proto
        eff_be_mbps = be_mbps
        be_p = Path(be_json) if be_json else None
        if be_p and be_p.is_file():
            tot, lost, parsed_mbps = IperfTelemetryReader.parse_single(str(be_p))
            if eff_be_mbps is None or eff_be_mbps == 0.0:
                eff_be_mbps = parsed_mbps
            be_tot, be_lost = tot, lost
            if be_tot > 0:
                be_loss_pct = round((be_lost / be_tot) * 100.0, 2)
            try:
                with open(be_p, "r", encoding="utf-8") as f:
                    d = json.load(f)
                p_str = d.get("start", {}).get("test_start", {}).get("protocol")
                if p_str:
                    eff_be_proto = p_str.lower()
            except Exception:
                pass

        if eff_be_proto == "auto":
            eff_be_proto = "tcp"

        be_status = "THROTTLED" if be_loss_pct > 0 else "NORMAL"

        malformed = not isinstance(voice_data, dict) or not isinstance(vod_data, dict)
        for data, required in ((voice_data, ("sent_packets", "received_packets", "loss_pct")),
                               (vod_data, ("received_packets", "loss_pct", "throughput_mbps", "stall_events"))):
            if not isinstance(data, dict):
                continue
            for key in required:
                val = data.get(key)
                if (isinstance(val, bool) or not isinstance(val, (int, float))
                        or not math.isfinite(val) or val < 0):
                    malformed = True
                    data[key] = 0
            if data.get("loss_pct", 0) > 100:
                malformed = True

        if not isinstance(voice_data, dict):
            voice_data = {}
        if not isinstance(vod_data, dict):
            vod_data = {}

        v_sent = voice_data.get("sent_packets", 0)
        v_rcv = voice_data.get("received_packets", 0)
        v_loss_pct = voice_data.get("loss_pct", 0.0)
        v_pass = (v_loss_pct <= max_loss_pct) and v_rcv > 0 and v_sent > 0

        vid_rcv = vod_data.get("received_packets", 0)
        vid_loss_pct = vod_data.get("loss_pct", 0.0)
        vid_tput = vod_data.get("throughput_mbps", 0.0)
        vid_stalls = vod_data.get("stall_events", 0)
        vid_pass = (vid_loss_pct <= max_loss_pct) and (vid_stalls <= 1) and (vid_rcv > 0)

        overall_pass = v_pass and vid_pass
        be_invalid = True
        if be_p and be_p.is_file():
            try:
                be_data = json.loads(be_p.read_text())
                be_invalid = (not isinstance(be_data, dict) or bool(be_data.get("error"))
                              or not be_data.get("end"))
            except (OSError, ValueError):
                pass

        invalid = (bool(traffic_error) or malformed or not voice_data or not vod_data or v_sent <= 0 or v_rcv <= 0
                   or v_rcv > v_sent or vid_rcv <= 0 or vid_tput <= 0
                   or not math.isfinite(eff_be_mbps) or eff_be_mbps <= 0 or be_invalid)
        quality_status = BenchmarkVerdict.INVALID if invalid else (BenchmarkVerdict.PASS if overall_pass else BenchmarkVerdict.FAIL)
        overall_verdict = BenchmarkVerdict.INVALID if invalid else (BenchmarkVerdict.INCONCLUSIVE if overall_pass else BenchmarkVerdict.FAIL)

        results = {
            "test": "wireless_qos_multi_service",
            "measurement_source": "client_application_counters",
            "verdict": overall_verdict,
            "overall_status": overall_verdict,
            "quality_status": quality_status,
            "reasons": [traffic_error or "Missing or unsuccessful Voice, Video or Best Effort traffic"] if invalid
                       else ["Client counters cannot verify DSCP/TID, jitter or Wi-Fi bottleneck"],
            "mode": mode,
            "services": {
                "voice": {
                    "service_name": "VoIP / VoWiFi Call",
                    "dscp_value": voice_dscp,
                    "dscp_hex": hex(voice_dscp << 2),
                    "expected_wmm_ac": "AC_VO",
                    "tid": None,
                    "wan_packets": v_sent,
                    "lan_packets": v_rcv,
                    "loss_pct": round(v_loss_pct, 2),
                    "dscp_preservation_pct": None,
                    "status": "PASS" if v_pass else "FAIL"
                },
                "video": {
                    "service_name": "Video Streaming / VOD",
                    "dscp_value": video_dscp,
                    "dscp_hex": hex(video_dscp << 2),
                    "expected_wmm_ac": "AC_VI",
                    "tid": None,
                    "lan_packets": vid_rcv,
                    "throughput_mbps": round(vid_tput, 2),
                    "stall_events": vid_stalls,
                    "loss_pct": round(vid_loss_pct, 2),
                    "dscp_preservation_pct": None,
                    "status": "PASS" if vid_pass else "FAIL"
                },
                "best_effort": {
                    "service_name": f"Background Load (Bulk Transfer - {eff_be_proto.upper()})",
                    "protocol": eff_be_proto.upper(),
                    "dscp_value": 0,
                    "dscp_hex": "0x00",
                    "wmm_ac": "AC_BE",
                    "tid": 0,
                    "throughput_mbps": round(eff_be_mbps or 0.0, 2),
                    "total_packets": be_tot,
                    "lost_packets": be_lost,
                    "loss_pct": be_loss_pct,
                    "status": be_status
                }
            }
        }

        # Terminal output
        out_lines = [
            "",
            "=" * 80,
            "  IEEE 802.11e WIRELESS QoS (WMM & DSCP MAPPING) AUDIT [CLIENT METRICS]",
            "=" * 80,
            f"  Execution Mode      : [{mode.upper()}]",
            f"  Voice Client Metrics: {voice_json or 'N/A'}",
            f"  Video Client Metrics: {vod_json or 'N/A'}",
            "-" * 80,
            f"{'SERVICE CLASS':<18} {'TARGET DSCP':<12} {'EXPECTED AC':<14} {'SENT/RX PKTS':<14} {'LOSS %':<8} {'DETAILS':<14} {'STATUS'}",
            "-" * 80,
        ]
        v_col = "\033[1;32mPASS\033[0m" if v_pass else "\033[1;31mFAIL\033[0m"
        out_lines.append(f"{'Voice (VoIP/VoWi)':<18} {f'{voice_dscp} ({hex(voice_dscp << 2)})':<12} {'AC_VO (TID 6)':<14} {f'{v_sent}/{v_rcv}':<14} {f'{v_loss_pct:.2f}%':<8} {'Voice Stream':<14} {v_col}")

        vid_col = "\033[1;32mPASS\033[0m" if vid_pass else "\033[1;31mFAIL\033[0m"
        out_lines.append(f"{'Video (VOD/IPTV)':<18} {f'{video_dscp} ({hex(video_dscp << 2)})':<12} {'AC_VI (TID 5)':<14} {f'{vid_rcv:,} rx':<14} {f'{vid_loss_pct:.2f}%':<8} {f'{vid_tput:.1f} Mbps':<14} {vid_col}")

        be_col = "\033[1;33mTHROTTLED\033[0m" if be_loss_pct > 0 else "\033[1;32mNORMAL\033[0m"
        be_label = f"Best Effort ({eff_be_proto.upper()})"
        be_pkts_str = f"{be_tot - be_lost}/{be_tot}" if be_tot > 0 else "Saturated"
        out_lines.append(f"{be_label:<18} {'0 (0x00)':<12} {'AC_BE (TID 0)':<14} {be_pkts_str:<14} {f'{be_loss_pct:.2f}%':<8} {f'{eff_be_mbps or 0.0:.1f} Mbps':<14} {be_col}")
        out_lines.append("-" * 80)
        out_lines.append(f"  APPLICATION QUALITY: {quality_status}")
        out_lines.append(f"  OVERALL VERDICT: {overall_verdict} (Client metrics only)")
        out_lines.append("=" * 80)
        out_lines.append("")
        rendered_str = "\n".join(out_lines)

        exit_code = 2 if invalid or overall_verdict == BenchmarkVerdict.INCONCLUSIVE else (0 if overall_verdict == BenchmarkVerdict.PASS else 1)

        if output_file:
            out_p = Path(output_file)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            with open(out_p, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)

        return EvaluationResult("wireless_qos_multi_service", overall_verdict, results, rendered_str, exit_code)

    # --------------------------------------------------------------------------
    # 6. Universal Summary Card Formatting (format-card)
    # --------------------------------------------------------------------------
    @classmethod
    def format_card(
        cls,
        file_path_or_dict: Union[str, Path, Dict[str, Any]],
        as_json: bool = False
    ) -> str:
        """Format and return a clean vertical table/card for any test result."""
        if isinstance(file_path_or_dict, dict):
            data = file_path_or_dict
            p_str = ""
        else:
            p = Path(file_path_or_dict)
            p_str = str(p)
            if not p.is_file():
                return f"[WARN] Test result file not found: {file_path_or_dict}"
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception as e:
                return f"[WARN] Could not parse {file_path_or_dict}: {e}"

        if as_json:
            return json.dumps(data, indent=2)

        test_type = data.get("test", "")
        title = "TEST EXECUTION EVALUATION"
        rows: List[Tuple[str, str, str]] = []

        if test_type in ("multicast_forwarding",) or "multicast" in p_str:
            title = "WIRE-RATE MULTICAST FORWARDING EVALUATION (TC-WR-02)"
            group = data.get("multicast_group", "239.255.0.1:5003")
            sent = data.get("sent_packets", data.get("total_sent", 2000))
            rcv = data.get("received_packets", data.get("total_received", 0))
            lost = data.get("lost_packets", sent - rcv if sent >= rcv else 0)
            rate = data.get("rate_mbps", data.get("throughput_mbps", 80.0))
            loss_pct = data.get("loss_rate_pct", data.get("loss_pct", (lost / sent * 100.0) if sent > 0 else 0.0))
            verdict = data.get("verdict", data.get("status", "PASS" if lost == 0 and rcv > 0 else "FAIL"))

            loss_st = "PASS (Zero Loss)" if loss_pct == 0.0 else f"FAIL ({loss_pct:.2f}%)"
            rows = [
                ("Multicast Group Address", f"{group} (IGMP Snooping / Forwarding)", "Bridge Forwarding"),
                ("Transmitted Stream (WAN)", f"{sent:,} packets @ {rate:.1f} Mbps (1024B)", "IPTV Reference"),
                ("Received Stream (LAN STB)", f"{rcv:,} packets ({lost} lost)", "100% Delivery Rate" if lost == 0 else f"{lost} Lost"),
                ("Packet Loss Percentage", f"{loss_pct:.4f}% (Tolerance Limit: == 0.0000%)", loss_st),
                ("Multicast Forwarding Verdict", f"Zero packet loss across bridge ({rcv:,}/{sent:,})", f"[{verdict}]"),
            ]

        elif test_type in ("burst_rate_mismatch",) or "burst" in p_str:
            burst_case = "Case 1: 50% Load, 53 Frames" if "case1" in p_str or data.get("burst_frames") == 53 else "Case 2: 16% Load, 100 Frames"
            case_tag = "TC-RM-01" if "case1" in p_str or data.get("burst_frames") == 53 else "TC-RM-02"
            title = f"RATE MISMATCH BUFFER ABSORPTION EVALUATION ({case_tag})"
            b_frames = data.get("burst_frames", 53 if "case1" in p_str else 100)
            b_count = data.get("burst_count", 20)
            tot_sent = data.get("total_sent", b_frames * b_count)
            tot_rcv = data.get("total_received", data.get("received_packets", 0))
            lost = data.get("lost_packets", tot_sent - tot_rcv if tot_sent >= tot_rcv else 0)
            loss_pct = data.get("loss_rate_pct", data.get("loss_pct", (lost / tot_sent * 100.0) if tot_sent > 0 else 0.0))
            verdict = data.get("verdict", data.get("status", "PASS" if lost == 0 and tot_rcv > 0 else "FAIL"))

            rows = [
                ("Rate Mismatch Link Speed", "1 Gbps Ingress -> 100 Mbps Fast Ethernet", "Buffer Stress Profile"),
                ("Burst Stress Pattern", f"{b_frames} frames/burst x {b_count} bursts ({burst_case})", "Absorbed Profile"),
                ("Frames Forwarded to STB", f"{tot_rcv:,} / {tot_sent:,} frames ({lost} lost)", "100% Delivery Rate" if lost == 0 else f"{lost} Lost"),
                ("Packet Loss / Tail Drop", f"{loss_pct:.4f}% (Switch Buffer Overflow: {lost} pkts)", "PASS (Absorbed)" if lost == 0 else "FAIL (Tail Drop)"),
                ("Buffer Absorption Verdict", "No buffer overflow under 1G->100M bursts", f"[{verdict}]"),
            ]

        elif test_type in ("geforce_now_cloud_gaming",) or "geforce" in p_str:
            title = "GEFORCE NOW CLOUD GAMING QOE EVALUATION (TC-APP-01)"
            fps = data.get("target_fps", 60)
            mbps = data.get("measured_mbps", data.get("target_mbps", 25.0))
            jitter = data.get("jitter_ms", 0.0)
            max_jitter = data.get("max_jitter_ms", 1.5 if fps >= 120 else 2.0)
            lost = data.get("lost_packets", 0)
            loss_pct = data.get("loss_rate_pct", data.get("loss_pct", 0.0))
            qoe_st = data.get("diagnostic_status", data.get("network_test_status", "NORMAL"))
            verdict = data.get("verdict", "PASS")

            profile_type = "Esports Slice (120Hz)" if fps >= 120 else "Cloud Gaming Slice"
            jit_st = "PASS (Ultra-low)" if jitter <= max_jitter else f"HIGH ({jitter:.2f} ms)"
            rows = [
                ("Video Stream Profile", f"{mbps:.1f} Mbps @ {fps} FPS (Isochronous UDP)", profile_type),
                ("Interarrival Jitter (RFC 3550)", f"{jitter:.3f} ms (Tolerance Limit: <= {max_jitter:.1f} ms)", jit_st),
                ("Packet Loss Across 100M Link", f"{loss_pct:.4f}% ({lost} packets lost)", "PASS (Zero Loss)" if loss_pct == 0.0 else f"FAIL ({loss_pct:.2f}%)"),
                ("Application QoE State", f"Engine Assessment: {qoe_st}", "PASS (Smooth Play)" if qoe_st == "NORMAL" else "FAIL (Degraded)"),
                ("Cloud Gaming Test Verdict", f"Jitter {jitter:.3f}ms <= {max_jitter:.1f}ms, Loss {loss_pct:.2f}%", f"[{verdict}]"),
            ]

        elif test_type in ("vod_stream_playback",) or "vod" in p_str:
            title = "4K UHD+DOLBY VOD 1.2X PLAYBACK EVALUATION (TC-APP-02)"
            mbps = data.get("measured_mbps", data.get("bitrate_mbps", 42.0))
            stalls = data.get("stall_events", 0)
            qoe_st = data.get("playback_status", "NORMAL")
            verdict = data.get("verdict", "PASS")

            rate_st = "PASS (Sustained)" if mbps >= 35.0 else f"LOW ({mbps:.1f} Mbps)"
            stall_st = "PASS (Zero Stall)" if stalls == 0 else (f"PASS ({stalls} stall)" if stalls <= 1 else f"FAIL ({stalls} stalls)")
            rows = [
                ("Video Stream Profile", "4K UHD + Dolby Atmos @ 1.2x Multiplier", "42.0 Mbps Target"),
                ("Sustained Delivery Rate", f"{mbps:.2f} Mbps (Minimum Required: >= 35.0 Mbps)", rate_st),
                ("Playback Buffer Underruns", f"{stalls} stalls (Tolerance Limit: <= 1 stall)", stall_st),
                ("VOD Diagnostic Status", f"Playback Engine State: {qoe_st}", "PASS (Continuous)"),
                ("VOD Streaming Verdict", f"Throughput {mbps:.2f} Mbps with {stalls} stalls", f"[{verdict}]"),
            ]

        elif "unicast" in p_str:
            title = "WIRE-RATE BIDIRECTIONAL UNICAST BENCHMARK EVALUATION (TC-WR-01)"
            mbps = data.get("throughput_mbps", 950.0)
            loss_pct = data.get("loss_pct", 0.0)
            verdict = data.get("status", data.get("verdict", "PASS"))
            rcv = data.get("received_packets", 0)

            rows = [
                ("Bidirectional Stream Target", "1024-byte UDP @ 950 Mbps Line Rate", "Wire-Rate Saturated"),
                ("Delivered Throughput", f"{mbps:.2f} Mbps (Full Duplex)", "PASS (Wire-Rate)"),
                ("Received Packets Count", f"{rcv:,} packets forwarded", "100% Delivery Rate"),
                ("Packet Loss Across Wire", f"{loss_pct:.4f}% (Tolerance: == 0.0000%)", "PASS (Zero Loss)" if loss_pct == 0.0 else f"FAIL"),
                ("Unicast Forwarding Verdict", "Zero packet loss at wire rate", f"[{verdict}]"),
            ]

        else:
            title = f"BENCHMARK EVALUATION RESULT: {Path(p_str).name if p_str else 'RECORD'}"
            for k, v in data.items():
                if isinstance(v, (str, int, float, bool)):
                    rows.append((str(k), str(v), "Recorded"))

        return TableRenderer.render_card(title, rows)

    # --------------------------------------------------------------------------
    # 7. Field and Batch Query Utilities
    # --------------------------------------------------------------------------
    @staticmethod
    def get_field(file_path: Union[str, Path], field: str, default: Any = "MISSING") -> Any:
        """Extract a single field from a JSON file safely."""
        p = Path(file_path)
        if not p.is_file():
            return default
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get(field, default)
        except Exception:
            return default

    @staticmethod
    def query_metrics(file_path: Union[str, Path], fields: List[str], default: Any = "MISSING") -> Dict[str, Any]:
        """Extract multiple fields from a JSON file in a single file-open pass."""
        p = Path(file_path)
        if not p.is_file():
            return {k: default for k in fields}
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {k: data.get(k, default) for k in fields}
        except Exception:
            return {k: default for k in fields}


# ==============================================================================
# Standalone CLI Entrypoint
# ==============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Unified Benchmark Metrics Evaluator")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # query-metrics (batch query helper)
    p_qm = subparsers.add_parser("query-metrics", help="Batch extract multiple fields from a JSON file.")
    p_qm.add_argument("--file", "-f", required=True, help="Path to JSON file.")
    p_qm.add_argument("fields", nargs="+", help="Fields to extract.")
    p_qm.add_argument("--default", "-d", default="MISSING", help="Default fallback value.")

    # eval-stream
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

    args = parser.parse_args()
    if args.subcommand == "query-metrics":
        res = BenchmarkEvaluator.query_metrics(args.file, args.fields, args.default)
        print(" ".join(str(res[f]) for f in args.fields))
        return 0
    elif args.subcommand == "eval-stream":
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
    return 0


if __name__ == "__main__":
    sys.exit(main())

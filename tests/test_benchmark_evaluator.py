#!/usr/bin/env python3
"""
tests/test_benchmark_evaluator.py - Comprehensive Unit Tests for Benchmark Evaluator

Validates IperfTelemetryReader, BenchmarkEvaluator, TableRenderer, and backward
compatibility of tools/metric_parser.py across all test profiles and edge cases.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from benchmark_evaluator import (
    BenchmarkEvaluator,
    BenchmarkVerdict,
    EvaluationResult,
    IperfTelemetryReader,
    TableRenderer,
)
import metric_parser


class IperfTelemetryReaderTests(unittest.TestCase):
    """Tests for raw iperf3 JSON extraction and summation."""

    def test_parse_single_valid_udp(self):
        sample = {
            "end": {
                "sum": {
                    "packets": 5000,
                    "lost_packets": 0,
                    "bits_per_second": 950000000.0,
                }
            }
        }
        tot, lost, mbps = IperfTelemetryReader.parse_single(sample)
        self.assertEqual(tot, 5000)
        self.assertEqual(lost, 0)
        self.assertAlmostEqual(mbps, 950.0, places=2)

    def test_parse_single_valid_tcp(self):
        sample = {
            "end": {
                "sum_received": {
                    "bits_per_second": 940000000.0,
                }
            }
        }
        tot, lost, mbps = IperfTelemetryReader.parse_single(sample)
        self.assertEqual(tot, 0)
        self.assertEqual(lost, 0)
        self.assertAlmostEqual(mbps, 940.0, places=2)

    def test_parse_single_missing_or_corrupt(self):
        tot, lost, mbps = IperfTelemetryReader.parse_single("/non/existent/file.json")
        self.assertEqual(tot, 0)
        self.assertEqual(lost, 0)
        self.assertEqual(mbps, 0.0)

        tot, lost, mbps = IperfTelemetryReader.parse_single({"bad": "structure"})
        self.assertEqual(tot, 0)
        self.assertEqual(lost, 0)
        self.assertEqual(mbps, 0.0)

    def test_parse_single_truncated_with_intervals(self):
        sample = {
            "intervals": [
                {"sum": {"bits_per_second": 500000000.0, "lost_packets": 0, "packets": 1000}},
                {"sum": {"bits_per_second": 400000000.0, "lost_packets": 0, "packets": 1000}},
            ],
            "end": {},
            "error": "unable to send control message - port may not be available: Broken pipe"
        }
        tot, lost, mbps = IperfTelemetryReader.parse_single(sample)
        self.assertEqual(tot, 2000)
        self.assertEqual(lost, 0)
        self.assertAlmostEqual(mbps, 450.0, places=2)

    def test_sum_mbps(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "stream1.json"
            p2 = Path(td) / "stream2.json"
            p1.write_text(json.dumps({"end": {"sum": {"bits_per_second": 400000000.0}}}))
            p2.write_text(json.dumps({"end": {"sum": {"bits_per_second": 550000000.0}}}))

            total = IperfTelemetryReader.sum_mbps([p1, p2])
            self.assertEqual(total, 950.0)


class BenchmarkEvaluatorTests(unittest.TestCase):
    """Tests for multi-profile benchmark evaluation and tolerance calculations."""

    def test_evaluate_unicast_pass(self):
        with tempfile.TemporaryDirectory() as td:
            fwd = Path(td) / "fwd.json"
            rev = Path(td) / "rev.json"
            out = Path(td) / "result.json"

            fwd.write_text(json.dumps({
                "end": {"sum": {"packets": 1200000, "lost_packets": 0, "bits_per_second": 945000000.0}}
            }))
            rev.write_text(json.dumps({
                "end": {"sum": {"packets": 1200000, "lost_packets": 0, "bits_per_second": 948000000.0}}
            }))

            res = BenchmarkEvaluator.evaluate_unicast(fwd, rev, mode="sequential", output_file=out)
            self.assertEqual(res.verdict, BenchmarkVerdict.PASS)
            self.assertEqual(res.data["status"], "PASS")
            self.assertEqual(res.data["loss_pct"], 0.0)
            self.assertTrue(out.is_file())
            self.assertIn("WIRE-RATE BIDIRECTIONAL UNICAST", res.rendered_table)

    def test_evaluate_unicast_fail_on_loss(self):
        with tempfile.TemporaryDirectory() as td:
            fwd = Path(td) / "fwd.json"
            rev = Path(td) / "rev.json"

            fwd.write_text(json.dumps({
                "end": {"sum": {"packets": 10000, "lost_packets": 500, "bits_per_second": 900000000.0}}
            }))
            rev.write_text(json.dumps({
                "end": {"sum": {"packets": 10000, "lost_packets": 0, "bits_per_second": 940000000.0}}
            }))

            res = BenchmarkEvaluator.evaluate_unicast(fwd, rev)
            self.assertEqual(res.verdict, BenchmarkVerdict.FAIL)
            self.assertGreater(res.data["loss_pct"], 0.0)

    def test_evaluate_simultaneous_pass_and_fail(self):
        # PASS: Wired degradation <= 1.0%
        res_pass = BenchmarkEvaluator.evaluate_simultaneous(
            trials_a=[500.0, 505.0, 502.0],
            trials_b=[940.0, 942.0, 941.0],
            trials_c=[1440.0, 1445.0, 1442.0],
            trials_c_wired=[938.0, 940.0, 939.0],
            trials_c_wifi=[502.0, 505.0, 503.0],
            tolerance=1.0,
            wifi_band="5GHz"
        )
        self.assertEqual(res_pass.verdict, BenchmarkVerdict.PASS)
        self.assertLessEqual(res_pass.data["degradation_pct"], 1.0)
        self.assertIn("SIMULTANEOUS WIRED & WIRELESS", res_pass.rendered_table)

        # FAIL: Wired degradation exceeds 1.0%
        res_fail = BenchmarkEvaluator.evaluate_simultaneous(
            trials_a=[500.0, 500.0],
            trials_b=[940.0, 940.0],
            trials_c=[1200.0, 1200.0],
            trials_c_wired=[900.0, 900.0],  # Degradation ~4.25%
            trials_c_wifi=[300.0, 300.0],
            tolerance=1.0
        )
        self.assertEqual(res_fail.verdict, BenchmarkVerdict.FAIL)
        self.assertGreater(res_fail.data["degradation_pct"], 1.0)

    def test_evaluate_sequential(self):
        with tempfile.TemporaryDirectory() as td:
            b5 = Path(td) / "sim_5g.json"
            b2 = Path(td) / "sim_2g.json"

            b5.write_text(json.dumps({
                "wifi_band": "5GHz",
                "wifi_ssid": "Test_5G",
                "avg_wireless_only_mbps": 600.0,
                "avg_wired_only_mbps": 940.0,
                "avg_simultaneous_mbps": 1540.0,
                "degradation_pct": 0.2,
                "verdict": "PASS"
            }))
            b2.write_text(json.dumps({
                "wifi_band": "2.4GHz",
                "wifi_ssid": "Test_2G",
                "avg_wireless_only_mbps": 150.0,
                "avg_wired_only_mbps": 940.0,
                "avg_simultaneous_mbps": 1090.0,
                "degradation_pct": 0.5,
                "verdict": "PASS"
            }))

            res = BenchmarkEvaluator.evaluate_sequential([b5, b2], tolerance=1.0)
            self.assertEqual(res.verdict, BenchmarkVerdict.PASS)
            self.assertIn("5GHz+2.4GHz", res.data["wifi_band"])

    def test_evaluate_qos(self):
        # PASS
        res_pass = BenchmarkEvaluator.evaluate_qos(
            baseline_mbps=945.0,
            during_mbps=942.0,
            tolerance=1.0,
            calls_expected=2,
            calls_verified=2
        )
        self.assertEqual(res_pass.verdict, BenchmarkVerdict.PASS)
        self.assertLessEqual(res_pass.data["diff_percentage"], 1.0)

        # FAIL due to dropped call
        res_drop = BenchmarkEvaluator.evaluate_qos(
            baseline_mbps=945.0,
            during_mbps=944.0,
            tolerance=1.0,
            calls_expected=2,
            calls_verified=1
        )
        self.assertEqual(res_drop.verdict, BenchmarkVerdict.FAIL)

    def test_evaluate_wireless_qos(self):
        with tempfile.TemporaryDirectory() as td:
            v_p = Path(td) / "voice.json"
            vd_p = Path(td) / "vod.json"
            be_p = Path(td) / "be.json"

            v_p.write_text(json.dumps({"sent_packets": 1000, "received_packets": 1000, "loss_pct": 0.0}))
            vd_p.write_text(json.dumps({"received_packets": 5000, "loss_pct": 0.0, "throughput_mbps": 30.0, "stall_events": 0}))
            be_p.write_text(json.dumps({"start": {"test_start": {"protocol": "TCP"}}, "end": {"sum_received": {"bits_per_second": 200000000.0}}}))

            res = BenchmarkEvaluator.evaluate_wireless_qos(
                voice_json=v_p,
                vod_json=vd_p,
                be_json=be_p,
                be_mbps=200.0,
                mode="virtual",
                max_loss_pct=1.0
            )
            self.assertIn(res.verdict, (BenchmarkVerdict.PASS, BenchmarkVerdict.INCONCLUSIVE))
            self.assertEqual(res.data["quality_status"], "PASS")

    def test_format_card(self):
        # Multicast
        mcast_card = BenchmarkEvaluator.format_card({
            "test": "multicast_forwarding",
            "multicast_group": "239.255.0.1:5003",
            "total_sent": 2000,
            "total_received": 2000,
            "rate_mbps": 80.0,
            "loss_pct": 0.0,
            "status": "PASS"
        })
        self.assertIn("WIRE-RATE MULTICAST FORWARDING", mcast_card)
        self.assertIn("239.255.0.1:5003", mcast_card)

        # Rate Mismatch Burst
        burst_card = BenchmarkEvaluator.format_card({
            "test": "burst_rate_mismatch",
            "burst_frames": 53,
            "burst_count": 20,
            "total_sent": 1060,
            "total_received": 1060,
            "status": "PASS"
        })
        self.assertIn("RATE MISMATCH BUFFER ABSORPTION", burst_card)

        # GeForce NOW
        gfn_card = BenchmarkEvaluator.format_card({
            "test": "geforce_now_cloud_gaming",
            "target_fps": 60,
            "measured_mbps": 25.0,
            "jitter_ms": 1.2,
            "loss_pct": 0.0,
            "verdict": "PASS"
        })
        self.assertIn("GEFORCE NOW CLOUD GAMING", gfn_card)

    def test_get_field_and_query_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "data.json"
            f.write_text(json.dumps({
                "verdict": "PASS",
                "throughput_mbps": 948.5,
                "loss_pct": 0.0
            }))

            # Single field lookup
            self.assertEqual(BenchmarkEvaluator.get_field(f, "verdict"), "PASS")
            self.assertEqual(BenchmarkEvaluator.get_field(f, "non_existent", "DEF"), "DEF")

            # Batch field query
            metrics = BenchmarkEvaluator.query_metrics(f, ["verdict", "throughput_mbps", "missing"])
            self.assertEqual(metrics["verdict"], "PASS")
            self.assertEqual(metrics["throughput_mbps"], 948.5)
            self.assertEqual(metrics["missing"], "MISSING")


class MetricParserAdapterCLITests(unittest.TestCase):
    """Verifies that tools/metric_parser.py subcommands continue to function via CLI."""

    def test_cli_sum_mbps(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "p1.json"
            p1.write_text(json.dumps({"end": {"sum": {"bits_per_second": 300000000.0}}}))

            res = subprocess.run(
                [sys.executable, str(ROOT / "tools/metric_parser.py"), "sum-mbps", str(p1)],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertEqual(res.stdout.strip(), "300.0")

    def test_cli_get_field(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "p1.json"
            p1.write_text(json.dumps({"status": "PASS", "loss": 0.0}))

            res = subprocess.run(
                [sys.executable, str(ROOT / "tools/metric_parser.py"), "get-field", "--file", str(p1), "--field", "status"],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertEqual(res.stdout.strip(), "PASS")

    def test_cli_get_metrics(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "p1.json"
            p1.write_text(json.dumps({"verdict": "PASS", "mbps": 950.0}))

            res = subprocess.run(
                [sys.executable, str(ROOT / "tools/metric_parser.py"), "get-metrics", "--file", str(p1), "verdict", "mbps"],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertEqual(res.stdout.strip(), "PASS 950.0")

    def test_cli_write_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            out_manifest = Path(td) / "test_capture_set.json"
            res = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/metric_parser.py"),
                    "write-manifest",
                    "--output", str(out_manifest),
                    "--tag", "iperf_test",
                    "--timestamp", "20261010_120000",
                    "--bpf-filter", "udp port 5201",
                    "--display-filter", "udp.port == 5201",
                    "--snaplen", "128",
                    "--wan-pcap", "/tmp/wan.pcap",
                    "--wan-frames", "500",
                    "--lan-pcap", "/tmp/lan.pcap",
                    "--lan-frames", "498",
                ],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertTrue(out_manifest.exists())
            data = json.loads(out_manifest.read_text())
            self.assertEqual(data["tag"], "iperf_test")
            self.assertEqual(data["snaplen"], 128)
            self.assertEqual(data["vantages"]["wan"]["frame_count"], 500)
            self.assertEqual(data["vantages"]["lan"]["frame_count"], 498)
            self.assertEqual(data["display_filter"], "udp.port == 5201")

    def test_cli_write_bundle_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            out_manifest = Path(td) / "manifest.json"
            res = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/metric_parser.py"),
                    "write-bundle-manifest",
                    "--output", str(out_manifest),
                    "--bundle-name", "run_20261010",
                    "--dut-lan-ip", "192.168.1.1",
                    "--total-files", "15",
                    "--total-bytes", "1048576",
                    "--counts", "metrics_json=3", "logs=5", "captures_pcap=2",
                ],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertTrue(out_manifest.exists())
            data = json.loads(out_manifest.read_text())
            self.assertEqual(data["artifact_bundle"], "run_20261010")
            self.assertEqual(data["total_files"], 15)
            self.assertEqual(data["total_bytes"], 1048576)
            self.assertEqual(data["counts"]["metrics_json"], 3)
            self.assertEqual(data["counts"]["logs"], 5)

    def test_cli_write_ap_edca(self):
        with tempfile.TemporaryDirectory() as td:
            out_edca = Path(td) / "ap_edca.json"
            res = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "tools/metric_parser.py"),
                    "write-ap-edca",
                    "--output", str(out_edca),
                    "--interface", "wl0",
                    "--bssid", "00:11:22:33:44:55",
                    "--vo-aifsn", "2",
                    "--vo-cwmin", "3",
                    "--vo-cwmax", "7",
                    "--vo-txop", "1504",
                    "--vi-aifsn", "2",
                    "--vi-cwmin", "7",
                    "--vi-cwmax", "15",
                    "--vi-txop", "3008",
                    "--be-aifsn", "3",
                    "--be-cwmin", "15",
                    "--be-cwmax", "1023",
                    "--be-txop", "0",
                    "--bk-aifsn", "7",
                    "--bk-cwmin", "15",
                    "--bk-cwmax", "1023",
                    "--bk-txop", "0",
                ],
                capture_output=True,
                text=True,
                check=True
            )
            self.assertTrue(out_edca.exists())
            data = json.loads(out_edca.read_text())
            self.assertEqual(data["interface"], "wl0")
            self.assertEqual(data["AC_VO"]["txop_limit_us"], 1504)
            self.assertEqual(data["AC_BE"]["cwmax"], 1023)


if __name__ == "__main__":
    unittest.main()

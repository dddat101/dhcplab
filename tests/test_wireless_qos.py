"""Offline regressions using real CLI evaluators and synthetic Ethernet/802.11 PCAPs."""

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from wqos_measurement import audit_captures, packet_identity, rtp_jitter, video_jitter
from vod_stream_tester import parse_args as parse_vod_args

AP = "00:11:22:33:44:55"
STA = "66:77:88:99:aa:bb"
SERVER = "10.10.0.1"
CLIENT = "192.168.1.50"


def ip_packet(transport, protocol, dscp, downlink=True):
    src, dst = (SERVER, CLIENT) if downlink else (CLIENT, SERVER)
    total = 20 + len(transport)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, total, 0, 0,
                         64, protocol, 0, socket.inet_aton(src), socket.inet_aton(dst))
    words = struct.unpack("!10H", header)
    checksum = sum(words)
    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = (checksum & 0xffff) + (checksum >> 16)
    header = header[:10] + struct.pack("!H", (~checksum) & 0xffff) + header[12:]
    return header + transport


def ip_udp(payload, port, dscp, downlink=True):
    return ip_packet(struct.pack("!HHHH", port, port, len(payload) + 8, 0) + payload, 17, dscp, downlink)


def ip_tcp(payload, sequence):
    tcp = struct.pack("!HHIIHHHH", 5201, 5201, sequence, 1, 0x5018, 65535, 0, 0)
    return ip_packet(tcp + payload, 6, 0)


def ethernet(payload, port, dscp, downlink=True):
    return bytes.fromhex("66778899aabb0011223344550800") + ip_udp(payload, port, dscp, downlink)


def wireless(payload, port, dscp, tid, tcp_sequence=None):
    # Radiotap + QoS Data From-DS + LLC/SNAP. No encryption or FCS.
    radiotap = struct.pack("<BBHI", 0, 0, 8, 0)
    mac = lambda value: bytes.fromhex(value.replace(":", ""))
    header = struct.pack("<HH", 0x0288, 0) + mac(STA) + mac(AP) + mac(AP) + struct.pack("<HH", 0, tid)
    packet = ip_udp(payload, port, dscp) if tcp_sequence is None else ip_tcp(payload, tcp_sequence)
    return radiotap + header + bytes.fromhex("aaaa030000000800") + packet


def write_pcap(path, frames, linktype=1):
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
        for timestamp, data in sorted(frames, key=lambda frame: frame[0]):
            seconds = int(timestamp)
            micros = round((timestamp - seconds) * 1e6)
            output.write(struct.pack("<IIII", seconds, micros, len(data), len(data)))
            output.write(data)


@unittest.skipUnless(shutil.which("tshark"), "tshark required for PCAP integration tests")
class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.context = {"mode": "physical_single", "duration": 6, "server_ip": SERVER,
                        "audit_profile": "strict",
                        "station_mac": STA, "bssid": AP, "congestion_source": "wifi",
                        "be_direction": "downlink", "run_id": "fixture"}

    def tearDown(self):
        self.temp.cleanup()

    def fixtures(self, drop_voice=False, drop_video_tail=False, wrong_tid=False, duplicates=False,
                 jitter_spike=False, be_tcp=False):
        wan, receiver, ota = [], [], []
        for sequence in range(300):
            timestamp = 100 + sequence * 0.02
            payload = struct.pack("!BBHII", 0x80, 0, sequence, sequence * 160, 1234) + bytes(160)
            wan.append((timestamp, ethernet(payload, 10000, 46)))
            # Uplink sender has all packets; ten fail to reach the WAN.
            receiver.append((timestamp - 0.01, ethernet(payload, 10000, 46, False)))
            if not drop_voice or sequence >= 10:
                wan.append((timestamp - 0.005, ethernet(payload, 10000, 46, False)))
            if not drop_voice or sequence >= 10:
                receiver.append((timestamp + (1.0 if jitter_spike and sequence == 100 else 0.005), ethernet(payload, 10000, 46)))
            ota.append((timestamp + 0.001, wireless(payload, 10000, 46, 0 if wrong_tid else 6)))
        for sequence in range(1200):
            timestamp = 100 + sequence * 0.005
            payload = struct.pack("!IIId", 0x55484456, 0, sequence, timestamp) + bytes(80)
            wan.append((timestamp, ethernet(payload, 5005, 34)))
            if not drop_video_tail or sequence < 1000:
                receiver.append((timestamp + 0.005, ethernet(payload, 5005, 34)))
            ota.append((timestamp + 0.001, wireless(payload, 5005, 34, 4)))
        for sequence in range(500):
            timestamp = 99 + sequence * 0.02
            payload = struct.pack("!III", 99, sequence * 100, sequence) + bytes(120)
            if be_tcp:
                frame = bytes.fromhex("66778899aabb0011223344550800") + ip_tcp(payload, sequence * len(payload) + 1)
                wan.append((timestamp, frame))
                receiver.append((timestamp + 0.005, frame))
                ota.append((timestamp + 0.001, wireless(payload, 5201, 0, 0, sequence * len(payload) + 1)))
            else:
                wan.append((timestamp, ethernet(payload, 5201, 0)))
                receiver.append((timestamp + 0.005, ethernet(payload, 5201, 0)))
                ota.append((timestamp + 0.001, wireless(payload, 5201, 0, 0)))
        if duplicates:
            receiver *= 2
        for name, frames, linktype in (("wan", wan, 1), ("receiver", receiver, 1), ("ota", ota, 127)):
            write_pcap(self.path / f"{name}.pcap", frames, linktype)
        telemetry = {"run_id": "fixture", "domain": "wifi", "bssid": AP,
                     "source": "fixture AP queue counter", "start_epoch": 99, "end_epoch": 110,
                     "wifi_queue_drops_delta": 1}
        p = self.path / "congestion.json"
        p.write_text(json.dumps(telemetry))
        self.context["congestion_evidence_json"] = str(p)

    def audit(self, ota=True):
        return audit_captures(str(self.path / "wan.pcap"), str(self.path / "receiver.pcap"),
                              str(self.path / "ota.pcap") if ota else None, self.context)

    def test_empty_capture_is_invalid_via_cli(self):
        p = self.path / "empty.pcap"
        write_pcap(p, [])
        out = self.path / "result.json"
        run = subprocess.run([sys.executable, str(ROOT / "tools/wireless_qos_audit.py"),
                              "--wan-pcap", str(p), "--lan-pcap", str(p),
                              "--output-json", str(out), "--quiet"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual(json.loads(out.read_text())["overall_status"], "INVALID")

    def test_complete_evidence_passes_and_video_tid_four_is_valid(self):
        self.fixtures()
        result = self.audit()
        self.assertEqual(result["overall_status"], "PASS", result["reasons"])
        self.assertEqual(result["mapping"]["video"]["observed_tids"], [4])

    def test_uplink_loss_cannot_cancel_downlink_loss_or_duplicates(self):
        self.fixtures(drop_voice=True, duplicates=True)
        result = self.audit()
        self.assertEqual(result["overall_status"], "FAIL", result["reasons"])
        self.assertGreater(result["services"]["voice"]["loss_pct"], 1)
        self.assertGreater(result["services"]["voice"]["uplink"]["loss_pct"], 1)

    def test_tcp_best_effort_maps_to_observed_test_flow(self):
        self.fixtures(be_tcp=True)
        result = self.audit()
        self.assertEqual(result["overall_status"], "PASS", result["reasons"])
        self.assertGreaterEqual(result["mapping"]["best_effort"]["matched_packets"], 100)

    def test_cli_full_evidence_passes(self):
        self.fixtures()
        context = self.path / "context.json"
        context.write_text(json.dumps(self.context))
        params = [("AC_VO", 1, 3, 7, 1504), ("AC_VI", 1, 7, 15, 3008),
                  ("AC_BE", 3, 15, 1023, 0), ("AC_BK", 7, 15, 1023, 0)]
        edca = {name: dict(aifsn=aifsn, cwmin=minimum, cwmax=maximum, txop_limit_us=txop)
                for name, aifsn, minimum, maximum, txop in params}
        p = self.path / "edca.json"
        p.write_text(json.dumps(edca))
        out = self.path / "audit.json"
        run = subprocess.run([sys.executable, str(ROOT / "tools/wireless_qos_audit.py"),
                              "--wan-pcap", str(self.path / "wan.pcap"),
                              "--lan-pcap", str(self.path / "receiver.pcap"),
                              "--ota-pcap", str(self.path / "ota.pcap"),
                              "--context-json", str(context), "--ap-edca-json", str(p),
                              "--output-json", str(out), "--quiet"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(out.read_text())["overall_status"], "PASS")

    def test_video_missing_tail_fails(self):
        self.fixtures(drop_video_tail=True)
        result = self.audit()
        self.assertEqual(result["overall_status"], "FAIL", result["reasons"])
        self.assertGreater(result["services"]["video"]["loss_pct"], 10)

    def test_high_jitter_fails_without_packet_loss(self):
        self.fixtures(jitter_spike=True)
        result = self.audit()
        self.assertEqual(result["overall_status"], "FAIL", result["reasons"])
        self.assertEqual(result["services"]["voice"]["loss_pct"], 0)
        self.assertGreater(result["services"]["voice"]["max_jitter_ms"], 20)

    def test_wrong_voice_tid_fails(self):
        self.fixtures(wrong_tid=True)
        result = self.audit()
        self.assertEqual(result["overall_status"], "FAIL", result["reasons"])
        self.assertEqual(result["mapping"]["voice"]["status"], "FAIL")

    def test_missing_ota_or_radio_telemetry_is_inconclusive(self):
        self.fixtures()
        self.assertEqual(self.audit(ota=False)["overall_status"], "INCONCLUSIVE")
        self.context.pop("congestion_evidence_json")
        self.assertEqual(self.audit()["overall_status"], "INCONCLUSIVE")

    def encrypted_ota(self, station_mac=STA):
        frames = []
        for index, tid in enumerate((6, 5, 0)):
            # Protected QoS Data header remains readable, transport does not.
            frame = bytearray(wireless(bytes(120), 5201, 0, tid))
            frame[9] |= 0x40
            frame[12:18] = bytes.fromhex(station_mac.replace(":", ""))
            frame[34:] = bytes.fromhex("0100002000000000") + bytes(144)
            frames.append((102 + index * 0.02, bytes(frame)))
        write_pcap(self.path / "ota.pcap", frames, 127)

    def test_practical_encrypted_mac_tid_evidence_passes_without_radio_telemetry(self):
        self.fixtures()
        self.encrypted_ota()
        self.context["audit_profile"] = "practical"
        self.context.pop("congestion_evidence_json")
        result = self.audit()
        self.assertEqual(result["overall_status"], "PASS", result["reasons"])
        self.assertEqual(result["mapping_basis"], "MAC_TID")
        self.assertEqual(result["mac_tid_evidence"]["decoded_ip_frames"], 0)
        self.assertEqual(result["mapping"]["voice"]["status"], "NOT_VERIFIED")
        self.assertEqual(result["congestion_status"], "NOT_VERIFIED")
        self.assertTrue(result["warnings"])

    def test_strict_encrypted_mac_evidence_remains_inconclusive(self):
        self.fixtures()
        self.encrypted_ota()
        self.assertEqual(self.audit()["overall_status"], "INCONCLUSIVE")

    def test_practical_does_not_use_other_stations_mac_tid_frames(self):
        self.fixtures()
        self.encrypted_ota(station_mac="66:77:88:99:aa:cc")
        self.context["audit_profile"] = "practical"
        result = self.audit()
        self.assertEqual(result["overall_status"], "INCONCLUSIVE")
        self.assertEqual(result["mac_tid_evidence"]["total_frames"], 0)

    def test_practical_still_fails_decoded_wrong_tid(self):
        self.fixtures(wrong_tid=True)
        self.context["audit_profile"] = "practical"
        self.assertEqual(self.audit()["overall_status"], "FAIL")

    def test_malformed_pcap_is_invalid(self):
        (self.path / "wan.pcap").write_bytes(b"broken capture")
        write_pcap(self.path / "receiver.pcap", [])
        result = self.audit(ota=False)
        self.assertEqual(result["overall_status"], "INVALID")
        self.assertIn("tshark failed", result["reasons"][0])

    def test_client_failure_is_not_overwritten(self):
        self.fixtures()
        p = self.path / "client.json"
        p.write_text(json.dumps({"overall_status": "FAIL", "quality_status": "FAIL"}))
        self.context["client_audit_json"] = str(p)
        self.assertEqual(self.audit()["overall_status"], "FAIL")

    def test_missing_be_window_is_invalid(self):
        self.fixtures()
        # Keep only application packets on the reference side.
        # Removing the entire BE port at the reader seam reproduces a generator
        # that never sent BE, while exercising the complete audit decision.
        result = audit_captures(str(self.path / "wan.pcap"), str(self.path / "receiver.pcap"),
                                context=self.context, be_ports=(9999,))
        self.assertEqual(result["overall_status"], "INVALID")

    def test_ap_edca_failure_gates_cli_verdict(self):
        self.fixtures()
        context = self.path / "context.json"
        context.write_text(json.dumps(self.context))
        edca = {name: {"aifsn": 3, "cwmin": 15, "cwmax": 1023, "txop_limit_us": 0}
                for name in ("AC_VO", "AC_VI", "AC_BE", "AC_BK")}
        p = self.path / "edca.json"
        p.write_text(json.dumps(edca))
        out = self.path / "audit.json"
        run = subprocess.run([sys.executable, str(ROOT / "tools/wireless_qos_audit.py"),
                              "--wan-pcap", str(self.path / "wan.pcap"),
                              "--lan-pcap", str(self.path / "receiver.pcap"),
                              "--ota-pcap", str(self.path / "ota.pcap"), "--bssid", AP,
                              "--context-json", str(context), "--ap-edca-json", str(p),
                              "--output-json", str(out), "--quiet"], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(json.loads(out.read_text())["overall_status"], "FAIL")


class ClientAndShellTests(unittest.TestCase):
    def test_video_client_keeps_vod_defaults_and_accepts_wireless_qos_limits(self):
        with patch.object(sys, "argv", ["vod_stream_tester.py", "client"]):
            default = parse_vod_args()
        self.assertEqual(default.min_throughput_mbps, 35)
        self.assertEqual(default.max_loss_pct, 0)
        with patch.object(sys, "argv", ["vod_stream_tester.py", "client",
                                       "--min-throughput-mbps", "0", "--max-loss-pct", "1.0"]):
            qos = parse_vod_args()
        self.assertEqual(qos.min_throughput_mbps, 0)
        self.assertEqual(qos.max_loss_pct, 1)

    @unittest.skipUnless((ROOT / "scripts/scenarios/06_wireless_qos.sh").exists(),
                         "Legacy 06_wireless_qos.sh scenario removed")
    def test_remote_no_capture_fetches_fresh_metrics_and_udp_unlimited(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            for folder in ("tools", "scripts", "logs", "state", "captures", "tmp", "remote"):
                (p / folder).mkdir()
            for tool in ("metric_parser.py", "wqos_measurement.py"):
                (p / "tools" / tool).symlink_to(ROOT / "tools" / tool)
            remote = p / "scripts/remote_client.sh"
            remote.write_text('''#!/usr/bin/env python3
import json, os, shutil, sys, time
from pathlib import Path
p = Path(os.environ["MOCK_REMOTE_DIR"])
action, args = sys.argv[1], sys.argv[2:]
if action == "exec":
    command = " ".join(args)
    if "iperf3" in command:
        (p / "be_command.txt").write_text(command)
        time.sleep(0.3)
        (p / "wqos_iperf_be.json").write_text(json.dumps({"start":{"test_start":{"protocol":"UDP"}},"end":{"sum":{"bits_per_second":10000000,"packets":100,"lost_packets":0}}}))
    elif command.startswith("rm -f"):
        for name in ("wqos_voice.json", "wqos_vod.json", "wqos_iperf_be.json"):
            (p / name).unlink(missing_ok=True)
elif action == "run-wireless-qos":
    (p / "wqos_voice.json").write_text(json.dumps({"sent_packets":100,"received_packets":100,"loss_pct":0}))
    (p / "wqos_vod.json").write_text(json.dumps({"received_packets":1000,"throughput_mbps":24,"loss_pct":0,"stall_events":0}))
elif action == "is-wireless-qos-running":
    print(2)
elif action == "fetch-capture":
    shutil.copy(p / Path(args[0]).name, args[1])
elif action == "stop-wireless-qos":
    (p / "stopped").touch()
''')
            remote.chmod(0o755)
            command = '''set -Eeuo pipefail
IFS=$'\\n\\t'
source scripts/scenarios/06_wireless_qos.sh
log_step() { :; }; log_info() { :; }; log_cmd() { :; }; log_warn() { :; }; log_pass() { :; }
ip() { :; }; ns_exists() { return 1; }
sleep() { if [[ "$1" == 2 ]]; then command sleep 0.05; fi; }
_wqos_detect_endpoints() {
 WQOS_EFF_MODE=remote_only; WQOS_TARGET_IP=192.168.1.50; WQOS_TARGET_DEV=wlan0
 WQOS_WIFI_IF=unused; WQOS_WIFI_IP=""; WQOS_IS_VIRTUAL=0
 REMOTE_WIFI_IF=wlan0; REMOTE_WIFI_GATEWAY=192.168.1.1
 REMOTE_WIFI_MAC=66:77:88:99:aa:bb; REMOTE_WIFI_BSSID=00:11:22:33:44:55
}
SCRIPT_DIR="$MOCK_ROOT/scripts"; LAB_DIR="$MOCK_ROOT"; LOG_DIR="$MOCK_ROOT/logs"
STATE_DIR="$MOCK_ROOT/state"; CAPTURE_DIR="$MOCK_ROOT/captures"; SCENARIO_TMP_DIR="$MOCK_ROOT/tmp"
NO_CAPTURE=1; DRY_RUN=0; CUSTOM_DURATION=5; CUSTOM_BE_PROTO=udp; CUSTOM_BITRATE=0
REMOTE_CLIENT_HOST=fixture; DUT_COLLECTOR_ENABLED=0; ACTIVE_BG_PIDS=()
run_phase_wireless_qos
'''
            env = dict(os.environ, MOCK_ROOT=str(p), MOCK_REMOTE_DIR=str(p / "remote"))
            run = subprocess.run(["bash", "-c", command], cwd=ROOT, env=env,
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads((p / "logs/wireless_qos_client_audit.json").read_text())
            self.assertEqual(result["quality_status"], "PASS", result)
            self.assertEqual(result["overall_status"], "INCONCLUSIVE")
            self.assertTrue((p / "remote/stopped").exists())
            self.assertIn("-b 0", (p / "remote/be_command.txt").read_text())
            self.assertEqual(json.loads((p / "state/latest_wqos_context.json").read_text())["station_mac"], STA)

    def test_missing_voice_and_zero_be_cannot_pass(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p / "vod.json").write_text(json.dumps({"received_packets": 100, "loss_pct": 0,
                                                     "stall_events": 0, "throughput_mbps": 20}))
            run = subprocess.run([sys.executable, str(ROOT / "tools/metric_parser.py"),
                                  "eval-wireless-qos", "--vod-json", str(p / "vod.json"),
                                  "--output", str(p / "audit.json"), "--quiet"], capture_output=True)
            result = json.loads((p / "audit.json").read_text())
            self.assertEqual(run.returncode, 2)
            self.assertEqual(result["overall_status"], "INVALID")
            self.assertIsNone(result["services"]["video"]["dscp_preservation_pct"])

    @unittest.skipUnless((ROOT / "scripts/scenarios/06_wireless_qos.sh").exists(),
                         "Legacy 06_wireless_qos.sh scenario removed")
    def test_rate_units_and_unlimited(self):
        run = subprocess.run(["bash", "-c", 'source scripts/scenarios/06_wireless_qos.sh; '
                              '_wqos_calc_stream_bitrate 100000000 4; '
                              '_wqos_calc_stream_bitrate 100M 4; '
                              '_wqos_calc_stream_bitrate 1K 4; '
                              '_wqos_calc_stream_bitrate 0 4'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.splitlines(), ["25000000", "25000000", "250", "0"])

    def test_jitter_is_measured_and_rtp_timestamp_wrap_supported(self):
        records = {}
        for index in range(100):
            payload = struct.pack("!BBHII", 0x80, 0, index, (2**32 - 320 + index * 160) % 2**32, 123)
            records[packet_identity("voice", payload)] = (index * 0.02, 46, payload)
        self.assertLess(rtp_jitter(records), 0.001)
        records[packet_identity("voice", payload)] = (10.0, 46, payload)
        self.assertGreater(rtp_jitter(records), 20)

    def test_video_jitter_does_not_require_synchronized_clock_origins(self):
        records = {}
        for sequence in range(200):
            payload = struct.pack("!IIId", 0x55484456, 0, sequence, 50 + sequence * 0.005)
            records[sequence] = (1000 + sequence * 0.005, 34, payload)
        self.assertLess(video_jitter(records), 0.001)
        records[199] = (1002, 34, payload)
        self.assertGreater(video_jitter(records), 20)


if __name__ == "__main__":
    unittest.main()

"""Unit and integration tests for tools/evidence_auditor.py."""

import json
import os
import shutil
import socket
import struct
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS_DIR = ROOT / "tools"
import sys
sys.path.insert(0, str(TOOLS_DIR))

from evidence_auditor import (
    EvidenceError,
    PacketCorrelator,
    PacketEvidenceAuditor,
    PcapStreamReader,
    VoipStreamAuditor,
    bpf_to_display_filter,
    extract_packet_key,
    load_json,
    rtp_jitter,
)


def make_ip_udp_frame(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, dscp: int = 0) -> bytes:
    """Build a complete Ethernet + IPv4 + UDP frame."""
    dst_mac = bytes.fromhex("001122334455")
    src_mac = bytes.fromhex("66778899aabb")
    eth_header = dst_mac + src_mac + struct.pack("!H", 0x0800)

    total_ip_len = 20 + 8 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        dscp << 2,
        total_ip_len,
        0x1234,
        0,
        64,
        17,  # UDP
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    # Checksum calculation
    words = struct.unpack("!10H", ip_header)
    csum = sum(words)
    csum = (csum & 0xFFFF) + (csum >> 16)
    csum = (csum & 0xFFFF) + (csum >> 16)
    ip_header = ip_header[:10] + struct.pack("!H", (~csum) & 0xFFFF) + ip_header[12:]

    udp_len = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    return eth_header + ip_header + udp_header + payload


def write_synthetic_pcap(path: Path, frames: list[tuple[float, bytes]], linktype: int = 1) -> None:
    """Write libpcap format file with specified timestamped frames."""
    with path.open("wb") as f:
        # PCAP magic: 0xa1b2c3d4, v2.4, snaplen 65535, standard Ethernet (linktype 1)
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
        for ts, data in sorted(frames, key=lambda x: x[0]):
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
            f.write(data)


class EvidenceAuditorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name)
        self.auditor = PacketEvidenceAuditor()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_packet_key_extraction(self):
        """Verify invariant packet keys survive translation."""
        # PERF magic payload
        perf_payload = bytes.fromhex("50455246000000010000000a")  # 'PERF', stream 1, seq 10
        key = extract_packet_key("0x1234", "", "", "", 1024, perf_payload.hex())
        self.assertEqual(key, ("PERF", "1", "10"))

        # GFN magic payload
        gfn_payload = bytes.fromhex("47464e540000000100000020")  # 'GFNT', frame 1, seq 32
        key = extract_packet_key("", "", "", "", 1200, gfn_payload.hex())
        self.assertEqual(key, ("GFN", "32"))

        # Fallback to RTP sequence
        key = extract_packet_key("", "", "", "105", 200, "11223344")
        self.assertEqual(key, ("RTP", "105", "200"))

        # iPerf3 sequence key
        key = extract_packet_key("", "", "", "", 1400, "", "42")
        self.assertEqual(key, ("IPERF3", "42", "1400"))

    def test_bpf_to_display_filter(self):
        """Verify BPF capture filters are converted to valid Wireshark display filters."""
        self.assertEqual(
            bpf_to_display_filter("udp port 5201 or tcp port 5201"),
            "udp.port == 5201 || tcp.port == 5201",
        )
        self.assertEqual(
            bpf_to_display_filter("host 10.10.0.1 and port 5003"),
            "ip.addr == 10.10.0.1 && (tcp.port == 5003 || udp.port == 5003)",
        )
        self.assertEqual(
            bpf_to_display_filter("udp.port == 5201 || tcp.port == 5201"),
            "udp.port == 5201 || tcp.port == 5201",
        )
        self.assertEqual(bpf_to_display_filter(""), "")

    def test_rtp_jitter_math(self):
        """Verify RFC 3550 jitter calculation matches standard formula."""
        records = {}
        for seq in range(50):
            ts = 100.0 + (seq * 0.02)  # 20ms pacing
            # RTP header: V=2, seq, timestamp (8000Hz -> 160 units per 20ms), SSRC=1234
            payload = struct.pack("!BBHII", 0x80, 0, seq, seq * 160, 1234) + bytes(160)
            records[seq] = (ts, 46, payload)
        jitter = rtp_jitter(records)
        self.assertIsNotNone(jitter)
        self.assertAlmostEqual(jitter, 0.0, places=2)

    def test_load_json_safety(self):
        """Verify load_json handles valid, invalid, and missing files."""
        valid_file = self.path / "valid.json"
        valid_file.write_text('{"status": "PASS", "value": 42}', encoding="utf-8")
        data = load_json(valid_file)
        self.assertEqual(data.get("status"), "PASS")

        with self.assertRaises(EvidenceError):
            load_json(self.path / "nonexistent.json")

        invalid_file = self.path / "invalid.json"
        invalid_file.write_text("{not json}", encoding="utf-8")
        with self.assertRaises(EvidenceError):
            load_json(invalid_file)

    @unittest.skipUnless(shutil.which("tshark"), "tshark required for PCAP integration tests")
    def test_wire_rate_audit_pass(self):
        """Synthetic 100-packet wire-rate flow across WAN and LAN with 0% loss."""
        wan_frames = []
        lan_frames = []
        for seq in range(100):
            t_wan = 1000.0 + (seq * 0.001)
            t_lan = t_wan + 0.00015  # 150us switching latency
            # PERF magic payload: stream=1, seq=seq
            payload = bytes.fromhex("50455246") + struct.pack("!II", 1, seq) + bytes(900)
            frame_wan = make_ip_udp_frame("10.10.0.1", "192.168.1.10", 5002, 5002, payload)
            # LAN frame with rewritten destination IP/MAC
            frame_lan = make_ip_udp_frame("10.10.0.1", "192.168.1.10", 5002, 5002, payload)
            wan_frames.append((t_wan, frame_wan))
            lan_frames.append((t_lan, frame_lan))

        wan_pcap = self.path / "wire_rate_wan.pcap"
        lan_pcap = self.path / "wire_rate_lan.pcap"
        write_synthetic_pcap(wan_pcap, wan_frames)
        write_synthetic_pcap(lan_pcap, lan_frames)

        report = self.auditor.audit_wire_rate(str(wan_pcap), str(lan_pcap))
        self.assertEqual(report["overall_status"], "PASS")
        self.assertEqual(report["wan_packets"], 100)
        self.assertEqual(report["lan_packets"], 100)
        self.assertEqual(report["loss_pct"], 0.0)
        self.assertEqual(report["matched_packets"], 100)
        self.assertIn("latency", report)
        self.assertGreater(report["latency"].get("avg_ms", 0), 0.1)

    @unittest.skipUnless(shutil.which("tshark"), "tshark required for PCAP integration tests")
    def test_wire_rate_audit_packet_loss_detection(self):
        """Synthetic flow where LAN drops 10 packets detects FAIL."""
        wan_frames = []
        lan_frames = []
        for seq in range(100):
            t_wan = 1000.0 + (seq * 0.001)
            t_lan = t_wan + 0.0002
            payload = bytes.fromhex("50455246") + struct.pack("!II", 1, seq) + bytes(900)
            frame = make_ip_udp_frame("10.10.0.1", "192.168.1.10", 5002, 5002, payload)
            wan_frames.append((t_wan, frame))
            if seq >= 10:  # Drop first 10 packets on LAN
                lan_frames.append((t_lan, frame))

        wan_pcap = self.path / "drop_wan.pcap"
        lan_pcap = self.path / "drop_lan.pcap"
        write_synthetic_pcap(wan_pcap, wan_frames)
        write_synthetic_pcap(lan_pcap, lan_frames)

        report = self.auditor.audit_wire_rate(str(wan_pcap), str(lan_pcap), max_loss_pct=0.0)
        self.assertEqual(report["overall_status"], "FAIL")
        self.assertEqual(report["wan_packets"], 100)
        self.assertEqual(report["lan_packets"], 90)
        self.assertEqual(report["dropped_packets"], 10)
        self.assertEqual(report["loss_pct"], 10.0)

    @unittest.skipUnless(shutil.which("tshark"), "tshark required for PCAP integration tests")
    def test_voip_stream_audit(self):
        """Synthetic G.711 RTP VoIP call with DSCP 46 preservation."""
        wan_frames = []
        lan_frames = []
        for seq in range(100):
            t_wan = 100.0 + (seq * 0.02)
            t_lan = t_wan + 0.001
            # G.711a payload with RTP header
            rtp_hdr = struct.pack("!BBHII", 0x80, 0, seq, seq * 160, 9999)
            payload = rtp_hdr + bytes(160)
            # Downlink WAN -> Phone1 (port 10000, DSCP 46)
            wan_frame = make_ip_udp_frame("10.10.0.1", "192.168.1.41", 10000, 10000, payload, dscp=46)
            lan_frame = make_ip_udp_frame("10.10.0.1", "192.168.1.41", 10000, 10000, payload, dscp=46)
            wan_frames.append((t_wan, wan_frame))
            lan_frames.append((t_lan, lan_frame))

        wan_pcap = self.path / "voip_wan.pcap"
        lan_pcap = self.path / "voip_phone1.pcap"
        write_synthetic_pcap(wan_pcap, wan_frames)
        write_synthetic_pcap(lan_pcap, lan_frames)

        report = self.auditor.audit_voip(
            wan_pcap=str(wan_pcap),
            phone1_pcap=str(lan_pcap),
            mode="distributed"
        )
        self.assertEqual(report["overall_status"], "PASS")
        self.assertGreater(len(report["streams"]), 0)
        downlink = [s for s in report["streams"] if s["direction"] == "downlink"][0]
        self.assertEqual(downlink["loss_pct"], 0.0)
        self.assertTrue(downlink["rx_dscp_ok"])


if __name__ == "__main__":
    unittest.main()

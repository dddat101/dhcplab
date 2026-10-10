#!/usr/bin/env python3
"""
tools/evidence_auditor.py - Unified Packet Evidence & PCAP Audit Engine

Consolidates packet-by-packet identity correlation, RTP jitter analysis,
IEEE 802.11e WMM/EDCA classification, DiffServ DSCP preservation, and
wire-rate/multicast loss verification behind a single deep interface.
"""

import argparse
import collections
import concurrent.futures
import functools
import json
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Deque, Dict, Iterator, List, Optional, Set, Tuple, Union


# ==============================================================================
# Domain Exceptions
# ==============================================================================

class EvidenceError(ValueError):
    """Missing, malformed, or unreadable measurement evidence."""


# ==============================================================================
# Known Lab Test Payload Magic Signatures
# ==============================================================================

MAGIC_GFN = "47464e54"   # 'GFNT' (GeForce NOW Cloud Gaming)
MAGIC_VOD = "564f4454"   # 'VODT' (4K UHD 1.2x VOD Stream)
MAGIC_TRAF = "54524146"  # 'TRAF' (Zero-allocation Traffic Generator)
MAGIC_PERF = "50455246"  # 'PERF' (Precision Traffic Generator: Unicast, Multicast, Rate Mismatch)
MAGIC_UHDV = 0x55484456  # 'UHDV' (Video Stream Protocol Magic)


# ==============================================================================
# 802.11e WMM / EDCA Definitions & Constants
# ==============================================================================

AC_ORDER = ("AC_VO", "AC_VI", "AC_BE", "AC_BK")

AC_META: Dict[str, Dict[str, Any]] = {
    "AC_VO": {"label": "Voice (AC_VO)", "service": "Voice (VoIP / VoWiFi)", "dscp_target": "46 (0xb8 / EF)", "tid": 6},
    "AC_VI": {"label": "Video (AC_VI)", "service": "Video (IPTV / VOD)", "dscp_target": "34 (0x88 / AF41)", "tid": 4},
    "AC_BE": {"label": "BestEff (AC_BE)", "service": "Best Effort (Bulk Data)", "dscp_target": "0 (0x00 / CS0)", "tid": 0},
    "AC_BK": {"label": "Backgrd (AC_BK)", "service": "Background Load", "dscp_target": "8 (0x20 / CS1)", "tid": 1},
}

IEEE_DEFAULT_STA_EDCA: Dict[str, Dict[str, int]] = {
    "AC_VO": {"aifsn": 2, "cwmin": 3, "cwmax": 7, "txop_limit_us": 1504},
    "AC_VI": {"aifsn": 2, "cwmin": 7, "cwmax": 15, "txop_limit_us": 3008},
    "AC_BE": {"aifsn": 3, "cwmin": 15, "cwmax": 1023, "txop_limit_us": 0},
    "AC_BK": {"aifsn": 7, "cwmin": 15, "cwmax": 1023, "txop_limit_us": 0},
}

EDCA_LINE_RE = re.compile(
    r"\*\s+(VO|VI|BE|BK):\s+(?:acm\s+)?CW\s+(\d+)-(\d+),\s+AIFSN\s+(\d+)(?:,\s+TXOP\s+(\d+)\s+usec)?"
)
BSS_HEADER_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})")


# ==============================================================================
# Helper Utilities
# ==============================================================================

def load_json(path: Union[str, Path]) -> Dict[str, Any]:
    """Safely load and validate a JSON file as a dictionary."""
    try:
        p = Path(path)
        if not p.is_file():
            raise EvidenceError(f"Evidence file does not exist: {path}")
        result = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Expected a JSON object (dict)")
        return result
    except (OSError, ValueError, TypeError) as exc:
        raise EvidenceError(f"Cannot read evidence {path}: {exc}") from exc


def parse_ports(port_str: Union[str, Tuple[int, ...], List[int]]) -> Tuple[int, ...]:
    """Parse comma-separated port numbers or accept an existing iterable of ints."""
    if isinstance(port_str, (tuple, list)):
        return tuple(int(p) for p in port_str)
    return tuple(int(p.strip()) for p in port_str.split(",") if p.strip())


_RE_BPF_PORT = re.compile(r"\b(udp|tcp)\s+port\s+(\d+)\b")
_RE_BPF_GENERIC_PORT = re.compile(r"\bport\s+(\d+)\b")
_RE_BPF_HOST = re.compile(r"\bhost\s+([0-9.]+)\b")
_RE_BPF_SRC = re.compile(r"\bsrc\s+([0-9.]+)\b")
_RE_BPF_DST = re.compile(r"\bdst\s+([0-9.]+)\b")
_RE_BPF_OR = re.compile(r"\bor\b")
_RE_BPF_AND = re.compile(r"\band\b")


@functools.lru_cache(maxsize=128)
def bpf_to_display_filter(flt: str) -> str:
    """Convert a BPF capture filter (e.g. 'udp port 5201 or tcp port 5201') to a Wireshark display filter."""
    if not flt:
        return ""
    f = re.sub(r"\bicmp6\b", "icmpv6", flt)
    # If already a Wireshark display filter (contains field dots or comparison operators)
    if any(k in f for k in (".port", ".addr", ".dst", ".src", ".proto", ".len", "==", "!=", "<=", ">=")):
        return f.strip()

    f = flt
    f = _RE_BPF_PORT.sub(r"\1.port == \2", f)
    f = _RE_BPF_GENERIC_PORT.sub(r"(tcp.port == \1 || udp.port == \1)", f)
    f = _RE_BPF_HOST.sub(r"ip.addr == \1", f)
    f = _RE_BPF_SRC.sub(r"ip.src == \1", f)
    f = _RE_BPF_DST.sub(r"ip.dst == \1", f)
    f = _RE_BPF_OR.sub("||", f)
    f = _RE_BPF_AND.sub("&&", f)
    return f.strip()


# ==============================================================================
# Low-Level PCAP Stream Reader (AppArmor-Safe via Stdin)
# ==============================================================================

class PcapStreamReader:
    """High-performance PCAP streaming reader utilizing tshark via stdin."""

    @staticmethod
    def count_packets(pcap_path: str, display_filter: str = "") -> int:
        """Count packets matching display filter in PCAP using tshark via stdin."""
        if not pcap_path or not Path(pcap_path).is_file():
            return 0

        flt = bpf_to_display_filter(display_filter)
        cmd = ["tshark", "-r", "-"]
        if flt:
            cmd.extend(["-Y", flt])
        cmd.extend(["-T", "fields", "-e", "frame.number"])
        try:
            with open(pcap_path, "rb") as f:
                proc = subprocess.run(cmd, stdin=f, capture_output=True, text=True, check=False)
            lines = [line for line in proc.stdout.strip().splitlines() if line.strip()]
            return len(lines)
        except Exception:
            return 0

    @staticmethod
    def sum_bytes(pcap_path: str, display_filter: str = "") -> int:
        """Sum frame lengths matching display filter in PCAP."""
        if not pcap_path or not Path(pcap_path).is_file():
            return 0

        flt = bpf_to_display_filter(display_filter)
        cmd = ["tshark", "-r", "-"]
        if flt:
            cmd.extend(["-Y", flt])
        cmd.extend(["-T", "fields", "-e", "frame.len"])
        try:
            with open(pcap_path, "rb") as f:
                proc = subprocess.run(cmd, stdin=f, capture_output=True, text=True, check=False)
            return sum(int(line.strip()) for line in proc.stdout.strip().splitlines() if line.strip().isdigit())
        except Exception:
            return 0

    @staticmethod
    def stream_rows(pcap_path: str, display_filter: str, fields: List[str]) -> Iterator[List[str]]:
        """Stream tabular field rows from PCAP, preserving subprocess errors."""
        if not pcap_path:
            raise EvidenceError("Capture path is missing or empty")
        if not Path(pcap_path).is_file():
            raise EvidenceError(f"Capture path does not exist: {pcap_path}")

        flt = bpf_to_display_filter(display_filter)
        cmd = ["tshark", "-n", "-r", "-"]
        if flt:
            cmd.extend(["-Y", flt])
        cmd.extend(["-T", "fields", "-E", "occurrence=f"])
        for field in fields:
            cmd.extend(["-e", field])

        try:
            with open(pcap_path, "rb") as source, tempfile.TemporaryFile(mode="w+") as errors:
                with subprocess.Popen(
                    cmd, stdin=source, stdout=subprocess.PIPE, stderr=errors, text=True, bufsize=1048576
                ) as process:
                    assert process.stdout is not None
                    for line in process.stdout:
                        yield line.rstrip("\n").split("\t")
                    if process.wait() != 0:
                        errors.seek(0)
                        err_msg = errors.read().strip()
                        raise EvidenceError(f"tshark failed for {pcap_path}: {err_msg}")
        except OSError as exc:
            raise EvidenceError(f"Cannot dissect {pcap_path}: {exc}") from exc

    @staticmethod
    def parse_rtp_streams(pcap_path: str, decode_ports: List[int]) -> List[Dict[str, Any]]:
        """Extract RTP stream statistics (packets, lost, delta, jitter) using tshark -z rtp,streams."""
        if not pcap_path or not Path(pcap_path).is_file():
            return []

        cmd = ["tshark"]
        for port in decode_ports:
            cmd.extend(["-d", f"udp.port=={port},rtp"])
        cmd.extend(["-r", "-", "-q", "-z", "rtp,streams"])

        try:
            with open(pcap_path, "rb") as f:
                proc = subprocess.run(cmd, stdin=f, capture_output=True, text=True, check=False)
            output = proc.stdout
        except Exception:
            return []

        streams = []
        lines = output.splitlines()
        in_table = False
        for line in lines:
            if "== RTP Streams ==" in line:
                in_table = True
                continue
            if in_table and line.startswith("="):
                continue
            if in_table and line.strip():
                parts = line.split()
                if len(parts) >= 14:
                    try:
                        pkts = int(parts[8])
                        lost_str = parts[9]
                        mean_delta = float(parts[12]) if len(parts) > 12 else 0.0
                        mean_jitter = float(parts[15]) if len(parts) > 15 else 0.0
                        streams.append({
                            "src_ip": parts[2],
                            "src_port": int(parts[3]),
                            "dst_ip": parts[4],
                            "dst_port": int(parts[5]),
                            "ssrc": parts[6],
                            "payload": parts[7],
                            "packets": pkts,
                            "lost_str": lost_str,
                            "mean_delta_ms": mean_delta,
                            "mean_jitter_ms": mean_jitter,
                        })
                    except (ValueError, IndexError):
                        continue
        return streams


# Alias for backward compatibility
tshark_rows = PcapStreamReader.stream_rows
run_tshark_count = PcapStreamReader.count_packets
run_tshark_sum_bytes = PcapStreamReader.sum_bytes
parse_rtp_streams = PcapStreamReader.parse_rtp_streams


# ==============================================================================
# Packet Identity Extraction & Transport Fingerprinting
# ==============================================================================

def packet_identity(service: str, payload: bytes) -> Optional[bytes]:
    """Transport identities survive NAT and distinguish retransmissions/duplicates."""
    if service == "voice" and len(payload) >= 12 and (payload[0] >> 6) == 2:
        return payload[2:12]  # RTP sequence, timestamp and SSRC
    if service == "video" and len(payload) >= 20:
        magic, stream_id, _ = struct.unpack("!III", payload[:12])
        if magic == MAGIC_UHDV and stream_id != 0xFFFFFFFF:
            return payload[:20]  # Includes send timestamp; excludes NAT probes/ACKs.
    return None


def extract_packet_key(
    ip_id: str,
    ipv6_flow: str,
    tcp_seq: str,
    rtp_seq: str,
    frame_len: int,
    payload_hex: str,
    iperf3_seq: str = "",
) -> Tuple[str, ...]:
    """Extract a unique, invariant packet fingerprint across NAT and L2/L3 translation."""
    if len(payload_hex) >= 16:
        pfx = payload_hex[:8]
        if pfx == MAGIC_PERF and len(payload_hex) >= 24:
            try:
                stream_id = int(payload_hex[8:16], 16)
                seq = int(payload_hex[16:24], 16)
                return ("PERF", str(stream_id), str(seq))
            except ValueError:
                pass
        elif pfx == MAGIC_GFN and len(payload_hex) >= 24:
            try:
                seq = int(payload_hex[16:24], 16)
                return ("GFN", str(seq))
            except ValueError:
                pass
        elif pfx == MAGIC_VOD and len(payload_hex) >= 32:
            try:
                seq = int(payload_hex[24:32], 16)
                return ("VOD", str(seq))
            except ValueError:
                pass
        elif pfx == MAGIC_TRAF:
            try:
                seq = int(payload_hex[8:16], 16)
                return ("TRAF", str(seq))
            except ValueError:
                pass

    if rtp_seq and rtp_seq != "0":
        clean_rtp_seq = rtp_seq.strip()
        if clean_rtp_seq and clean_rtp_seq != "0":
            return ("RTP", clean_rtp_seq, str(frame_len))

    if iperf3_seq and iperf3_seq != "0":
        clean_iperf3 = iperf3_seq.strip()
        if clean_iperf3 and clean_iperf3 != "0":
            return ("IPERF3", clean_iperf3, str(frame_len))

    if tcp_seq and tcp_seq != "0":
        clean_tcp_seq = tcp_seq.strip()
        if clean_tcp_seq and clean_tcp_seq != "0":
            return ("TCP", clean_tcp_seq, str(frame_len))

    if ip_id and ip_id not in ("0x0000", "0"):
        clean_ip_id = ip_id.strip()
        if clean_ip_id and clean_ip_id not in ("0x0000", "0"):
            return ("IPID", clean_ip_id, str(frame_len), payload_hex[:16])

    if ipv6_flow and ipv6_flow not in ("0x00000000", "0"):
        clean_v6_flow = ipv6_flow.strip()
        if clean_v6_flow and clean_v6_flow not in ("0x00000000", "0"):
            return ("IPV6", clean_v6_flow, str(frame_len), payload_hex[:16])

    return ("RAW", str(frame_len), payload_hex[:32])


# ==============================================================================
# Jitter & Timing Engines
# ==============================================================================

def rtp_jitter(records: Dict[Any, Tuple[float, int, bytes]]) -> Optional[float]:
    """RFC 3550 interarrival jitter per SSRC, G.711 clock 8000 Hz, milliseconds."""
    states: Dict[int, Tuple[float, int, int, float]] = {}
    maximum: Optional[float] = None
    for arrival, _, payload in sorted(records.values(), key=lambda x: x[0]):
        if len(payload) < 12:
            continue
        _, _, sequence, timestamp, ssrc = struct.unpack("!BBHII", payload[:12])
        previous = states.get(ssrc)
        jitter = 0.0
        if previous:
            last_arrival, last_timestamp, last_sequence, jitter = previous
            delta = (timestamp - last_timestamp + 2**31) % 2**32 - 2**31
            jitter += (abs((arrival - last_arrival) * 1000 - delta / 8) - jitter) / 16
            maximum = jitter if maximum is None else max(maximum, jitter)
        states[ssrc] = (arrival, timestamp, sequence, jitter)
    return maximum


def video_jitter(records: Dict[Any, Tuple[float, int, bytes]]) -> Optional[float]:
    """Smoothed interarrival variation from Video's embedded send timestamps in milliseconds."""
    states: Dict[int, Tuple[float, float, float]] = {}
    maximum: Optional[float] = None
    for arrival, _, payload in sorted(records.values(), key=lambda x: x[0]):
        if len(payload) < 20:
            continue
        _, stream_id, _, sent = struct.unpack("!IIId", payload[:20])
        if not math.isfinite(sent):
            raise EvidenceError("Non-finite Video send timestamp")
        jitter = 0.0
        if stream_id in states:
            last_arrival, last_sent, jitter = states[stream_id]
            delta = abs((arrival - last_arrival) - (sent - last_sent)) * 1000
            jitter += (delta - jitter) / 16
            maximum = jitter if maximum is None else max(maximum, jitter)
        states[stream_id] = (arrival, sent, jitter)
    return maximum


def compare_direction(
    sent: Dict[Any, Tuple[float, int, bytes]],
    received: Dict[Any, Tuple[float, int, bytes]],
    dscp: int,
    window: Optional[Tuple[float, float]] = None
) -> Tuple[Dict[str, Any], Dict[Any, Tuple[float, int, bytes]], Dict[Any, Tuple[float, int, bytes]]]:
    """Compare directional packet counts and DSCP preservation between sender and receiver."""
    selected = {
        key: value for key, value in sent.items()
        if window is None or (window[0] <= value[0] <= window[1])
    }
    matched = {key: received[key] for key in selected if key in received}
    count = len(selected)
    loss = 100.0 * (count - len(matched)) / count if count else None
    preservation = 100.0 * sum(value[1] == dscp for value in matched.values()) / len(matched) if matched else None
    marked = 100.0 * sum(value[1] == dscp for value in selected.values()) / count if count else None
    metrics = {
        "sent_packets": count,
        "received_packets": len(matched),
        "loss_pct": loss,
        "dscp_preservation_pct": preservation,
        "sender_dscp_pct": marked,
    }
    return metrics, selected, matched


# ==============================================================================
# IEEE 802.11e WMM EDCA Parameter Parsing & Verification
# ==============================================================================

def parse_wmm_parameter_element(bss_block: str) -> Tuple[Dict[str, Dict[str, int]], bool, Dict[str, Any]]:
    """Parse the WMM Parameter Element section of one BSS block."""
    params: Dict[str, Dict[str, int]] = {}
    meta: Dict[str, Any] = {"ie_source": "unknown", "last_seen_ms": None, "wmm_ie_present": False}

    src_m = re.search(r"Information elements from (Probe Response|Beacon) frame", bss_block)
    if src_m:
        meta["ie_source"] = src_m.group(1)
    seen_m = re.search(r"last seen:\s*(\d+)\s*ms", bss_block)
    if seen_m:
        meta["last_seen_ms"] = int(seen_m.group(1))

    wmm_m = re.search(r"\n\tWMM:(.*?)(?=\n\t[A-Za-z]|\Z)", bss_block, re.DOTALL)
    if not wmm_m:
        return params, False, meta
    meta["wmm_ie_present"] = True
    wmm_section = wmm_m.group(1)

    for m in EDCA_LINE_RE.finditer(wmm_section):
        ac_tag, cwmin, cwmax, aifsn, txop = m.groups()
        txop_us = int(txop) if txop else 0
        params[f"AC_{ac_tag}"] = {
            "aifsn": int(aifsn),
            "cwmin": int(cwmin),
            "cwmax": int(cwmax),
            "txop_limit_us": txop_us,
            "txop_limit_units": txop_us // 32,
        }
    uapsd = re.search(r"\*\s+u-APSD", wmm_section) is not None
    return params, uapsd, meta


def parse_wmm_parameter_from_pcap(
    pcap_path: str, target_bssid: Optional[str] = None
) -> Tuple[Dict[str, Dict[str, int]], Optional[bool], Dict[str, Any]]:
    """Parse WMM Parameter Element from Beacon or Probe Response in an 802.11 PCAP."""
    params: Dict[str, Dict[str, int]] = {}
    meta: Dict[str, Any] = {
        "ie_source": "PCAP Over-The-Air Frame",
        "last_seen_ms": None,
        "wmm_ie_present": False,
        "bssid": target_bssid,
        "source_frame": None,
    }
    if not pcap_path or not Path(pcap_path).is_file():
        return params, None, meta

    flt = "wlan.fc.type_subtype == 0x08 or wlan.fc.type_subtype == 0x05"
    if target_bssid:
        flt = f"({flt}) and wlan.bssid == {target_bssid.lower()}"

    fields = ["frame.number", "wlan.bssid", "wlan.tag.number", "wlan.tag.oui", "wlan.tag.oui.type", "wlan.tag.data"]
    for row in PcapStreamReader.stream_rows(pcap_path, flt, fields):
        if len(row) < 6:
            continue
        f_num, bssid, tag_nums, ouis, oui_types, tag_datas = row[:6]
        tags = [t.strip() for t in tag_nums.split(",")]
        ouis_list = [o.strip() for o in ouis.split(",")]
        types_list = [t.strip() for t in oui_types.split(",")]
        datas_list = [d.strip() for d in tag_datas.split(",")]

        for i, tag_num in enumerate(tags):
            if tag_num == "221" and i < len(ouis_list) and i < len(types_list) and i < len(datas_list):
                oui = ouis_list[i].replace(":", "").lower()
                oui_type = types_list[i].strip()
                if oui.startswith("0050f2") and oui_type == "2":
                    meta["wmm_ie_present"] = True
                    meta["bssid"] = bssid
                    meta["source_frame"] = int(f_num)
                    raw_data = bytes.fromhex(datas_list[i].replace(":", ""))
                    if len(raw_data) >= 18:
                        ac_order = ["AC_BE", "AC_BK", "AC_VI", "AC_VO"]
                        for ac_idx, ac_name in enumerate(ac_order):
                            rec_offset = 2 + (ac_idx * 4)
                            if rec_offset + 4 <= len(raw_data):
                                aci_aifsn, ecw, txop = struct.unpack("!BBH", raw_data[rec_offset:rec_offset + 4])
                                aifsn = aci_aifsn & 0x0F
                                cwmin = (1 << (ecw & 0x0F)) - 1
                                cwmax = (1 << ((ecw >> 4) & 0x0F)) - 1
                                txop_us = txop * 32
                                params[ac_name] = {
                                    "aifsn": aifsn,
                                    "cwmin": cwmin,
                                    "cwmax": cwmax,
                                    "txop_limit_us": txop_us,
                                    "txop_limit_units": txop,
                                }
                        return params, False, meta
    return params, None, meta


def read_ap_edca_file(json_path: str) -> Dict[str, Any]:
    """Read DUT AP-side transmit EDCA parameters exported via dut_collector."""
    result: Dict[str, Any] = {
        "status": "NOT_VERIFIED",
        "parameters": {},
        "raw_source": json_path,
        "source_type": "unknown",
        "reasons": [],
    }
    if not json_path or not Path(json_path).is_file():
        result["reasons"].append(f"AP EDCA configuration file not found: {json_path}")
        return result

    try:
        data = load_json(json_path)
    except EvidenceError as exc:
        result["reasons"].append(str(exc))
        return result

    ap_params = data.get("ap_edca") or data.get("edca") or data
    if not isinstance(ap_params, dict):
        result["reasons"].append("Expected JSON dictionary of EDCA parameters")
        return result

    parsed: Dict[str, Dict[str, int]] = {}
    for ac in AC_ORDER:
        val = ap_params.get(ac) or ap_params.get(ac.lower()) or ap_params.get(ac.replace("AC_", ""))
        if isinstance(val, dict):
            try:
                parsed[ac] = {
                    "aifsn": int(val["aifsn"]),
                    "cwmin": int(val["cwmin"]),
                    "cwmax": int(val["cwmax"]),
                    "txop_limit_us": int(val.get("txop_limit_us", val.get("txop", 0))),
                }
            except (KeyError, ValueError) as exc:
                result["reasons"].append(f"Invalid fields in {ac}: {exc}")
                return result

    if len(parsed) < 3:
        result["reasons"].append(f"Incomplete AP EDCA entries (found {len(parsed)}/4)")
        return result

    result["parameters"] = parsed
    result["source_type"] = data.get("source", "dut_config")
    result["status"] = "PASS"
    return result


def ota_mapping(
    path: str,
    expected: Dict[str, Any],
    bssid: str,
    station_mac: str,
    voice_ports: Tuple[int, ...],
    video_ports: Tuple[int, ...],
    be_ports: Tuple[int, ...],
    voice_dscp: int = 46,
    video_dscp: int = 34,
) -> Dict[str, Any]:
    """Require decoded test-flow identities, AP->STA direction and actual QoS TIDs."""
    result = {
        name: {
            "status": "NOT_VERIFIED",
            "matched_packets": 0,
            "mapping_pct": None,
            "coverage_pct": None,
            "observed_tids": [],
        }
        for name in expected
    }
    if not path or not bssid or not station_mac:
        return result

    found: Dict[str, Dict[Any, Set[Tuple[int, int]]]] = {name: {} for name in expected}
    flt = (
        f"wlan.fc.type == 2 and wlan.bssid == {bssid.lower()} and wlan.ta == {bssid.lower()} "
        f"and wlan.ra == {station_mac.lower()} and (udp or tcp)"
    )
    fields = ["udp.srcport", "udp.payload", "ip.dsfield.dscp", "wlan.qos.tid", "tcp.srcport", "tcp.seq_raw", "tcp.len"]

    for row in PcapStreamReader.stream_rows(path, flt, fields):
        try:
            sport, raw, dscp_str, tid_str, tcp_sport, tcp_seq, tcp_len = row
            if not tid_str:
                continue
            port = int(sport or tcp_sport)
            dscp = int(dscp_str)
            tid = int(tid_str)
            name = (
                "voice" if port in voice_ports
                else "video" if port in video_ports
                else "best_effort" if port in be_ports
                else None
            )
            if name not in expected:
                continue

            payload = bytes.fromhex(raw.replace(":", ""))
            if tcp_sport:
                if name != "best_effort" or int(tcp_len) <= 0:
                    continue
                key = ("tcp", tcp_seq, tcp_len)
            else:
                ident = packet_identity(name, payload) if name != "best_effort" else payload[:12]
                key = (port, ident) if name != "best_effort" and ident else ident

            if not key or key not in expected[name]:
                continue
            found[name].setdefault(key, set()).add((dscp, tid))
        except (ValueError, IndexError) as exc:
            raise EvidenceError(f"Malformed OTA evidence in {path}: {exc}") from exc

    targets = {
        "voice": (voice_dscp, {6, 7}),
        "video": (video_dscp, {4, 5}),
        "best_effort": (0, {0, 3}),
    }
    for name, packets in found.items():
        if packets:
            target_dscp, tids = targets[name]
            good = sum(
                all(ds == target_dscp and tid in tids for ds, tid in observations)
                for observations in packets.values()
            )
            pct = 100.0 * good / len(packets)
            coverage = 100.0 * len(packets) / len(expected[name]) if expected[name] else None
            enough = len(packets) >= (50 if name == "voice" else 100)
            enough = enough and coverage is not None and coverage >= 95.0
            status = "FAIL" if pct < 95.0 else "PASS" if enough else "NOT_VERIFIED"
            result[name] = {
                "status": status,
                "matched_packets": len(packets),
                "mapping_pct": pct,
                "coverage_pct": coverage,
                "observed_tids": sorted({tid for observations in packets.values() for _, tid in observations}),
            }
    return result


def ota_mac_categories(path: str, bssid: str, station_mac: str) -> Dict[str, Any]:
    """Observe AP->station access categories without decrypting payload."""
    result: Dict[str, Any] = {
        "status": "NOT_VERIFIED",
        "basis": "MAC_TID",
        "bssid": bssid,
        "station_mac": station_mac,
        "direction": "AP_TO_STA",
        "total_frames": 0,
        "protected_frames": 0,
        "decoded_ip_frames": 0,
        "categories": {},
    }
    if not path or not bssid or not station_mac:
        return result

    tids = {tid: 0 for tid in range(8)}
    flt = (
        f"wlan.fc.type_subtype == 0x28 and wlan.bssid == {bssid.lower()} "
        f"and wlan.ta == {bssid.lower()} and wlan.ra == {station_mac.lower()}"
    )
    for row in PcapStreamReader.stream_rows(path, flt, ["wlan.qos.tid", "wlan.fc.protected", "ip.src"]):
        try:
            tid_str, protected, ip_src = row
            if not tid_str:
                continue
            tid = int(tid_str)
            if tid in tids:
                tids[tid] += 1
                result["total_frames"] += 1
                result["protected_frames"] += (1 if protected.lower() in ("1", "true") else 0)
                result["decoded_ip_frames"] += (1 if ip_src else 0)
        except (ValueError, IndexError) as exc:
            raise EvidenceError(f"Malformed OTA MAC/TID evidence: {exc}") from exc

    for name, ac, members in (
        ("voice", "AC_VO", (6, 7)),
        ("video", "AC_VI", (4, 5)),
        ("best_effort", "AC_BE", (0, 3)),
    ):
        count = sum(tids[tid] for tid in members)
        result["categories"][name] = {
            "ac": ac,
            "frame_count": count,
            "observed_tids": [tid for tid in members if tids[tid]],
            "status": "OBSERVED" if count else "NOT_OBSERVED",
        }
    result["status"] = "OBSERVED" if result["total_frames"] else "NOT_VERIFIED"
    return result


# ==============================================================================
# Cross-DUT PCAP Frame Correlator (Zero Loss & Latency Profiling)
# ==============================================================================

class PacketCorrelator:
    """Ground-truth packet-by-packet identity correlation across ingress & egress captures."""

    @staticmethod
    def stream_pcap_frames(
        pcap_path: str, display_filter: str = ""
    ) -> Iterator[Tuple[int, float, int, Tuple[str, ...]]]:
        """Stream packet metadata from PCAP: (frame_number, epoch_timestamp, frame_length, packet_key)."""
        fields = [
            "frame.number",
            "frame.time_epoch",
            "frame.len",
            "ip.id",
            "ipv6.flow",
            "tcp.seq",
            "rtp.seq",
            "iperf3.sequence",
            "data.data",
        ]
        for row in PcapStreamReader.stream_rows(pcap_path, display_filter, fields):
            n = len(row)
            if n >= 9:
                f_num_s, t_epoch_s, f_len_s, ip_id, ipv6_flow, tcp_seq, rtp_seq, iperf3_seq, payload_hex = row[:9]
            elif n >= 3:
                f_num_s, t_epoch_s, f_len_s = row[0], row[1], row[2]
                ip_id = row[3] if n > 3 else ""
                ipv6_flow = row[4] if n > 4 else ""
                tcp_seq = row[5] if n > 5 else ""
                rtp_seq = row[6] if n > 6 else ""
                iperf3_seq = row[7] if n > 7 else ""
                payload_hex = row[8] if n > 8 else ""
            else:
                continue

            try:
                f_num = int(f_num_s)
                t_epoch = float(t_epoch_s)
                f_len = int(f_len_s)
                key = extract_packet_key(ip_id, ipv6_flow, tcp_seq, rtp_seq, f_len, payload_hex, iperf3_seq)
                yield (f_num, t_epoch, f_len, key)
            except (ValueError, IndexError):
                continue

    @classmethod
    def correlate(
        cls,
        wan_pcap: str,
        lan_pcap: str,
        display_filter: str = "",
        max_skew: float = 2.0
    ) -> Dict[str, Any]:
        """Perform deep packet-by-packet correlation between WAN ingress and LAN egress."""
        t_start = time.perf_counter()

        def _ingest_wan() -> Tuple[Dict[Tuple[str, ...], Deque[Tuple[int, float, int]]], int, int]:
            q: Dict[Tuple[str, ...], Deque[Tuple[int, float, int]]] = collections.defaultdict(collections.deque)
            tot_p = 0
            tot_b = 0
            for f_num, t_epoch, f_len, key in cls.stream_pcap_frames(wan_pcap, display_filter):
                tot_p += 1
                tot_b += f_len
                q[key].append((f_num, t_epoch, f_len))
            return q, tot_p, tot_b

        def _ingest_lan() -> List[Tuple[int, float, int, Tuple[str, ...]]]:
            return list(cls.stream_pcap_frames(lan_pcap, display_filter))

        # Parallel PCAP streaming: overlap external tshark C process execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f_wan = executor.submit(_ingest_wan)
            f_lan = executor.submit(_ingest_lan)
            wan_queue, wan_total_packets, wan_total_bytes = f_wan.result()
            lan_frames = f_lan.result()

        lan_total_packets = 0
        lan_total_bytes = 0
        matched_packets = 0
        matched_bytes = 0
        reordered_packets = 0
        extraneous_packets = 0
        last_wan_fnum = 0
        latencies_ms: List[float] = []
        max_delay_ms = max_skew * 1000.0

        # Correlate LAN packets against indexed WAN packets
        for f_num, t_epoch, f_len, key in lan_frames:
            lan_total_packets += 1
            lan_total_bytes += f_len
            queue = wan_queue.get(key)
            matched_item = None

            if queue:
                # Fast path: in-order arrival at queue head
                first_item = queue[0]
                delay = (t_epoch - first_item[1]) * 1000.0
                if -100.0 <= delay <= max_delay_ms:
                    matched_item = queue.popleft()
                else:
                    # Slow path: out-of-order or expired items
                    for idx, item in enumerate(queue):
                        w_fnum, w_tepoch, w_len = item
                        delay = (t_epoch - w_tepoch) * 1000.0
                        if -100.0 <= delay <= max_delay_ms:
                            matched_item = item
                            del queue[idx]
                            break

            if matched_item:
                w_fnum, w_tepoch, w_len = matched_item
                matched_packets += 1
                matched_bytes += f_len
                if w_fnum < last_wan_fnum:
                    reordered_packets += 1
                last_wan_fnum = w_fnum
                delay_ms = (t_epoch - w_tepoch) * 1000.0
                if delay_ms >= 0:
                    latencies_ms.append(delay_ms)
            else:
                extraneous_packets += 1

        dropped_packets = sum(len(q) for q in wan_queue.values())
        dropped_bytes = sum(sum(item[2] for item in q) for q in wan_queue.values())
        t_elapsed = time.perf_counter() - t_start

        lat_stats: Dict[str, float] = {}
        if latencies_ms:
            latencies_ms.sort()
            n = len(latencies_ms)
            mean_val = sum(latencies_ms) / n
            lat_stats = {
                "min_ms": round(latencies_ms[0], 3),
                "p50_ms": round(latencies_ms[n // 2], 3),
                "p90_ms": round(latencies_ms[min(int(n * 0.90), n - 1)], 3),
                "p99_ms": round(latencies_ms[min(int(n * 0.99), n - 1)], 3),
                "max_ms": round(latencies_ms[-1], 3),
                "avg_ms": round(mean_val, 3),
                "stddev_ms": round(math.sqrt(sum((x - mean_val) ** 2 for x in latencies_ms) / n), 3) if n > 1 else 0.0,
            }

        loss_pct = round((dropped_packets / wan_total_packets * 100.0), 3) if wan_total_packets > 0 else 0.0
        reorder_pct = round((reordered_packets / matched_packets * 100.0), 3) if matched_packets > 0 else 0.0

        if wan_total_packets == 0 and lan_total_packets == 0:
            status = "NO_TRAFFIC"
        elif loss_pct == 0.0 and reorder_pct == 0.0:
            status = "PASS"
        elif loss_pct <= 0.1:
            status = "PASS_WITH_TOLERANCE"
        else:
            status = "FAIL"

        return {
            "test": "pcap_packet_correlation",
            "wan_pcap": wan_pcap,
            "lan_pcap": lan_pcap,
            "filter": display_filter,
            "wan_total_packets": wan_total_packets,
            "wan_total_bytes": wan_total_bytes,
            "lan_total_packets": lan_total_packets,
            "lan_total_bytes": lan_total_bytes,
            "matched_packets": matched_packets,
            "matched_bytes": matched_bytes,
            "dropped_packets": dropped_packets,
            "dropped_bytes": dropped_bytes,
            "loss_pct": loss_pct,
            "reordered_packets": reordered_packets,
            "reorder_pct": reorder_pct,
            "extraneous_packets": extraneous_packets,
            "latency": lat_stats,
            "status": status,
            "duration_s": round(t_elapsed, 3),
        }


# ==============================================================================
# VoIP Multi-Stream Analyzer
# ==============================================================================

class VoipStreamAuditor:
    """Evaluates VoIP RTP streams across WAN and LAN/Wi-Fi phone interfaces."""

    @staticmethod
    def audit_stream(
        stream_name: str,
        direction: str,
        tx_pcap: str,
        tx_filter: str,
        rx_pcap: str,
        rx_filter: str,
        dscp_target: int = 46
    ) -> Dict[str, Any]:
        """Audit an individual directional media stream."""
        tx_count = PcapStreamReader.count_packets(tx_pcap, tx_filter)
        rx_count = PcapStreamReader.count_packets(rx_pcap, rx_filter)
        tx_dscp = PcapStreamReader.count_packets(tx_pcap, f"({tx_filter}) and ip.dsfield == {hex(dscp_target << 2)}")
        rx_dscp = PcapStreamReader.count_packets(rx_pcap, f"({rx_filter}) and ip.dsfield == {hex(dscp_target << 2)}")

        loss_pkts = max(0, tx_count - rx_count) if tx_count > 0 else 0
        loss_pct = round((loss_pkts / tx_count) * 100.0, 3) if tx_count > 0 else 0.0
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

    @classmethod
    def audit(
        cls,
        wan_pcap: str,
        phone1_pcap: Optional[str] = None,
        phone2_pcap: Optional[str] = None,
        lan_pcap: Optional[str] = None,
        mode: str = "distributed"
    ) -> Dict[str, Any]:
        """Audit VoIP streams across WAN and client endpoints."""
        streams_detail = []
        overall_pass = True

        p1_cap = phone1_pcap or lan_pcap or ""
        p2_cap = phone2_pcap or lan_pcap or ""

        # WAN <-> Phone 1
        if p1_cap and Path(p1_cap).is_file():
            down1 = cls.audit_stream(
                "WAN->Phone1", "downlink",
                wan_pcap, "udp.port == 10000 or udp.port == 5060",
                p1_cap, "udp.port == 10000 or udp.port == 5060"
            )
            up1 = cls.audit_stream(
                "Phone1->WAN", "uplink",
                p1_cap, "udp.port == 10000 or udp.port == 5060",
                wan_pcap, "udp.port == 10000 or udp.port == 5060"
            )
            streams_detail.extend([down1, up1])
            if down1["loss_pct"] > 1.0 or up1["loss_pct"] > 1.0 or not (down1["rx_dscp_ok"] and up1["rx_dscp_ok"]):
                overall_pass = False

        # WAN <-> Phone 2
        if p2_cap and Path(p2_cap).is_file() and p2_cap != p1_cap:
            down2 = cls.audit_stream(
                "WAN->Phone2", "downlink",
                wan_pcap, "udp.port == 10002 or udp.port == 5062",
                p2_cap, "udp.port == 10002 or udp.port == 5062"
            )
            up2 = cls.audit_stream(
                "Phone2->WAN", "uplink",
                p2_cap, "udp.port == 10002 or udp.port == 5062",
                wan_pcap, "udp.port == 10002 or udp.port == 5062"
            )
            streams_detail.extend([down2, up2])
            if down2["loss_pct"] > 1.0 or up2["loss_pct"] > 1.0 or not (down2["rx_dscp_ok"] and up2["rx_dscp_ok"]):
                overall_pass = False

        # If no phone endpoints provided, fallback to WAN count
        if not streams_detail:
            wan_rtp = PcapStreamReader.count_packets(wan_pcap, "udp.port >= 10000 and udp.port <= 10004")
            wan_dscp = PcapStreamReader.count_packets(wan_pcap, "udp.port >= 10000 and udp.port <= 10004 and ip.dsfield == 0xb8")
            status = "PASS" if wan_rtp > 100 and wan_dscp >= (wan_rtp * 0.95) else "FAIL"
            return {
                "test": "voip_pcap_audit",
                "mode": mode,
                "overall_status": status,
                "wan_rtp_packets": wan_rtp,
                "wan_dscp46_packets": wan_dscp,
                "streams": [],
            }

        return {
            "test": "voip_pcap_audit",
            "mode": mode,
            "overall_status": "PASS" if overall_pass and streams_detail else "FAIL",
            "streams": streams_detail,
        }


# ==============================================================================
# Wireless WMM QoS Multi-Service Analyzer
# ==============================================================================

def read_capture_services(
    path: str,
    server_ip: str,
    voice_ports: Tuple[int, ...],
    video_ports: Tuple[int, ...],
    be_ports: Tuple[int, ...],
) -> Tuple[Dict[str, Dict[str, Dict[Any, Tuple[float, int, bytes]]]], Dict[str, Any]]:
    """Dissect and bucket capture traffic by service class (Voice, Video, Best Effort)."""
    services: Dict[str, Dict[str, Dict[Any, Tuple[float, int, bytes]]]] = {
        name: {"downlink": {}, "uplink": {}} for name in ("voice", "video")
    }
    be: Dict[str, Any] = {
        "packets": 0,
        "bytes": 0,
        "first": None,
        "last": None,
        "bins": set(),
        "samples": {},
        "sample_bins": {},
    }
    fields = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "udp.payload",
        "ip.dsfield.dscp",
        "tcp.srcport",
        "tcp.dstport",
        "ip.len",
        "tcp.seq_raw",
        "tcp.len",
    ]

    for row in PcapStreamReader.stream_rows(path, "ip and (udp or tcp)", fields):
        if len(row) != len(fields):
            raise EvidenceError(f"Malformed tshark row in {path}")
        ts_str, src, dst, sport, dport, payload, dscp_str, tcp_sport, tcp_dport, length, tcp_seq, tcp_len = row
        try:
            ts = float(ts_str)
            direction = "downlink" if src == server_ip else "uplink" if dst == server_ip else None
            if direction is None:
                continue

            server_port = int((sport or tcp_sport) if direction == "downlink" else (dport or tcp_dport))
            if server_port in be_ports and direction == "downlink":
                if int(length) > 100:
                    be["packets"] += 1
                    be["bytes"] += int(length)
                    be["first"] = ts if be["first"] is None else min(be["first"], ts)
                    be["last"] = ts if be["last"] is None else max(be["last"], ts)
                    be["bins"].add(math.floor(ts))
                    second = math.floor(ts)
                    if be["sample_bins"].get(second, 0) < 64:
                        key = (("tcp", tcp_seq, tcp_len) if tcp_sport else bytes.fromhex(payload.replace(":", ""))[:12])
                        if key and key not in be["samples"]:
                            be["samples"][key] = ts
                            be["sample_bins"][second] = be["sample_bins"].get(second, 0) + 1
                continue

            service = "voice" if server_port in voice_ports else "video" if server_port in video_ports else None
            if service is None or not sport:
                continue

            raw = bytes.fromhex(payload.replace(":", ""))
            ident = packet_identity(service, raw)
            if ident is not None:
                record_key = (server_port, ident)
                records = services[service][direction]
                if record_key not in records:
                    records[record_key] = (ts, int(dscp_str), raw)
        except (ValueError, IndexError) as exc:
            raise EvidenceError(f"Malformed transport evidence in {path}: {exc}") from exc

    return services, be


def congestion_status(context: Dict[str, Any], window: Optional[Tuple[float, float]], receiver_be: Dict[str, Any]) -> str:
    """Only radio telemetry covering this measurement window proves its bottleneck."""
    if context.get("congestion_source") != "wifi" or context.get("be_direction", "downlink") != "downlink":
        return "NOT_VERIFIED"
    if not window or receiver_be["packets"] == 0:
        return "NOT_VERIFIED"
    path = context.get("congestion_evidence_json")
    if not path:
        return "NOT_VERIFIED"
    evidence = load_json(path)
    if (evidence.get("run_id") != context.get("run_id") or evidence.get("domain") != "wifi"
            or evidence.get("bssid", "").lower() != context.get("bssid", "").lower()
            or not evidence.get("source")):
        raise EvidenceError("Congestion telemetry does not identify this run/BSSID")
    try:
        first, last = float(evidence["start_epoch"]), float(evidence["end_epoch"])
        backlog = float(evidence.get("wifi_queue_backlog_packets", 0))
        drops = float(evidence.get("wifi_queue_drops_delta", 0))
        busy = float(evidence.get("channel_busy_pct", 0))
        if (not all(math.isfinite(v) for v in (first, last, backlog, drops, busy))
                or min(backlog, drops, busy) < 0 or busy > 100 or last < first):
            raise ValueError("non-finite or out-of-range telemetry")
        covers = first <= window[0] and last >= window[1]
    except (ValueError, TypeError, KeyError) as exc:
        raise EvidenceError("Invalid congestion telemetry counters/window") from exc
    return "PASS" if covers and (backlog > 0 or drops > 0 or busy >= 90) else "NOT_VERIFIED"


def audit_captures(
    wan_path: str,
    receiver_path: str,
    ota_path: Optional[str] = None,
    context: Optional[Dict[str, Any]] = None,
    voice_ports: Tuple[int, ...] = (10000,),
    video_ports: Tuple[int, ...] = (5005,),
    be_ports: Tuple[int, ...] = (5201,),
    voice_dscp: int = 46,
    video_dscp: int = 34,
    max_loss: float = 1.0,
    max_jitter: float = 20.0,
) -> Dict[str, Any]:
    context = context or {}
    profile = context.get("audit_profile", "practical")
    result: Dict[str, Any] = {
        "test": "wireless_qos_multi_service",
        "mode": context.get("mode", "unknown"),
        "audit_profile": profile,
        "warnings": [],
        "overall_status": "INVALID",
        "verdict": "INVALID",
        "reasons": [],
        "services": {},
        "audit_evidence": {"wan_pcap": wan_path, "receiver_pcap": receiver_path, "ota_pcap": ota_path},
    }
    if context.get("be_direction", "downlink") != "downlink":
        result.update(overall_status="INCONCLUSIVE", verdict="INCONCLUSIVE",
                      reasons=["Uplink BE does not establish the downlink WMM congestion claim"])
        return result
    try:
        if profile not in ("practical", "strict"):
            raise EvidenceError(f"Unknown audit profile: {profile}")
        server_ip = context.get("server_ip", "10.10.0.1")
        wan, be = read_capture_services(wan_path, server_ip, voice_ports, video_ports, be_ports)
        receiver, rx_be = read_capture_services(receiver_path, server_ip, voice_ports, video_ports, be_ports)
        spans = [list(wan[name]["downlink"].values()) for name in ("voice", "video")]
        needs_radio_be = context.get("congestion_source", "wifi") == "wifi"
        if not all(spans) or be["first"] is None or (needs_radio_be and rx_be["packets"] == 0):
            raise EvidenceError("Missing downstream Voice, Video or Best Effort traffic")
        start = max(be["first"] + 1.0, *(min(v[0] for v in span) for span in spans))
        end = min(be["last"] - 0.2, *(max(v[0] for v in span) for span in spans))
        minimum = max(2.0, 0.8 * float(context.get("duration", 0)))
        if not math.isfinite(end - start) or end - start < minimum:
            raise EvidenceError("Insufficient common steady-state measurement window")
        window = (start, end)
        if any(second not in be["bins"] for second in range(math.ceil(start), math.floor(end))):
            raise EvidenceError("Best Effort traffic has a gap in the measurement window")
        result["measurement_window"] = {"start_epoch": start, "end_epoch": end, "duration_s": end - start}
        expected = {}
        failures = []
        for name, dscp in (("voice", voice_dscp), ("video", video_dscp)):
            metrics, selected, matched = compare_direction(wan[name]["downlink"], receiver[name]["downlink"], dscp, window)
            expected[name] = selected
            metrics.update({"service_name": name, "dscp_value": dscp,
                            "wan_packets": metrics["sent_packets"], "lan_packets": metrics["received_packets"]})
            if metrics["sent_packets"] < (50 if name == "voice" else 100):
                raise EvidenceError(f"Insufficient {name} packets")
            passed = (metrics["loss_pct"] <= max_loss and (metrics["dscp_preservation_pct"] or 0) >= 95
                      and (metrics["sender_dscp_pct"] or 0) >= 95)
            jitter = rtp_jitter(matched) if name == "voice" else video_jitter(matched)
            metrics["max_jitter_ms"] = jitter
            passed = passed and jitter is not None and jitter < max_jitter
            if name == "voice":
                uplink, _, _ = compare_direction(receiver[name]["uplink"], wan[name]["uplink"], dscp)
                metrics["uplink"] = uplink
                if not uplink["sent_packets"]:
                    raise EvidenceError("Missing voice uplink evidence")
                passed = (passed and uplink["loss_pct"] <= max_loss
                          and (uplink["dscp_preservation_pct"] or 0) >= 95
                          and (uplink["sender_dscp_pct"] or 0) >= 95)
            metrics["status"] = "PASS" if passed else "FAIL"
            if not passed:
                failures.append(f"{name} loss, DSCP or jitter threshold exceeded")
            result["services"][name] = metrics
        be_span = rx_be["last"] - rx_be["first"] if rx_be["packets"] else 0
        result["services"]["best_effort"] = {"status": "ACTIVE" if rx_be["packets"] else "NOT_OBSERVED_ON_WIFI", "dscp_value": 0,
            "wan_packets": be["packets"], "lan_packets": rx_be["packets"], "loss_pct": None,
            "throughput_mbps": rx_be["bytes"] * 8 / max(be_span, 0.001) / 1e6}
        expected["best_effort"] = {key: ts for key, ts in be["samples"].items() if start <= ts <= end}
        mapping = ota_mapping(ota_path, expected, context.get("bssid"), context.get("station_mac"),
                              voice_ports, video_ports, be_ports, voice_dscp, video_dscp)
        result["mapping"] = mapping
        mac_evidence = ota_mac_categories(ota_path, context.get("bssid"), context.get("station_mac"))
        result["mac_tid_evidence"] = mac_evidence
        if any(m["status"] == "FAIL" for m in mapping.values()):
            failures.append("Observed test-flow DSCP/TID mapping failure")
        result["congestion_status"] = congestion_status(context, window, rx_be)
        client_path = context.get("client_audit_json")
        if client_path:
            client = load_json(client_path)
            result["client_metrics"] = client
            if client.get("overall_status") == "INVALID":
                raise EvidenceError("Client metrics are invalid")
            if client.get("quality_status") == "FAIL":
                failures.append("Client quality check failed")
        result["quality_status"] = "FAIL" if failures else "PASS"
        missing = []
        if context.get("mode") in ("virtual", "unknown", None):
            missing.append("Physical Wi-Fi execution not verified")
        decoded = all(m["status"] == "PASS" for m in mapping.values())
        mac_observed = all(mac_evidence["categories"].get(name, {}).get("status") == "OBSERVED"
                           for name in ("voice", "video", "best_effort"))
        result["mapping_basis"] = "DECODED_FLOW" if decoded else "MAC_TID" if mac_observed else "IP_DSCP_ONLY"
        if not decoded:
            if profile == "strict":
                missing.append("Decoded OTA test-flow DSCP/TID mapping not fully verified")
            elif mac_observed:
                result["warnings"].append("ACs observed by AP/station MAC and TID; encrypted test flows are not individually correlated")
            else:
                missing.append("Expected station AC_VO, AC_VI and AC_BE not observed in OTA MAC/TID evidence")
        if result["congestion_status"] != "PASS":
            if profile == "strict":
                missing.append("Wi-Fi bottleneck telemetry not verified")
            else:
                result["warnings"].append("Concurrent Wi-Fi BE load verified; radio bottleneck location was not measured")
        if context.get("congestion_source", "wifi") != "wifi":
            missing.append("Wired BE does not establish the Wi-Fi load condition")
        status = "FAIL" if failures else "INCONCLUSIVE" if missing else "PASS"
        result.update(overall_status=status, verdict=status, reasons=failures + missing)
    except EvidenceError as exc:
        result["reasons"].append(str(exc))
    return result


# ==============================================================================
# The Unified Deep Module: PacketEvidenceAuditor
# ==============================================================================

class PacketEvidenceAuditor:
    """The unified evidence auditor presenting a small, deep interface to callers."""

    def __init__(self) -> None:
        pass

    def audit_wire_rate(
        self,
        wan_pcap: str,
        lan_pcap: str,
        display_filter: str = "",
        max_loss_pct: float = 0.0
    ) -> Dict[str, Any]:
        """Audit bidirectional or unidirectional wire-rate traffic preservation across DUT."""
        corr = PacketCorrelator.correlate(wan_pcap, lan_pcap, display_filter)
        loss = corr.get("loss_pct", 100.0)
        corr_status = corr.get("status", "FAIL")
        if loss <= max_loss_pct and corr.get("matched_packets", 0) > 0:
            status = "PASS"
        elif corr_status in ("PASS", "PASS_WITH_TOLERANCE"):
            status = corr_status
        else:
            status = "FAIL"
        return {
            "test": "wire_rate_audit",
            "overall_status": status,
            "wan_packets": corr["wan_total_packets"],
            "lan_packets": corr["lan_total_packets"],
            "matched_packets": corr["matched_packets"],
            "dropped_packets": corr["dropped_packets"],
            "loss_pct": loss,
            "latency": corr.get("latency", {}),
            "reordered_packets": corr.get("reordered_packets", 0),
        }

    def audit_multicast(
        self,
        wan_pcap: str,
        lan_pcap: str,
        mcast_group: str = "239.255.0.1",
        port: int = 5003
    ) -> Dict[str, Any]:
        """Audit multicast IPTV forwarding preservation from WAN to LAN."""
        flt = f"ip.dst == {mcast_group} and udp.dstport == {port}"
        corr = PacketCorrelator.correlate(wan_pcap, lan_pcap, flt)
        loss = corr.get("loss_pct", 100.0)
        status = "PASS" if loss == 0.0 and corr.get("matched_packets", 0) > 0 else "FAIL"
        return {
            "test": "multicast_audit",
            "mcast_group": mcast_group,
            "port": port,
            "overall_status": status,
            "wan_packets": corr["wan_total_packets"],
            "lan_packets": corr["lan_total_packets"],
            "loss_pct": loss,
            "latency": corr.get("latency", {}),
        }

    def audit_voip(
        self,
        wan_pcap: str,
        phone1_pcap: Optional[str] = None,
        phone2_pcap: Optional[str] = None,
        lan_pcap: Optional[str] = None,
        mode: str = "distributed"
    ) -> Dict[str, Any]:
        """Audit VoIP streams across WAN and client endpoints."""
        return VoipStreamAuditor.audit(wan_pcap, phone1_pcap, phone2_pcap, lan_pcap, mode)

    def audit_wireless_qos(
        self,
        wan_pcap: str,
        lan_pcap: str,
        wifi_pcap: Optional[str] = None,
        ota_pcap: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        voice_ports: Tuple[int, ...] = (10000,),
        video_ports: Tuple[int, ...] = (5005,),
        be_ports: Tuple[int, ...] = (5201,),
        voice_dscp: int = 46,
        video_dscp: int = 34,
    ) -> Dict[str, Any]:
        """Audit IEEE 802.11e WMM & DSCP Mapping evidence across WAN, LAN, and Wi-Fi."""
        receiver = wifi_pcap or lan_pcap
        return audit_captures(
            wan_pcap, receiver, ota_pcap, context,
            voice_ports, video_ports, be_ports, voice_dscp, video_dscp
        )

    def audit_correlation(
        self,
        wan_pcap: str,
        lan_pcap: str,
        display_filter: str = "",
        max_skew: float = 2.0
    ) -> Dict[str, Any]:
        """Perform deep packet-by-packet identity correlation and micro-latency profiling."""
        return PacketCorrelator.correlate(wan_pcap, lan_pcap, display_filter, max_skew)


# ==============================================================================
# Terminal Card Formatting
# ==============================================================================

def print_audit_card(results: Dict[str, Any]) -> None:
    """Print an attractive, human-readable terminal audit card."""
    test_type = results.get("test", "Evidence Audit")
    status = results.get("overall_status") or results.get("status") or results.get("verdict", "UNKNOWN")

    status_color = "\033[1;32m" if status in ("PASS", "PASS_WITH_TOLERANCE") else (
        "\033[1;33m" if status in ("PARTIAL", "INCONCLUSIVE") else "\033[1;31m"
    )
    reset = "\033[0m"

    print("\n" + "=" * 70)
    print(f"  PACKET EVIDENCE AUDIT: [{test_type.upper()}]")
    print("=" * 70)
    print(f"  Overall Status : {status_color}{status}{reset}")

    if "wan_packets" in results and "lan_packets" in results:
        print(f"  WAN Packets    : {results.get('wan_packets', 0):,}")
        print(f"  LAN Packets    : {results.get('lan_packets', 0):,}")
        print(f"  Loss Pct       : {results.get('loss_pct', 0.0):.2f}%")

    if "matched_packets" in results:
        print(f"  Matched Frames : {results.get('matched_packets', 0):,}")

    if "latency" in results and results["latency"]:
        lat = results["latency"]
        print(f"  Forward Latency: min={lat.get('min_ms')}ms | p50={lat.get('p50_ms')}ms | p99={lat.get('p99_ms')}ms | max={lat.get('max_ms')}ms")

    if "services" in results and results["services"]:
        print("-" * 70)
        print(f"  {'SERVICE':<12} {'DSCP':<6} {'WAN PKTS':>10} {'RX PKTS':>10} {'LOSS %':>8} {'STATUS':>10}")
        print("-" * 70)
        for name, m in results["services"].items():
            loss = f"{m.get('loss_pct', 0.0):.2f}%" if m.get("loss_pct") is not None else "N/A"
            print(f"  {name:<12} {m.get('dscp_value', 'N/A')!s:<6} {m.get('sent_packets', 0):>10,} {m.get('received_packets', 0):>10,} {loss:>8} {m.get('status', 'N/A'):>10}")

    if "streams" in results and results["streams"]:
        print("-" * 70)
        print(f"  {'STREAM':<16} {'DIR':<10} {'TX PKTS':>10} {'RX PKTS':>10} {'LOSS %':>8} {'DSCP OK':>8}")
        print("-" * 70)
        for s in results["streams"]:
            dscp_ok = "YES" if s.get("rx_dscp_ok") else "NO"
            print(f"  {s['stream']:<16} {s['direction']:<10} {s['tx_packets']:>10,} {s['rx_packets']:>10,} {s['loss_pct']:>7.2f}% {dscp_ok:>8}")

    print("=" * 70 + "\n")


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Unified Packet Evidence & PCAP Auditor")
    parser.add_argument("--capture-set", "--manifest", dest="capture_set_json", default=None,
                        help="Path to capture_set.json manifest produced by Capture Session module")
    parser.add_argument("--wan", "--wan-pcap", dest="wan_pcap", default=None, help="Ingress WAN PCAP file")
    parser.add_argument("--lan", "--lan-pcap", dest="lan_pcap", default=None, help="Egress LAN PCAP file")
    parser.add_argument("--wifi", "--wifi-pcap", dest="wifi_pcap", default=None, help="Wi-Fi station PCAP file")
    parser.add_argument("--phone1", "--phone1-pcap", dest="phone1_pcap", default=None, help="VoIP Phone 1 PCAP file")
    parser.add_argument("--phone2", "--phone2-pcap", dest="phone2_pcap", default=None, help="VoIP Phone 2 PCAP file")
    parser.add_argument("--ota", "--ota-pcap", dest="ota_pcap", default=None, help="Over-the-Air 802.11 monitor PCAP file")
    parser.add_argument("--filter", default="", help="Wireshark display filter")
    parser.add_argument("--context-json", default=None, help="Test run context metadata JSON")
    parser.add_argument("--mcast-group", default="239.255.0.1", help="Multicast group IP")
    parser.add_argument("--mcast-port", type=int, default=5003, help="Multicast UDP port")
    parser.add_argument("--voice-ports", default="10000,5060", help="Voice UDP ports")
    parser.add_argument("--video-ports", default="5005", help="Video UDP ports")
    parser.add_argument("--be-ports", default="5201", help="Best-effort ports")
    parser.add_argument("--mode", default="distributed", help="Test execution mode")
    parser.add_argument("--profile", default="auto",
                        choices=["auto", "wire_rate", "multicast", "voip", "wireless_qos", "correlate"],
                        help="Audit verification profile")
    parser.add_argument("--output-json", "-o", default="", help="Path to write JSON result")
    parser.add_argument("--quiet", action="store_true", help="Suppress card formatting")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    # Load from capture set manifest if provided
    if args.capture_set_json:
        try:
            cs = load_json(args.capture_set_json)
            vantages = cs.get("vantages", {})
            if not args.wan_pcap and "wan" in vantages:
                args.wan_pcap = vantages["wan"].get("path")
            if not args.lan_pcap:
                args.lan_pcap = vantages.get("lan_merged", {}).get("path") or vantages.get("lan", {}).get("path")
            if not args.wifi_pcap and "wifi" in vantages:
                args.wifi_pcap = vantages["wifi"].get("path")
            if not args.filter:
                args.filter = cs.get("display_filter") or bpf_to_display_filter(cs.get("bpf_filter", ""))
        except Exception as exc:
            print(f"Error loading capture set manifest {args.capture_set_json}: {exc}", file=sys.stderr)
            return 1

    if args.filter:
        args.filter = bpf_to_display_filter(args.filter)

    if not args.wan_pcap:
        print("Error: --wan or a valid --capture-set manifest is required.", file=sys.stderr)
        return 2

    auditor = PacketEvidenceAuditor()
    profile = args.profile

    # Auto-detection of profile if not explicitly pinned
    if profile == "auto":
        if args.phone1_pcap or args.phone2_pcap or "voice" in args.wan_pcap.lower():
            profile = "voip"
        elif args.ota_pcap or (args.context_json and "wireless" in str(args.context_json).lower()):
            profile = "wireless_qos"
        elif "mcast" in args.wan_pcap.lower() or "multicast" in args.filter.lower() or "239." in args.filter:
            profile = "multicast"
        elif args.filter and ("tcp.port" in args.filter or "udp.port" in args.filter or "port" in args.filter):
            profile = "wire_rate"
        else:
            profile = "wire_rate"

    results: Dict[str, Any] = {}

    if profile == "wire_rate":
        lan = args.lan_pcap or args.wifi_pcap or ""
        results = auditor.audit_wire_rate(args.wan_pcap, lan, args.filter)
    elif profile == "multicast":
        lan = args.lan_pcap or ""
        results = auditor.audit_multicast(args.wan_pcap, lan, args.mcast_group, args.mcast_port)
    elif profile == "voip":
        results = auditor.audit_voip(args.wan_pcap, args.phone1_pcap, args.phone2_pcap, args.lan_pcap, args.mode)
    elif profile == "wireless_qos":
        ctx = load_json(args.context_json) if args.context_json else {}
        results = auditor.audit_wireless_qos(
            args.wan_pcap,
            args.lan_pcap or "",
            args.wifi_pcap,
            args.ota_pcap,
            ctx,
            parse_ports(args.voice_ports),
            parse_ports(args.video_ports),
            parse_ports(args.be_ports),
        )
    elif profile == "correlate":
        lan = args.lan_pcap or args.wifi_pcap or ""
        results = auditor.audit_correlation(args.wan_pcap, lan, args.filter)

    if args.output_json:
        out_p = Path(args.output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(results, indent=2), encoding="utf-8")

    if not args.quiet:
        print_audit_card(results)

    status = results.get("overall_status") or results.get("status") or results.get("verdict")
    return 0 if status in ("PASS", "PASS_WITH_TOLERANCE", "OBSERVED") else 1


if __name__ == "__main__":
    sys.exit(main())

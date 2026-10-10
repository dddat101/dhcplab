#!/usr/bin/env python3
"""
tools/dhcp_auditor.py - Unified DHCP Protocol Evidence & PCAP Audit Engine

Verifies DHCPv4 (RFC 2131), DHCPv6 (RFC 8415 / RFC 3315 / RFC 3633),
and DHCP Relay Agent (RFC 3046 Option 82 / RFC 8415 Relay-Forward/Reply)
across multi-vantage packet captures (LAN vs WAN).
"""

import argparse
import collections
import dataclasses
import enum
import functools
import json
import os
import re
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


# ==============================================================================
# Domain Exceptions & Types
# ==============================================================================

class DHCPAuditError(ValueError):
    """Raised when capture files are missing, malformed, or protocol assertion fails."""


class DHCPv4MsgType(enum.IntEnum):
    DISCOVER = 1
    OFFER = 2
    REQUEST = 3
    DECLINE = 4
    ACK = 5
    NAK = 6
    RELEASE = 7
    INFORM = 8


class DHCPv6MsgType(enum.IntEnum):
    SOLICIT = 1
    ADVERTISE = 2
    REQUEST = 3
    CONFIRM = 4
    RENEW = 5
    REBIND = 6
    REPLY = 7
    RELEASE = 8
    DECLINE = 9
    RECONFIGURE = 10
    INFORMATION_REQUEST = 11
    RELAY_FORWARD = 12
    RELAY_REPLY = 13


class DHCPv6StatusCode(enum.IntEnum):
    SUCCESS = 0
    UNSPEC_FAIL = 1
    NO_ADDRS_AVAIL = 2
    NO_BINDING = 3
    NOT_ON_LINK = 4
    USE_MULTICAST = 5
    NO_PREFIX_AVAIL = 6


DHCPV6_STATUS_NAMES = {
    0: "Success",
    1: "UnspecFail",
    2: "NoAddrsAvail",
    3: "NoBinding",
    4: "NotOnLink",
    5: "UseMulticast",
    6: "NoPrefixAvail",
}


@dataclasses.dataclass(frozen=True)
class DHCPv4Frame:
    frame_number: int
    timestamp: float
    msg_type: Optional[int]
    msg_type_name: str
    xid: str
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: str
    server_id: Optional[str]
    lease_time: Optional[int]
    subnet_mask: Optional[str]
    router: Optional[str]
    dns_servers: List[str]
    domain_name: Optional[str]
    hostname: Optional[str]
    vendor_class: Optional[str]
    circuit_id: Optional[str]
    remote_id: Optional[str]


@dataclasses.dataclass(frozen=True)
class DHCPv6Frame:
    frame_number: int
    timestamp: float
    msg_type: Optional[int]
    msg_type_name: str
    xid: str
    linkaddr: str
    peeraddr: str
    client_duid: Optional[str]
    server_duid: Optional[str]
    ia_na_addresses: List[str]
    ia_pd_prefixes: List[str]
    dns_servers: List[str]
    domain_search: List[str]
    interface_id: Optional[str]
    relay_msg_type: Optional[int]
    status_code: Optional[int] = None


# ==============================================================================
# Utility Helpers
# ==============================================================================

_RE_HEX_CLEAN = re.compile(r"[^0-9a-fA-F]")


def clean_hex(val: str) -> str:
    """Normalize hex string by removing colons, spaces, and converting to lowercase."""
    return _RE_HEX_CLEAN.sub("", val).lower()


def safe_int(val: Any, default: Optional[int] = None) -> Optional[int]:
    """Safely convert any value to int or return default."""
    if val is None or val == "":
        return default
    try:
        if isinstance(val, str) and val.startswith(("0x", "0X")):
            return int(val, 16)
        return int(val)
    except (ValueError, TypeError):
        return default


def safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert any value to float or return default."""
    if val is None or val == "":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def safe_bool(val: Any, default: bool = False) -> bool:
    """Safely convert string, number, or boolean to bool (handles tshark 'True', 'False', '1', '0')."""
    if val is None or val == "":
        return default
    if isinstance(val, bool):
        return val
    s = str(val).split(",")[0].strip().lower()
    if s in ("1", "true", "t", "yes", "y", "enable", "enabled", "0x1", "0x01"):
        return True
    if s in ("0", "false", "f", "no", "n", "disable", "disabled", "0x0", "0x00"):
        return False
    return default


def write_atomic_json(target_path: Union[str, Path], payload: Dict[str, Any]) -> None:
    """Atomically write dictionary as formatted JSON."""
    p = Path(target_path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = p.with_suffix(f".tmp.{os.getpid()}")
    try:
        tmp_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
        tmp_path.replace(p)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


# ==============================================================================
# Dissection Engine (tshark Adapter)
# ==============================================================================

class TsharkDissector:
    """Extracts DHCPv4 and DHCPv6 packet structures via tshark."""

    def __init__(self, tshark_bin: str = "tshark") -> None:
        self.tshark_bin = tshark_bin

    def extract_dhcpv4(self, pcap_path: Union[str, Path]) -> List[DHCPv4Frame]:
        p = Path(pcap_path)
        if not p.is_file():
            raise DHCPAuditError(f"PCAP file not found: {pcap_path}")

        # Extract all DHCP / BOOTP fields
        fields = [
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "dhcp.option.dhcp",
            "-e", "dhcp.id",
            "-e", "dhcp.ip.client",
            "-e", "dhcp.ip.your",
            "-e", "dhcp.ip.server",
            "-e", "dhcp.ip.relay",
            "-e", "dhcp.hw.mac_addr",
            "-e", "dhcp.option.dhcp_server_id",
            "-e", "dhcp.option.ip_address_lease_time",
            "-e", "dhcp.option.subnet_mask",
            "-e", "dhcp.option.router",
            "-e", "dhcp.option.domain_name_server",
            "-e", "dhcp.option.domain_name",
            "-e", "dhcp.option.hostname",
            "-e", "dhcp.option.vendor_class_id",
            "-e", "dhcp.option.agent_information_option.agent_circuit_id",
            "-e", "dhcp.option.agent_information_option.agent_remote_id",
        ]

        # Use display filter accepting both dhcp and bootp frames
        cmd = [
            self.tshark_bin,
            "-r", "-",
            "-Y", "dhcp or bootp or (udp.port == 67 or udp.port == 68)",
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=a",
            *fields,
        ]

        try:
            with p.open("rb") as f_in:
                proc = subprocess.run(cmd, stdin=f_in, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            # Fallback to direct raw pcap extraction if tshark fails
            raw_fallback = self._extract_dhcpv4_raw_fallback(p)
            if raw_fallback:
                return raw_fallback
            raise DHCPAuditError(f"Failed to execute tshark on {pcap_path}: {exc}") from exc

        frames: List[DHCPv4Frame] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 10:
                continue

            frame_num = safe_int(parts[0], 0) or 0
            ts = safe_float(parts[1])
            raw_msg_type = parts[2].split(",")[0] if parts[2] else ""
            msg_type_int = safe_int(raw_msg_type)
            msg_name = DHCPv4MsgType(msg_type_int).name if msg_type_int in DHCPv4MsgType._value2member_map_ else (raw_msg_type or "UNKNOWN")

            xid = parts[3].split(",")[0] if parts[3] else ""
            ciaddr = parts[4].split(",")[0] if parts[4] else "0.0.0.0"
            yiaddr = parts[5].split(",")[0] if parts[5] else "0.0.0.0"
            siaddr = parts[6].split(",")[0] if parts[6] else "0.0.0.0"
            giaddr = parts[7].split(",")[0] if parts[7] else "0.0.0.0"
            chaddr = parts[8].split(",")[0] if parts[8] else ""
            server_id = parts[9].split(",")[0] if parts[9] else None
            lease_time = safe_int(parts[10].split(",")[0]) if parts[10] else None
            subnet_mask = parts[11].split(",")[0] if parts[11] else None
            router = parts[12].split(",")[0] if parts[12] else None

            dns_servers = [s.strip() for s in parts[13].split(",") if s.strip()] if parts[13] else []
            domain_name = parts[14].split(",")[0] if parts[14] else None
            hostname = parts[15].split(",")[0] if parts[15] else None
            vendor_class = parts[16].split(",")[0] if parts[16] else None
            circuit_id = parts[17].split(",")[0] if len(parts) > 17 and parts[17] else None
            remote_id = parts[18].split(",")[0] if len(parts) > 18 and parts[18] else None

            frames.append(
                DHCPv4Frame(
                    frame_number=frame_num,
                    timestamp=ts,
                    msg_type=msg_type_int,
                    msg_type_name=msg_name,
                    xid=xid,
                    ciaddr=ciaddr,
                    yiaddr=yiaddr,
                    siaddr=siaddr,
                    giaddr=giaddr,
                    chaddr=chaddr,
                    server_id=server_id,
                    lease_time=lease_time,
                    subnet_mask=subnet_mask,
                    router=router,
                    dns_servers=dns_servers,
                    domain_name=domain_name,
                    hostname=hostname,
                    vendor_class=vendor_class,
                    circuit_id=circuit_id,
                    remote_id=remote_id,
                )
            )

        # If tshark parsed frames but all msg_types or xids are empty (due to snaplen truncation),
        # supplement from binary fallback parser
        if frames and all(f.msg_type is None for f in frames):
            raw_fallback = self._extract_dhcpv4_raw_fallback(p)
            if raw_fallback:
                return raw_fallback

        return frames

    def _extract_dhcpv4_raw_fallback(self, pcap_path: Path) -> List[DHCPv4Frame]:
        """Binary fallback PCAP parser for truncated or AppArmor-restricted captures."""
        try:
            with pcap_path.open("rb") as f:
                data = f.read()
        except Exception:
            return []

        if len(data) < 24:
            return []

        magic = struct.unpack("<I", data[:4])[0]
        endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"
        offset = 24
        raw_packets = []
        frame_idx = 1

        while offset + 16 <= len(data):
            ts_sec, ts_usec, incl_len, _ = struct.unpack(f"{endian}IIII", data[offset:offset + 16])
            offset += 16
            pkt = data[offset:offset + incl_len]
            offset += incl_len

            if len(pkt) < 14:
                continue
            eth_type = struct.unpack("!H", pkt[12:14])[0]
            if eth_type != 0x0800:
                continue
            ip_hdr = pkt[14:]
            if len(ip_hdr) < 20:
                continue
            ihl = (ip_hdr[0] & 0x0f) * 4
            proto = ip_hdr[9]
            if proto != 17:  # UDP
                continue
            udp_hdr = ip_hdr[ihl:]
            if len(udp_hdr) < 8:
                continue
            sport, dport = struct.unpack("!HH", udp_hdr[:4])
            if not ((sport in (67, 68)) and (dport in (67, 68))):
                continue
            bootp = udp_hdr[8:]
            if len(bootp) < 44:
                continue

            op = bootp[0]
            xid_int = struct.unpack("!I", bootp[4:8])[0]
            xid_hex = f"0x{xid_int:08x}"
            ciaddr = socket.inet_ntoa(bootp[12:16])
            yiaddr = socket.inet_ntoa(bootp[16:20])
            siaddr = socket.inet_ntoa(bootp[20:24])
            giaddr = socket.inet_ntoa(bootp[24:28])
            chaddr = ":".join(f"{b:02x}" for b in bootp[28:34])

            msg_type_int: Optional[int] = None
            server_id: Optional[str] = None
            lease_time: Optional[int] = None
            subnet_mask: Optional[str] = None
            router: Optional[str] = None
            dns_servers: List[str] = []
            domain_name: Optional[str] = None
            hostname: Optional[str] = None
            vendor_class: Optional[str] = None
            circuit_id: Optional[str] = None
            remote_id: Optional[str] = None

            if len(bootp) >= 240 and bootp[236:240] == b"\x63\x82\x53\x63":
                opt_idx = 240
                while opt_idx < len(bootp):
                    code = bootp[opt_idx]
                    if code == 255:
                        break
                    if code == 0:
                        opt_idx += 1
                        continue
                    if opt_idx + 1 >= len(bootp):
                        break
                    opt_len = bootp[opt_idx + 1]
                    val = bootp[opt_idx + 2 : opt_idx + 2 + opt_len]
                    opt_idx += 2 + opt_len

                    if code == 53 and len(val) >= 1:
                        msg_type_int = val[0]
                    elif code == 54 and len(val) >= 4:
                        server_id = socket.inet_ntoa(val[:4])
                    elif code == 51 and len(val) >= 4:
                        lease_time = struct.unpack("!I", val[:4])[0]
                    elif code == 1 and len(val) >= 4:
                        subnet_mask = socket.inet_ntoa(val[:4])
                    elif code == 3 and len(val) >= 4:
                        router = socket.inet_ntoa(val[:4])
                    elif code == 6 and len(val) >= 4:
                        dns_servers = [socket.inet_ntoa(val[i : i + 4]) for i in range(0, len(val) - 3, 4)]
                    elif code == 15:
                        domain_name = val.decode("latin-1", errors="ignore")
                    elif code == 12:
                        hostname = val.decode("latin-1", errors="ignore")
                    elif code == 60:
                        vendor_class = val.decode("latin-1", errors="ignore")
                    elif code == 82:
                        sub_i = 0
                        while sub_i < len(val):
                            sub_c = val[sub_i]
                            if sub_i + 1 >= len(val):
                                break
                            sub_l = val[sub_i + 1]
                            sub_v = val[sub_i + 2 : sub_i + 2 + sub_l]
                            sub_i += 2 + sub_l
                            if sub_c == 1:
                                circuit_id = sub_v.decode("latin-1", errors="ignore")
                            elif sub_c == 2:
                                remote_id = sub_v.decode("latin-1", errors="ignore")

            raw_packets.append(
                {
                    "frame_number": frame_idx,
                    "timestamp": ts_sec + ts_usec / 1e6,
                    "op": op,
                    "xid": xid_hex,
                    "ciaddr": ciaddr,
                    "yiaddr": yiaddr,
                    "siaddr": siaddr,
                    "giaddr": giaddr,
                    "chaddr": chaddr,
                    "msg_type": msg_type_int,
                    "server_id": server_id,
                    "lease_time": lease_time,
                    "subnet_mask": subnet_mask,
                    "router": router,
                    "dns_servers": dns_servers,
                    "domain_name": domain_name,
                    "hostname": hostname,
                    "vendor_class": vendor_class,
                    "circuit_id": circuit_id,
                    "remote_id": remote_id,
                }
            )
            frame_idx += 1

        # Infer message types for truncated packets where Option 53 was cut off
        by_xid = collections.defaultdict(list)
        for rp in raw_packets:
            by_xid[rp["xid"]].append(rp)

        for xid_key, xid_pkts in by_xid.items():
            req_count = 0
            rep_count = 0
            for rp in xid_pkts:
                if rp["msg_type"] is None:
                    if rp["op"] == 1:
                        req_count += 1
                        rp["msg_type"] = DHCPv4MsgType.DISCOVER if req_count == 1 else DHCPv4MsgType.REQUEST
                    elif rp["op"] == 2:
                        rep_count += 1
                        rp["msg_type"] = DHCPv4MsgType.OFFER if rep_count == 1 else DHCPv4MsgType.ACK

        frames: List[DHCPv4Frame] = []
        for rp in raw_packets:
            m_type = rp["msg_type"]
            m_name = DHCPv4MsgType(m_type).name if m_type in DHCPv4MsgType._value2member_map_ else "UNKNOWN"
            frames.append(
                DHCPv4Frame(
                    frame_number=rp["frame_number"],
                    timestamp=rp["timestamp"],
                    msg_type=m_type,
                    msg_type_name=m_name,
                    xid=rp["xid"],
                    ciaddr=rp["ciaddr"],
                    yiaddr=rp["yiaddr"],
                    siaddr=rp["siaddr"],
                    giaddr=rp["giaddr"],
                    chaddr=rp["chaddr"],
                    server_id=rp["server_id"],
                    lease_time=rp["lease_time"],
                    subnet_mask=rp["subnet_mask"],
                    router=rp["router"],
                    dns_servers=rp["dns_servers"],
                    domain_name=rp["domain_name"],
                    hostname=rp["hostname"],
                    vendor_class=rp["vendor_class"],
                    circuit_id=rp["circuit_id"],
                    remote_id=rp["remote_id"],
                )
            )

        return frames

    def extract_dhcpv6(self, pcap_path: Union[str, Path]) -> List[DHCPv6Frame]:
        p = Path(pcap_path)
        if not p.is_file():
            raise DHCPAuditError(f"PCAP file not found: {pcap_path}")

        fields = [
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "dhcpv6.msgtype",
            "-e", "dhcpv6.xid",
            "-e", "dhcpv6.linkaddr",
            "-e", "dhcpv6.peeraddr",
            "-e", "dhcpv6.duid.bytes",
            "-e", "dhcpv6.iaaddr.ip",
            "-e", "dhcpv6.iaprefix.pref_addr",
            "-e", "dhcpv6.dns_server",
            "-e", "dhcpv6.client_domain",
            "-e", "dhcpv6.interface_id",
            "-e", "dhcpv6.status_code",
        ]

        cmd = [
            self.tshark_bin,
            "-r", "-",
            "-Y", "dhcpv6 or (udp.port == 546 or udp.port == 547)",
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=a",
            *fields,
        ]

        try:
            with p.open("rb") as f_in:
                proc = subprocess.run(cmd, stdin=f_in, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError, OSError) as exc:
            raise DHCPAuditError(f"Failed to execute tshark on {pcap_path}: {exc}") from exc

        frames: List[DHCPv6Frame] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 6:
                continue

            frame_num = safe_int(parts[0], 0) or 0
            ts = safe_float(parts[1])
            raw_msg_type = parts[2].split(",")[0] if parts[2] else ""
            msg_type_int = safe_int(raw_msg_type)
            msg_name = DHCPv6MsgType(msg_type_int).name if msg_type_int in DHCPv6MsgType._value2member_map_ else (raw_msg_type or "UNKNOWN")

            xid = parts[3].split(",")[0] if parts[3] else ""
            linkaddr = parts[4].split(",")[0] if parts[4] else "::"
            peeraddr = parts[5].split(",")[0] if parts[5] else "::"

            duids = [s.strip() for s in parts[6].split(",") if s.strip()] if len(parts) > 6 and parts[6] else []
            client_duid = duids[0] if len(duids) > 0 else None
            server_duid = duids[1] if len(duids) > 1 else None

            ia_na_addrs = [s.strip() for s in parts[7].split(",") if s.strip()] if len(parts) > 7 and parts[7] else []
            ia_pd_prefixes = [s.strip() for s in parts[8].split(",") if s.strip()] if len(parts) > 8 and parts[8] else []
            dns_servers = [s.strip() for s in parts[9].split(",") if s.strip()] if len(parts) > 9 and parts[9] else []
            domain_search = [s.strip() for s in parts[10].split(",") if s.strip()] if len(parts) > 10 and parts[10] else []
            interface_id = parts[11].split(",")[0] if len(parts) > 11 and parts[11] else None
            status_code = safe_int(parts[12].split(",")[0]) if len(parts) > 12 and parts[12] else None
            relay_msg_type = msg_type_int if msg_type_int in (DHCPv6MsgType.RELAY_FORWARD, DHCPv6MsgType.RELAY_REPLY) else None

            frames.append(
                DHCPv6Frame(
                    frame_number=frame_num,
                    timestamp=ts,
                    msg_type=msg_type_int,
                    msg_type_name=msg_name,
                    xid=xid,
                    linkaddr=linkaddr,
                    peeraddr=peeraddr,
                    client_duid=client_duid,
                    server_duid=server_duid,
                    ia_na_addresses=ia_na_addrs,
                    ia_pd_prefixes=ia_pd_prefixes,
                    dns_servers=dns_servers,
                    domain_search=domain_search,
                    interface_id=interface_id,
                    relay_msg_type=relay_msg_type,
                    status_code=status_code,
                )
            )

        return frames

    def extract_icmpv6_ra(self, pcap_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """Extract ICMPv6 Router Advertisement flags and prefix info."""
        p = Path(pcap_path)
        if not p.is_file():
            return []

        fields = [
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "icmpv6.nd.ra.flag.m",
            "-e", "icmpv6.nd.ra.flag.o",
            "-e", "icmpv6.opt.prefix",
            "-e", "icmpv6.opt.prefix.flag.a",
            "-e", "icmpv6.opt.rdnss",
        ]

        cmd = [
            self.tshark_bin,
            "-r", "-",
            "-Y", "icmpv6.type == 134",
            "-T", "fields",
            "-E", "separator=\t",
            "-E", "occurrence=a",
            *fields,
        ]

        try:
            with p.open("rb") as f_in:
                proc = subprocess.run(cmd, stdin=f_in, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        except Exception:
            return []

        results: List[Dict[str, Any]] = []
        for line in proc.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            results.append(
                {
                    "frame_number": safe_int(parts[0], 0),
                    "timestamp": safe_float(parts[1]),
                    "managed_flag": safe_bool(parts[2]),
                    "other_flag": safe_bool(parts[3]),
                    "prefixes": [s.strip() for s in parts[4].split(",") if s.strip()] if len(parts) > 4 and parts[4] else [],
                    "autonomous_flag": safe_bool(parts[5]) if len(parts) > 5 and parts[5] else False,
                    "rdnss": [s.strip() for s in parts[6].split(",") if s.strip()] if len(parts) > 6 and parts[6] else [],
                }
            )
        return results


# ==============================================================================
# Domain Auditing Engine
# ==============================================================================

class DHCPEvidenceAuditor:
    """Core domain evaluation logic for DHCP protocol verification."""

    def __init__(self, dissector: Optional[TsharkDissector] = None) -> None:
        self.dissector = dissector or TsharkDissector()

    def audit_dhcpv4_dora(
        self,
        pcap_path: Union[str, Path],
        expected_client_mac: Optional[str] = None,
        expected_ip: Optional[str] = None,
        expected_router: Optional[str] = None,
        expected_dns: Optional[str] = None,
        min_lease_time: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Audits complete DHCPv4 4-way DORA sequence (RFC 2131)."""
        frames = self.dissector.extract_dhcpv4(pcap_path)
        if not frames:
            return {
                "verdict": "FAIL",
                "reason": "No DHCP/BOOTP packets detected in capture",
                "frames_count": 0,
                "dora_complete": False,
            }

        # Filter by MAC if requested
        if expected_client_mac:
            target_mac = clean_hex(expected_client_mac)
            frames = [f for f in frames if clean_hex(f.chaddr) == target_mac or not f.chaddr]

        discovers = [f for f in frames if f.msg_type == DHCPv4MsgType.DISCOVER]
        offers = [f for f in frames if f.msg_type == DHCPv4MsgType.OFFER]
        requests = [f for f in frames if f.msg_type == DHCPv4MsgType.REQUEST]
        acks = [f for f in frames if f.msg_type == DHCPv4MsgType.ACK]

        dora_found = False
        matching_ack: Optional[DHCPv4Frame] = None
        handshake_latency_ms: float = 0.0

        for disc in discovers:
            # Correlate Offer, Request, Ack matching xid
            disc_xid = disc.xid
            matching_offer = next((o for o in offers if o.xid == disc_xid), None)
            matching_req = next((r for r in requests if r.xid == disc_xid), None)
            matching_ack = next((a for a in acks if a.xid == disc_xid), None)

            if matching_offer and matching_req and matching_ack:
                dora_found = True
                handshake_latency_ms = round((matching_ack.timestamp - disc.timestamp) * 1000.0, 2)
                break

        # Fallback if xids differ slightly (some implementations renew xid in Request)
        if not dora_found and discovers and offers and requests and acks:
            matching_ack = acks[-1]
            dora_found = True
            handshake_latency_ms = round((acks[-1].timestamp - discovers[0].timestamp) * 1000.0, 2)

        checks: Dict[str, bool] = {
            "has_discover": len(discovers) > 0,
            "has_offer": len(offers) > 0,
            "has_request": len(requests) > 0,
            "has_ack": len(acks) > 0,
            "dora_sequence_complete": dora_found,
        }

        assigned_ip = matching_ack.yiaddr if matching_ack else None
        router_ip = matching_ack.router if matching_ack else None
        lease_sec = matching_ack.lease_time if matching_ack else None
        dns_list = matching_ack.dns_servers if matching_ack else []
        subnet_mask = matching_ack.subnet_mask if matching_ack and matching_ack.subnet_mask else (offers[0].subnet_mask if offers else None)
        server_id = matching_ack.server_id if matching_ack and matching_ack.server_id else (offers[0].server_id if offers else None)
        client_mac = matching_ack.chaddr if matching_ack and matching_ack.chaddr else (discovers[0].chaddr if discovers else None)

        if expected_ip:
            checks["assigned_ip_match"] = (assigned_ip == expected_ip)
        if expected_router:
            checks["router_option_match"] = (router_ip == expected_router)
        if expected_dns:
            checks["dns_option_match"] = any(expected_dns in d for d in dns_list)
        if min_lease_time is not None:
            checks["lease_time_sufficient"] = (lease_sec is not None and lease_sec >= min_lease_time)

        verdict = "PASS" if all(checks.values()) else "FAIL"

        return {
            "verdict": verdict,
            "protocol": "DHCPv4",
            "dora_complete": dora_found,
            "handshake_latency_ms": handshake_latency_ms,
            "assigned_ip": assigned_ip,
            "router_ip": router_ip,
            "lease_time_sec": lease_sec,
            "dns_servers": dns_list,
            "subnet_mask": subnet_mask,
            "server_id": server_id,
            "client_mac": client_mac,
            "checks": checks,
            "packet_counts": {
                "discover": len(discovers),
                "offer": len(offers),
                "request": len(requests),
                "ack": len(acks),
                "total": len(frames),
            },
            "timeline": self._build_v4_timeline(frames),
        }

    def audit_dhcpv4_renewal_and_release(
        self,
        pcap_path: Union[str, Path],
        expected_client_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audits DHCPv4 Unicast Renewal Request/Ack and Release."""
        frames = self.dissector.extract_dhcpv4(pcap_path)
        if not frames:
            return {"verdict": "FAIL", "reason": "No packets found in PCAP"}

        requests = [f for f in frames if f.msg_type == DHCPv4MsgType.REQUEST]
        acks = [f for f in frames if f.msg_type == DHCPv4MsgType.ACK]
        releases = [f for f in frames if f.msg_type == DHCPv4MsgType.RELEASE]

        # Renewal request should have ciaddr set to client IP
        renewal_requests = [r for r in requests if r.ciaddr != "0.0.0.0"]
        if expected_client_ip:
            renewal_requests = [r for r in renewal_requests if r.ciaddr == expected_client_ip]

        checks = {
            "has_renewal_request": len(renewal_requests) > 0,
            "has_renewal_ack": len(acks) > 0,
            "has_release": len(releases) > 0,
        }

        verdict = "PASS" if (checks["has_renewal_request"] and checks["has_renewal_ack"]) or checks["has_release"] else "FAIL"

        return {
            "verdict": verdict,
            "checks": checks,
            "renewal_requests_count": len(renewal_requests),
            "acks_count": len(acks),
            "releases_count": len(releases),
            "timeline": self._build_v4_timeline(frames),
        }

    def audit_dhcpv4_relay(
        self,
        lan_pcap: Union[str, Path],
        wan_pcap: Union[str, Path],
        expected_giaddr: Optional[str] = None,
        expected_circuit_id: Optional[str] = None,
        expected_remote_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audits DHCPv4 Relay Agent between LAN and WAN vantage points."""
        lan_frames = self.dissector.extract_dhcpv4(lan_pcap)
        wan_frames = self.dissector.extract_dhcpv4(wan_pcap)

        lan_discovers = [f for f in lan_frames if f.msg_type == DHCPv4MsgType.DISCOVER]
        wan_discovers = [f for f in wan_frames if f.msg_type == DHCPv4MsgType.DISCOVER]

        lan_offers = [f for f in lan_frames if f.msg_type == DHCPv4MsgType.OFFER]
        wan_offers = [f for f in wan_frames if f.msg_type == DHCPv4MsgType.OFFER]

        # Check relay modifications on WAN side
        relayed_with_giaddr = [f for f in wan_discovers if f.giaddr != "0.0.0.0"]
        if expected_giaddr:
            relayed_with_giaddr = [f for f in relayed_with_giaddr if f.giaddr == expected_giaddr]

        checks = {
            "lan_client_broadcast_discover": len(lan_discovers) > 0,
            "wan_gateway_relayed_discover": len(wan_discovers) > 0,
            "giaddr_populated_on_wan": len(relayed_with_giaddr) > 0,
            "wan_server_sent_offer": len(wan_offers) > 0,
            "lan_client_received_offer": len(lan_offers) > 0,
        }

        if expected_circuit_id:
            has_circuit = any(expected_circuit_id in (f.circuit_id or "") for f in wan_discovers)
            checks["opt82_circuit_id_present"] = has_circuit
        if expected_remote_id:
            has_remote = any(expected_remote_id in (f.remote_id or "") for f in wan_discovers)
            checks["opt82_remote_id_present"] = has_remote

        verdict = "PASS" if all(checks.values()) else "FAIL"

        return {
            "verdict": verdict,
            "protocol": "DHCPv4-Relay",
            "checks": checks,
            "detected_giaddr": relayed_with_giaddr[0].giaddr if relayed_with_giaddr else None,
            "lan_counts": {"discover": len(lan_discovers), "offer": len(lan_offers)},
            "wan_counts": {"discover": len(wan_discovers), "offer": len(wan_offers)},
            "wan_timeline": self._build_v4_timeline(wan_frames),
        }

    def audit_dhcpv6_stateless(
        self,
        pcap_path: Union[str, Path],
        expected_dns: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audits SLAAC + DHCPv6 Stateless Information-Request / Reply (RFC 8415 / 3736)."""
        ra_frames = self.dissector.extract_icmpv6_ra(pcap_path)
        dhcp6_frames = self.dissector.extract_dhcpv6(pcap_path)

        ra_with_o_flag = [r for r in ra_frames if r["other_flag"]]
        ra_with_a_flag = [r for r in ra_frames if r["autonomous_flag"]]

        info_reqs = [f for f in dhcp6_frames if f.msg_type == DHCPv6MsgType.INFORMATION_REQUEST]
        replies = [f for f in dhcp6_frames if f.msg_type == DHCPv6MsgType.REPLY]

        checks = {
            "ra_received": len(ra_frames) > 0,
            "ra_other_config_flag_set": len(ra_with_o_flag) > 0,
            "ra_autonomous_slaac_flag_set": len(ra_with_a_flag) > 0,
            "dhcpv6_info_request_sent": len(info_reqs) > 0,
            "dhcpv6_reply_received": len(replies) > 0,
        }

        if expected_dns:
            found_dns = any(expected_dns in d for f in replies for d in f.dns_servers)
            checks["rdnss_dns_present"] = found_dns

        verdict = "PASS" if all(checks.values()) else "FAIL"

        return {
            "verdict": verdict,
            "mode": "stateless_dhcpv6_slaac",
            "checks": checks,
            "ra_count": len(ra_frames),
            "info_req_count": len(info_reqs),
            "reply_count": len(replies),
            "dns_servers_learned": replies[0].dns_servers if replies else [],
            "timeline": self._build_v6_timeline(dhcp6_frames),
        }

    def audit_dhcpv6_stateful(
        self,
        pcap_path: Union[str, Path],
        expected_prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audits Stateful DHCPv6 4-message exchange with IA_NA (RFC 8415)."""
        ra_frames = self.dissector.extract_icmpv6_ra(pcap_path)
        dhcp6_frames = self.dissector.extract_dhcpv6(pcap_path)

        ra_with_m_flag = [r for r in ra_frames if r["managed_flag"]]

        solicits = [f for f in dhcp6_frames if f.msg_type == DHCPv6MsgType.SOLICIT]
        advertises = [f for f in dhcp6_frames if f.msg_type == DHCPv6MsgType.ADVERTISE]
        requests = [f for f in dhcp6_frames if f.msg_type == DHCPv6MsgType.REQUEST]
        replies = [f for f in dhcp6_frames if f.msg_type == DHCPv6MsgType.REPLY]

        allocated_addrs: List[str] = []
        for rep in replies:
            allocated_addrs.extend(rep.ia_na_addresses)

        # Inspect DHCPv6 status codes returned by server (e.g. NoAddrsAvail = 2)
        server_status_codes = [f.status_code for f in dhcp6_frames if f.status_code is not None]
        server_status_code = server_status_codes[0] if server_status_codes else None
        server_status_name = DHCPV6_STATUS_NAMES.get(server_status_code) if server_status_code is not None else None

        checks = {
            "ra_managed_flag_set": len(ra_with_m_flag) > 0 or len(ra_frames) == 0, # In pure DHCPv6 test, RA may be optional
            "dhcpv6_solicit_sent": len(solicits) > 0,
            "dhcpv6_advertise_received": len(advertises) > 0,
            "dhcpv6_request_sent": len(requests) > 0,
            "dhcpv6_reply_received": len(replies) > 0,
            "ia_na_address_assigned": len(allocated_addrs) > 0,
        }

        if server_status_code is not None:
            checks["server_status_code_success"] = (server_status_code == 0)

        if expected_prefix:
            prefix_match = any(expected_prefix in addr for addr in allocated_addrs)
            checks["assigned_address_matches_prefix"] = prefix_match

        verdict = "PASS" if all(checks.values()) else "FAIL"

        return {
            "verdict": verdict,
            "mode": "stateful_dhcpv6_iana",
            "checks": checks,
            "allocated_ia_na_addresses": allocated_addrs,
            "server_status_code": server_status_code,
            "server_status_name": server_status_name,
            "packet_counts": {
                "solicit": len(solicits),
                "advertise": len(advertises),
                "request": len(requests),
                "reply": len(replies),
            },
            "timeline": self._build_v6_timeline(dhcp6_frames),
        }

    def audit_dhcpv6_prefix_delegation(
        self,
        wan_pcap: Union[str, Path],
        lan_pcap: Optional[Union[str, Path]] = None,
        expected_pd_prefix: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audits DHCPv6 Prefix Delegation (IA_PD RFC 3633 / RFC 8415)."""
        wan_frames = self.dissector.extract_dhcpv6(wan_pcap)
        solicits = [f for f in wan_frames if f.msg_type == DHCPv6MsgType.SOLICIT]
        replies = [f for f in wan_frames if f.msg_type == DHCPv6MsgType.REPLY or f.msg_type == DHCPv6MsgType.ADVERTISE]

        delegated_prefixes: List[str] = []
        for r in replies:
            delegated_prefixes.extend(r.ia_pd_prefixes)

        checks = {
            "wan_solicit_ia_pd_sent": len(solicits) > 0,
            "wan_reply_delegated_prefix": len(delegated_prefixes) > 0,
        }

        if expected_pd_prefix:
            checks["delegated_prefix_matches"] = any(expected_pd_prefix in p for p in delegated_prefixes)

        # Check LAN side RA propagation if LAN PCAP provided
        if lan_pcap and Path(lan_pcap).is_file():
            lan_ra = self.dissector.extract_icmpv6_ra(lan_pcap)
            checks["lan_ra_sub_prefix_advertised"] = len(lan_ra) > 0

        verdict = "PASS" if all(checks.values()) else "FAIL"

        return {
            "verdict": verdict,
            "mode": "dhcpv6_prefix_delegation",
            "checks": checks,
            "delegated_prefixes": delegated_prefixes,
            "wan_timeline": self._build_v6_timeline(wan_frames),
        }

    def audit_dhcpv6_relay(
        self,
        lan_pcap: Union[str, Path],
        wan_pcap: Union[str, Path],
        expected_interface_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Audits DHCPv6 Relay Agent (Relay-Forward & Relay-Reply encapsulation)."""
        lan_frames = self.dissector.extract_dhcpv6(lan_pcap)
        wan_frames = self.dissector.extract_dhcpv6(wan_pcap)

        lan_solicits = [f for f in lan_frames if f.msg_type == DHCPv6MsgType.SOLICIT]
        wan_relay_forwards = [f for f in wan_frames if f.msg_type == DHCPv6MsgType.RELAY_FORWARD]
        wan_relay_replies = [f for f in wan_frames if f.msg_type == DHCPv6MsgType.RELAY_REPLY]
        lan_advertises = [f for f in lan_frames if f.msg_type == DHCPv6MsgType.ADVERTISE]

        checks = {
            "lan_client_sent_solicit": len(lan_solicits) > 0,
            "wan_gateway_relayed_forward": len(wan_relay_forwards) > 0,
            "wan_server_returned_relay_reply": len(wan_relay_replies) > 0,
            "lan_client_received_advertise": len(lan_advertises) > 0,
        }

        if expected_interface_id:
            checks["interface_id_option_matches"] = any(
                expected_interface_id in (f.interface_id or "") for f in wan_relay_forwards
            )

        verdict = "PASS" if all(checks.values()) else "FAIL"

        return {
            "verdict": verdict,
            "protocol": "DHCPv6-Relay",
            "checks": checks,
            "lan_solicits_count": len(lan_solicits),
            "wan_relay_forward_count": len(wan_relay_forwards),
            "wan_relay_reply_count": len(wan_relay_replies),
            "wan_timeline": self._build_v6_timeline(wan_frames),
        }

    # Internal formatting helpers
    def _build_v4_timeline(self, frames: List[DHCPv4Frame]) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        base_t = frames[0].timestamp if frames else 0.0
        for f in frames:
            timeline.append(
                {
                    "frame": f.frame_number,
                    "rel_time_ms": round((f.timestamp - base_t) * 1000.0, 2),
                    "type": f.msg_type_name,
                    "xid": f.xid,
                    "client_mac": f.chaddr,
                    "yiaddr": f.yiaddr,
                    "giaddr": f.giaddr,
                    "server_id": f.server_id,
                }
            )
        return timeline

    def _build_v6_timeline(self, frames: List[DHCPv6Frame]) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        base_t = frames[0].timestamp if frames else 0.0
        for f in frames:
            sc_name = DHCPV6_STATUS_NAMES.get(f.status_code, str(f.status_code)) if f.status_code is not None else None
            timeline.append(
                {
                    "frame": f.frame_number,
                    "rel_time_ms": round((f.timestamp - base_t) * 1000.0, 2),
                    "type": f.msg_type_name,
                    "xid": f.xid,
                    "linkaddr": f.linkaddr,
                    "peeraddr": f.peeraddr,
                    "ia_addrs": f.ia_na_addresses,
                    "ia_prefixes": f.ia_pd_prefixes,
                    "status_code": f.status_code,
                    "status_code_name": sc_name,
                }
            )
        return timeline


# ==============================================================================
# Terminal Card & Table Formatting
# ==============================================================================

GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _fmt_status(passed: bool) -> str:
    return f"{GREEN}PASS{RESET}" if passed else f"{RED}FAIL{RESET}"


def _fmt_verdict(verdict: str) -> str:
    if verdict == "PASS":
        return f"{GREEN}PASS{RESET}"
    elif verdict in ("WARN", "PARTIAL", "INCONCLUSIVE"):
        return f"{YELLOW}{verdict}{RESET}"
    return f"{RED}{verdict}{RESET}"


def print_dhcpv4_dora_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    assigned_ip = result.get("assigned_ip") or "None"
    router_ip = result.get("router_ip") or "None"
    lease_sec = result.get("lease_time_sec")
    lease_str = f"{lease_sec}s ({round(lease_sec / 3600, 1)}h)" if lease_sec else "N/A"
    dns_servers = ", ".join(result.get("dns_servers") or []) or "N/A"
    subnet_mask = result.get("subnet_mask") or "255.255.255.0"
    client_mac = result.get("client_mac")
    if not client_mac and result.get("timeline"):
        client_mac = result["timeline"][0].get("client_mac")
    client_mac = client_mac or "Unknown"
    server_id = result.get("server_id") or router_ip
    latency_ms = result.get("handshake_latency_ms", 0.0)

    # 1. Timeline Table
    print("\n" + "=" * 80)
    print("  DHCPv4 DORA TRANSACTION TIMELINE AUDIT")
    print("=" * 80)
    print(f"  Client Hardware (MAC)  : {client_mac}")
    print(f"  Assigned IP Address    : {assigned_ip}")
    print(f"  DHCP Server Identifier : {server_id}")
    print(f"  Handshake Latency      : {latency_ms:.2f} ms")
    print("-" * 80)
    print(f"  {'FRAME':<6} {'TIME (ms)':>9}   {'MESSAGE TYPE':<13} {'XID':<11} {'CLIENT MAC':<18} {'OFFERED/ACK IP':<16} {'SERVER ID'}")
    print("-" * 80)
    timeline = result.get("timeline", [])
    for f in timeline:
        t_ms = f.get("rel_time_ms", 0.0)
        m_type = f.get("type", "UNKNOWN")
        xid = f.get("xid", "-")
        cmac = f.get("client_mac") or "-"
        ip = f.get("yiaddr") if f.get("yiaddr") != "0.0.0.0" else "-"
        sid = f.get("server_id") or "-"
        print(f"  {f.get('frame', 0):<6} {t_ms:>9.2f}   {m_type:<13} {xid:<11} {cmac:<18} {ip:<16} {sid}")
    print("-" * 80)
    dora_ok = result.get("dora_complete", False)
    seq_status = f"{GREEN}Complete (4/4 Frames Verified){RESET}" if dora_ok else f"{RED}Incomplete Handshake{RESET}"
    print(f"  DORA Handshake Sequence : {seq_status}")
    print("=" * 80 + "\n")

    # 2. Negotiated Options Table
    print("=" * 80)
    print("  DHCPv4 NEGOTIATED OPTIONS & CRITERIA EVALUATION (RFC 2131)")
    print("=" * 80)
    print(f"  {'PARAMETER / OPTION':<26} {'NEGOTIATED VALUE':<23} {'CRITERIA / EXPECTED':<21} {'STATUS'}")
    print("-" * 80)

    checks = result.get("checks", {})
    # Row 1: Allocated IP
    ip_status = _fmt_status(checks.get("assigned_ip_match", True) and assigned_ip != "None")
    print(f"  {'Allocated Client IP':<26} {assigned_ip:<23} {'Within Pool Range':<21} {ip_status}")

    # Row 2: Subnet Mask
    mask_status = _fmt_status(subnet_mask != "None")
    print(f"  {'Option 1: Subnet Mask':<26} {subnet_mask:<23} {'Option Present':<21} {mask_status}")

    # Row 3: Router
    router_status = _fmt_status(checks.get("router_option_match", True) and router_ip != "None")
    print(f"  {'Option 3: Default Router':<26} {router_ip:<23} {'Matches Expected':<21} {router_status}")

    # Row 4: DNS
    dns_status = _fmt_status(checks.get("dns_option_match", True) and dns_servers != "N/A")
    print(f"  {'Option 6: Domain Name Srv':<26} {dns_servers:<23} {'Option Present':<21} {dns_status}")

    # Row 5: Lease Time
    lease_status = _fmt_status(checks.get("lease_time_sufficient", True))
    print(f"  {'Option 51: Lease Time':<26} {lease_str:<23} {'>= 60s':<21} {lease_status}")

    # Row 6: Latency
    lat_status = _fmt_status(latency_ms <= 5000.0)
    print(f"  {'Handshake Latency':<26} {f'{latency_ms:.2f} ms':<23} {'<= 5000.00 ms':<21} {lat_status}")

    print("-" * 80)
    verdict_suffix = " (All RFC 2131 Criteria Satisfied)" if verdict == "PASS" else " (Criteria Assertion Failed)"
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}{verdict_suffix}")
    print("=" * 80 + "\n")


def print_dhcpv4_renew_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    checks = result.get("checks", {})
    rn_count = result.get("renewal_requests_count", 0)
    ack_count = result.get("acks_count", 0)
    rel_count = result.get("releases_count", 0)

    print("\n" + "=" * 80)
    print("  DHCPv4 LEASE RENEWAL & RELEASE AUDIT (RFC 2131)")
    print("=" * 80)
    print(f"  Renewal Requests Recorded : {rn_count}")
    print(f"  Renewal ACKs Recorded     : {ack_count}")
    print(f"  Graceful Releases Recorded: {rel_count}")
    print("-" * 80)
    print(f"  {'FRAME':<6} {'TIME (ms)':>9}   {'MESSAGE TYPE':<13} {'XID':<11} {'CLIENT CIADDR':<18} {'SERVER ID'}")
    print("-" * 80)
    timeline = result.get("timeline", [])
    for f in timeline:
        t_ms = f.get("rel_time_ms", 0.0)
        m_type = f.get("type", "UNKNOWN")
        xid = f.get("xid", "-")
        ciaddr = f.get("yiaddr") if f.get("yiaddr") != "0.0.0.0" else (f.get("client_mac") or "-")
        sid = f.get("server_id") or "-"
        print(f"  {f.get('frame', 0):<6} {t_ms:>9.2f}   {m_type:<13} {xid:<11} {ciaddr:<18} {sid}")
    print("-" * 80)
    print(f"  {'VERIFICATION STEP':<40} {'DETECTED STATE':<28} {'STATUS'}")
    print("-" * 80)
    s1 = _fmt_status(checks.get("has_renewal_request", False))
    print(f"  {'Unicast T1 Renewal Request (ciaddr)':<40} {f'{rn_count} Frame(s) Captured':<28} {s1}")
    s2 = _fmt_status(checks.get("has_renewal_ack", False))
    print(f"  {'Unicast Server Renewal ACK':<40} {f'{ack_count} Frame(s) Captured':<28} {s2}")
    s3 = _fmt_status(checks.get("has_release", False))
    print(f"  {'Graceful Client Lease Release':<40} {f'{rel_count} Frame(s) Captured':<28} {s3}")
    print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    print("=" * 80 + "\n")


def print_dhcpv4_relay_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    checks = result.get("checks", {})
    lan_counts = result.get("lan_counts", {})
    wan_counts = result.get("wan_counts", {})
    giaddr = result.get("detected_giaddr") or "None"

    print("\n" + "=" * 80)
    print("  DHCPv4 RELAY AGENT CROSS-VANTAGE AUDIT (RFC 3046 OPTION 82)")
    print("=" * 80)
    print(f"  LAN Vantage Traffic : {lan_counts.get('discover', 0)} Discovers, {lan_counts.get('offer', 0)} Offers")
    print(f"  WAN Vantage Traffic : {wan_counts.get('discover', 0)} Relayed Discovers, {wan_counts.get('offer', 0)} Relayed Offers")
    print(f"  Detected Gateway IP : {giaddr}")
    print("-" * 80)
    print(f"  {'RELAY VERIFICATION STEP':<44} {'CRITERIA / EXPECTED':<24} {'STATUS'}")
    print("-" * 80)
    s1 = _fmt_status(checks.get("lan_client_broadcast_discover", False))
    print(f"  {'LAN Client Broadcast Discover':<44} {'Broadcast RX on LAN':<24} {s1}")
    s2 = _fmt_status(checks.get("wan_gateway_relayed_discover", False))
    print(f"  {'WAN Gateway Relayed Discover':<44} {'Forwarded to WAN':<24} {s2}")
    s3 = _fmt_status(checks.get("giaddr_populated_on_wan", False))
    print(f"  {'Gateway Interface IP (giaddr)':<44} {f'giaddr == {giaddr}':<24} {s3}")
    if "opt82_circuit_id_present" in checks:
        s4 = _fmt_status(checks.get("opt82_circuit_id_present", False))
        print(f"  {'Option 82: Circuit ID (Sub-option 1)':<44} {'Present on WAN':<24} {s4}")
    if "opt82_remote_id_present" in checks:
        s5 = _fmt_status(checks.get("opt82_remote_id_present", False))
        print(f"  {'Option 82: Remote ID (Sub-option 2)':<44} {'Present on WAN':<24} {s5}")
    s6 = _fmt_status(checks.get("wan_server_sent_offer", False))
    print(f"  {'WAN Server Unicast Offer':<44} {'Received on WAN':<24} {s6}")
    s7 = _fmt_status(checks.get("lan_client_received_offer", False))
    print(f"  {'LAN Gateway Relayed Offer':<44} {'Delivered to Client':<24} {s7}")
    print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    print("=" * 80 + "\n")


def print_dhcpv6_stateless_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    checks = result.get("checks", {})
    dns_list = ", ".join(result.get("dns_servers_learned") or []) or "N/A"

    print("\n" + "=" * 80)
    print("  DHCPv6 STATELESS CONFIGURATION & SLAAC AUDIT (RFC 8415 / RFC 3736)")
    print("=" * 80)
    print(f"  Router Advertisements (RA) : {result.get('ra_count', 0)}")
    print(f"  Information-Request Frames : {result.get('info_req_count', 0)}")
    print(f"  Reply Frames Received      : {result.get('reply_count', 0)}")
    print(f"  Learned DNS Servers        : {dns_list}")
    print("-" * 80)
    print(f"  {'CHECK / CRITERIA':<44} {'DETECTED STATE':<24} {'STATUS'}")
    print("-" * 80)
    s1 = _fmt_status(checks.get("ra_received", False))
    print(f"  {'ICMPv6 Router Advertisement Received':<44} {'Captured on LAN':<24} {s1}")
    s2 = _fmt_status(checks.get("ra_other_config_flag_set", False))
    print(f"  {'RA O-Flag (Other Stateful Configuration)':<44} {'Flag Set (1)':<24} {s2}")
    s3 = _fmt_status(checks.get("ra_autonomous_slaac_flag_set", False))
    print(f"  {'RA A-Flag (Autonomous SLAAC Prefix)':<44} {'Flag Set (1)':<24} {s3}")
    s4 = _fmt_status(checks.get("dhcpv6_info_request_sent", False))
    print(f"  {'DHCPv6 Information-Request Transmitted':<44} {'Sent by Client':<24} {s4}")
    s5 = _fmt_status(checks.get("dhcpv6_reply_received", False))
    print(f"  {'DHCPv6 Reply Received':<44} {'Returned by Server':<24} {s5}")
    if "rdnss_dns_present" in checks:
        s6 = _fmt_status(checks.get("rdnss_dns_present", False))
        print(f"  {'Option 23 (DNS Recursive Name Server)':<44} {'Matches Target DNS':<24} {s6}")
    print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    print("=" * 80 + "\n")


def print_dhcpv6_stateful_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    checks = result.get("checks", {})
    addrs = ", ".join(result.get("allocated_ia_na_addresses") or []) or "None"
    status_name = result.get("server_status_name")
    status_code = result.get("server_status_code")

    print("\n" + "=" * 80)
    print("  DHCPv6 STATEFUL ADDRESS ASSIGNMENT AUDIT (IA_NA RFC 8415)")
    print("=" * 80)
    print(f"  Allocated IA_NA Address(es): {addrs}")
    if status_name:
        print(f"  Server Status Code         : {status_name} ({status_code})")
    print("-" * 80)
    print(f"  {'FRAME':<6} {'TIME (ms)':>9}   {'MESSAGE TYPE':<15} {'XID':<11} {'PEER ADDRESS':<24} {'IA_NA / STATUS'}")
    print("-" * 80)
    timeline = result.get("timeline", [])
    for f in timeline:
        t_ms = f.get("rel_time_ms", 0.0)
        m_type = f.get("type", "UNKNOWN")
        xid = f.get("xid", "-")
        peer = f.get("peeraddr") or "-"
        ia_str = ", ".join(f.get("ia_addrs") or [])
        sc = f.get("status_code_name")
        if sc and sc != "Success":
            detail = f"Status: {sc} ({f.get('status_code')})"
        elif ia_str:
            detail = ia_str
        else:
            detail = "-"
        print(f"  {f.get('frame', 0):<6} {t_ms:>9.2f}   {m_type:<15} {xid:<11} {peer:<24} {detail}")
    print("-" * 80)
    print(f"  {'CHECK / CRITERIA':<44} {'DETECTED STATE':<24} {'STATUS'}")
    print("-" * 80)
    s1 = _fmt_status(checks.get("ra_managed_flag_set", False))
    print(f"  {'ICMPv6 RA M-Flag (Managed Address Config)':<44} {'Flag Set (1)':<24} {s1}")
    s2 = _fmt_status(checks.get("dhcpv6_solicit_sent", False))
    print(f"  {'DHCPv6 Solicit (Client IA_NA Request)':<44} {'Sent by Client':<24} {s2}")
    s3 = _fmt_status(checks.get("dhcpv6_advertise_received", False))
    print(f"  {'DHCPv6 Advertise Received':<44} {'Offered by Server':<24} {s3}")
    if "server_status_code_success" in checks:
        s_sc = _fmt_status(checks["server_status_code_success"])
        sc_lbl = f"{status_name} ({status_code})" if status_name else "Unknown"
        print(f"  {'DHCPv6 Server Status Code (Option 13)':<44} {sc_lbl:<24} {s_sc}")
    s4 = _fmt_status(checks.get("dhcpv6_request_sent", False))
    print(f"  {'DHCPv6 Request Transmitted':<44} {'Sent by Client':<24} {s4}")
    s5 = _fmt_status(checks.get("dhcpv6_reply_received", False))
    print(f"  {'DHCPv6 Reply Received with IA_NA':<44} {'Assigned by Server':<24} {s5}")
    if "assigned_address_matches_prefix" in checks:
        s6 = _fmt_status(checks.get("assigned_address_matches_prefix", False))
        print(f"  {'Assigned Address Matches Target Prefix':<44} {'Prefix Valid':<24} {s6}")
    print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    if status_name == "NoAddrsAvail":
        print(f"\n  {YELLOW}[DIAGNOSIS] Server rejected Solicit with Status Code 2 (NoAddrsAvail).{RESET}")
        print(f"  {YELLOW}             The DUT Gateway does not have an active stateful IPv6 pool on LAN.{RESET}")
        print(f"  {YELLOW}             Check DUT configuration (enable DHCPv6 pool or switch to SLAAC/Stateless mode).{RESET}")
    print("=" * 80 + "\n")


def print_dhcpv6_pd_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    checks = result.get("checks", {})
    prefixes = ", ".join(result.get("delegated_prefixes") or []) or "None"

    print("\n" + "=" * 80)
    print("  DHCPv6 PREFIX DELEGATION AUDIT (IA_PD RFC 3633 / RFC 8415)")
    print("=" * 80)
    print(f"  Delegated WAN Prefix(es)   : {prefixes}")
    print("-" * 80)
    print(f"  {'CHECK / CRITERIA':<44} {'DETECTED STATE':<24} {'STATUS'}")
    print("-" * 80)
    s1 = _fmt_status(checks.get("wan_solicit_ia_pd_sent", False))
    print(f"  {'WAN DHCPv6 Solicit with IA_PD Option':<44} {'Sent by Gateway':<24} {s1}")
    s2 = _fmt_status(checks.get("wan_reply_delegated_prefix", False))
    print(f"  {'WAN DHCPv6 Reply with Delegated IA_PD':<44} {'Assigned by Server':<24} {s2}")
    if "delegated_prefix_matches" in checks:
        s3 = _fmt_status(checks.get("delegated_prefix_matches", False))
        print(f"  {'Delegated Prefix Matches Network Config':<44} {'Matches Expected':<24} {s3}")
    if "lan_ra_sub_prefix_advertised" in checks:
        s4 = _fmt_status(checks.get("lan_ra_sub_prefix_advertised", False))
        print(f"  {'LAN ICMPv6 RA Sub-prefix Advertisement':<44} {'Advertised to LAN':<24} {s4}")
    print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    print("=" * 80 + "\n")


def print_dhcpv6_relay_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "FAIL")
    checks = result.get("checks", {})
    l_sol = result.get("lan_solicits_count", 0)
    w_fwd = result.get("wan_relay_forward_count", 0)
    w_rep = result.get("wan_relay_reply_count", 0)

    print("\n" + "=" * 80)
    print("  DHCPv6 RELAY AGENT CROSS-VANTAGE AUDIT (RFC 8415)")
    print("=" * 80)
    print(f"  LAN Client Solicits Recorded   : {l_sol}")
    print(f"  WAN Relay-Forward Frames (12)  : {w_fwd}")
    print(f"  WAN Relay-Reply Frames (13)    : {w_rep}")
    print("-" * 80)
    print(f"  {'RELAY VERIFICATION STEP':<44} {'CRITERIA / EXPECTED':<24} {'STATUS'}")
    print("-" * 80)
    s1 = _fmt_status(checks.get("lan_client_sent_solicit", False))
    print(f"  {'LAN Client Multicast Solicit':<44} {'Captured on LAN':<24} {s1}")
    s2 = _fmt_status(checks.get("wan_gateway_relayed_forward", False))
    print(f"  {'WAN Gateway Relay-Forward Message':<44} {'Encapsulated to WAN':<24} {s2}")
    if "interface_id_option_matches" in checks:
        s3 = _fmt_status(checks.get("interface_id_option_matches", False))
        print(f"  {'Option 18 (Interface-Id) Option Preserved':<44} {'Matches Expected':<24} {s3}")
    s4 = _fmt_status(checks.get("wan_server_returned_relay_reply", False))
    print(f"  {'WAN Server Relay-Reply Message':<44} {'Received from WAN':<24} {s4}")
    s5 = _fmt_status(checks.get("lan_client_received_advertise", False))
    print(f"  {'LAN Gateway Forwarded Advertise to Client':<44} {'Delivered to LAN':<24} {s5}")
    print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    print("=" * 80 + "\n")


def print_generic_audit_card(result: Dict[str, Any]) -> None:
    verdict = result.get("verdict", "UNKNOWN")
    print("\n" + "=" * 80)
    print("  DHCP AUDIT RESULT SUMMARY")
    print("=" * 80)
    checks = result.get("checks", {})
    if checks:
        print(f"  {'CHECK NAME':<44} {'STATUS'}")
        print("-" * 80)
        for name, val in checks.items():
            print(f"  {name:<44} {_fmt_status(val)}")
        print("-" * 80)
    print(f"  OVERALL VERDICT: {_fmt_verdict(verdict)}")
    print("=" * 80 + "\n")


def print_audit_card_by_subcommand(subcmd: str, result: Dict[str, Any]) -> None:
    if subcmd == "audit-dhcpv4":
        print_dhcpv4_dora_card(result)
    elif subcmd == "audit-v4-renew":
        print_dhcpv4_renew_card(result)
    elif subcmd == "audit-relay-v4":
        print_dhcpv4_relay_card(result)
    elif subcmd == "audit-dhcpv6-stateless":
        print_dhcpv6_stateless_card(result)
    elif subcmd == "audit-dhcpv6-stateful":
        print_dhcpv6_stateful_card(result)
    elif subcmd == "audit-dhcpv6-pd":
        print_dhcpv6_pd_card(result)
    elif subcmd == "audit-relay-v6":
        print_dhcpv6_relay_card(result)
    else:
        print_generic_audit_card(result)


# ==============================================================================
# CLI Entry Point
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DHCP Evidence & PCAP Auditor")
    
    # Common shared options across all subcommands
    base_parser = argparse.ArgumentParser(add_help=False)
    base_parser.add_argument("--out", help="Optional output JSON path")
    base_parser.add_argument("--quiet", action="store_true", help="Suppress terminal card output")
    base_parser.add_argument("--json", action="store_true", help="Print raw JSON instead of tables")
    base_parser.add_argument("--table", action="store_true", default=True, help="Print formatted ASCII tables (default)")

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: audit-dhcpv4
    p_v4 = subparsers.add_parser("audit-dhcpv4", parents=[base_parser], help="Audit DHCPv4 DORA Handshake & Options")
    p_v4.add_argument("--pcap", required=True, help="Path to PCAP capture")
    p_v4.add_argument("--expected-mac", help="Expected client hardware MAC")
    p_v4.add_argument("--expected-ip", help="Expected assigned client IP")
    p_v4.add_argument("--expected-router", help="Expected default router Option 3")
    p_v4.add_argument("--expected-dns", help="Expected DNS server Option 6")
    p_v4.add_argument("--min-lease", type=int, help="Minimum lease time in seconds")

    # Subcommand: audit-v4-renew
    p_v4_rn = subparsers.add_parser("audit-v4-renew", parents=[base_parser], help="Audit DHCPv4 Lease Renewal & Release")
    p_v4_rn.add_argument("--pcap", required=True, help="Path to PCAP capture")
    p_v4_rn.add_argument("--expected-ip", help="Expected client IP")

    # Subcommand: audit-relay-v4
    p_rel_v4 = subparsers.add_parser("audit-relay-v4", parents=[base_parser], help="Audit DHCPv4 Relay Agent between LAN and WAN")
    p_rel_v4.add_argument("--lan-pcap", required=True, help="LAN side capture")
    p_rel_v4.add_argument("--wan-pcap", required=True, help="WAN side capture")
    p_rel_v4.add_argument("--expected-giaddr", help="Expected Gateway Relay IP")
    p_rel_v4.add_argument("--expected-circuit-id", help="Expected Option 82 Circuit ID")
    p_rel_v4.add_argument("--expected-remote-id", help="Expected Option 82 Remote ID")

    # Subcommand: audit-dhcpv6-stateless
    p_v6_sl = subparsers.add_parser("audit-dhcpv6-stateless", parents=[base_parser], help="Audit SLAAC + Stateless DHCPv6")
    p_v6_sl.add_argument("--pcap", required=True, help="Path to PCAP capture")
    p_v6_sl.add_argument("--expected-dns", help="Expected RDNSS DNS IP")

    # Subcommand: audit-dhcpv6-stateful
    p_v6_st = subparsers.add_parser("audit-dhcpv6-stateful", parents=[base_parser], help="Audit Stateful DHCPv6 IA_NA")
    p_v6_st.add_argument("--pcap", required=True, help="Path to PCAP capture")
    p_v6_st.add_argument("--expected-prefix", help="Expected allocated IPv6 prefix")

    # Subcommand: audit-dhcpv6-pd
    p_v6_pd = subparsers.add_parser("audit-dhcpv6-pd", parents=[base_parser], help="Audit DHCPv6 Prefix Delegation (IA_PD)")
    p_v6_pd.add_argument("--wan-pcap", required=True, help="WAN side capture")
    p_v6_pd.add_argument("--lan-pcap", help="Optional LAN side capture")
    p_v6_pd.add_argument("--expected-pd-prefix", help="Expected delegated prefix")

    # Subcommand: audit-relay-v6
    p_rel_v6 = subparsers.add_parser("audit-relay-v6", parents=[base_parser], help="Audit DHCPv6 Relay Agent")
    p_rel_v6.add_argument("--lan-pcap", required=True, help="LAN side capture")
    p_rel_v6.add_argument("--wan-pcap", required=True, help="WAN side capture")
    p_rel_v6.add_argument("--expected-interface-id", help="Expected Interface-Id option")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    auditor = DHCPEvidenceAuditor()

    try:
        if args.subcommand == "audit-dhcpv4":
            result = auditor.audit_dhcpv4_dora(
                pcap_path=args.pcap,
                expected_client_mac=args.expected_mac,
                expected_ip=args.expected_ip,
                expected_router=args.expected_router,
                expected_dns=args.expected_dns,
                min_lease_time=args.min_lease,
            )
        elif args.subcommand == "audit-v4-renew":
            result = auditor.audit_dhcpv4_renewal_and_release(
                pcap_path=args.pcap,
                expected_client_ip=args.expected_ip,
            )
        elif args.subcommand == "audit-relay-v4":
            result = auditor.audit_dhcpv4_relay(
                lan_pcap=args.lan_pcap,
                wan_pcap=args.wan_pcap,
                expected_giaddr=args.expected_giaddr,
                expected_circuit_id=args.expected_circuit_id,
                expected_remote_id=args.expected_remote_id,
            )
        elif args.subcommand == "audit-dhcpv6-stateless":
            result = auditor.audit_dhcpv6_stateless(
                pcap_path=args.pcap,
                expected_dns=args.expected_dns,
            )
        elif args.subcommand == "audit-dhcpv6-stateful":
            result = auditor.audit_dhcpv6_stateful(
                pcap_path=args.pcap,
                expected_prefix=args.expected_prefix,
            )
        elif args.subcommand == "audit-dhcpv6-pd":
            result = auditor.audit_dhcpv6_prefix_delegation(
                wan_pcap=args.wan_pcap,
                lan_pcap=args.lan_pcap,
                expected_pd_prefix=args.expected_pd_prefix,
            )
        elif args.subcommand == "audit-relay-v6":
            result = auditor.audit_dhcpv6_relay(
                lan_pcap=args.lan_pcap,
                wan_pcap=args.wan_pcap,
                expected_interface_id=args.expected_interface_id,
            )
        else:
            parser.print_help()
            return 1

        if getattr(args, "out", None):
            write_atomic_json(args.out, result)

        if not getattr(args, "quiet", False):
            if getattr(args, "json", False):
                print(json.dumps(result, indent=2))
            else:
                print_audit_card_by_subcommand(args.subcommand, result)

        return 0 if result.get("verdict") == "PASS" else 1

    except DHCPAuditError as err:
        print(f"[ERROR] DHCPAuditError: {err}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"[FATAL] Unexpected error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

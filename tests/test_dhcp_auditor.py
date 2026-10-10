#!/usr/bin/env python3
"""
tests/test_dhcp_auditor.py - Unit tests for DHCP Evidence Auditor
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

from dhcp_auditor import (
    DHCPAuditError,
    DHCPEvidenceAuditor,
    DHCPv4Frame,
    DHCPv6Frame,
    DHCPv4MsgType,
    DHCPv6MsgType,
    TsharkDissector,
    clean_hex,
    safe_bool,
)


def test_clean_hex():
    assert clean_hex("02:00:00:00:01:aa") == "0200000001aa"
    assert clean_hex("AA-BB-CC-DD-EE-FF") == "aabbccddeeff"
    assert clean_hex("1234") == "1234"


def test_audit_dhcpv4_dora_complete():
    mock_dissector = MagicMock(spec=TsharkDissector)
    now = 1000.0
    mock_dissector.extract_dhcpv4.return_value = [
        DHCPv4Frame(
            frame_number=1,
            timestamp=now,
            msg_type=DHCPv4MsgType.DISCOVER,
            msg_type_name="DISCOVER",
            xid="0x12345678",
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr="02:00:00:00:01:0a",
            server_id=None,
            lease_time=None,
            subnet_mask=None,
            router=None,
            dns_servers=[],
            domain_name=None,
            hostname="test-host",
            vendor_class=None,
            circuit_id=None,
            remote_id=None,
        ),
        DHCPv4Frame(
            frame_number=2,
            timestamp=now + 0.05,
            msg_type=DHCPv4MsgType.OFFER,
            msg_type_name="OFFER",
            xid="0x12345678",
            ciaddr="0.0.0.0",
            yiaddr="192.168.1.100",
            siaddr="192.168.1.1",
            giaddr="0.0.0.0",
            chaddr="02:00:00:00:01:0a",
            server_id="192.168.1.1",
            lease_time=7200,
            subnet_mask="255.255.255.0",
            router="192.168.1.1",
            dns_servers=["192.168.1.1"],
            domain_name="home.gateway",
            hostname=None,
            vendor_class=None,
            circuit_id=None,
            remote_id=None,
        ),
        DHCPv4Frame(
            frame_number=3,
            timestamp=now + 0.06,
            msg_type=DHCPv4MsgType.REQUEST,
            msg_type_name="REQUEST",
            xid="0x12345678",
            ciaddr="0.0.0.0",
            yiaddr="0.0.0.0",
            siaddr="0.0.0.0",
            giaddr="0.0.0.0",
            chaddr="02:00:00:00:01:0a",
            server_id="192.168.1.1",
            lease_time=None,
            subnet_mask=None,
            router=None,
            dns_servers=[],
            domain_name=None,
            hostname="test-host",
            vendor_class=None,
            circuit_id=None,
            remote_id=None,
        ),
        DHCPv4Frame(
            frame_number=4,
            timestamp=now + 0.10,
            msg_type=DHCPv4MsgType.ACK,
            msg_type_name="ACK",
            xid="0x12345678",
            ciaddr="0.0.0.0",
            yiaddr="192.168.1.100",
            siaddr="192.168.1.1",
            giaddr="0.0.0.0",
            chaddr="02:00:00:00:01:0a",
            server_id="192.168.1.1",
            lease_time=7200,
            subnet_mask="255.255.255.0",
            router="192.168.1.1",
            dns_servers=["192.168.1.1", "8.8.8.8"],
            domain_name="home.gateway",
            hostname="test-host",
            vendor_class=None,
            circuit_id=None,
            remote_id=None,
        ),
    ]

    auditor = DHCPEvidenceAuditor(dissector=mock_dissector)
    result = auditor.audit_dhcpv4_dora(
        pcap_path="dummy.pcap",
        expected_client_mac="02:00:00:00:01:0a",
        expected_ip="192.168.1.100",
        expected_router="192.168.1.1",
        expected_dns="8.8.8.8",
        min_lease_time=3600,
    )

    assert result["verdict"] == "PASS"
    assert result["dora_complete"] is True
    assert result["assigned_ip"] == "192.168.1.100"
    assert result["router_ip"] == "192.168.1.1"
    assert result["handshake_latency_ms"] == 100.0
    assert result["packet_counts"]["discover"] == 1
    assert result["packet_counts"]["ack"] == 1


def test_audit_dhcpv4_relay_correlation():
    mock_dissector = MagicMock(spec=TsharkDissector)
    now = 1000.0

    # LAN vantage: broadcast Discover, Offer
    mock_dissector.extract_dhcpv4.side_effect = [
        [
            DHCPv4Frame(
                frame_number=1,
                timestamp=now,
                msg_type=DHCPv4MsgType.DISCOVER,
                msg_type_name="DISCOVER",
                xid="0xabcd",
                ciaddr="0.0.0.0",
                yiaddr="0.0.0.0",
                siaddr="0.0.0.0",
                giaddr="0.0.0.0",
                chaddr="02:00:00:00:01:0a",
                server_id=None,
                lease_time=None,
                subnet_mask=None,
                router=None,
                dns_servers=[],
                domain_name=None,
                hostname=None,
                vendor_class=None,
                circuit_id=None,
                remote_id=None,
            ),
            DHCPv4Frame(
                frame_number=4,
                timestamp=now + 0.08,
                msg_type=DHCPv4MsgType.OFFER,
                msg_type_name="OFFER",
                xid="0xabcd",
                ciaddr="0.0.0.0",
                yiaddr="192.168.1.150",
                siaddr="10.10.0.1",
                giaddr="192.168.1.1",
                chaddr="02:00:00:00:01:0a",
                server_id="10.10.0.1",
                lease_time=7200,
                subnet_mask="255.255.255.0",
                router="192.168.1.1",
                dns_servers=[],
                domain_name=None,
                hostname=None,
                vendor_class=None,
                circuit_id=None,
                remote_id=None,
            ),
        ],
        # WAN vantage: Relayed Discover with giaddr and Option 82, WAN Offer
        [
            DHCPv4Frame(
                frame_number=2,
                timestamp=now + 0.01,
                msg_type=DHCPv4MsgType.DISCOVER,
                msg_type_name="DISCOVER",
                xid="0xabcd",
                ciaddr="0.0.0.0",
                yiaddr="0.0.0.0",
                siaddr="0.0.0.0",
                giaddr="192.168.1.1",
                chaddr="02:00:00:00:01:0a",
                server_id=None,
                lease_time=None,
                subnet_mask=None,
                router=None,
                dns_servers=[],
                domain_name=None,
                hostname=None,
                vendor_class=None,
                circuit_id="eth-lan",
                remote_id="gw-01",
            ),
            DHCPv4Frame(
                frame_number=3,
                timestamp=now + 0.04,
                msg_type=DHCPv4MsgType.OFFER,
                msg_type_name="OFFER",
                xid="0xabcd",
                ciaddr="0.0.0.0",
                yiaddr="192.168.1.150",
                siaddr="10.10.0.1",
                giaddr="192.168.1.1",
                chaddr="02:00:00:00:01:0a",
                server_id="10.10.0.1",
                lease_time=7200,
                subnet_mask="255.255.255.0",
                router="192.168.1.1",
                dns_servers=[],
                domain_name=None,
                hostname=None,
                vendor_class=None,
                circuit_id="eth-lan",
                remote_id="gw-01",
            ),
        ],
    ]

    auditor = DHCPEvidenceAuditor(dissector=mock_dissector)
    result = auditor.audit_dhcpv4_relay(
        lan_pcap="lan.pcap",
        wan_pcap="wan.pcap",
        expected_giaddr="192.168.1.1",
        expected_circuit_id="eth-lan",
        expected_remote_id="gw-01",
    )

    assert result["verdict"] == "PASS"
    assert result["detected_giaddr"] == "192.168.1.1"
    assert result["checks"]["giaddr_populated_on_wan"] is True
    assert result["checks"]["opt82_circuit_id_present"] is True
    assert result["checks"]["opt82_remote_id_present"] is True


def test_audit_dhcpv6_stateful_exchange():
    mock_dissector = MagicMock(spec=TsharkDissector)
    now = 1000.0

    mock_dissector.extract_icmpv6_ra.return_value = [
        {
            "frame_number": 1,
            "timestamp": now,
            "managed_flag": True,
            "other_flag": True,
            "prefixes": ["2001:db8:100::/64"],
            "autonomous_flag": False,
            "rdnss": ["2001:db8:100::1"],
        }
    ]

    mock_dissector.extract_dhcpv6.return_value = [
        DHCPv6Frame(
            frame_number=2,
            timestamp=now + 0.01,
            msg_type=DHCPv6MsgType.SOLICIT,
            msg_type_name="SOLICIT",
            xid="0x112233",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="00010001...",
            server_duid=None,
            ia_na_addresses=[],
            ia_pd_prefixes=[],
            dns_servers=[],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
        ),
        DHCPv6Frame(
            frame_number=3,
            timestamp=now + 0.03,
            msg_type=DHCPv6MsgType.ADVERTISE,
            msg_type_name="ADVERTISE",
            xid="0x112233",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="00010001...",
            server_duid="00010002...",
            ia_na_addresses=["2001:db8:100:1::1050"],
            ia_pd_prefixes=[],
            dns_servers=["2001:db8:100::1"],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
        ),
        DHCPv6Frame(
            frame_number=4,
            timestamp=now + 0.04,
            msg_type=DHCPv6MsgType.REQUEST,
            msg_type_name="REQUEST",
            xid="0x112233",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="00010001...",
            server_duid="00010002...",
            ia_na_addresses=["2001:db8:100:1::1050"],
            ia_pd_prefixes=[],
            dns_servers=[],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
        ),
        DHCPv6Frame(
            frame_number=5,
            timestamp=now + 0.06,
            msg_type=DHCPv6MsgType.REPLY,
            msg_type_name="REPLY",
            xid="0x112233",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="00010001...",
            server_duid="00010002...",
            ia_na_addresses=["2001:db8:100:1::1050"],
            ia_pd_prefixes=[],
            dns_servers=["2001:db8:100::1"],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
        ),
    ]

    auditor = DHCPEvidenceAuditor(dissector=mock_dissector)
    result = auditor.audit_dhcpv6_stateful(
        pcap_path="v6_stateful.pcap",
        expected_prefix="2001:db8:100:1::",
    )

    assert result["verdict"] == "PASS"
    assert "2001:db8:100:1::1050" in result["allocated_ia_na_addresses"]
    assert result["checks"]["ia_na_address_assigned"] is True
    assert result["checks"]["assigned_address_matches_prefix"] is True


def test_audit_dhcpv6_stateful_no_addrs_avail():
    mock_dissector = MagicMock(spec=TsharkDissector)
    now = 1000.0

    mock_dissector.extract_icmpv6_ra.return_value = [
        {
            "frame_number": 1,
            "timestamp": now,
            "managed_flag": True,
            "other_flag": True,
            "prefixes": ["2001:db8:100::/64"],
            "autonomous_flag": False,
            "rdnss_servers": ["2001:db8:100::1"],
        }
    ]

    mock_dissector.extract_dhcpv6.return_value = [
        DHCPv6Frame(
            frame_number=2,
            timestamp=now + 0.1,
            msg_type=DHCPv6MsgType.SOLICIT,
            msg_type_name="SOLICIT",
            xid="0x123456",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="0001...",
            server_duid=None,
            ia_na_addresses=[],
            ia_pd_prefixes=[],
            dns_servers=[],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
        ),
        DHCPv6Frame(
            frame_number=3,
            timestamp=now + 0.2,
            msg_type=DHCPv6MsgType.ADVERTISE,
            msg_type_name="ADVERTISE",
            xid="0x123456",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="0001...",
            server_duid="00010002...",
            ia_na_addresses=[],
            ia_pd_prefixes=[],
            dns_servers=[],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
            status_code=2,  # NoAddrsAvail
        ),
    ]

    auditor = DHCPEvidenceAuditor(dissector=mock_dissector)
    result = auditor.audit_dhcpv6_stateful(pcap_path="v6_stateful_fail.pcap")

    assert result["verdict"] == "FAIL"
    assert result["server_status_code"] == 2
    assert result["server_status_name"] == "NoAddrsAvail"
    assert result["checks"]["server_status_code_success"] is False
    assert result["checks"]["ia_na_address_assigned"] is False


def test_safe_bool():
    assert safe_bool("True") is True
    assert safe_bool("true") is True
    assert safe_bool("1") is True
    assert safe_bool("False") is False
    assert safe_bool("false") is False
    assert safe_bool("0") is False
    assert safe_bool(True) is True
    assert safe_bool(False) is False
    assert safe_bool("True,True") is True
    assert safe_bool("False,False") is False
    assert safe_bool(None, default=False) is False
    assert safe_bool("", default=True) is True


def test_audit_dhcpv6_stateless_flags():
    mock_dissector = MagicMock(spec=TsharkDissector)
    mock_dissector.extract_icmpv6_ra.return_value = [
        {
            "frame_number": 1,
            "timestamp": 1000.0,
            "managed_flag": False,
            "other_flag": True,
            "prefixes": ["2001:db8:100::"],
            "autonomous_flag": True,
            "rdnss": ["2001:db8:100::1"],
        }
    ]
    mock_dissector.extract_dhcpv6.return_value = [
        DHCPv6Frame(
            frame_number=2,
            timestamp=1000.1,
            msg_type=DHCPv6MsgType.INFORMATION_REQUEST,
            msg_type_name="INFORMATION-REQUEST",
            xid="0x123456",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="0001...",
            server_duid=None,
            ia_na_addresses=[],
            ia_pd_prefixes=[],
            dns_servers=[],
            domain_search=[],
            interface_id=None,
            relay_msg_type=None,
        ),
        DHCPv6Frame(
            frame_number=3,
            timestamp=1000.2,
            msg_type=DHCPv6MsgType.REPLY,
            msg_type_name="REPLY",
            xid="0x123456",
            linkaddr="::",
            peeraddr="fe80::1",
            client_duid="0001...",
            server_duid="00010002...",
            ia_na_addresses=[],
            ia_pd_prefixes=[],
            dns_servers=["2001:db8:100::1"],
            domain_search=["home.gateway"],
            interface_id=None,
            relay_msg_type=None,
        ),
    ]

    auditor = DHCPEvidenceAuditor(dissector=mock_dissector)
    result = auditor.audit_dhcpv6_stateless(pcap_path="v6_stateless.pcap", expected_dns="2001:db8:100::1")

    assert result["verdict"] == "PASS"
    assert result["checks"]["ra_received"] is True
    assert result["checks"]["ra_other_config_flag_set"] is True
    assert result["checks"]["ra_autonomous_slaac_flag_set"] is True
    assert result["checks"]["dhcpv6_info_request_sent"] is True
    assert result["checks"]["dhcpv6_reply_received"] is True
    assert result["checks"]["rdnss_dns_present"] is True


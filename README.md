# DHCPLab - Home Gateway DHCP Conformance Test Lab (`dhcplab`)

A production-grade Linux Network Test Lab framework for automated verification and deep protocol conformance auditing of **DHCPv4**, **DHCPv6**, and **DHCP Relay** on Home Gateway Devices (CPE / ONT / AP Routers).

---

## 1. Project Capabilities

- **DHCPv4 Server Conformance (RFC 2131)**:
  - Full 4-way DORA handshake (Discover, Offer, Request, Ack)
  - IP Address pool allocation and boundary enforcement
  - Standard option negotiation: Subnet Mask (Option 1), Default Gateway (Option 3), DNS Servers (Option 6), Hostname (Option 12), Domain Name (Option 15), Lease Time (Option 51), Server Identifier (Option 54), Vendor Class (Option 60)
  - T1 timer unicast renewal and graceful release (DHCPRELEASE)
  - Static MAC-to-IP address reservation
- **DHCPv6 Conformance (RFC 8415 / RFC 3736 / RFC 3633)**:
  - Stateless DHCPv6 with SLAAC (RA flags `M=0`, `O=1`, `A=1`, RDNSS Option 23)
  - Stateful DHCPv6 Non-Temporary Address Allocation (`IA_NA` Option 3 & Option 5)
  - DHCPv6 Prefix Delegation (`IA_PD` Option 25) with downstream LAN subnet distribution
- **DHCP Relay Agent Conformance (RFC 3046 / RFC 8415)**:
  - DHCPv4 Relay with Option 82 (Circuit ID & Remote ID) and `giaddr` insertion
  - DHCPv6 Relay Agent (`Relay-Forward` Type 12 and `Relay-Reply` Type 13) encapsulation
- **Dual-Sided Evidence Analytics**:
  - Wire-level PCAP packet dissection via `tools/dhcp_auditor.py`
  - Cross-vantage LAN vs WAN correlation
  - Quantitative pass/fail scorecard and ASCII packet timelines via `scripts/verify_compliance.sh`

---

## 2. Testbed Topologies

- **Virtual Simulation Mode (`--virtual`)**: 100% software emulation inside Linux network namespaces (`ns-wan`, `ns-dut`, `ns-pc`, `ns-stb`). Ideal for CI/CD and offline protocol verification.
- **Physical Single-PC Dual-NIC Mode (`--single`)**: Bridges dedicated physical Ethernet adapters (`WAN_IF`, `LAN_IF`) directly to the external hardware Gateway DUT.

---

## 3. Quick Start

```bash
# 1. Non-destructive pre-flight environment check
./scripts/diagnose.sh

# 2. Initialize topology (Virtual Mode)
sudo ./scripts/setup.sh --virtual

# Or for Physical Hardware DUT Mode:
# sudo ./scripts/setup.sh --single

# 3. Inspect runtime state
./scripts/show_state.sh
./scripts/dut_emulator.sh status
./scripts/client_dhcp.sh status

# 4. List available test scenarios
./scripts/scenario.sh list

# 5. Execute DHCP test scenarios
sudo ./scripts/scenario.sh dhcpv4_dora
sudo ./scripts/scenario.sh dhcpv4_renewal_release
sudo ./scripts/scenario.sh dhcpv4_static_reservation
sudo ./scripts/scenario.sh dhcpv6_stateless
sudo ./scripts/scenario.sh dhcpv6_stateful
sudo ./scripts/scenario.sh dhcpv6_pd
sudo ./scripts/scenario.sh dhcpv4_relay
sudo ./scripts/scenario.sh dhcpv6_relay

# 6. Evaluate compliance scorecard & packet timeline evidence
./scripts/verify_compliance.sh

# 7. Safe teardown
sudo ./scripts/cleanup.sh
```

---

## 4. Test Scenario Catalog

| ID | Title | Protocol Scope |
| :--- | :--- | :--- |
| `dhcpv4_dora` | DHCPv4 Server DORA Handshake | RFC 2131 4-way DORA, Options 1/3/6/12/15/51/54/60 |
| `dhcpv4_renewal_release` | DHCPv4 Lease Renewal & Release | T1 unicast renewal Request/Ack & DHCPRELEASE |
| `dhcpv4_static_reservation` | DHCPv4 Static MAC Reservation | Pre-configured MAC binding to fixed IP |
| `dhcpv6_stateless` | Stateless DHCPv6 & SLAAC | RA (M=0, O=1, A=1) + Information-Request (Opt 23 RDNSS) |
| `dhcpv6_stateful` | Stateful DHCPv6 (IA_NA) | RA (M=1) + Solicit/Advertise/Request/Reply + IA_NA (Opt 3/5) |
| `dhcpv6_pd` | DHCPv6 Prefix Delegation (IA_PD) | WAN IA_PD delegation (/56) + LAN /64 advertisement + ping6 |
| `dhcpv4_relay` | DHCPv4 Relay Agent (Option 82) | LAN broadcast Discover -> WAN unicast with giaddr & Option 82 |
| `dhcpv6_relay` | DHCPv6 Relay Agent | LAN Solicit -> WAN Relay-Forward (Opt 9/18) -> Relay-Reply |

See [docs/DHCP_VERIFICATION_GUIDE.md](docs/DHCP_VERIFICATION_GUIDE.md) for full technical details.

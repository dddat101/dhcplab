#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 07: DHCPv4 RELAY AGENT (OPTION 82)
# Verifies DHCPv4 Relay Agent with Option 82 Injection and giaddr Forwarding (RFC 3046 / RFC 2131)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S07_DEFAULT_DURATION=12

s07_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 07] DHCPv4 RELAY AGENT & OPTION 82 FORWARDING          |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv4_relay, relay_v4, opt82_relay
  Objective        : Validate DHCPv4 Relay Agent functionality:
                     1. Gateway intercepts LAN client broadcast DHCPDISCOVER.
                     2. Sets giaddr (Gateway IP address) to 192.168.1.1.
                     3. Injects Option 82 (Relay Agent Information Option).
                     4. Forwards unicast Discover across WAN to Central Server (10.10.0.1).
                     5. Central Server returns DHCPOFFER to giaddr.
                     6. Gateway relays DHCPOFFER back to client on LAN.
  RFC Reference    : RFC 3046 (DHCP Relay Agent Information Option) & RFC 2131
  Pass Criteria    :
    1. Cross-vantage correlation: LAN broadcast vs WAN unicast.
    2. giaddr field is correctly populated on WAN frames.
    3. Option 82 Circuit-ID / Remote-ID sub-options verified.
    4. Client successfully acquires lease from Central Server.

  Examples:
    sudo ./scripts/scenario.sh dhcpv4_relay
    ./scripts/scenario.sh --dry-run dhcpv4_relay
EOF
}

s07_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv4_relay]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    return 0
}

s07_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would start Central DHCP server on WAN and Relay Agent on DUT"
        return 0
    fi

    # 1. Start Upstream WAN Central DHCP Server
    if [[ -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
        log_info "Starting WAN Central DHCP server..."
        "${SCRIPT_DIR}/wan_server.sh" start dnsmasq || true
    fi

    # 2. Configure DUT in DHCPv4 Relay mode
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        local wan_srv="${WAN_SERVER_IP:-10.10.0.1}"
        log_info "Starting DUT in DHCPv4 Relay mode pointing to ${wan_srv}..."
        "${SCRIPT_DIR}/dut_emulator.sh" relay-v4 "${wan_srv}"
    fi
}

s07_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local expected_giaddr="${DUT_LAN_IP:-192.168.1.1}"
    local out_json="${LOG_DIR}/dhcpv4_relay_result.json"

    log_step "Executing DHCPv4 Relay Agent Verification (LAN -> DUT -> WAN)..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would trigger client DHCP request and audit dual-sided captures"
        return 0
    fi

    # Trigger client lease request
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v4 pc "" "RelayClient" "VendorRelay" || true
    fi

    sleep 2
    log_info "DHCPv4 Relay transaction completed on ${lan_ns}."
}

s07_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv4_relay_result.json"
    local expected_giaddr="${DUT_LAN_IP:-192.168.1.1}"
    local lan_pcap wan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv4_relay" || echo "")"
    wan_pcap="$(resolve_pcap "wan" "dhcpv4_relay" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert DHCPv4 Relay verification from ${out_json}"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv4_relay]"
    if [[ -n "${lan_pcap}" && -n "${wan_pcap}" && -f "${lan_pcap}" && -f "${wan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-relay-v4 \
            --lan-pcap "${lan_pcap}" \
            --wan-pcap "${wan_pcap}" \
            --expected-giaddr "${expected_giaddr}" \
            --out "${out_json}" || true
    else
        log_error "One or both PCAP files missing for cross-vantage audit (lan: ${lan_pcap:-<empty>}, wan: ${wan_pcap:-<empty>})"
        return 1
    fi

    if [[ ! -f "${out_json}" ]]; then
        log_error "Scenario audit result JSON not found at ${out_json}"
        return 1
    fi

    local verdict="FAIL" giaddr=""
    if command -v jq >/dev/null 2>&1; then
        verdict="$(jq -r '.verdict // "FAIL"' "${out_json}")"
        giaddr="$(jq -r '.detected_giaddr // "none"' "${out_json}")"
    else
        verdict="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("verdict", "FAIL"))' "${out_json}")"
        giaddr="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("detected_giaddr", "none"))' "${out_json}")"
    fi

    if [[ "${verdict}" == "PASS" ]]; then
        log_pass "DHCPv4 Relay Agent: PASS (giaddr verified: ${giaddr})"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-relay-v4 --lan-pcap %s --wan-pcap %s\n' "${lan_pcap}" "${wan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "DHCPv4 Relay Agent: FAIL (giaddr: ${giaddr})"
        return 1
    fi
}

s07_scenario_teardown() {
    if (( ${DRY_RUN:-0} == 1 )); then
        return 0
    fi
    # Stop relay daemon on DUT
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" stop
    fi
    log_debug "Teardown for scenario [dhcpv4_relay] complete."
}

scenario_register \
    --id "dhcpv4_relay" \
    --name "DHCPv4 Relay Agent (Option 82)" \
    --desc "Validate DHCPv4 Relay Agent giaddr forwarding and Option 82 injection (RFC 3046 / 2131)" \
    --aliases "relay_v4,opt82_relay" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "udp port 67 or udp port 68" \
    --duration "${S07_DEFAULT_DURATION}" \
    --run-fn "s07_scenario_run" \
    --validate-fn "s07_scenario_validate" \
    --setup-fn "s07_scenario_setup" \
    --verify-fn "s07_scenario_verify" \
    --teardown-fn "s07_scenario_teardown" \
    --help-fn "s07_scenario_help"

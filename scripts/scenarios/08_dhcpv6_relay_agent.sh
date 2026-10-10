#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 08: DHCPv6 RELAY AGENT
# Verifies DHCPv6 Relay-Forward and Relay-Reply Encapsulation (RFC 8415 / 3315)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S08_DEFAULT_DURATION=12

s08_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 08] DHCPv6 RELAY AGENT (RELAY-FORWARD & RELAY-REPLY)   |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv6_relay, relay_v6, relay_forward
  Objective        : Validate DHCPv6 Relay Agent encapsulation:
                     1. Gateway intercepts LAN client multicast Solicit (ff02::1:2).
                     2. Encapsulates into Relay-Forward message (Type 12) with
                        Option 9 (Relay-Message) and Option 18 (Interface-Id).
                     3. Transmits Relay-Forward across WAN to Central Server (2001:db8:10::1).
                     4. Central Server returns Relay-Reply (Type 13).
                     5. Gateway decapsulates and forwards Advertise to LAN client.
  RFC Reference    : RFC 8415 (Section 19 - Relay Agent Behavior)
  Pass Criteria    :
    1. Cross-vantage correlation: LAN Solicit vs WAN Relay-Forward.
    2. Relay-Forward Option 9 contains complete original Solicit.
    3. Server returns Relay-Reply message on WAN.
    4. Client on LAN successfully receives Advertise / Reply.

  Examples:
    sudo ./scripts/scenario.sh dhcpv6_relay
    ./scripts/scenario.sh --dry-run dhcpv6_relay
EOF
}

s08_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv6_relay]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    return 0
}

s08_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would start Central DHCPv6 server on WAN and Relay Agent on DUT"
        return 0
    fi

    # 1. Start Upstream WAN Central DHCPv6 Server
    if [[ -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
        log_info "Starting WAN Central DHCPv6 server..."
        "${SCRIPT_DIR}/wan_server.sh" start dnsmasq || true
    fi

    # 2. Configure DUT in DHCPv6 Relay mode
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        local wan_srv_v6="${WAN_SERVER_IP_V6:-2001:db8:10::1}"
        log_info "Starting DUT in DHCPv6 Relay mode pointing to [${wan_srv_v6}]..."
        "${SCRIPT_DIR}/dut_emulator.sh" relay-v6 "${wan_srv_v6}"
    fi
}

s08_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local out_json="${LOG_DIR}/dhcpv6_relay_result.json"

    log_step "Executing DHCPv6 Relay Agent Verification (LAN -> DUT -> WAN)..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would trigger client DHCPv6 solicit and audit dual-sided captures"
        return 0
    fi

    # Trigger client Solicit request
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v6 pc stateful || true
    fi

    sleep 2
    log_info "DHCPv6 Relay transaction completed on ${lan_ns}."
}

s08_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv6_relay_result.json"
    local lan_pcap wan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv6_relay" || echo "")"
    wan_pcap="$(resolve_pcap "wan" "dhcpv6_relay" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert DHCPv6 Relay verification from ${out_json}"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv6_relay]"
    if [[ -n "${lan_pcap}" && -n "${wan_pcap}" && -f "${lan_pcap}" && -f "${wan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-relay-v6 \
            --lan-pcap "${lan_pcap}" \
            --wan-pcap "${wan_pcap}" \
            --out "${out_json}" || true
    else
        log_error "One or both PCAP files missing for cross-vantage audit (lan: ${lan_pcap:-<empty>}, wan: ${wan_pcap:-<empty>})"
        return 1
    fi

    if [[ ! -f "${out_json}" ]]; then
        log_error "Scenario audit result JSON not found at ${out_json}"
        return 1
    fi

    local verdict="FAIL"
    if command -v jq >/dev/null 2>&1; then
        verdict="$(jq -r '.verdict // "FAIL"' "${out_json}")"
    else
        verdict="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("verdict", "FAIL"))' "${out_json}")"
    fi

    if [[ "${verdict}" == "PASS" ]]; then
        log_pass "DHCPv6 Relay Agent: PASS (Relay-Forward / Relay-Reply encapsulation verified)"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-relay-v6 --lan-pcap %s --wan-pcap %s\n' "${lan_pcap}" "${wan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "DHCPv6 Relay Agent: FAIL"
        return 1
    fi
}

s08_scenario_teardown() {
    if (( ${DRY_RUN:-0} == 1 )); then
        return 0
    fi
    # Stop relay daemon on DUT
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" stop
    fi
    log_debug "Teardown for scenario [dhcpv6_relay] complete."
}

scenario_register \
    --id "dhcpv6_relay" \
    --name "DHCPv6 Relay Agent" \
    --desc "Validate DHCPv6 Relay-Forward & Relay-Reply encapsulation (RFC 8415 / 3315)" \
    --aliases "relay_v6,relay_forward" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "udp port 546 or udp port 547" \
    --duration "${S08_DEFAULT_DURATION}" \
    --run-fn "s08_scenario_run" \
    --validate-fn "s08_scenario_validate" \
    --setup-fn "s08_scenario_setup" \
    --verify-fn "s08_scenario_verify" \
    --teardown-fn "s08_scenario_teardown" \
    --help-fn "s08_scenario_help"

#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 03: DHCPv4 STATIC MAC RESERVATION
# Verifies Static Host / Fixed IP Address Allocation bound to Client MAC Address
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S03_DEFAULT_DURATION=10

s03_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 03] DHCPv4 STATIC MAC ADDRESS RESERVATION              |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv4_static_reservation, static_reservation, dhcp_static
  Objective        : Validate that the Gateway reserves and assigns a specific
                     static IPv4 address to a designated hardware MAC address.
  RFC Reference    : RFC 2131 (Section 4.3.1)
  Pass Criteria    :
    1. Client with reserved MAC requests IP address.
    2. Server DHCPOFFER and DHCPACK match exactly the configured static IP.
    3. Assigned IP matches DUT_DHCPV4_STATIC_IP (default: 192.168.1.99).

  Examples:
    sudo ./scripts/scenario.sh dhcpv4_static_reservation
    ./scripts/scenario.sh --dry-run dhcpv4_static_reservation
EOF
}

s03_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv4_static_reservation]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    return 0
}

s03_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would ensure DUT DHCPv4 server is active with static reservation"
        return 0
    fi

    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" server-v4
    fi
}

s03_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local reserved_mac="${DUT_DHCPV4_STATIC_MAC:-02:00:00:00:01:99}"
    local reserved_ip="${DUT_DHCPV4_STATIC_IP:-192.168.1.99}"
    local out_json="${LOG_DIR}/dhcpv4_static_reservation_result.json"

    log_step "Executing DHCPv4 Static Reservation Verification for MAC [${reserved_mac}]..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would configure client MAC to ${reserved_mac}"
        log_info "[DRY-RUN] Would assert assigned IP is ${reserved_ip}"
        return 0
    fi

    # Trigger synchronous lease request with reserved MAC
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v4 pc "${reserved_mac}" "reserved-pc" "StaticClient" || true
    fi

    sleep 1
    log_info "DHCPv4 static MAC lease request completed on ${lan_ns}."
}

s03_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv4_static_reservation_result.json"
    local reserved_mac="${DUT_DHCPV4_STATIC_MAC:-02:00:00:00:01:99}"
    local reserved_ip="${DUT_DHCPV4_STATIC_IP:-192.168.1.99}"
    local lan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv4_static_reservation" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert static reservation match for ${reserved_ip}"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv4_static_reservation]"
    if [[ -n "${lan_pcap}" && -f "${lan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-dhcpv4 \
            --pcap "${lan_pcap}" \
            --expected-mac "${reserved_mac}" \
            --expected-ip "${reserved_ip}" \
            --out "${out_json}" || true
    else
        log_error "LAN PCAP not found at ${lan_pcap:-<empty>}. Capture may be disabled or empty."
        return 1
    fi

    if [[ ! -f "${out_json}" ]]; then
        log_error "Scenario audit result JSON not found at ${out_json}"
        return 1
    fi

    local verdict="FAIL" assigned_ip=""
    if command -v jq >/dev/null 2>&1; then
        verdict="$(jq -r '.verdict // "FAIL"' "${out_json}")"
        assigned_ip="$(jq -r '.assigned_ip // "none"' "${out_json}")"
    else
        verdict="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("verdict", "FAIL"))' "${out_json}")"
        assigned_ip="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("assigned_ip", "none"))' "${out_json}")"
    fi

    if [[ "${verdict}" == "PASS" && "${assigned_ip}" == "${reserved_ip}" ]]; then
        log_pass "Static MAC Reservation: PASS (MAC mapped directly to ${assigned_ip})"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-dhcpv4 --pcap %s\n' "${lan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "Static MAC Reservation: FAIL (Expected: ${reserved_ip}, Got: ${assigned_ip})"
        return 1
    fi
}

s03_scenario_teardown() {
    if (( ${DRY_RUN:-0} == 1 )); then
        return 0
    fi
    # Restore original client MAC
    local lan_ns="${PC_NS:-ns-pc}"
    if ns_exists "${lan_ns}"; then
        local iface
        iface="$(ip -n "${lan_ns}" -o link show | awk -F': ' '$2 != "lo" {print $2; exit}' || echo "eth0")"
        ip -n "${lan_ns}" link set "${iface}" address "02:00:00:00:01:0a" 2>/dev/null || true
    fi
    log_debug "Teardown for scenario [dhcpv4_static_reservation] complete."
}

scenario_register \
    --id "dhcpv4_static_reservation" \
    --name "DHCPv4 Static MAC Reservation" \
    --desc "Validate static IP address reservation bound to client MAC address" \
    --aliases "static_reservation,dhcp_static" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "udp port 67 or udp port 68" \
    --duration "${S03_DEFAULT_DURATION}" \
    --run-fn "s03_scenario_run" \
    --validate-fn "s03_scenario_validate" \
    --setup-fn "s03_scenario_setup" \
    --verify-fn "s03_scenario_verify" \
    --teardown-fn "s03_scenario_teardown" \
    --help-fn "s03_scenario_help"

#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 04: STATELESS DHCPv6 & SLAAC
# Verifies SLAAC Address Autoconfiguration and DHCPv6 Information-Request (RFC 8415 / 3736)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S04_DEFAULT_DURATION=10

s04_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 04] STATELESS DHCPv6 WITH SLAAC & INFORMATION-REQUEST  |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv6_stateless, slaac_dhcpv6, v6_stateless
  Objective        : Validate Stateless DHCPv6 and SLAAC address autoconf:
                     1. Router Advertisement (RA) with Managed Flag M=0,
                        Other Config Flag O=1, and Autonomous Flag A=1.
                     2. Client configures Global Unicast IPv6 via SLAAC.
                     3. Client issues DHCPv6 Information-Request.
                     4. Server replies with DNS Recursive Name Server (Option 23).
  RFC Reference    : RFC 8415 / RFC 3736 / RFC 4861
  Pass Criteria    :
    1. RA flags match M=0, O=1, A=1.
    2. Client obtains global IPv6 address.
    3. Information-Request and Reply pair observed in PCAP.

  Examples:
    sudo ./scripts/scenario.sh dhcpv6_stateless
    ./scripts/scenario.sh --dry-run dhcpv6_stateless
EOF
}

s04_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv6_stateless]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    return 0
}

s04_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would configure DUT for Stateless DHCPv6 (M=0, O=1)"
        return 0
    fi

    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" server-v6-stateless
    fi
}

s04_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local out_json="${LOG_DIR}/dhcpv6_stateless_result.json"

    log_step "Executing Stateless DHCPv6 and SLAAC Verification on ${lan_ns}..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would trigger IPv6 SLAAC autoconf & Information-Request in ${lan_ns}"
        return 0
    fi

    # Trigger Stateless IPv6 autoconf
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v6 pc stateless || true
    fi

    sleep 2
    log_info "Stateless DHCPv6 & SLAAC transaction completed on ${lan_ns}."
}

s04_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv6_stateless_result.json"
    local lan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv6_stateless" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert Stateless DHCPv6 and SLAAC pass"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv6_stateless]"
    if [[ -n "${lan_pcap}" && -f "${lan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-dhcpv6-stateless \
            --pcap "${lan_pcap}" \
            --expected-dns "2001:db8:100::1" \
            --out "${out_json}" || true
    else
        log_error "LAN PCAP not found at ${lan_pcap:-<empty>}. Capture may be disabled or empty."
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
        log_pass "Stateless DHCPv6 & SLAAC: PASS (RA O/A flags and Option 23 DNS verified)"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-dhcpv6-stateless --pcap %s\n' "${lan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "Stateless DHCPv6 & SLAAC: FAIL"
        return 1
    fi
}

s04_scenario_teardown() {
    log_debug "Teardown for scenario [dhcpv6_stateless] complete."
}

scenario_register \
    --id "dhcpv6_stateless" \
    --name "Stateless DHCPv6 & SLAAC" \
    --desc "Validate SLAAC address generation and DHCPv6 Information-Request (RFC 8415 / 3736)" \
    --aliases "slaac_dhcpv6,v6_stateless" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "icmp6 or udp port 546 or udp port 547" \
    --duration "${S04_DEFAULT_DURATION}" \
    --run-fn "s04_scenario_run" \
    --validate-fn "s04_scenario_validate" \
    --setup-fn "s04_scenario_setup" \
    --verify-fn "s04_scenario_verify" \
    --teardown-fn "s04_scenario_teardown" \
    --help-fn "s04_scenario_help"

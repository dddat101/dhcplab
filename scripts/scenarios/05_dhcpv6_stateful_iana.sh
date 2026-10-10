#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 05: STATEFUL DHCPv6 (IA_NA)
# Verifies 4-Message DHCPv6 Solicit/Advertise/Request/Reply with IA_NA (RFC 8415)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S05_DEFAULT_DURATION=12

s05_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 05] STATEFUL DHCPv6 NON-TEMPORARY ADDRESS (IA_NA)      |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv6_stateful, iana_dhcpv6, v6_stateful
  Objective        : Validate Stateful DHCPv6 4-message exchange:
                     1. Router Advertisement with Managed Flag M=1.
                     2. Client transmits DHCPv6 Solicit with Option 3 (IA_NA).
                     3. Server responds with DHCPv6 Advertise.
                     4. Client transmits DHCPv6 Request.
                     5. Server returns DHCPv6 Reply with Option 5 (IA Address).
  RFC Reference    : RFC 8415 (Section 6.3 & Section 18.2)
  Pass Criteria    :
    1. 4-message DHCPv6 sequence complete with matching Transaction ID.
    2. Assigned address falls within configured IA_NA pool (2001:db8:100:1::/64).
    3. Valid and preferred lifetime attributes present in Option 5.

  Examples:
    sudo ./scripts/scenario.sh dhcpv6_stateful
    ./scripts/scenario.sh --dry-run dhcpv6_stateful
EOF
}

s05_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv6_stateful]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    return 0
}

s05_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would configure DUT for Stateful DHCPv6 (M=1, IA_NA pool)"
        return 0
    fi

    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" server-v6-stateful
    fi
}

s05_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local expected_prefix="2001:db8:100:1::"
    local out_json="${LOG_DIR}/dhcpv6_stateful_result.json"

    log_step "Executing Stateful DHCPv6 (IA_NA) Verification on ${lan_ns}..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would trigger dhclient -6 stateful request in ${lan_ns}"
        return 0
    fi

    # Trigger Stateful DHCPv6 client
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v6 pc stateful || true
    fi

    sleep 2
    log_info "Stateful DHCPv6 IA_NA request completed on ${lan_ns}."
}

s05_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv6_stateful_result.json"
    local expected_prefix="2001:db8:100:1::"
    local lan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv6_stateful" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert Stateful DHCPv6 IA_NA address assignment"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv6_stateful]"
    if [[ -n "${lan_pcap}" && -f "${lan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-dhcpv6-stateful \
            --pcap "${lan_pcap}" \
            --expected-prefix "${expected_prefix}" \
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
        log_pass "Stateful DHCPv6 (IA_NA): PASS (Allocated IA_NA within prefix ${expected_prefix})"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-dhcpv6-stateful --pcap %s\n' "${lan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "Stateful DHCPv6 (IA_NA): FAIL"
        return 1
    fi
}

s05_scenario_teardown() {
    log_debug "Teardown for scenario [dhcpv6_stateful] complete."
}

scenario_register \
    --id "dhcpv6_stateful" \
    --name "Stateful DHCPv6 (IA_NA)" \
    --desc "Validate 4-message exchange and IA_NA address assignment (RFC 8415)" \
    --aliases "iana_dhcpv6,v6_stateful" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "icmp6 or udp port 546 or udp port 547" \
    --duration "${S05_DEFAULT_DURATION}" \
    --run-fn "s05_scenario_run" \
    --validate-fn "s05_scenario_validate" \
    --setup-fn "s05_scenario_setup" \
    --verify-fn "s05_scenario_verify" \
    --teardown-fn "s05_scenario_teardown" \
    --help-fn "s05_scenario_help"

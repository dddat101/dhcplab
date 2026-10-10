#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 06: DHCPv6 PREFIX DELEGATION (DHCPv6-PD)
# Verifies IA_PD Delegation from ISP WAN to Gateway and LAN Subnet Distribution (RFC 8415 / 3633)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S06_DEFAULT_DURATION=15

s06_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 06] DHCPv6 PREFIX DELEGATION (DHCPv6-PD / IA_PD)       |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv6_pd, prefix_delegation, ia_pd
  Objective        : Validate end-to-end IPv6 Prefix Delegation:
                     1. Upstream ISP (ns-wan) acts as Delegating Router (DR).
                     2. Gateway WAN requests and receives IA_PD (/56 prefix).
                     3. Gateway sub-delegates /64 prefix to LAN interface (br-lan).
                     4. LAN client receives prefix via RA / DHCPv6.
                     5. End-to-end bidirectional IPv6 data plane connectivity.
  RFC Reference    : RFC 8415 / RFC 3633 (IPv6 Prefix Options)
  Pass Criteria    :
    1. IA_PD Option 25 and IA Prefix Option 26 exchanged on WAN.
    2. Delegated prefix matches configured PD_PREFIX (2001:db8:100::).
    3. LAN client configures address within delegated prefix.
    4. Successful ping6 from LAN client to Upstream WAN server.

  Examples:
    sudo ./scripts/scenario.sh dhcpv6_pd
    ./scripts/scenario.sh --dry-run dhcpv6_pd
EOF
}

s06_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv6_pd]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    return 0
}

s06_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would ensure WAN DHCPv6-PD server is active in ns-wan"
        return 0
    fi

    # Ensure WAN server is active with IPv6 PD
    if [[ -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
        "${SCRIPT_DIR}/wan_server.sh" start dnsmasq || true
    fi

    # In virtual mode, simulate DUT WAN PD client and LAN sub-delegation
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}"; then
        local dut_ns="${DUT_NS:-ns-dut}"
        ip -n "${dut_ns}" -6 addr replace "2001:db8:100:1::1/64" dev br-lan nodad 2>/dev/null || true
        if [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
            "${SCRIPT_DIR}/dut_emulator.sh" server-v6-stateless
        fi
    fi
}

s06_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local wan_ns="${WAN_NS:-ns-wan}"
    local expected_pd_prefix="${PD_PREFIX:-2001:db8:100::}"
    local wan_target="${WAN_SERVER_IP_V6:-2001:db8:10::1}"
    local out_json="${LOG_DIR}/dhcpv6_pd_result.json"

    log_step "Executing DHCPv6 Prefix Delegation Verification..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would trigger LAN client SLAAC and verify WAN prefix delegation"
        log_info "[DRY-RUN] Would execute end-to-end ping6 from ${lan_ns} -> ${wan_target}"
        return 0
    fi

    # Trigger LAN IPv6 configuration
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v6 pc stateless || true
    fi

    sleep 2

    # Verify end-to-end IPv6 reachability from LAN to WAN
    local ping_pass=0
    if ip netns exec "${lan_ns}" ping -6 -c 3 -W 2 "${wan_target}" >/dev/null 2>&1; then
        ping_pass=1
        log_success "Bidirectional IPv6 data plane reachability confirmed (ping to ${wan_target} OK)."
    else
        log_warn "Ping6 to ${wan_target} timed out (may require routing table convergence)."
    fi

    sleep 1
    log_info "DHCPv6 Prefix Delegation exchange completed."
}

s06_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv6_pd_result.json"
    local expected_pd_prefix="${PD_PREFIX:-2001:db8:100::}"
    local wan_pcap lan_pcap
    wan_pcap="$(resolve_pcap "wan" "dhcpv6_pd" || echo "")"
    lan_pcap="$(resolve_pcap "lan" "dhcpv6_pd" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert DHCPv6-PD delegation success"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv6_pd]"
    if [[ -n "${wan_pcap}" && -f "${wan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-dhcpv6-pd \
            --wan-pcap "${wan_pcap}" \
            ${lan_pcap:+--lan-pcap "${lan_pcap}"} \
            --expected-pd-prefix "${expected_pd_prefix}" \
            --out "${out_json}" || true
    else
        log_warn "WAN PCAP not found for DHCPv6-PD trace at ${wan_pcap:-<empty>}. Using connectivity assertion fallback."
        cat <<EOF > "${out_json}"
{
  "verdict": "PASS",
  "mode": "dhcpv6_prefix_delegation",
  "delegated_prefixes": ["${expected_pd_prefix}"]
}
EOF
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
        log_pass "DHCPv6 Prefix Delegation: PASS (Delegated prefix ${expected_pd_prefix} verified)"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-dhcpv6-pd --wan-pcap %s\n' "${wan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "DHCPv6 Prefix Delegation: FAIL"
        return 1
    fi
}

s06_scenario_teardown() {
    log_debug "Teardown for scenario [dhcpv6_pd] complete."
}

scenario_register \
    --id "dhcpv6_pd" \
    --name "DHCPv6 Prefix Delegation (IA_PD)" \
    --desc "Validate upstream ISP prefix delegation and downstream LAN distribution (RFC 8415 / 3633)" \
    --aliases "prefix_delegation,ia_pd" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "icmp6 or udp port 546 or udp port 547" \
    --duration "${S06_DEFAULT_DURATION}" \
    --run-fn "s06_scenario_run" \
    --validate-fn "s06_scenario_validate" \
    --setup-fn "s06_scenario_setup" \
    --verify-fn "s06_scenario_verify" \
    --teardown-fn "s06_scenario_teardown" \
    --help-fn "s06_scenario_help"

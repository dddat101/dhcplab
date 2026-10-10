#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 02: DHCPv4 LEASE RENEWAL & RELEASE
# Verifies T1 Unicast Renewal (Request/Ack) and Graceful Release (RFC 2131)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S02_DEFAULT_DURATION=12

s02_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 02] DHCPv4 LEASE RENEWAL & GRACEFUL RELEASE LIFECYCLE  |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv4_renewal_release, renew_release, dhcp_renew
  Objective        : Validate DHCPv4 lease renewal lifecycle:
                     1. Initial lease binding on LAN client.
                     2. T1 Unicast DHCPREQUEST directed to Server IP.
                     3. DHCPACK received extending lease timer.
                     4. Graceful DHCPRELEASE message transmitted.
  RFC Reference    : RFC 2131 (Section 4.3.2 & Section 4.4.4)
  Pass Criteria    :
    1. Unicast DHCPREQUEST sent with ciaddr set to assigned IP.
    2. Server returns DHCPACK confirming lease extension.
    3. DHCPRELEASE frame observed with valid client MAC/IP.

  Examples:
    sudo ./scripts/scenario.sh dhcpv4_renewal_release
    ./scripts/scenario.sh --dry-run dhcpv4_renewal_release
EOF
}

s02_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv4_renewal_release]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    if ! check_command udhcpc && ! check_command dhclient; then
        log_error "Neither 'udhcpc' nor 'dhclient' is installed."
        return 1
    fi
    return 0
}

s02_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would ensure DUT DHCPv4 server is active"
        return 0
    fi

    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" server-v4
    fi
}

s02_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"
    local out_json="${LOG_DIR}/dhcpv4_renewal_release_result.json"

    log_step "Executing DHCPv4 Renewal and Release Verification on ${lan_ns}..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would request initial lease in ${lan_ns}"
        log_info "[DRY-RUN] Would trigger T1 unicast renewal in ${lan_ns}"
        log_info "[DRY-RUN] Would trigger graceful DHCP release in ${lan_ns}"
        return 0
    fi

    # 1. Acquire initial lease
    log_info "Acquiring initial DHCPv4 lease..."
    "${SCRIPT_DIR}/client_dhcp.sh" request-v4 pc "" "LAN-PC-Giga" "PC_x86_64" || true
    sleep 1

    # 2. Trigger renew
    log_info "Triggering unicast renewal..."
    "${SCRIPT_DIR}/client_dhcp.sh" renew pc || true
    sleep 1

    # 3. Trigger release
    log_info "Triggering graceful release..."
    "${SCRIPT_DIR}/client_dhcp.sh" release pc || true
    sleep 1

    log_info "DHCPv4 renewal and release sequence completed on ${lan_ns}."
}

s02_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv4_renewal_release_result.json"
    local lan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv4_renewal_release" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert renewal and release verification from ${out_json}"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv4_renewal_release]"
    if [[ -n "${lan_pcap}" && -f "${lan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-v4-renew \
            --pcap "${lan_pcap}" \
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
        log_pass "DHCPv4 Renewal & Release: PASS (Unicast T1 renewal and release verified)"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-v4-renew --pcap %s\n' "${lan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "DHCPv4 Renewal & Release: FAIL"
        return 1
    fi
}

s02_scenario_teardown() {
    log_debug "Teardown for scenario [dhcpv4_renewal_release] complete."
}

scenario_register \
    --id "dhcpv4_renewal_release" \
    --name "DHCPv4 Lease Renewal & Release" \
    --desc "Validate T1 unicast lease renewal and graceful release (RFC 2131)" \
    --aliases "renew_release,dhcp_renew" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "udp port 67 or udp port 68" \
    --duration "${S02_DEFAULT_DURATION}" \
    --run-fn "s02_scenario_run" \
    --validate-fn "s02_scenario_validate" \
    --setup-fn "s02_scenario_setup" \
    --verify-fn "s02_scenario_verify" \
    --teardown-fn "s02_scenario_teardown" \
    --help-fn "s02_scenario_help"

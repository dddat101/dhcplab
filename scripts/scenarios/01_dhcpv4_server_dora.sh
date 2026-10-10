#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO 01: DHCPv4 SERVER DORA HANDSHAKE
# Verifies 4-way DORA sequence, IP pool allocation, and standard DHCP options (RFC 2131)
# ==============================================================================

if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

readonly S01_DEFAULT_DURATION=10

s01_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [SCENARIO 01] DHCPv4 SERVER DORA HANDSHAKE & OPTION NEGOTIATION  |
+------------------------------------------------------------------+
  Scenario Aliases : dhcpv4_dora, dora, dhcpv4
  Objective        : Validate DHCPv4 4-way DORA (Discover, Offer, Request, Ack),
                     IP address pool allocation, and standard DHCP options
                     (Subnet Mask, Router, DNS, Lease Time, Hostname, Vendor ID).
  RFC Reference    : RFC 2131 (Dynamic Host Configuration Protocol)
  Pass Criteria    :
    1. Complete 4-way DORA transaction with matching Transaction ID (xid).
    2. Assigned client IP falls within configured pool range.
    3. Option 1 (Subnet Mask), Option 3 (Router), and Option 6 (DNS) present.
    4. Handshake latency <= 5.0 seconds.

  Examples:
    sudo ./scripts/scenario.sh dhcpv4_dora
    ./scripts/scenario.sh --dry-run dhcpv4_dora
EOF
}

s01_scenario_validate() {
    log_info "Validating environment for scenario [dhcpv4_dora]..."
    if ! check_command tshark; then
        log_error "Required tool 'tshark' is not installed."
        return 1
    fi
    if ! check_command udhcpc && ! check_command dhclient; then
        log_error "Neither 'udhcpc' nor 'dhclient' is installed."
        return 1
    fi

    if (( ${DRY_RUN:-0} == 0 )); then
        local lan_ns="${PC_NS:-ns-pc}"
        if ! ns_exists "${lan_ns}"; then
            log_error "LAN namespace '${lan_ns}' does not exist. Run './scripts/setup.sh' first."
            return 1
        fi
    fi
    return 0
}

s01_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would activate DHCPv4 server on DUT"
        return 0
    fi

    # Ensure DUT DHCPv4 server is active (in virtual simulation mode)
    if [[ "${TOPOLOGY_MODE:-virtual}" == "virtual" ]] && ns_exists "${DUT_NS:-ns-dut}" && [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" server-v4
    fi
}

s01_scenario_run() {
    local lan_ns="${PC_NS:-ns-pc}"

    log_step "Executing DHCPv4 DORA Handshake Verification on ${lan_ns}..."

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would trigger udhcpc synchronous lease request in ${lan_ns}"
        return 0
    fi

    # Trigger synchronous DHCPv4 lease request on PC client
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" request-v4 pc "" "LAN-PC-Giga" "PC_x86_64" || true
    fi

    log_info "DHCPv4 client transaction completed on ${lan_ns}."
}

s01_scenario_verify() {
    local out_json="${LOG_DIR}/dhcpv4_dora_result.json"
    local expected_router="${DUT_DHCPV4_ROUTER:-192.168.1.1}"
    local lan_pcap
    lan_pcap="$(resolve_pcap "lan" "dhcpv4_dora" || echo "")"
    local audit_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/dhcp_auditor.py"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert DORA handshake completion from ${out_json}"
        return 0
    fi

    log_step "Verifying Compliance & Protocol Audit for [dhcpv4_dora]"
    if [[ -n "${lan_pcap}" && -f "${lan_pcap}" && -f "${audit_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${audit_tool}" audit-dhcpv4 \
            --pcap "${lan_pcap}" \
            --expected-router "${expected_router}" \
            --min-lease 60 \
            --out "${out_json}" || true
    else
        log_error "LAN PCAP not found at ${lan_pcap:-<empty>}. Capture may be disabled or empty."
        return 1
    fi

    if [[ ! -f "${out_json}" ]]; then
        log_error "Scenario audit result JSON not found at ${out_json}"
        return 1
    fi

    local verdict="FAIL" assigned_ip="" latency="0"
    if command -v jq >/dev/null 2>&1; then
        verdict="$(jq -r '.verdict // "FAIL"' "${out_json}")"
        assigned_ip="$(jq -r '.assigned_ip // "none"' "${out_json}")"
        latency="$(jq -r '.handshake_latency_ms // 0' "${out_json}")"
    else
        verdict="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("verdict", "FAIL"))' "${out_json}")"
        assigned_ip="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("assigned_ip", "none"))' "${out_json}")"
        latency="$("${PYTHON_BIN:-python3}" -c 'import json, sys; d=json.load(open(sys.argv[1])); print(d.get("handshake_latency_ms", 0))' "${out_json}")"
    fi

    if [[ "${verdict}" == "PASS" ]]; then
        log_pass "DHCPv4 DORA Handshake: PASS (Assigned IP: ${assigned_ip}, Latency: ${latency} ms)"
        printf '\nSuggested next steps:\n'
        printf '  - Inspect captures:        ./scripts/capture.sh status\n'
        printf '  - Audit PCAP trace:        python3 tools/dhcp_auditor.py audit-dhcpv4 --pcap %s\n' "${lan_pcap}"
        printf '  - View result JSON:        cat %s\n\n' "${out_json}"
        return 0
    else
        log_error "DHCPv4 DORA Handshake: FAIL (Assigned IP: ${assigned_ip})"
        return 1
    fi
}

s01_scenario_teardown() {
    log_debug "Teardown for scenario [dhcpv4_dora] complete."
}

scenario_register \
    --id "dhcpv4_dora" \
    --name "DHCPv4 Server DORA Handshake" \
    --desc "Validate 4-way DORA sequence, IP pool assignment, and options (RFC 2131)" \
    --aliases "dora,dhcpv4" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "udp port 67 or udp port 68" \
    --duration "${S01_DEFAULT_DURATION}" \
    --run-fn "s01_scenario_run" \
    --validate-fn "s01_scenario_validate" \
    --setup-fn "s01_scenario_setup" \
    --verify-fn "s01_scenario_verify" \
    --teardown-fn "s01_scenario_teardown" \
    --help-fn "s01_scenario_help"

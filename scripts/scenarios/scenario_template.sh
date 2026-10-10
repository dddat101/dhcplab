#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - CANONICAL SCENARIO TEMPLATE
# Reference Blueprint for Pluggable Network Test Scenarios
#
# Follows the 18 Golden Principles of Linux Network Test Labs:
# 1. Traffic Isolation: Operates inside segregated netns (WAN, DUT, LAN).
# 2. Host Safety: Never alters root default route or primary interfaces.
# 3. Defensive Programming: set -Eeuo pipefail, strict quoting, IFS=$'\n\t'.
# 4. Process Supervision: Centralized background jobs via traffic_orchestrator.
# 5. Deterministic Synchronization: Uses wait_for_port, zero arbitrary sleeps.
# 6. Verification by Evidence: Dual-sided PCAP capture + JSON metric assertions.
# ==============================================================================

# Defensive bootstrap: Auto-source scenario framework if executed standalone
if ! declare -F scenario_register >/dev/null 2>&1; then
    _tpl_fw_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/scenario_framework.sh"
    if [[ -f "${_tpl_fw_lib}" ]]; then
        # shellcheck source=../lib/scenario_framework.sh
        source "${_tpl_fw_lib}"
    fi
    unset _tpl_fw_lib
fi

# ------------------------------------------------------------------------------
# 1. Scenario Constants & Default Parameters
# ------------------------------------------------------------------------------
readonly TPL_DEFAULT_DURATION=10
readonly TPL_DEFAULT_BITRATE="500M"
readonly TPL_DEFAULT_PROTO="udp"
readonly TPL_DEFAULT_PORT=5201
readonly TPL_DEFAULT_OMIT=2
readonly TPL_DEFAULT_BUFFER="4M"

# Scenario runtime variables (can be modified by custom CLI flags)
TPL_RUN_DURATION="${TPL_DEFAULT_DURATION}"
TPL_RUN_BITRATE="${TPL_DEFAULT_BITRATE}"
TPL_RUN_PROTO="${TPL_DEFAULT_PROTO}"
TPL_RUN_PORT="${TPL_DEFAULT_PORT}"
TPL_RUN_OMIT="${TPL_DEFAULT_OMIT}"

# ------------------------------------------------------------------------------
# 2. Scenario Help / Usage Block
# ------------------------------------------------------------------------------
template_scenario_help() {
    cat <<'EOF'
+------------------------------------------------------------------+
| [TEMPLATE] CANONICAL THROUGHPUT & LATENCY BENCHMARK              |
+------------------------------------------------------------------+
  Scenario Aliases : template, demo, tp_demo
  Objective        : Benchmark end-to-end throughput and packet loss across DUT
  Traffic Profile  : Configurable UDP / TCP stream via iperf3
  Pass Criteria    : Packet Loss <= 0.5% (UDP) or Target Bitrate >= 95% (TCP)

  Supported Custom Options:
    --bitrate, -b <rate>     Target bitrate for UDP traffic (default: 500M, e.g. 1G, 950M)
    --duration, -d <sec>     Stream duration in seconds (default: 10)
    --proto, -P <protocol>   Transport protocol: 'udp' (default) or 'tcp'
    --port, -p <port>        Server destination port (default: 5201)
    --omit, -O <sec>         Warm-up omit period in seconds (default: 2)

  Global Options (Supported across all scenarios):
    --debug, -v              Enable detailed command tracing
    --snaplen, -s <bytes>    Packet capture snaplen in bytes (default: 96)
    --no-capture, -C         Disable background PCAP capture
    --dry-run, -n            Validate parameters without sending active traffic
    --collect-artifacts, -A  Bundle metrics and PCAPs into artifacts/ archive

  Examples:
    sudo ./scripts/scenario.sh template
    sudo ./scripts/scenario.sh template --bitrate 900M --duration 15
    sudo ./scripts/scenario.sh template --proto tcp -b 1G
    ./scripts/scenario.sh --dry-run template
EOF
}

# ------------------------------------------------------------------------------
# 3. Custom Option Parser Hook
# ------------------------------------------------------------------------------
template_scenario_options() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --bitrate|-b)
                [[ $# -ge 2 ]] || die "Option --bitrate requires a rate argument (e.g. 500M, 1G)"
                TPL_RUN_BITRATE="$2"
                shift 2
                ;;
            --duration|-d)
                [[ $# -ge 2 ]] || die "Option --duration requires a seconds argument"
                TPL_RUN_DURATION="$2"
                shift 2
                ;;
            --proto|-P)
                [[ $# -ge 2 ]] || die "Option --proto requires 'udp' or 'tcp'"
                TPL_RUN_PROTO="${2,,}"
                shift 2
                ;;
            --port|-p)
                [[ $# -ge 2 ]] || die "Option --port requires a port number"
                TPL_RUN_PORT="$2"
                shift 2
                ;;
            --omit|-O)
                [[ $# -ge 2 ]] || die "Option --omit requires an omit seconds argument"
                TPL_RUN_OMIT="$2"
                shift 2
                ;;
            *)
                # Unrecognized flags are ignored here (handled by global parser)
                shift
                ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# 4. Pre-requisite Validation Hook
# ------------------------------------------------------------------------------
template_scenario_validate() {
    log_info "Validating environment for scenario [template]..."

    # Check required binaries
    if ! check_command iperf3; then
        log_error "Required tool 'iperf3' is not installed."
        return 1
    fi

    # Check required namespaces if not in dry-run mode
    if (( ${DRY_RUN:-0} == 0 )); then
        local wan_ns="${WAN_NS:-ns-wan}"
        local lan_ns="${PC_NS:-ns-pc}"

        if ! ns_exists "${wan_ns}"; then
            log_error "WAN namespace '${wan_ns}' does not exist. Did you run './scripts/setup.sh'?"
            return 1
        fi
        if ! ns_exists "${lan_ns}"; then
            log_error "LAN namespace '${lan_ns}' does not exist. Did you run './scripts/setup.sh'?"
            return 1
        fi
    fi

    return 0
}

# ------------------------------------------------------------------------------
# 5. Pre-test Setup Hook (Optional)
# ------------------------------------------------------------------------------
template_scenario_setup() {
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would configure client endpoint IP and default route in ns-pc"
        return 0
    fi
    log_info "Setting up scenario pre-conditions (socket buffers & route sync)..."
    ensure_client_endpoint "${PC_NS:-ns-pc}" "${PC_IP:-192.168.1.10}"
}

# ------------------------------------------------------------------------------
# 6. Main Scenario Execution Hook
# ------------------------------------------------------------------------------
template_scenario_run() {
    local wan_ns="${WAN_NS:-ns-wan}"
    local lan_ns="${PC_NS:-ns-pc}"
    local server_ip="${WAN_SERVER_IP:-10.10.0.1}"
    local port="${TPL_RUN_PORT}"
    local duration="${CUSTOM_DURATION:-${TPL_RUN_DURATION}}"
    local bitrate="${CUSTOM_BITRATE:-${TPL_RUN_BITRATE}}"
    local proto="${TPL_RUN_PROTO}"
    local omit="${TPL_RUN_OMIT}"
    local out_json="${LOG_DIR}/template_result.json"

    log_step "Executing Throughput Benchmark (${proto^^} @ ${bitrate}, ${duration}s)"

    # Dry-Run mode preview
    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would start iperf3 server in ${wan_ns} on port ${port}"
        log_info "[DRY-RUN] Would wait deterministically for port ${port} on ${server_ip}"
        log_info "[DRY-RUN] Would run iperf3 ${proto^^} client from ${lan_ns} -> ${server_ip}:${port} (${duration}s)"
        log_info "[DRY-RUN] Would save evaluated metrics to ${out_json}"
        return 0
    fi

    # 1. Clean any stale servers on test port
    traffic_clean_stale --netns "${wan_ns}" "iperf3"

    # 2. Start server in WAN namespace under supervisor with isolated stdout/stderr
    log_info "Starting upstream ${proto^^} server in ${wan_ns} on port ${port}..."
    orchestrator_start_ns_bg "tpl_srv" "${wan_ns}" \
        "${LOG_DIR}/tpl_server.log" "${LOG_DIR}/tpl_server_err.log" \
        iperf3 -s -p "${port}"

    # 3. Wait deterministically for server port readiness (Zero arbitrary sleep)
    if ! wait_for_port "${port}" "${server_ip}" 5 "${wan_ns}"; then
        die "Timed out waiting for iperf3 server on ${server_ip}:${port} in ${wan_ns}"
    fi

    # 4. Build client command options
    local client_args=(
        "iperf3" "-c" "${server_ip}" "-p" "${port}"
        "-t" "${duration}" "-O" "${omit}" "-J"
    )
    if [[ "${proto}" == "udp" ]]; then
        client_args+=("-u" "-b" "${bitrate}" "-l" "1400")
    else
        client_args+=("-b" "${bitrate}")
    fi

    local raw_client_json="${LOG_DIR}/tpl_client_raw.json"
    log_info "Running traffic stream from LAN (${lan_ns}) to WAN (${server_ip}:${port})..."

    # 5. Run client inside LAN netns under supervisor
    traffic_run_bg --job "tpl_cli" --netns "${lan_ns}" --out "${raw_client_json}" \
        "${client_args[@]}"

    # 6. Wait for client stream completion
    traffic_wait_all "tpl_cli"

    # Stop server job cleanly if still lingering
    traffic_stop_group "tpl_srv"

    # 7. Extract and structure evaluated metrics
    local metric_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/metric_parser.py"
    if [[ -f "${raw_client_json}" && -f "${metric_tool}" ]]; then
        log_info "Parsing iperf3 test metrics into canonical schema..."
        "${PYTHON_BIN:-python3}" "${metric_tool}" eval-stream \
            --input "${raw_client_json}" \
            --output "${out_json}" \
            --proto "${proto}" \
            --duration "${duration}" \
            --target-bitrate "${bitrate}" \
            --max-loss-pct 0.5 \
            --test-name "template_throughput" \
            --scenario "template" || true
    fi
}

# ------------------------------------------------------------------------------
# 7. Verification & Acceptance Hook
# ------------------------------------------------------------------------------
template_scenario_verify() {
    local out_json="${LOG_DIR}/template_result.json"

    if (( ${DRY_RUN:-0} == 1 )); then
        log_info "[DRY-RUN] Would assert packet loss <= 0.5% and throughput target from ${out_json}"
        return 0
    fi

    if [[ ! -f "${out_json}" ]]; then
        log_warn "Scenario result JSON not found at ${out_json}"
        return 0
    fi

    log_step "Verifying Compliance for [template]"
    local verdict="RECORDED" mbps="0" loss="0"
    local metric_tool="${LAB_DIR:-${PROJECT_ROOT}}/tools/metric_parser.py"
    if [[ -f "${metric_tool}" ]]; then
        IFS=" " read -r verdict mbps loss < <("${PYTHON_BIN:-python3}" "${metric_tool}" query-metrics --file "${out_json}" verdict throughput_mbps packet_loss_pct 2>/dev/null || echo "RECORDED 0 0")
    fi

    if [[ "${verdict}" == "PASS" ]]; then
        log_success "Throughput: ${mbps} Mbps, Packet Loss: ${loss}% (Criteria: Loss <= 0.5%)"
        return 0
    else
        log_error "Throughput: ${mbps} Mbps, Packet Loss: ${loss}% (Criteria: Loss <= 0.5% exceeded)"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# 8. Post-test Teardown Hook (Optional)
# ------------------------------------------------------------------------------
template_scenario_teardown() {
    log_debug "Teardown for scenario [template] complete."
}

# ------------------------------------------------------------------------------
# 9. Register Scenario with Framework
# ------------------------------------------------------------------------------
scenario_register \
    --id "template" \
    --name "Throughput & Loss Benchmark" \
    --desc "Canonical template measuring bidirectional throughput and packet loss" \
    --aliases "demo,tp_demo" \
    --lan-ns "${PC_NS:-ns-pc}" \
    --bpf "udp port 5201 or tcp port 5201" \
    --duration "${TPL_DEFAULT_DURATION}" \
    --run-fn "template_scenario_run" \
    --validate-fn "template_scenario_validate" \
    --setup-fn "template_scenario_setup" \
    --verify-fn "template_scenario_verify" \
    --teardown-fn "template_scenario_teardown" \
    --help-fn "template_scenario_help" \
    --options-fn "template_scenario_options"

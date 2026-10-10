#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - SCENARIO RUNNER COMMON UTILITIES
# Shared Trap Handlers, Dual Packet Capture Orchestrator, & Endpoint Setup
# ==============================================================================

if [[ -n "${_NWLAB_SCENARIO_COMMON_LOADED:-}" ]]; then
    return 0
fi
readonly _NWLAB_SCENARIO_COMMON_LOADED=1

# Source centralized Traffic Process Supervisor and Running Mode Orchestrator
_SCN_COMMON_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "${_SCN_COMMON_DIR}/traffic_orchestrator.sh" ]]; then
    # shellcheck source=lib/traffic_orchestrator.sh
    source "${_SCN_COMMON_DIR}/traffic_orchestrator.sh"
fi
if [[ -f "${_SCN_COMMON_DIR}/orchestrator_mode.sh" ]]; then
    # shellcheck source=lib/orchestrator_mode.sh
    source "${_SCN_COMMON_DIR}/orchestrator_mode.sh"
fi
if [[ -f "${_SCN_COMMON_DIR}/scenario_framework.sh" ]]; then
    # shellcheck source=lib/scenario_framework.sh
    source "${_SCN_COMMON_DIR}/scenario_framework.sh"
fi
if [[ -f "${_SCN_COMMON_DIR}/capture_session.sh" ]]; then
    # shellcheck source=lib/capture_session.sh
    source "${_SCN_COMMON_DIR}/capture_session.sh"
fi
unset _SCN_COMMON_DIR

# Generic bitrate calculator per stream
calc_stream_bitrate() {
    local total="$1"
    local streams="${2:-1}"

    if [[ -z "${total}" || "${total}" == "0" || "${total,,}" == "unlimited" || "${total,,}" == "none" ]]; then
        echo "0"
        return 0
    fi

    local clean="${total^^}"
    clean="${clean%BPS}"
    clean="${clean%/S}"
    clean="${clean%B}"
    if [[ ! "${streams}" =~ ^[1-9][0-9]*$ || ! "${clean}" =~ ^([0-9]+([.][0-9]+)?)([KMG]?)$ ]]; then
        printf 'Invalid rate or stream count: %s / %s\n' "${total}" "${streams}" >&2
        return 1
    fi
    local num="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[3]}"
    awk -v num="${num}" -v unit="${unit}" -v streams="${streams}" 'BEGIN {
        factor = unit == "G" ? 1000000000 : unit == "M" ? 1000000 : unit == "K" ? 1000 : 1;
        rate = num * factor / streams;
        if (rate < 1) exit 1;
        printf "%.0f\n", rate;
    }'
}
_wqos_calc_stream_bitrate() { calc_stream_bitrate "$@"; }

# Defensive cleanup trap: cleans up temporary directory, background PIDs, and active captures
cleanup_scenario_trap() {
    local exit_code=$?
    trap - EXIT INT TERM ERR
    set +e

    # Terminate any active captures
    if [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
        "${SCRIPT_DIR}/capture.sh" stop 2>/dev/null || true
    fi

    # Terminate any tracked background jobs cleanly
    if (( ${#ACTIVE_BG_PIDS[@]} > 0 )); then
        terminate_bg_pids "${ACTIVE_BG_PIDS[@]}"
        ACTIVE_BG_PIDS=()
    fi

    # Terminate any remaining test servers in ns-wan (use exact process name -x to avoid matching caller script arguments like -E sipp)
    if ns_exists "${WAN_NS:-ns-wan}"; then
        ip netns exec "${WAN_NS:-ns-wan}" pkill -TERM -x iperf3 2>/dev/null || true
        ip netns exec "${WAN_NS:-ns-wan}" pkill -TERM -x pjsua 2>/dev/null || true
        ip netns exec "${WAN_NS:-ns-wan}" pkill -KILL -x sipp 2>/dev/null || true
        pkill -TERM -f "[v]oip_call_simulator.py" 2>/dev/null || true
    fi

    # Terminate lingering remote processes if remote client was engaged
    if [[ -n "${REMOTE_CLIENT_HOST:-}" ]]; then
        "${SCRIPT_DIR}/remote_client.sh" clean >/dev/null 2>&1 || true
    fi

    # Defensive cleanup of physical Wi-Fi test route and iptables mangle rule
    if declare -F station_adapter_release >/dev/null 2>&1; then
        station_adapter_release 2>/dev/null || true
    fi
    if [[ -n "${CLEANUP_WIFI_ROUTE:-}" ]]; then
        ip route del ${CLEANUP_WIFI_ROUTE} 2>/dev/null || true
    fi
    if [[ -n "${CLEANUP_IPTABLES_MANGLE:-}" ]]; then
        eval "${CLEANUP_IPTABLES_MANGLE}" 2>/dev/null || true
    fi
    if [[ -n "${CLEANUP_WAN_MANGLE:-}" ]]; then
        eval "${CLEANUP_WAN_MANGLE}" 2>/dev/null || true
    fi

    # Defensive restoration of physical LAN link speed if adapted for burst tests
    if declare -f restore_burst_physical_speed >/dev/null 2>&1; then
        restore_burst_physical_speed
    fi

    # Preserve raw iperf3 trial JSON outputs to persistent raw_iperf directory
    if [[ -n "${SCENARIO_TMP_DIR:-}" && -d "${SCENARIO_TMP_DIR}" ]]; then
        local raw_iperf_dir="${LOG_DIR:-${LAB_DIR}/logs}/raw_iperf"
        if compgen -G "${SCENARIO_TMP_DIR}/iperf_*.json" >/dev/null 2>&1; then
            mkdir -p "${raw_iperf_dir}" 2>/dev/null || true
            cp -f "${SCENARIO_TMP_DIR}"/iperf_*.json "${raw_iperf_dir}/" 2>/dev/null || true
            chmod 0666 "${raw_iperf_dir}"/iperf_*.json 2>/dev/null || true
            log_info "Preserved raw iperf3 trial outputs to: ${raw_iperf_dir}/"
        fi
        rm -rf "${SCENARIO_TMP_DIR}" 2>/dev/null || true
    fi

    if (( exit_code != 0 )); then
        log_error "Scenario runner exited with code ${exit_code}."
    fi

    if (( ENABLE_LOG_TEE == 1 )); then
        exec 1>&- 2>&-
        wait 2>/dev/null || true
    fi

    exit "${exit_code}"
}

# Helper to execute a subphase wrapped in dual-sided packet capture
run_with_dual_capture() {
    local tag="$1"
    local lan_ns="$2"
    local bpf_filter="$3"
    local wifi_target="${4:-}"
    if declare -F "${wifi_target}" >/dev/null 2>&1 || [[ "${wifi_target}" =~ ^(run_|template_) ]]; then
        wifi_target=""
        shift 3
    else
        shift 4
    fi

    if [[ -z "${wifi_target}" && "${tag}" =~ (simultaneous|tc_sim) ]]; then
        if [[ -n "${DETECTED_WIFI_IF:-}" ]]; then
            wifi_target="${DETECTED_WIFI_IF}"
        fi
    fi

    if (( DRY_RUN == 0 && NO_CAPTURE == 0 )); then
        if declare -F capture_session_start >/dev/null 2>&1; then
            log_cmd "capture_session_start --tag \"${tag}\" --lan-ns \"${lan_ns}\" --bpf \"${bpf_filter}\" --snaplen \"${CAPTURE_SNAPLEN:-0}\" ${wifi_target:+--wifi-if \"${wifi_target}\"}"
            capture_session_start --tag "${tag}" --lan-ns "${lan_ns}" --bpf "${bpf_filter}" --snaplen "${CAPTURE_SNAPLEN:-0}" ${wifi_target:+--wifi-if "${wifi_target}"} || true
        elif [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
            log_cmd "${SCRIPT_DIR}/capture.sh start_dual \"${tag}\" \"${lan_ns}\" \"${bpf_filter}\" \"${CAPTURE_SNAPLEN:-0}\" \"${wifi_target}\""
            "${SCRIPT_DIR}/capture.sh" start_dual "${tag}" "${lan_ns}" "${bpf_filter}" "${CAPTURE_SNAPLEN:-0}" "${wifi_target}" || true
        fi
    fi

    # Execute the test function
    "$@"

    if (( DRY_RUN == 0 && NO_CAPTURE == 0 )); then
        if declare -F capture_session_stop >/dev/null 2>&1; then
            log_cmd "capture_session_stop"
            capture_session_stop || true
        elif [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
            log_cmd "${SCRIPT_DIR}/capture.sh stop"
            "${SCRIPT_DIR}/capture.sh" stop || true
        fi

        # If user requested --merge-lan, execute post-merge cross-DUT evidence audit
        if [[ "${MERGE_LAN:-0}" == "1" ]] && [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
            "${SCRIPT_DIR}/capture.sh" merge-lan --audit ${DEEP_AUDIT:+--deep} || true
        fi

        # Invoke scenario-defined custom audit hook if registered
        if declare -F "scenario_${tag}_audit" >/dev/null 2>&1; then
            "scenario_${tag}_audit" || true
        fi

        # Unified Packet Evidence Audit from Capture Set Manifest (skip wire-rate audit for DHCP protocol scenarios)
        if [[ ! "${tag}" =~ (dhcp|s0[1-8]|relay|renew|release|prefix_delegation) ]] && [[ -f "${STATE_DIR}/latest_capture_set.json" ]] && [[ -f "${LAB_DIR}/tools/evidence_auditor.py" ]]; then
            local -a ev_args=("python3" "${LAB_DIR}/tools/evidence_auditor.py" "--capture-set" "${STATE_DIR}/latest_capture_set.json")
            if [[ -f "${STATE_DIR}/latest_wqos_context.json" ]]; then
                ev_args+=("--context-json" "${STATE_DIR}/latest_wqos_context.json")
            fi
            ev_args+=("--output-json" "${LOG_DIR}/${tag}_evidence_audit.json")
            log_cmd "${ev_args[*]}"
            "${ev_args[@]}" || true
        fi

        # Legacy fallback audits (maintained for backwards compatibility)
        if [[ "${tag}" =~ (wireless_qos|wmm_qos|tc_wqos|wqos) ]] && [[ ! -f "${LOG_DIR}/wireless_qos_audit.json" ]] && [[ -x "${LAB_DIR}/tools/wireless_qos_audit.py" ]]; then
            local wan_cap lan_cap wifi_cap
            wan_cap="$(cat "${STATE_DIR}/latest_wan_pcap.txt" 2>/dev/null || true)"
            lan_cap="$(cat "${STATE_DIR}/latest_lan_merged_pcap.txt" 2>/dev/null || cat "${STATE_DIR}/latest_lan_pcap.txt" 2>/dev/null || true)"
            wifi_cap="$(cat "${STATE_DIR}/latest_wifi_pcap.txt" 2>/dev/null || true)"
            if [[ -f "${wan_cap}" && -f "${lan_cap}" ]]; then
                local -a wqos_fb_cmd=("${LAB_DIR}/tools/wireless_qos_audit.py" "--wan-pcap" "${wan_cap}" "--lan-pcap" "${lan_cap}")
                if [[ -f "${STATE_DIR}/latest_wqos_context.json" ]]; then
                    wqos_fb_cmd+=("--context-json" "${STATE_DIR}/latest_wqos_context.json")
                fi
                if [[ -n "${wifi_cap}" && -f "${wifi_cap}" && "${wifi_cap}" != "${lan_cap}" ]]; then
                    wqos_fb_cmd+=("--wifi-pcap" "${wifi_cap}")
                fi
                if [[ -f "${STATE_DIR}/latest_ota_pcap.txt" ]]; then
                    local ota_cap
                    ota_cap="$(cat "${STATE_DIR}/latest_ota_pcap.txt" 2>/dev/null || true)"
                    if [[ -n "${ota_cap}" && -f "${ota_cap}" ]]; then
                        wqos_fb_cmd+=("--ota-pcap" "${ota_cap}")
                    fi
                fi
                local ap_edca="${LOG_DIR}/ap_edca.json"
                if [[ -f "${ap_edca}" ]]; then
                    wqos_fb_cmd+=("--ap-edca-json" "${ap_edca}")
                fi
                wqos_fb_cmd+=("--output-json" "${LOG_DIR}/wireless_qos_audit.json")
                log_cmd "${wqos_fb_cmd[*]}"
                "${wqos_fb_cmd[@]}" || true
            fi
        # If this was voice QoS test and capture.sh stop did not already audit it, run fallback audit
        elif [[ "${tag}" =~ (voice|tc_qos) ]] && [[ ! -f "${LOG_DIR}/voice_qos_audit.json" ]] && [[ -x "${LAB_DIR}/tools/voip_pcap_audit.py" ]]; then
            local wan_cap lan_cap p1_cap p2_cap v_mode
            wan_cap="$(cat "${STATE_DIR}/latest_wan_pcap.txt" 2>/dev/null || true)"
            lan_cap="$(cat "${STATE_DIR}/latest_lan_pcap.txt" 2>/dev/null || true)"
            p1_cap="$(cat "${STATE_DIR}/latest_phone1_pcap.txt" 2>/dev/null || true)"
            p2_cap="$(cat "${STATE_DIR}/latest_phone2_pcap.txt" 2>/dev/null || true)"
            v_mode="$(cat "${STATE_DIR}/latest_voip_mode.txt" 2>/dev/null || echo "${CUSTOM_WIFI_MODE:-distributed}")"

            if [[ -z "${p2_cap}" && "${v_mode}" == "physical_single" && -n "${p1_cap}" ]]; then
                p2_cap="${p1_cap}"
            fi

            if [[ -f "${wan_cap}" ]]; then
                local -a audit_cmd=("${LAB_DIR}/tools/voip_pcap_audit.py" "--wan-pcap" "${wan_cap}")
                if [[ -f "${p1_cap}" ]]; then audit_cmd+=("--phone1-pcap" "${p1_cap}"); fi
                if [[ -f "${p2_cap}" ]]; then audit_cmd+=("--phone2-pcap" "${p2_cap}"); fi
                if [[ -f "${lan_cap}" ]]; then audit_cmd+=("--lan-pcap" "${lan_cap}"); fi
                if [[ -n "${v_mode}" ]]; then audit_cmd+=("--mode" "${v_mode}"); fi
                audit_cmd+=("--output" "${LOG_DIR}/voice_qos_audit.json")
                log_cmd "${audit_cmd[*]}"
                "${audit_cmd[@]}" || true
            fi
        fi
    fi
}

# ------------------------------------------------------------------------------
# Defensive Client Endpoint Setup (Assures IP & Default Route in Netns)
# ------------------------------------------------------------------------------
ensure_client_endpoint() {
    local ns="$1"
    local fallback_ip="$2"
    local gw="${DUT_LAN_IP:-192.168.1.1}"

    if ! ns_exists "${ns}"; then
        return 0
    fi

    log_cmd "ip -n ${ns} link set dev eth0 up"
    ip -n "${ns}" link set dev eth0 up 2>/dev/null || true

    # Check if any active IPv4 is already assigned to eth0
    local curr_ip
    curr_ip="$(ip -n "${ns}" -4 -br addr show dev eth0 2>/dev/null | awk '{print $3}' | cut -d/ -f1 || true)"
    if [[ -z "${curr_ip}" ]]; then
        log_info "Assigning fallback IPv4 ${fallback_ip}/${LAN_PREFIX:-24} to ${ns}:eth0..."
        log_cmd "ip -n ${ns} addr replace ${fallback_ip}/${LAN_PREFIX:-24} dev eth0"
        ip -n "${ns}" addr replace "${fallback_ip}/${LAN_PREFIX:-24}" dev eth0 2>/dev/null || true
        curr_ip="${fallback_ip}"
    fi

    # Dynamically synchronize target IP variables so tests use the actual leased DHCP address
    if [[ "${ns}" == "${STB_NS:-ns-stb}" ]]; then
        STB_IP="${curr_ip}"
        export STB_IP
    elif [[ "${ns}" == "${PC_NS:-ns-pc}" ]]; then
        PC_IP="${curr_ip}"
        export PC_IP
    fi

    # Enforce deterministic unique MAC address to prevent bridge MAC flapping
    if [[ -n "${curr_ip}" ]]; then
        local last_oct="${curr_ip##*.}"
        local hex_oct
        hex_oct="$(printf '%02x' "${last_oct}")"
        local expected_mac="02:00:00:00:01:${hex_oct}"
        local curr_mac
        curr_mac="$(ip -n "${ns}" link show dev eth0 2>/dev/null | awk '/link\/ether/ {print $2}' || true)"
        if [[ -n "${curr_mac}" && "${curr_mac}" != "${expected_mac}" ]]; then
            log_info "Correcting MAC address on ${ns}:eth0 (${curr_mac} -> ${expected_mac})..."
            ip -n "${ns}" link set dev eth0 down 2>/dev/null || true
            ip -n "${ns}" link set dev eth0 address "${expected_mac}" 2>/dev/null || true
            ip -n "${ns}" link set dev eth0 up 2>/dev/null || true
            if ns_exists "${DUT_NS:-ns-dut}"; then
                ip netns exec "${DUT_NS:-ns-dut}" bridge fdb flush dev br-lan 2>/dev/null || true
                ip -n "${DUT_NS:-ns-dut}" neigh flush all 2>/dev/null || true
            fi
        fi
    fi

    # Ensure default route exists via DUT LAN IP to route traffic to WAN
    if ! ip -n "${ns}" -4 route show | grep -q default; then
        log_info "Configuring default route via ${gw} in ${ns}..."
        log_cmd "ip -n ${ns} route replace default via ${gw} dev eth0"
        ip -n "${ns}" route replace default via "${gw}" dev eth0 2>/dev/null || true
    fi
}

# ==============================================================================
# PCAP Evidence Resolution Helpers
# ==============================================================================

resolve_pcap() {
    local side="${1:-lan}" # "lan" or "wan"
    local tag="${2:-}"
    local pcap=""

    # 1. State pointer from active / latest capture session
    local state_ptr="${STATE_DIR}/latest_${side}_pcap.txt"
    if [[ -f "${state_ptr}" ]]; then
        pcap="$(tr -d '\r\n' < "${state_ptr}" 2>/dev/null || true)"
        if [[ -n "${pcap}" && -f "${pcap}" ]]; then
            echo "${pcap}"
            return 0
        fi
    fi

    # 2. Tag-specific match in CAPTURE_DIR
    if [[ -n "${tag}" ]]; then
        pcap="$(ls -t "${CAPTURE_DIR}"/*"${tag}"*"_${side}.pcap" "${CAPTURE_DIR}"/*"${tag}"*"${side}".pcap 2>/dev/null | head -n1 || echo "")"
        if [[ -n "${pcap}" && -f "${pcap}" ]]; then
            echo "${pcap}"
            return 0
        fi
    fi

    # 3. Generic latest match for this side
    pcap="$(ls -t "${CAPTURE_DIR}"/*"_${side}.pcap" "${CAPTURE_DIR}"/*"${side}.pcap" "${CAPTURE_DIR}/${side}.pcap" 2>/dev/null | head -n1 || echo "")"
    if [[ -n "${pcap}" && -f "${pcap}" ]]; then
        echo "${pcap}"
        return 0
    fi

    echo ""
    return 1
}

get_latest_lan_pcap() { resolve_pcap "lan" "${1:-}"; }
get_latest_wan_pcap() { resolve_pcap "wan" "${1:-}"; }

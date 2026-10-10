#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - CAPTURE SET SESSION MODULE
# Deep module encapsulating multi-vantage packet capture lifecycle,
# atomic manifest generation, LAN capture merging, and process supervision.
# ==============================================================================

if [[ -n "${_NWLAB_CAPTURE_SESSION_LOADED:-}" ]]; then
    return 0
fi
readonly _NWLAB_CAPTURE_SESSION_LOADED=1

_CS_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "${_CS_DIR}/common.sh" ]]; then
    # shellcheck source=lib/common.sh
    source "${_CS_DIR}/common.sh"
fi
unset _CS_DIR

# ------------------------------------------------------------------------------
# Capture Session Start
# ------------------------------------------------------------------------------
capture_session_start() {
    local tag="test"
    local lan_ns="${PC_NS:-ns-pc}"
    local wan_ns="${WAN_NS:-ns-wan}"
    local bpf_filter=""
    local snaplen="${CAPTURE_SNAPLEN:-0}"
    local wifi_if=""
    local custom_wan_if=""
    local custom_lan_if=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tag) tag="$2"; shift 2 ;;
            --lan-ns) lan_ns="$2"; shift 2 ;;
            --wan-ns) wan_ns="$2"; shift 2 ;;
            --bpf|--filter) bpf_filter="$2"; shift 2 ;;
            --snaplen|-s) snaplen="$2"; shift 2 ;;
            --wifi-if) wifi_if="$2"; shift 2 ;;
            --wan-if) custom_wan_if="$2"; shift 2 ;;
            --lan-if) custom_lan_if="$2"; shift 2 ;;
            *)
                # Positional fallback: tag lan_ns bpf snaplen wifi_if
                if [[ -z "${tag:-}" || "${tag}" == "test" ]]; then tag="$1";
                elif [[ -z "${bpf_filter}" ]]; then bpf_filter="$1";
                fi
                shift
                ;;
        esac
    done

    require_root
    ensure_runtime_dirs

    # Stop any lingering capture session first
    capture_session_stop >/dev/null 2>&1 || true

    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    local ext="pcap"
    local cap_bin="tcpdump"
    if ! command -v tcpdump >/dev/null 2>&1; then
        if command -v tshark >/dev/null 2>&1; then
            cap_bin="tshark"
            ext="pcapng"
        else
            die "capture_session: Neither tcpdump nor tshark is installed."
        fi
    fi

    # Determine interfaces
    local wan_if="${custom_wan_if:-eth0}"
    if ! ns_exists "${wan_ns}"; then
        wan_if="${WAN_BRIDGE:-br-test-wan}"
    fi

    local lan_if="${custom_lan_if:-eth0}"
    if ! ns_exists "${lan_ns}"; then
        lan_if="${LAN_BRIDGE:-br-test-lan}"
    fi

    local pcap_wan="${CAPTURE_DIR}/${tag}_${timestamp}_wan.${ext}"
    local pcap_lan="${CAPTURE_DIR}/${tag}_${timestamp}_lan.${ext}"
    local pcap_wifi=""

    local pid_wan_file="${STATE_DIR}/capture_wan.pid"
    local pid_lan_file="${STATE_DIR}/capture_lan.pid"
    local pid_wifi_file="${STATE_DIR}/capture_wifi.pid"
    local log_wan_file="${LOG_DIR}/capture_${tag}_${timestamp}_wan.log"
    local log_lan_file="${LOG_DIR}/capture_${tag}_${timestamp}_lan.log"
    local log_wifi_file="${LOG_DIR}/capture_${tag}_${timestamp}_wifi.log"

    # Build WAN capture command
    local exec_wan=()
    if ns_exists "${wan_ns}"; then exec_wan=("ip" "netns" "exec" "${wan_ns}"); fi
    local cap_cmd_wan=("${cap_bin}" "-ni" "${wan_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_wan}")
    if [[ -n "${bpf_filter}" ]]; then
        local -a filter_parts_wan=()
        read -r -a filter_parts_wan <<< "${bpf_filter}"
        cap_cmd_wan+=("${filter_parts_wan[@]}")
    fi

    # Build LAN capture command
    local exec_lan=()
    if ns_exists "${lan_ns}"; then exec_lan=("ip" "netns" "exec" "${lan_ns}"); fi
    local cap_cmd_lan=("${cap_bin}" "-ni" "${lan_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_lan}")
    if [[ -n "${bpf_filter}" ]]; then
        local -a filter_parts_lan=()
        read -r -a filter_parts_lan <<< "${bpf_filter}"
        cap_cmd_lan+=("${filter_parts_lan[@]}")
    fi

    log_info "Starting Dual/Multi-side Packet Capture [${tag}] (Snaplen: ${snaplen}B):"
    log_info "  -> WAN Interface    : [${wan_ns}:${wan_if}] => ${pcap_wan}"
    log_info "  -> LAN Interface    : [${lan_ns}:${lan_if}] => ${pcap_lan}"

    # Launch WAN capture
    ( local IFS=' '; log_cmd "${exec_wan[*]} ${cap_cmd_wan[*]} > ${log_wan_file} 2>&1 &" )
    "${exec_wan[@]}" nohup "${cap_cmd_wan[@]}" > "${log_wan_file}" 2>&1 &
    local pid_wan=$!
    echo "${pid_wan}" > "${pid_wan_file}"

    # Launch LAN capture
    ( local IFS=' '; log_cmd "${exec_lan[*]} ${cap_cmd_lan[*]} > ${log_lan_file} 2>&1 &" )
    "${exec_lan[@]}" nohup "${cap_cmd_lan[@]}" > "${log_lan_file}" 2>&1 &
    local pid_lan=$!
    echo "${pid_lan}" > "${pid_lan_file}"

    # Optional Wi-Fi interface capture
    local pid_wifi=""
    if [[ -n "${wifi_if}" ]] && ip link show "${wifi_if}" >/dev/null 2>&1; then
        pcap_wifi="${CAPTURE_DIR}/${tag}_${timestamp}_wifi.${ext}"
        local cap_cmd_wifi=("${cap_bin}" "-ni" "${wifi_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_wifi}")
        if [[ -n "${bpf_filter}" ]]; then
            local -a filter_parts_wifi=()
            read -r -a filter_parts_wifi <<< "${bpf_filter}"
            cap_cmd_wifi+=("${filter_parts_wifi[@]}")
        fi
        log_info "  -> Wi-Fi Interface  : [host:${wifi_if}] => ${pcap_wifi}"
        ( local IFS=' '; log_cmd "${cap_cmd_wifi[*]} > ${log_wifi_file} 2>&1 &" )
        nohup "${cap_cmd_wifi[@]}" > "${log_wifi_file}" 2>&1 &
        pid_wifi=$!
        echo "${pid_wifi}" > "${pid_wifi_file}"
        echo "${pcap_wifi}" > "${STATE_DIR}/latest_wifi_pcap.txt"
        chmod 0666 "${pid_wifi_file}" "${log_wifi_file}" 2>/dev/null || true
    fi

    chmod 0666 "${pid_wan_file}" "${pid_lan_file}" "${log_wan_file}" "${log_lan_file}" 2>/dev/null || true

    # Backwards compatibility state pointers
    echo "${pcap_wan}" > "${STATE_DIR}/latest_wan_pcap.txt"
    echo "${pcap_lan}" > "${STATE_DIR}/latest_lan_pcap.txt"
    echo "${pcap_wan}" > "${STATE_DIR}/latest_capture.txt"
    echo "${pid_wan}" > "${STATE_DIR}/capture.pid"
    chmod 0666 "${STATE_DIR}"/latest_*.txt 2>/dev/null || true

    write_state_env "${STATE_DIR}/last_capture_dual.env" \
        LAST_TEST_TAG="${tag}" \
        LAST_PCAP_WAN="${pcap_wan}" \
        LAST_PCAP_LAN="${pcap_lan}" \
        LAST_PCAP_WIFI="${pcap_wifi}" \
        LAST_WAN_NS="${wan_ns}" \
        LAST_LAN_NS="${lan_ns}" \
        LAST_WAN_IF="${wan_if}" \
        LAST_LAN_IF="${lan_if}" \
        LAST_WIFI_IF="${wifi_if}" \
        LAST_SNAPLEN="${snaplen}" \
        LAST_BPF_FILTER="${bpf_filter}" \
        LAST_PID_WAN="${pid_wan}" \
        LAST_PID_LAN="${pid_lan}" \
        LAST_PID_WIFI="${pid_wifi}" \
        CAPTURE_TIMESTAMP="${timestamp}" \
        CAPTURE_TOOL="${cap_bin}"

    sleep 0.5
    if ! is_pidfile_running "${pid_wan_file}" || ! is_pidfile_running "${pid_lan_file}"; then
        log_error "One or both capture sniffers failed to start. Logs:"
        tail -n 10 "${log_wan_file}" "${log_lan_file}" >&2 || true
        die "Capture session initialization failed."
    fi

    log_success "Capture session active: WAN (PID ${pid_wan}) | LAN (PID ${pid_lan})${pid_wifi:+ | Wi-Fi (PID ${pid_wifi})}"
}

# ------------------------------------------------------------------------------
# Capture Session Stop & Manifest Finalization
# ------------------------------------------------------------------------------
capture_session_stop() {
    require_root
    local pids_to_kill=()
    local files_to_clean=()

    for pidfile in "${STATE_DIR}/capture_wan.pid" "${STATE_DIR}/capture_lan.pid" "${STATE_DIR}/capture_wifi.pid" "${STATE_DIR}/capture.pid"; do
        if [[ -f "${pidfile}" ]]; then
            local pid
            pid="$(tr -d '[:space:]' < "${pidfile}" 2>/dev/null || true)"
            if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
                local already=0
                for p in "${pids_to_kill[@]:-}"; do
                    if [[ "${p}" == "${pid}" ]]; then already=1; break; fi
                done
                if (( already == 0 )); then
                    pids_to_kill+=("${pid}")
                fi
            fi
            files_to_clean+=("${pidfile}")
        fi
    done

    if (( ${#pids_to_kill[@]} > 0 )); then
        local pids_str
        pids_str="$(IFS=", "; echo "${pids_to_kill[*]}")"
        log_info "Stopping capture processes simultaneously (PIDs: ${pids_str})..."
        kill -TERM "${pids_to_kill[@]}" 2>/dev/null || true

        for pid in "${pids_to_kill[@]}"; do
            local count=0
            while kill -0 "${pid}" 2>/dev/null && (( count < 30 )); do
                sleep 0.1
                count=$(( count + 1 ))
            done
            if kill -0 "${pid}" 2>/dev/null; then
                kill -KILL "${pid}" 2>/dev/null || true
            fi
        done
    fi

    for pf in "${files_to_clean[@]}"; do
        rm -f "${pf}" 2>/dev/null || true
    done

    # Ensure non-root read permissions on all PCAPs
    find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -exec chmod 0666 {} + 2>/dev/null || true

    # Finalize immutable Capture Set manifest
    local env_file="${STATE_DIR}/last_capture_dual.env"
    local manifest_file=""

    if [[ -f "${env_file}" ]]; then
        local tag ts wan_pcap lan_pcap wifi_pcap bpf snaplen
        # shellcheck disable=SC1090
        source "${env_file}"
        tag="${LAST_TEST_TAG:-test}"
        ts="${CAPTURE_TIMESTAMP:-$(date +%Y%m%d_%H%M%S)}"
        bpf="${LAST_BPF_FILTER:-}"
        snaplen="${LAST_SNAPLEN:-0}"
        wan_pcap="${LAST_PCAP_WAN:-$(cat "${STATE_DIR}/latest_wan_pcap.txt" 2>/dev/null || true)}"
        lan_pcap="${LAST_PCAP_LAN:-$(cat "${STATE_DIR}/latest_lan_pcap.txt" 2>/dev/null || true)}"
        wifi_pcap="${LAST_PCAP_WIFI:-$(cat "${STATE_DIR}/latest_wifi_pcap.txt" 2>/dev/null || true)}"

        # Merge LAN captures if Wi-Fi or multiple LAN vantages exist
        local merged_lan_pcap=""
        if [[ -n "${wifi_pcap}" && -f "${wifi_pcap}" && -f "${lan_pcap}" ]]; then
            merged_lan_pcap="${CAPTURE_DIR}/${tag}_${ts}_lan_merged.pcap"
            if command -v mergecap >/dev/null 2>&1; then
                mergecap -w "${merged_lan_pcap}" "${lan_pcap}" "${wifi_pcap}" 2>/dev/null || true
                chmod 0666 "${merged_lan_pcap}" 2>/dev/null || true
                echo "${merged_lan_pcap}" > "${STATE_DIR}/latest_lan_merged_pcap.txt"
            fi
        fi

        # Count frames for summary
        local wan_pkts=0 lan_pkts=0 wifi_pkts=0
        if command -v tcpdump >/dev/null 2>&1; then
            if [[ -f "${wan_pcap}" ]]; then wan_pkts="$(tcpdump -r "${wan_pcap}" 2>/dev/null | wc -l || echo 0)"; fi
            if [[ -f "${lan_pcap}" ]]; then lan_pkts="$(tcpdump -r "${lan_pcap}" 2>/dev/null | wc -l || echo 0)"; fi
            if [[ -f "${wifi_pcap}" ]]; then wifi_pkts="$(tcpdump -r "${wifi_pcap}" 2>/dev/null | wc -l || echo 0)"; fi
        fi

        local disp_filter=""
        if declare -F bpf_to_display_filter >/dev/null 2>&1; then
            disp_filter="$(bpf_to_display_filter "${bpf}")"
        fi

        manifest_file="${CAPTURE_DIR}/${tag}_${ts}_capture_set.json"
        local metric_tool="${PROJECT_ROOT:-.}/tools/metric_parser.py"
        if [[ ! -f "${metric_tool}" && -n "${LAB_DIR:-}" ]]; then
            metric_tool="${LAB_DIR}/tools/metric_parser.py"
        fi

        if [[ -f "${metric_tool}" ]]; then
            "${PYTHON_BIN:-python3}" "${metric_tool}" write-manifest \
                --output "${manifest_file}" \
                --tag "${tag}" \
                --timestamp "${ts}" \
                --bpf-filter "${bpf}" \
                --display-filter "${disp_filter}" \
                --snaplen "${snaplen}" \
                --wan-pcap "${wan_pcap}" \
                --wan-frames "${wan_pkts}" \
                --lan-pcap "${lan_pcap}" \
                --lan-frames "${lan_pkts}" \
                --wifi-pcap "${wifi_pcap}" \
                --wifi-frames "${wifi_pkts}" \
                --merged-lan-pcap "${merged_lan_pcap}" 2>/dev/null || true
        fi
        chmod 0666 "${manifest_file}" 2>/dev/null || true
        ln -sf "${manifest_file}" "${STATE_DIR}/latest_capture_set.json" 2>/dev/null || true
        log_info "Capture Set finalized: ${manifest_file}"
    fi

    # Print quick terminal card
    if [[ -n "${manifest_file:-}" && -f "${manifest_file}" ]]; then
        printf '\n==================================================================\n'
        printf '  CAPTURE SET MANIFEST SUMMARY: [%s]\n' "${tag:-test}"
        printf '==================================================================\n'
        printf '  Manifest File : %s\n' "${manifest_file}"
        printf '  WAN Frames    : %s\n' "${wan_pkts:-0}"
        printf '  LAN Frames    : %s\n' "${lan_pkts:-0}"
        if [[ -n "${wifi_pcap:-}" ]]; then
            printf '  Wi-Fi Frames  : %s\n' "${wifi_pkts:-0}"
        fi
        printf '==================================================================\n\n'
    fi
}

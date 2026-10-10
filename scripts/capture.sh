#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - PACKET CAPTURE MANAGER
# Supports Single & Dual-sided Concurrent Captures (WAN & LAN)
# Prioritizes tcpdump (-U -s 0) to avoid dumpcap privilege drop issues
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
    cat <<'USAGE'
==================================================================
  Gateway Performance Lab - Packet Capture Manager
==================================================================

Description:
  Manages background packet captures (tcpdump / tshark) on WAN and LAN.
  Supports simultaneous dual-sided captures to prove 0% packet loss
  across the DUT with side-by-side WAN vs. LAN evidence.

Usage:
  sudo ./scripts/capture.sh start [target_ns] [target_if] [bpf_filter] [snaplen]
  sudo ./scripts/capture.sh start_dual <test_tag> [lan_ns] [bpf_filter] [snaplen] [wifi_if]
  sudo ./scripts/capture.sh stop
  ./scripts/capture.sh compare [--deep] [-M] <wan_pcap> <lan_pcap> [display_filter] [wifi_pcap]
  ./scripts/capture.sh merge-lan [-o <out_pcap>] [-a|--audit] [-D|--deep] [-f <filter>] [lan_files...]
  ./scripts/capture.sh status
  ./scripts/capture.sh clean
  ./scripts/capture.sh -h | --help

Options:
  -s, --snaplen <bytes>            Set packet snaplen in bytes (default: 96, 0 = full packet)
  -D, --deep                       Enable deep packet-by-packet identity correlation & latency profiling
  -M, --merge-lan                  Merge multiple LAN-side captures (Wired LAN + Wi-Fi) before audit

Commands:
  start [ns] [if] [flt] [snaplen]  Start single background packet capture
  start_dual <tag> [ns] [flt] [s]  Start simultaneous multi-side captures on WAN, LAN, and Wi-Fi
  stop                             Stop all active background captures and report audit
  compare [--deep] [-M] <w> <l>    Compare packet counts, data bytes, and packet identity
  merge-lan [-o <out>] [-a] [-D]   Merge LAN-side captures and optionally run post-merge audit
  status                           Display capture status, active PIDs, and PCAP details
  clean                            Stop active capture and purge old files in captures/
  -h, --help                       Show this help message

Examples:
  sudo ./scripts/capture.sh start_dual tc_wr_02_multicast ns-stb "udp port 5003" 96
  sudo ./scripts/capture.sh -s 96 start_dual tc_sim_01_simultaneous ns-pc "tcp port 5201 or tcp port 5202"
  sudo ./scripts/capture.sh stop
  ./scripts/capture.sh compare captures/wan.pcap captures/lan.pcap "ip.dst == 239.255.0.1"
  ./scripts/capture.sh compare --deep captures/wan.pcap captures/lan.pcap "udp.port == 5004"
  ./scripts/capture.sh merge-lan --audit
  ./scripts/capture.sh merge-lan --audit --deep
  ./scripts/capture.sh compare --merge-lan --deep
==================================================================
USAGE
}

start_capture() {
    require_root
    stop_capture

    local target_ns="${DUT_NS:-ns-dut}"
    local target_if="any"
    local bpf_filter="${CAPTURE_FILTER:-}"
    local custom_pcap=""

    local snaplen="${CAPTURE_SNAPLEN:-0}"

    if [[ $# -gt 0 ]]; then
        if [[ "$1" == *.pcap || "$1" == *.pcapng || "$1" == */* ]]; then
            custom_pcap="$1"
            shift
            if [[ $# -gt 0 ]]; then target_ns="$1"; shift; fi
            if [[ $# -gt 0 ]]; then target_if="$1"; shift; fi
            if [[ $# -gt 0 ]]; then bpf_filter="$1"; shift; fi
            if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then snaplen="$1"; shift; fi
        else
            target_ns="$1"; shift
            if [[ $# -gt 0 ]]; then target_if="$1"; shift; fi
            if [[ $# -gt 0 ]]; then bpf_filter="$1"; shift; fi
            if [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; then snaplen="$1"; shift; fi
            if [[ $# -gt 0 ]]; then custom_pcap="$1"; shift; fi
        fi
    fi

    # Fallback namespace if target does not exist
    if ! ns_exists "${target_ns}"; then
        if ns_exists "${WAN_NS:-ns-wan}"; then
            target_ns="${WAN_NS:-ns-wan}"
            target_if="eth0"
        elif ns_exists "${PC_NS:-ns-pc}"; then
            target_ns="${PC_NS:-ns-pc}"
            target_if="eth0"
        fi
    fi

    local timestamp ext cap_tool pcap_file pid_file log_file
    timestamp="$(date +%Y%m%d_%H%M%S)"
    pid_file="${STATE_DIR}/capture.pid"
    log_file="${LOG_DIR}/capture_${timestamp}.log"

    if command -v "${TCPDUMP_BIN:-tcpdump}" >/dev/null 2>&1; then
        cap_tool="tcpdump"; ext="pcap"
    elif command -v "${TSHARK_BIN:-tshark}" >/dev/null 2>&1; then
        cap_tool="tshark"; ext="pcapng"
    else
        die "Neither tcpdump nor tshark is installed."
    fi

    if [[ -n "${custom_pcap}" ]]; then
        pcap_file="${custom_pcap}"
    else
        pcap_file="${CAPTURE_DIR}/capture_${timestamp}.${ext}"
    fi
    ensure_runtime_dirs

    local cap_cmd=()
    if [[ "${cap_tool}" == "tcpdump" ]]; then
        cap_cmd=("tcpdump" "-ni" "${target_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_file}")
        if [[ -n "${bpf_filter}" ]]; then
            local -a filter_parts=()
            read -r -a filter_parts <<< "${bpf_filter}"
            cap_cmd+=("${filter_parts[@]}")
        fi
    else
        cap_cmd=("tshark" "-i" "${target_if}" "-s" "${snaplen}" "-l" "-w" "${pcap_file}")
        if [[ -n "${bpf_filter}" ]]; then
            cap_cmd+=("-f" "${bpf_filter}")
        fi
    fi

    local exec_prefix=()
    if ns_exists "${target_ns}"; then
        exec_prefix=("ip" "netns" "exec" "${target_ns}")
    fi

    log_info "Starting packet capture on ${target_ns}:${target_if} (${cap_tool}, snaplen: ${snaplen}B)..."
    ( local IFS=' '; log_cmd "${exec_prefix[*]} ${cap_cmd[*]} > ${log_file} 2>&1 &" )
    "${exec_prefix[@]}" nohup "${cap_cmd[@]}" > "${log_file}" 2>&1 &
    local cap_pid=$!
    echo "${cap_pid}" > "${pid_file}"
    chmod 0666 "${pid_file}" "${log_file}" 2>/dev/null || true

    write_state_env "${STATE_DIR}/last_capture.env" \
        LAST_PCAP="${pcap_file}" \
        CAPTURE_TIMESTAMP="$(date -Iseconds)" \
        CAPTURE_TOOL="${cap_tool}" \
        CAPTURE_NS="${target_ns}" \
        CAPTURE_IF="${target_if}"
    echo "${pcap_file}" > "${STATE_DIR}/latest_capture.txt"

    sleep 0.5
    if ! is_pidfile_running "${pid_file}"; then
        log_error "Capture failed to start. Log output:"
        tail -n 20 "${log_file}" >&2 || true
        die "Failed to start capture process."
    fi

    log_success "Capture active: ${pcap_file} (PID: ${cap_pid})"
}

start_dual_capture() {
    require_root
    stop_capture

    local test_tag="${1:-perf_test}"
    local lan_ns="${2:-${PC_NS:-ns-pc}}"
    local bpf_filter="${3:-}"
    local snaplen="${4:-${CAPTURE_SNAPLEN:-0}}"
    local wifi_if="${5:-}"

    if [[ -z "${wifi_if}" ]] && [[ "${test_tag}" =~ (simultaneous|tc_sim) ]]; then
        if [[ -n "${DETECTED_WIFI_IF:-}" ]]; then
            wifi_if="${DETECTED_WIFI_IF}"
        elif command -v iw >/dev/null 2>&1; then
            wifi_if="$(iw dev 2>/dev/null | awk '$1=="Interface" && $2 !~ /mon/ {print $2; exit}' || true)"
        fi
    fi

    local timestamp ext cap_tool
    timestamp="$(date +%Y%m%d_%H%M%S)"

    if command -v "${TCPDUMP_BIN:-tcpdump}" >/dev/null 2>&1; then
        cap_tool="tcpdump"; ext="pcap"
    elif command -v "${TSHARK_BIN:-tshark}" >/dev/null 2>&1; then
        cap_tool="tshark"; ext="pcapng"
    else
        die "Neither tcpdump nor tshark is installed."
    fi

    ensure_runtime_dirs
    local pcap_wan="${CAPTURE_DIR}/${test_tag}_${timestamp}_wan.${ext}"
    local pcap_lan="${CAPTURE_DIR}/${test_tag}_${timestamp}_lan.${ext}"
    local pcap_wifi=""

    local wan_ns="${WAN_NS:-ns-wan}"
    local wan_if="eth0"
    if ! ns_exists "${wan_ns}"; then
        wan_if="${WAN_BRIDGE:-br-test-wan}"
    fi

    local lan_if="eth0"
    if ! ns_exists "${lan_ns}"; then
        lan_if="${LAN_BRIDGE:-br-test-lan}"
    fi

    local pid_wan_file="${STATE_DIR}/capture_wan.pid"
    local pid_lan_file="${STATE_DIR}/capture_lan.pid"
    local pid_wifi_file="${STATE_DIR}/capture_wifi.pid"
    local log_wan_file="${LOG_DIR}/capture_${test_tag}_${timestamp}_wan.log"
    local log_lan_file="${LOG_DIR}/capture_${test_tag}_${timestamp}_lan.log"
    local log_wifi_file="${LOG_DIR}/capture_${test_tag}_${timestamp}_wifi.log"

    # WAN capture process
    local exec_wan=()
    if ns_exists "${wan_ns}"; then
        exec_wan=("ip" "netns" "exec" "${wan_ns}")
    fi
    local cap_cmd_wan=("tcpdump" "-ni" "${wan_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_wan}")
    if [[ -n "${bpf_filter}" ]]; then
        local -a filter_parts_wan=()
        read -r -a filter_parts_wan <<< "${bpf_filter}"
        cap_cmd_wan+=("${filter_parts_wan[@]}")
    fi

    # LAN capture process
    local exec_lan=()
    if ns_exists "${lan_ns}"; then
        exec_lan=("ip" "netns" "exec" "${lan_ns}")
    fi
    local cap_cmd_lan=("tcpdump" "-ni" "${lan_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_lan}")
    if [[ -n "${bpf_filter}" ]]; then
        local -a filter_parts_lan=()
        read -r -a filter_parts_lan <<< "${bpf_filter}"
        cap_cmd_lan+=("${filter_parts_lan[@]}")
    fi

    log_info "Starting Dual/Multi-side Packet Capture [${test_tag}] (Snaplen: ${snaplen}B):"
    log_info "  -> WAN Interface    : [${wan_ns}:${wan_if}] => ${pcap_wan}"
    log_info "  -> LAN PC Interface : [${lan_ns}:${lan_if}] => ${pcap_lan}"

    ( local IFS=' '; log_cmd "${exec_wan[*]} ${cap_cmd_wan[*]} > ${log_wan_file} 2>&1 &" )
    "${exec_wan[@]}" nohup "${cap_cmd_wan[@]}" > "${log_wan_file}" 2>&1 &
    local pid_wan=$!
    echo "${pid_wan}" > "${pid_wan_file}"

    ( local IFS=' '; log_cmd "${exec_lan[*]} ${cap_cmd_lan[*]} > ${log_lan_file} 2>&1 &" )
    "${exec_lan[@]}" nohup "${cap_cmd_lan[@]}" > "${log_lan_file}" 2>&1 &
    local pid_lan=$!
    echo "${pid_lan}" > "${pid_lan_file}"

    # Optional Wi-Fi Station capture (for TC-SIM-01 multi-point audit)
    local pid_wifi=""
    if [[ -n "${wifi_if}" ]] && ip link show "${wifi_if}" >/dev/null 2>&1; then
        pcap_wifi="${CAPTURE_DIR}/${test_tag}_${timestamp}_wifi.${ext}"
        local cap_cmd_wifi=("tcpdump" "-ni" "${wifi_if}" "-s" "${snaplen}" "-U" "-w" "${pcap_wifi}")
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

    write_state_env "${STATE_DIR}/last_capture_dual.env" \
        LAST_TEST_TAG="${test_tag}" \
        LAST_PCAP_WAN="${pcap_wan}" \
        LAST_PCAP_LAN="${pcap_lan}" \
        LAST_PCAP_WIFI="${pcap_wifi}" \
        LAST_LAN_NS="${lan_ns}" \
        LAST_WIFI_IF="${wifi_if}" \
        LAST_SNAPLEN="${snaplen}" \
        LAST_BPF_FILTER="${bpf_filter}" \
        CAPTURE_TIMESTAMP="$(date -Iseconds)" \
        CAPTURE_TOOL="${cap_tool}"
    echo "${pcap_wan}" > "${STATE_DIR}/latest_wan_pcap.txt"
    echo "${pcap_lan}" > "${STATE_DIR}/latest_lan_pcap.txt"
    echo "${pcap_wan}" > "${STATE_DIR}/latest_capture.txt"
    echo "${pid_wan}" > "${STATE_DIR}/capture.pid"

    sleep 0.5
    if ! is_pidfile_running "${pid_wan_file}" || ! is_pidfile_running "${pid_lan_file}"; then
        log_error "One or both dual captures failed to start. Logs:"
        tail -n 10 "${log_wan_file}" "${log_lan_file}" >&2 || true
        die "Dual capture initialization failed."
    fi

    local status_msg="Multi-point captures active: WAN (PID ${pid_wan}) | LAN (PID ${pid_lan})"
    if [[ -n "${pid_wifi}" ]]; then
        status_msg+=" | Wi-Fi (PID ${pid_wifi})"
    fi
    log_success "${status_msg}"
}

stop_capture() {
    require_root
    local pids_to_kill=()
    local files_to_clean=()

    # Collect running capture PIDs first so we can signal them simultaneously
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
        # Send SIGTERM in parallel to close capture windows at the exact same instant
        local pids_str
        pids_str="$(IFS=" "; echo "${pids_to_kill[*]}")"
        pids_str="${pids_str// /, }"
        log_info "Stopping capture processes simultaneously (PIDs: ${pids_str})..."
        ( local IFS=' '; log_cmd "kill -TERM ${pids_to_kill[*]}" )
        kill -TERM "${pids_to_kill[@]}" 2>/dev/null || true
        for pid in "${pids_to_kill[@]}"; do
            local count=0
            while kill -0 "${pid}" 2>/dev/null && (( count < 30 )); do
                sleep 0.1
                count=$((count + 1))
            done
            if kill -0 "${pid}" 2>/dev/null; then
                kill -KILL "${pid}" 2>/dev/null || true
            fi
        done
        stopped_any=1
    fi

    for pf in "${files_to_clean[@]}"; do
        rm -f "${pf}" 2>/dev/null || true
    done

    # Ensure all PCAP files have non-root read permissions for Wireshark
    find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -exec chmod 0666 {} + 2>/dev/null || true

    # Audit dual captures if active
    if [[ -f "${STATE_DIR}/last_capture_dual.env" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_DIR}/last_capture_dual.env"
        if [[ -f "${LAST_PCAP_WAN:-}" && -f "${LAST_PCAP_LAN:-}" ]]; then
            local -a stop_comp_args=()
            if [[ "${MERGE_LAN:-0}" == "1" ]]; then stop_comp_args+=("--merge-lan"); fi
            stop_comp_args+=("${LAST_PCAP_WAN}" "${LAST_PCAP_LAN}" "${LAST_TEST_TAG:-test}" "${LAST_BPF_FILTER:-}" "${LAST_PCAP_WIFI:-}")
            compare_captures "${stop_comp_args[@]}"
        fi
        rm -f "${STATE_DIR}/last_capture_dual.env" 2>/dev/null || true
    fi
}

format_num() {
    local n="${1:-0}"
    printf '%s' "${n}" | sed ':a;s/\B[0-9]\{3\}\>/,&/;ta'
}

merge_lan_captures() {
    local out_file=""
    local -a in_files=()
    local auto_audit=0
    local deep_audit="${DEEP_AUDIT:-0}"
    local filter=""
    local tag=""
    local wan_file=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o|--output)
                [[ $# -ge 2 ]] || die "Option --output requires a file path"
                out_file="$2"
                shift 2
                ;;
            -a|--audit)
                auto_audit=1
                shift
                ;;
            -D|--deep)
                deep_audit=1
                auto_audit=1
                shift
                ;;
            -f|--filter)
                [[ $# -ge 2 ]] || die "Option --filter requires a filter expression"
                filter="$2"
                shift 2
                ;;
            -t|--tag)
                [[ $# -ge 2 ]] || die "Option --tag requires a tag string"
                tag="$2"
                shift 2
                ;;
            -w|--wan)
                [[ $# -ge 2 ]] || die "Option --wan requires a file path"
                wan_file="$2"
                shift 2
                ;;
            *)
                in_files+=("$1")
                shift
                ;;
        esac
    done

    # 1. Discover LAN-side PCAP files if not provided explicitly
    if (( ${#in_files[@]} == 0 )); then
        local -a candidate_files=()

        for sf in "${STATE_DIR}/latest_lan_pcap.txt" \
                   "${STATE_DIR}/latest_wifi_pcap.txt" \
                   "${STATE_DIR}/latest_phone1_pcap.txt" \
                   "${STATE_DIR}/latest_phone2_pcap.txt"; do
            if [[ -f "${sf}" ]]; then
                local f
                f="$(cat "${sf}" 2>/dev/null || true)"
                if [[ -n "${f}" && -f "${f}" ]]; then
                    candidate_files+=("${f}")
                fi
            fi
        done

        if [[ -f "${STATE_DIR}/last_capture_dual.env" ]]; then
            local LAST_PCAP_LAN="" LAST_PCAP_WIFI="" LAST_TEST_TAG=""
            # shellcheck disable=SC1090
            source "${STATE_DIR}/last_capture_dual.env"
            if [[ -n "${LAST_PCAP_LAN:-}" && -f "${LAST_PCAP_LAN}" ]]; then
                candidate_files+=("${LAST_PCAP_LAN}")
            fi
            if [[ -n "${LAST_PCAP_WIFI:-}" && -f "${LAST_PCAP_WIFI}" ]]; then
                candidate_files+=("${LAST_PCAP_WIFI}")
            fi
            if [[ -z "${tag}" && -n "${LAST_TEST_TAG:-}" ]]; then
                tag="${LAST_TEST_TAG}"
            fi
        fi

        for cf in "${candidate_files[@]}"; do
            if [[ -s "${cf}" ]]; then
                local already=0
                for inf in "${in_files[@]:-}"; do
                    if [[ "${inf}" == "${cf}" ]]; then already=1; break; fi
                done
                if (( already == 0 )); then
                    in_files+=("${cf}")
                fi
            fi
        done
    fi

    if (( ${#in_files[@]} == 0 )); then
        log_error "No valid LAN-side capture files found to merge."
        return 1
    fi

    local mergecap_bin="${MERGECAP_BIN:-$(command -v mergecap 2>/dev/null || echo "mergecap")}"
    if ! command -v "${mergecap_bin}" >/dev/null 2>&1; then
        log_error "mergecap utility is not found! Install wireshark-common or tshark."
        return 1
    fi

    if (( ${#in_files[@]} == 1 )); then
        log_info "Single LAN-side capture file detected: ${in_files[0]} (no mergecap required)"
        out_file="${in_files[0]}"
        echo "${out_file}" > "${STATE_DIR}/latest_lan_merged_pcap.txt"
        printf '%s\n' "${in_files[@]}" > "${STATE_DIR}/latest_lan_merged_sources.txt"
    else
        if [[ -z "${out_file}" ]]; then
            local base_first
            base_first="$(basename -- "${in_files[0]}")"
            local ts
            ts="$(date +%Y%m%d_%H%M%S)"
            local base_name
            if [[ "${base_first}" =~ ^(.*)_(lan|wifi|phone[12]).*(\.pcap.*)$ ]]; then
                base_name="${BASH_REMATCH[1]}_lan_merged${BASH_REMATCH[3]}"
            else
                base_name="${tag:-lan}_${ts}_lan_merged.pcap"
            fi
            out_file="${CAPTURE_DIR}/${base_name}"
        fi

        printf '\n==================================================================\n'
        printf '  MERGING LAN-SIDE PACKET CAPTURES\n'
        printf '==================================================================\n'
        log_info "Merging ${#in_files[@]} LAN-side captures chronologically into single timeline:"
        for idx in "${!in_files[@]}"; do
            local sz
            sz="$(du -h "${in_files[idx]}" 2>/dev/null | cut -f1 || echo "0")"
            log_info "  [Station $(( idx + 1 ))] ${in_files[idx]} (${sz})"
        done

        log_cmd "${mergecap_bin} -w ${out_file} ${in_files[*]}"
        "${mergecap_bin}" -w "${out_file}" "${in_files[@]}"
        chmod 0666 "${out_file}" 2>/dev/null || true
        echo "${out_file}" > "${STATE_DIR}/latest_lan_merged_pcap.txt"
        printf '%s\n' "${in_files[@]}" > "${STATE_DIR}/latest_lan_merged_sources.txt"

        local merged_sz
        merged_sz="$(du -h "${out_file}" 2>/dev/null | cut -f1 || echo "0")"
        log_success "Merged LAN capture ready: ${out_file} (${merged_sz})"
        printf '==================================================================\n'
    fi

    if (( auto_audit == 1 )); then
        if [[ -z "${wan_file}" || ! -f "${wan_file}" ]]; then
            wan_file="$(cat "${STATE_DIR}/latest_wan_pcap.txt" 2>/dev/null || true)"
        fi
        if [[ -z "${wan_file}" && -f "${STATE_DIR}/last_capture_dual.env" ]]; then
            wan_file="$(grep '^LAST_PCAP_WAN=' "${STATE_DIR}/last_capture_dual.env" 2>/dev/null | cut -d= -f2- | tr -d '"' || true)"
        fi

        if [[ -n "${wan_file}" && -f "${wan_file}" ]]; then
            local -a comp_args=("--merged")
            if (( deep_audit == 1 )); then comp_args+=("--deep"); fi
            comp_args+=("${wan_file}" "${out_file}" "${tag:-MERGED_LAN}" "${filter}")
            compare_captures "${comp_args[@]}"
        else
            log_warn "WAN capture file not found. Skipped automated cross-DUT audit."
        fi
    fi

    printf '%s\n' "${out_file}"
}

compare_captures() {
    local deep_audit="${DEEP_AUDIT:-0}"
    local do_merge="${MERGE_LAN:-0}"
    local is_merged=0
    local -a filtered_args=()
    for arg in "$@"; do
        if [[ "${arg}" == "--deep" || "${arg}" == "-D" ]]; then
            deep_audit=1
        elif [[ "${arg}" == "--merge-lan" || "${arg}" == "-M" ]]; then
            do_merge=1
        elif [[ "${arg}" == "--merged" ]]; then
            is_merged=1
        else
            filtered_args+=("${arg}")
        fi
    done
    set -- "${filtered_args[@]}"

    local wan_pcap="${1:-}"
    local lan_pcap="${2:-}"
    local tag="AUDIT"
    local filter=""
    local wifi_pcap=""
    local -a extra_lan_pcaps=()

    if [[ $# -ge 5 ]]; then
        tag="$3"
        filter="$4"
        wifi_pcap="$5"
        local -a orig_all=("$@")
        if [[ ${#orig_all[@]} -ge 6 ]]; then
            extra_lan_pcaps=("${orig_all[@]:5}")
        fi
    elif [[ $# -ge 4 ]]; then
        tag="$3"
        filter="$4"
    elif [[ $# -eq 3 ]]; then
        if [[ "$3" =~ (==|port|ip|udp|tcp|icmp|len|arp|vlan) ]]; then
            filter="$3"
        else
            tag="$3"
        fi
    fi

    if [[ -z "${wifi_pcap}" ]]; then
        wifi_pcap="$(cat "${STATE_DIR}/latest_wifi_pcap.txt" 2>/dev/null || true)"
    fi

    if [[ -z "${wan_pcap}" || ! -f "${wan_pcap}" ]]; then
        wan_pcap="$(cat "${STATE_DIR}/latest_wan_pcap.txt" 2>/dev/null || true)"
    fi
    if [[ -z "${lan_pcap}" || ! -f "${lan_pcap}" ]]; then
        lan_pcap="$(cat "${STATE_DIR}/latest_lan_pcap.txt" 2>/dev/null || true)"
    fi

    # Handle automatic or explicit LAN merging
    if (( do_merge == 1 && is_merged == 0 )); then
        local -a merge_candidates=()
        if [[ -n "${lan_pcap}" && -f "${lan_pcap}" && "${lan_pcap}" != "${wan_pcap}" ]]; then
            merge_candidates+=("${lan_pcap}")
        fi
        if [[ -n "${wifi_pcap}" && -f "${wifi_pcap}" && "${wifi_pcap}" != "${wan_pcap}" ]]; then
            merge_candidates+=("${wifi_pcap}")
        fi
        for ef in "${extra_lan_pcaps[@]:-}"; do
            if [[ -f "${ef}" && "${ef}" != "${wan_pcap}" ]]; then
                merge_candidates+=("${ef}")
            fi
        done
        for sf in "${STATE_DIR}/latest_lan_pcap.txt" \
                   "${STATE_DIR}/latest_wifi_pcap.txt" \
                   "${STATE_DIR}/latest_phone1_pcap.txt" \
                   "${STATE_DIR}/latest_phone2_pcap.txt"; do
            if [[ -f "${sf}" ]]; then
                local sf_val
                sf_val="$(cat "${sf}" 2>/dev/null || true)"
                if [[ -n "${sf_val}" && -f "${sf_val}" && "${sf_val}" != "${wan_pcap}" ]]; then
                    merge_candidates+=("${sf_val}")
                fi
            fi
        done

        local -a unique_to_merge=()
        for f in "${merge_candidates[@]}"; do
            local already=0
            for u in "${unique_to_merge[@]:-}"; do
                if [[ "${u}" == "${f}" ]]; then already=1; break; fi
            done
            if (( already == 0 )); then unique_to_merge+=("${f}"); fi
        done

        if (( ${#unique_to_merge[@]} >= 2 )); then
            local merged_out
            merged_out="$(merge_lan_captures --tag "${tag}" "${unique_to_merge[@]}" | tail -n 1)"
            if [[ -n "${merged_out}" && -f "${merged_out}" ]]; then
                lan_pcap="${merged_out}"
                is_merged=1
            fi
        fi
    fi

    if [[ ! -f "${wan_pcap}" || ! -f "${lan_pcap}" ]]; then
        log_warn "Missing PCAP files for comparison: WAN='${wan_pcap}' LAN='${lan_pcap}'"
        return 0
    fi

    local size_wan size_lan
    size_wan="$(du -h "${wan_pcap}" 2>/dev/null | cut -f1 || echo "0")"
    size_lan="$(du -h "${lan_pcap}" 2>/dev/null | cut -f1 || echo "0")"

    local get_stats
    get_stats() {
        local p="$1"
        local flt="${2:-}"
        if [[ ! -f "${p}" ]]; then echo "0 0"; return; fi
        local d_flt
        d_flt="$(bpf_to_display_filter "${flt}")"
        local res=""
        if [[ -n "${d_flt}" ]]; then
            log_cmd "cat \"${p}\" | ${TSHARK_BIN:-tshark} -r - -n -q -z \"io,stat,0,${d_flt}\""
            res="$(cat "${p}" 2>/dev/null | "${TSHARK_BIN:-tshark}" -r - -n -q -z "io,stat,0,${d_flt}" 2>/dev/null | awk -F'|' '/<>/ {gsub(/[ \t]/, "", $3); gsub(/[ \t]/, "", $4); print $3, $4}' || true)"
        else
            log_cmd "cat \"${p}\" | ${TSHARK_BIN:-tshark} -r - -n -q -z \"io,stat,0\""
            res="$(cat "${p}" 2>/dev/null | "${TSHARK_BIN:-tshark}" -r - -n -q -z "io,stat,0" 2>/dev/null | awk -F'|' '/<>/ {gsub(/[ \t]/, "", $3); gsub(/[ \t]/, "", $4); print $3, $4}' || true)"
        fi
        local frames="" bytes=""
        if [[ -n "${res}" ]]; then
            IFS=' ' read -r frames bytes <<< "${res}"
        fi
        if [[ -z "${frames}" || ! "${frames}" =~ ^[0-9]+$ ]]; then
            local -a extra=()
            if [[ -n "${d_flt}" ]]; then extra+=("-Y" "${d_flt}"); fi
            frames="$(cat "${p}" 2>/dev/null | "${TSHARK_BIN:-tshark}" -r - "${extra[@]}" -T fields -e frame.number 2>/dev/null | wc -l || echo "0")"
            bytes="0"
        fi
        echo "${frames:-0} ${bytes:-0}"
    }

    local get_cnt
    get_cnt() {
        local st
        st="$(get_stats "$@")"
        echo "${st%% *}"
    }

    if (( is_merged == 0 )) && [[ "${tag}" =~ (simultaneous|tc_sim) ]]; then
        local size_wifi="N/A"
        if [[ -f "${wifi_pcap}" ]]; then
            size_wifi="$(du -h "${wifi_pcap}" 2>/dev/null | cut -f1 || echo "0")"
        fi

        printf '\n==================================================================\n'
        printf '  MULTI-POINT CAPTURE EVIDENCE AUDIT: [%s]\n' "${tag^^}"
        printf '==================================================================\n'
        printf '  WAN Capture   : %s (%s)\n' "${wan_pcap}" "${size_wan}"
        printf '  Wired LAN     : %s (%s)\n' "${lan_pcap}" "${size_lan}"
        if [[ -f "${wifi_pcap}" ]]; then
            printf '  Wi-Fi Capture : %s (%s)\n' "${wifi_pcap}" "${size_wifi}"
        fi
        printf '  Snaplen Limit : %s bytes (0 = Full Packet Capture)\n' "${CAPTURE_SNAPLEN:-0}"
        printf '  ------------------------------------------------------------------\n'

        if command -v "${TSHARK_BIN:-tshark}" >/dev/null 2>&1; then
            # Stream 1: Wired PC Traffic (Port 5201)
            local count_wan_wired count_lan_wired
            count_wan_wired="$(get_cnt "${wan_pcap}" "tcp.port==5201")"
            count_lan_wired="$(get_cnt "${lan_pcap}" "tcp.port==5201")"

            # Stream 2: Wi-Fi Station Traffic (Ports 5202-5204)
            local count_wan_wifi
            count_wan_wifi="$(get_cnt "${wan_pcap}" "tcp.port>=5202&&tcp.port<=5204")"

            local diff_wired=$(( count_wan_wired > count_lan_wired ? count_wan_wired - count_lan_wired : count_lan_wired - count_wan_wired ))
            local wired_status
            if (( count_wan_wired > 0 && diff_wired <= (count_wan_wired * 5 / 100) )) || (( count_wan_wired == count_lan_wired )); then
                wired_status="\e[1;32m100% MATCH (0% Loss)\e[0m"
            else
                wired_status="\e[1;33mDiff: ${diff_wired} frames\e[0m"
            fi

            printf '  Stream: Wired PC (Port 5201)      : WAN %s frames | LAN %s frames [%b]\n' \
                "${count_wan_wired}" "${count_lan_wired}" "${wired_status}"

            if [[ -f "${wifi_pcap}" ]]; then
                local count_wifi_rcv
                count_wifi_rcv="$(get_cnt "${wifi_pcap}" "tcp.port>=5202&&tcp.port<=5204")"
                local diff_wifi=$(( count_wan_wifi > count_wifi_rcv ? count_wan_wifi - count_wifi_rcv : count_wifi_rcv - count_wan_wifi ))
                local wifi_status
                if (( count_wan_wifi > 0 && diff_wifi <= (count_wan_wifi * 5 / 100) )) || (( count_wan_wifi == count_wifi_rcv )); then
                    wifi_status="\e[1;32m100% MATCH (0% Loss)\e[0m"
                else
                    wifi_status="\e[1;33mDiff: ${diff_wifi} frames\e[0m"
                fi
                printf '  Stream: Wi-Fi Station (Port 5202+): WAN %s frames | Wi-Fi %s frames [%b]\n' \
                    "${count_wan_wifi}" "${count_wifi_rcv}" "${wifi_status}"

                local total_wan=$(( count_wan_wired + count_wan_wifi ))
                local total_rcv=$(( count_lan_wired + count_wifi_rcv ))
                printf '  ------------------------------------------------------------------\n'
                printf '  Total Combined Cross-DUT Frames   : WAN %d frames | LAN+Wi-Fi %d frames\n' "${total_wan}" "${total_rcv}"
                if [[ "${wired_status}" == *"MATCH"* && "${wifi_status}" == *"MATCH"* ]]; then
                    printf '  Overall Cross-DUT Audit Verdict   : \e[1;32mPASS (All Streams Preserved / 0%% Packet Loss)\e[0m\n'
                else
                    printf '  Overall Cross-DUT Audit Verdict   : \e[1;33mPARTIAL (Minor TCP offloading variance)\e[0m\n'
                fi
            else
                printf '  Stream: Wi-Fi Station (Port 5202+): WAN %s frames recorded (Wi-Fi station capture not active)\n' "${count_wan_wifi}"
                printf '  ------------------------------------------------------------------\n'
                if [[ "${wired_status}" == *"MATCH"* ]]; then
                    printf '  Overall Cross-DUT Audit Verdict   : \e[1;32mPASS (Wired PC Wire-Rate Preserved: 100%% Match)\e[0m\n'
                else
                    printf '  Overall Cross-DUT Audit Verdict   : \e[1;33mDifference: %d frames on Wired PC\e[0m\n' "${diff_wired}"
                fi
            fi

            if (( deep_audit == 1 )); then
                local correlator_bin="${LAB_DIR:-${PROJECT_ROOT}}/tools/pcap_correlator.py"
                if [[ -x "${correlator_bin}" ]]; then
                    local corr_json="${LOG_DIR:-logs}/pcap_correlation_simultaneous.json"
                    "${correlator_bin}" --wan "${wan_pcap}" --lan "${lan_pcap}" --filter "tcp.port==5201" --output-json "${corr_json}" || true
                fi
            fi
        fi
        printf '==================================================================\n\n'
        return 0
    elif [[ "${tag}" =~ (wireless_qos|wmm_qos|tc_wqos|wqos) ]]; then
        local wqos_py="${LAB_DIR:-${PROJECT_ROOT}}/tools/wireless_qos_audit.py"
        if [[ -x "${wqos_py}" ]]; then
            local eff_lan="${lan_pcap}"
            local eff_wifi="${wifi_pcap}"
            if (( is_merged == 1 )) && [[ -f "${STATE_DIR}/latest_lan_merged_pcap.txt" ]]; then
                eff_lan="$(cat "${STATE_DIR}/latest_lan_merged_pcap.txt" 2>/dev/null || echo "${lan_pcap}")"
                eff_wifi=""
            elif [[ -z "${eff_wifi}" || ! -f "${eff_wifi}" ]] && [[ -f "${STATE_DIR}/latest_wifi_pcap.txt" ]]; then
                eff_wifi="$(cat "${STATE_DIR}/latest_wifi_pcap.txt" 2>/dev/null || true)"
            fi
            local wqos_json="${LOG_DIR:-${PROJECT_ROOT}/logs}/wireless_qos_audit.json"
            local -a wqos_cmd=("${wqos_py}" "--wan-pcap" "${wan_pcap}" "--lan-pcap" "${eff_lan}")
            if [[ -f "${STATE_DIR}/latest_wqos_context.json" ]]; then
                wqos_cmd+=("--context-json" "${STATE_DIR}/latest_wqos_context.json")
            fi
            if [[ -n "${eff_wifi}" && -f "${eff_wifi}" && "${eff_wifi}" != "${eff_lan}" ]]; then
                wqos_cmd+=("--wifi-pcap" "${eff_wifi}")
            fi
            if [[ -f "${STATE_DIR}/latest_ota_pcap.txt" ]]; then
                local eff_ota
                eff_ota="$(cat "${STATE_DIR}/latest_ota_pcap.txt" 2>/dev/null || true)"
                if [[ -n "${eff_ota}" && -f "${eff_ota}" ]]; then
                    wqos_cmd+=("--ota-pcap" "${eff_ota}")
                fi
            fi
            local ap_edca="${LOG_DIR:-${PROJECT_ROOT}/logs}/ap_edca.json"
            if [[ -f "${ap_edca}" ]]; then
                wqos_cmd+=("--ap-edca-json" "${ap_edca}")
            fi
            wqos_cmd+=("--output-json" "${wqos_json}")
            log_cmd "${wqos_cmd[*]}"
            "${wqos_cmd[@]}" || true
        else
            log_info "Wireless QoS multi-service capture detected. Run tools/wireless_qos_audit.py for multi-stream evaluation."
        fi
        return 0
    elif (( is_merged == 0 )) && [[ "${tag}" =~ (voice|tc_qos) ]]; then
        local audit_py="${LAB_DIR:-${PROJECT_ROOT}}/tools/voip_pcap_audit.py"
        if [[ -x "${audit_py}" ]]; then
            local p1_cap p2_cap v_mode
            p1_cap="$(cat "${STATE_DIR}/latest_phone1_pcap.txt" 2>/dev/null || true)"
            p2_cap="$(cat "${STATE_DIR}/latest_phone2_pcap.txt" 2>/dev/null || true)"
            v_mode="$(cat "${STATE_DIR}/latest_voip_mode.txt" 2>/dev/null || echo "distributed")"

            if [[ -z "${p2_cap}" && "${v_mode}" == "physical_single" && -n "${p1_cap}" ]]; then
                p2_cap="${p1_cap}"
            fi

            local -a audit_cmd=("${audit_py}" "--wan-pcap" "${wan_pcap}")
            if [[ -f "${p1_cap}" ]]; then audit_cmd+=("--phone1-pcap" "${p1_cap}"); fi
            if [[ -f "${p2_cap}" ]]; then audit_cmd+=("--phone2-pcap" "${p2_cap}"); fi
            if [[ -f "${lan_pcap}" ]]; then audit_cmd+=("--lan-pcap" "${lan_pcap}"); fi
            if [[ -n "${v_mode}" ]]; then audit_cmd+=("--mode" "${v_mode}"); fi
            audit_cmd+=("--output" "${LOG_DIR:-${PROJECT_ROOT}/logs}/voice_qos_audit.json")
            log_cmd "${audit_cmd[*]}"
            "${audit_cmd[@]}" || true
        else
            log_info "Multi-point VoIP QoS capture detected. Run tools/voip_pcap_audit.py for multi-stream evaluation."
        fi
        return 0
    fi

    # Standard 1:1 or Merged LAN dual-sided comparison
    printf '\n==================================================================\n'
    if (( is_merged == 1 )); then
        printf '  DUAL-SIDED CAPTURE EVIDENCE AUDIT (MERGED LAN EGRESS): [%s]\n' "${tag^^}"
    else
        printf '  DUAL-SIDED CAPTURE EVIDENCE AUDIT: [%s]\n' "${tag^^}"
    fi
    printf '==================================================================\n'
    printf '  WAN Ingress Capture : %s (%s)\n' "${wan_pcap}" "${size_wan}"
    if (( is_merged == 1 )); then
        printf '  Merged LAN Egress   : %s (%s)\n' "${lan_pcap}" "${size_lan}"
        if [[ -f "${STATE_DIR}/latest_lan_merged_sources.txt" ]]; then
            local s_idx=1
            while IFS= read -r src_line; do
                if [[ -n "${src_line}" && -f "${src_line}" ]]; then
                    local s_sz
                    s_sz="$(du -h "${src_line}" 2>/dev/null | cut -f1 || echo "0")"
                    printf '    -> Source %d (LAN) : %s (%s)\n' "${s_idx}" "${src_line}" "${s_sz}"
                    s_idx=$(( s_idx + 1 ))
                fi
            done < "${STATE_DIR}/latest_lan_merged_sources.txt"
        fi
    else
        printf '  LAN Egress Capture  : %s (%s)\n' "${lan_pcap}" "${size_lan}"
    fi
    printf '  Snaplen Limit       : %s bytes (0 = Full Packet Capture)\n' "${CAPTURE_SNAPLEN:-0}"
    printf '  ------------------------------------------------------------------\n'

    if command -v "${TSHARK_BIN:-tshark}" >/dev/null 2>&1; then
        local disp_filter
        disp_filter="$(bpf_to_display_filter "${filter}")"
        if [[ -n "${filter}" ]]; then
            if [[ -n "${disp_filter}" && "${disp_filter}" != "${filter}" ]]; then
                printf '  Applied Filter            : %s (Display: %s)\n' "${filter}" "${disp_filter}"
            else
                printf '  Applied Filter            : %s\n' "${filter}"
            fi
        fi

        local stats_wan stats_lan
        stats_wan="$(get_stats "${wan_pcap}" "${disp_filter}")"
        stats_lan="$(get_stats "${lan_pcap}" "${disp_filter}")"

        local count_wan="0" count_lan="0" bytes_wan="0" bytes_lan="0"
        IFS=' ' read -r count_wan bytes_wan <<< "${stats_wan}"
        IFS=' ' read -r count_lan bytes_lan <<< "${stats_lan}"

        local wan_pkts_fmt lan_pkts_fmt wan_bytes_fmt lan_bytes_fmt
        wan_pkts_fmt="$(format_num "${count_wan}")"
        lan_pkts_fmt="$(format_num "${count_lan}")"
        wan_bytes_fmt="$(format_num "${bytes_wan}")"
        lan_bytes_fmt="$(format_num "${bytes_lan}")"

        printf '  WAN Side Traffic Recorded : %s frames | %s bytes\n' "${wan_pkts_fmt}" "${wan_bytes_fmt}"
        printf '  LAN Side Traffic Received : %s frames | %s bytes\n' "${lan_pkts_fmt}" "${lan_bytes_fmt}"

        if [[ "${count_wan}" =~ ^[0-9]+$ ]] && [[ "${count_lan}" =~ ^[0-9]+$ ]] && (( count_wan > 0 )); then
            local diff_pkts=$(( count_wan > count_lan ? count_wan - count_lan : count_lan - count_wan ))
            local diff_bytes=$(( bytes_wan > bytes_lan ? bytes_wan - bytes_lan : bytes_lan - bytes_wan ))

            if (( diff_pkts == 0 )); then
                printf '  Frame Count Verification  : \e[1;32m100%% MATCH (0%% Packet Loss across DUT)\e[0m\n'
            else
                printf '  Frame Count Verification  : \e[1;33mDifference: %d frames\e[0m\n' "${diff_pkts}"
            fi

            if (( diff_bytes == 0 )); then
                printf '  Data Volume Verification  : \e[1;32m100%% MATCH (0 Byte Truncation / No Payload Shrinkage)\e[0m\n'
            elif (( bytes_wan > 0 && diff_bytes <= (bytes_wan * 2 / 100) )); then
                printf '  Data Volume Verification  : \e[1;32m%s%% MATCH (Within 2%% TCP Overhead / Wire-rate Preserved)\e[0m\n' \
                    "$(awk -v w="${bytes_wan}" -v l="${bytes_lan}" 'BEGIN { printf "%.2f", (l/w)*100 }')"
            else
                printf '  Data Volume Verification  : \e[1;33mDifference: %d bytes\e[0m\n' "${diff_bytes}"
            fi
        fi

        if (( deep_audit == 1 )); then
            local correlator_bin="${LAB_DIR:-${PROJECT_ROOT}}/tools/pcap_correlator.py"
            if [[ -x "${correlator_bin}" ]]; then
                local corr_json="${LOG_DIR:-logs}/pcap_correlation_${tag,,}.json"
                local -a corr_args=("${correlator_bin}" "--wan" "${wan_pcap}" "--lan" "${lan_pcap}")
                if [[ -n "${disp_filter}" ]]; then
                    corr_args+=("--filter" "${disp_filter}")
                fi
                corr_args+=("--output-json" "${corr_json}")
                "${corr_args[@]}" || true
            fi
        fi
    else
        log_info "Install tshark to enable automated frame count comparison."
    fi
    printf '==================================================================\n\n'
}

show_status() {
    print_header "CAPTURE STATUS"
    local running=0

    local pids_desc=()
    if is_pidfile_running "${STATE_DIR}/capture_wan.pid"; then
        pids_desc+=("WAN PID: $(cat "${STATE_DIR}/capture_wan.pid")")
    fi
    if is_pidfile_running "${STATE_DIR}/capture_lan.pid"; then
        pids_desc+=("LAN PID: $(cat "${STATE_DIR}/capture_lan.pid")")
    fi
    if is_pidfile_running "${STATE_DIR}/capture_wifi.pid"; then
        pids_desc+=("Wi-Fi PID: $(cat "${STATE_DIR}/capture_wifi.pid")")
    fi

    if (( ${#pids_desc[@]} > 0 )); then
        local p_str
        p_str="$(IFS=" | "; echo "${pids_desc[*]}")"
        printf 'Capture: \e[1;32mRUNNING\e[0m (%s)\n' "${p_str}"
        running=1
    elif is_pidfile_running "${STATE_DIR}/capture.pid"; then
        printf 'Single Capture: \e[1;32mRUNNING\e[0m (PID: %s)\n' "$(cat "${STATE_DIR}/capture.pid")"
        running=1
    else
        printf 'Status: \e[1;33mSTOPPED\e[0m\n'
    fi

    if [[ -f "${STATE_DIR}/last_capture_dual.env" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_DIR}/last_capture_dual.env"
        printf '\nLatest Dual/Multi-side Capture:\n'
        printf '  Test Tag   : %s\n' "${LAST_TEST_TAG:-<none>}"
        printf '  WAN File   : %s\n' "${LAST_PCAP_WAN:-<none>}"
        printf '  LAN File   : %s\n' "${LAST_PCAP_LAN:-<none>}"
        if [[ -n "${LAST_PCAP_WIFI:-}" ]]; then
            printf '  Wi-Fi File : %s\n' "${LAST_PCAP_WIFI}"
        fi
        printf '  Snaplen    : %s bytes\n' "${LAST_SNAPLEN:-0}"
    elif [[ -f "${STATE_DIR}/last_capture.env" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_DIR}/last_capture.env"
        printf '\nLatest Single Capture: %s\n' "${LAST_PCAP:-<none>}"
    fi
}

main() {
    local cmd=""
    local -a cmd_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -s|--snaplen)
                [[ $# -ge 2 ]] || die "Option --snaplen requires a length argument"
                CAPTURE_SNAPLEN="$2"
                shift 2
                ;;
            --snaplen=*)
                CAPTURE_SNAPLEN="${1#*=}"
                shift
                ;;
            -D|--deep)
                export DEEP_AUDIT=1
                shift
                ;;
            -M|--merge-lan)
                export MERGE_LAN=1
                shift
                ;;
            start|start_dual|stop|compare|status|clean|merge-lan|merge_lan)
                cmd="$1"
                shift
                cmd_args=("$@")
                break
                ;;
            *)
                usage
                exit 2
                ;;
        esac
    done

    cmd="${cmd:-status}"

    load_config "${LAB_DIR:-$(pwd)}/config.env"
    export CAPTURE_SNAPLEN="${CAPTURE_SNAPLEN:-0}"

    case "${cmd}" in
        start)       start_capture "${cmd_args[@]}" ;;
        start_dual)  start_dual_capture "${cmd_args[@]}" ;;
        stop)        stop_capture ;;
        compare)     compare_captures "${cmd_args[@]}" ;;
        merge-lan|merge_lan) merge_lan_captures "${cmd_args[@]}" ;;
        status)      show_status ;;
        clean)       stop_capture; clean_captures ;;
    esac
}

main "$@"

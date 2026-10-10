#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - REMOTE PC CLIENT MANAGER
# Manages secondary test PC over SSH for distributed multi-station benchmarking
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

CLI_HOST=""
CLI_USER=""
CLI_PORT=""
CLI_KEY=""
CLI_DIR=""
WITH_CONFIG=0
SILENT=0

usage() {
    cat <<'EOF'
==================================================================
  Gateway Performance Lab - Remote PC Client Manager
==================================================================

Description:
  Orchestrates a secondary/remote client PC over SSH to perform
  distributed multi-station benchmarking (e.g. concurrent 2.4GHz +
  5GHz physical Wi-Fi stations or multi-PC wired + wireless load).
  The remote PC is assumed to host a clone of this repository.

Usage:
  ./scripts/remote_client.sh [COMMAND] [OPTIONS]

Commands:
  test, ping         Verify SSH connectivity and validate remote toolchain
                     (python3, iperf3, iw, nmcli, sudo rights).
  sync, deploy       Synchronize lab codebase to remote PC using rsync
                     (excludes .git, logs, captures, state).
  status             Query remote PC network interfaces and Wi-Fi state.
  wifi-connect <bnd> Connect remote PC to DUT SSID (2g, 5g, 6g).
  wifi-status, info  Query remote PC Wi-Fi connection, SSID, Band, Signal, IP, and DUT reachability.
  wifi-env [opts]    Export remote PC Wi-Fi environment variables suitable for eval / source.
  wifi-ip            Query and print remote PC active Wi-Fi IPv4 address.
  run-iperf [args]   Execute iperf3 client on remote PC towards WAN server.
  run-voip [opts]    Execute VoIP call client (pjsua, sipp, python) on remote PC.
  is-voip-running    Check if remote VoIP client process is currently alive (outputs 1 or 0).
  run-vod [opts]     Execute VOD video client on remote PC.
  run-wireless-qos   Execute concurrent Voice & Video QoS clients on remote PC.
  is-wireless-qos-running Check if remote Wireless QoS clients are alive.
  stop-wireless-qos  Stop remote Wireless QoS client processes.
  start-capture [if] Start background packet capture on remote PC.
  stop-capture [pcap]Stop remote background packet capture.
  start-ota-monitor [opts] Put remote Wi-Fi card into 802.11 monitor mode (mon0)
                     and start over-the-air packet capture (DLT_IEEE802_11_RADIO).
  stop-ota-monitor [opts]  Stop OTA monitor capture, restore managed Wi-Fi mode,
                     and optionally fetch capture locally (--fetch).
  status-ota-monitor Query remote OTA monitor interface and capture state.
  audit-ota-wmm [opts] Perform standalone over-the-air WMM EDCA audit
                     (captures OTA beacon/probe frames on remote sniffer and parses EDCA).
  fetch-capture <rem>Download capture file from remote PC to local path.
  exec <cmd...>      Run an arbitrary command in remote lab directory.
  clean, stop        Terminate lingering test tasks (iperf3, voip, vod, tcpdump) on remote.

Options:
  -H, --host <host>  Remote PC hostname or IP address (overrides config.env).
  -u, --user <user>  SSH username on remote PC (overrides config.env).
  -p, --port <port>  SSH port (default: 22).
  -i, --key <path>   Path to SSH private key.
  -d, --dir <path>   Absolute path to lab directory on remote PC.
  --freq <mhz>       Operating frequency in MHz for OTA monitor (e.g. 5180, 5745).
  --channel <ch>     Operating Wi-Fi channel for OTA monitor (e.g. 36, 149, 11).
  --width <20|40|80> Channel bandwidth in MHz for OTA monitor (default: 40).
  --center-freq <mhz>Center frequency for HT40/VHT80 monitor sniffing.
  --mon-if <iface>   Monitor virtual interface name (default: mon0).
  --bpf <filter>     BPF filter for remote tcpdump capture.
  --bssid <mac>      Target BSSID MAC filter for OTA capture.
  --fetch [dst]      Fetch remote capture to local destination upon stop.
  --with-config      Also sync local config.env during 'sync' command.
  -s, --silent       Suppress non-essential progress logging.
  -h, --help         Show this help message and exit.

Examples:
  ./scripts/remote_client.sh test
  ./scripts/remote_client.sh sync --with-config
  ./scripts/remote_client.sh status
  ./scripts/remote_client.sh wifi-connect 2g
  ./scripts/remote_client.sh start-ota-monitor --channel 36 --width 40
  ./scripts/remote_client.sh stop-ota-monitor --fetch ./captures/remote_ota_5g.pcap
  ./scripts/remote_client.sh status-ota-monitor
  ./scripts/remote_client.sh run-iperf -c 10.10.0.1 -p 5202 -t 5
  ./scripts/remote_client.sh exec uname -a
==================================================================
EOF
}

resolve_config() {
    load_config "${LAB_DIR}/config.env"

    TARGET_HOST="${CLI_HOST:-${REMOTE_CLIENT_HOST:-}}"
    TARGET_USER="${CLI_USER:-${REMOTE_CLIENT_USER:-}}"
    if [[ -z "${TARGET_USER}" || "${TARGET_USER}" == "root" ]]; then
        if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
            TARGET_USER="${SUDO_USER}"
        else
            TARGET_USER="${USER:-network}"
        fi
    fi
    TARGET_PORT="${CLI_PORT:-${REMOTE_CLIENT_PORT:-22}}"
    TARGET_KEY="${CLI_KEY:-${REMOTE_CLIENT_KEY:-${REMOTE_CLIENT_PUBLIC_KEY:-${REMOTE_CLIENT_SSH_KEY:-}}}}"
    TARGET_DIR="${CLI_DIR:-${REMOTE_CLIENT_DIR:-${LAB_DIR}}}"
    SSH_OPTS_STR="${REMOTE_CLIENT_SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new}"

    # Resolve tilde (~) expansion under sudo or standard user
    if [[ "${TARGET_KEY}" =~ ^~(/.*)?$ ]]; then
        local base_home=""
        if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
            base_home="$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6 || true)"
            if [[ -z "${base_home}" ]]; then
                base_home="/home/${SUDO_USER}"
            fi
        else
            base_home="${HOME:-/root}"
        fi
        TARGET_KEY="${base_home}${BASH_REMATCH[1]}"
    fi

    # If user configured path to a public key (*.pub), switch to the private key counterpart for SSH/rsync authentication
    if [[ "${TARGET_KEY}" == *.pub && -f "${TARGET_KEY%.pub}" ]]; then
        TARGET_KEY="${TARGET_KEY%.pub}"
    fi

    # Auto-detect SSH private key when running under sudo or standard user
    if [[ -z "${TARGET_KEY}" || ! -f "${TARGET_KEY}" ]]; then
        local candidates=()
        if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
            local sudo_home
            sudo_home="$(getent passwd "${SUDO_USER}" 2>/dev/null | cut -d: -f6 || echo "/home/${SUDO_USER}")"
            candidates+=("${sudo_home}/.ssh/id_ed25519" "${sudo_home}/.ssh/id_rsa" "${sudo_home}/.ssh/id_ecdsa")
        fi
        candidates+=("${HOME:-/root}/.ssh/id_ed25519" "${HOME:-/root}/.ssh/id_rsa" "${HOME:-/root}/.ssh/id_ecdsa")
        for k in "${candidates[@]}"; do
            if [[ -f "${k}" ]]; then
                TARGET_KEY="${k}"
                break
            fi
        done
    fi

    if [[ -z "${TARGET_HOST}" ]]; then
        log_error "Remote client host not specified."
        log_error "Set REMOTE_CLIENT_HOST in config.env or provide -H <ip_or_host>."
        exit 1
    fi
}

get_ssh_transport_opt() {
    local opt="ssh"
    if [[ -n "${TARGET_PORT}" && "${TARGET_PORT}" != "22" ]]; then
        opt+=" -p ${TARGET_PORT}"
    fi
    if [[ -n "${TARGET_KEY}" && -f "${TARGET_KEY}" ]]; then
        opt+=" -i ${TARGET_KEY}"
    fi
    if [[ -n "${SSH_OPTS_STR}" ]]; then
        opt+=" ${SSH_OPTS_STR}"
    fi
    printf '%s' "${opt}"
}

get_ssh_cmd() {
    local cmd=("ssh")
    if [[ -n "${TARGET_PORT}" && "${TARGET_PORT}" != "22" ]]; then
        cmd+=("-p" "${TARGET_PORT}")
    fi
    if [[ -n "${TARGET_KEY}" && -f "${TARGET_KEY}" ]]; then
        cmd+=("-i" "${TARGET_KEY}")
    fi
    if [[ -n "${SSH_OPTS_STR}" ]]; then
        local -a parsed_opts=()
        IFS=" " read -r -a parsed_opts <<< "${SSH_OPTS_STR}"
        cmd+=("${parsed_opts[@]}")
    fi
    cmd+=("${TARGET_USER}@${TARGET_HOST}")
    printf '%s\0' "${cmd[@]}"
}

remote_ssh_exec() {
    local -a ssh_base=()
    while IFS= read -r -d '' arg; do
        ssh_base+=("${arg}")
    done < <(get_ssh_cmd)

    local remote_cmd="$1"
    log_cmd "${ssh_base[*]} \"bash -c 'cd \\\"${TARGET_DIR}\\\" && ${remote_cmd}'\""
    "${ssh_base[@]}" "bash -c 'cd \"${TARGET_DIR}\" && ${remote_cmd}'"
}

remote_ssh_raw() {
    local -a ssh_base=()
    while IFS= read -r -d '' arg; do
        ssh_base+=("${arg}")
    done < <(get_ssh_cmd)

    local raw_cmd="$1"
    log_cmd "${ssh_base[*]} bash -s <<< '${raw_cmd}'"
    printf '%s\n' "${raw_cmd}" | "${ssh_base[@]}" "bash -s"
}

cmd_test() {
    print_header "REMOTE CLIENT CONNECTIVITY & TOOLCHAIN PROBE"
    log_info "Target Endpoint : ${TARGET_USER}@${TARGET_HOST}:${TARGET_PORT}"
    log_info "Remote Lab Path : ${TARGET_DIR}"

    # 1. Test basic SSH connectivity
    log_info "Testing SSH authentication and shell access..."
    local remote_uname
    if ! remote_uname="$(remote_ssh_raw 'uname -srm 2>/dev/null')"; then
        log_error "Failed to connect to ${TARGET_USER}@${TARGET_HOST} via SSH."
        log_error "Please verify:"
        log_error "  1. Remote host is powered on and reachable via ping: 'ping -c 2 ${TARGET_HOST}'"
        log_error "  2. SSH public key is installed on remote: 'ssh-copy-id -p ${TARGET_PORT} ${TARGET_USER}@${TARGET_HOST}'"
        log_error "  3. Correct SSH user/key is set in config.env or command line."
        return 1
    fi
    log_success "SSH Connection OK. Remote OS: ${remote_uname}"

    # 2. Check remote directory
    log_info "Checking remote lab directory..."
    if remote_ssh_raw "[[ -d \"${TARGET_DIR}\" ]]"; then
        log_success "Remote lab directory exists: ${TARGET_DIR}"
    else
        log_warn "Remote directory does not exist: ${TARGET_DIR}"
        log_info "Run './scripts/remote_client.sh sync' to deploy the workspace."
    fi

    # 3. Check remote tools
    log_info "Probing remote toolchain availability..."
    local check_script='
        tools=(python3 iperf3 iw nmcli ip sudo)
        for t in "${tools[@]}"; do
            if command -v "$t" >/dev/null 2>&1; then
                echo "TOOL:$t:OK:$(command -v "$t")"
            else
                echo "TOOL:$t:MISSING"
            fi
        done
        if sudo -n true 2>/dev/null; then
            echo "SUDO:PASSWORDLESS"
        else
            echo "SUDO:NEEDS_PASSWORD"
        fi
    '
    local remote_probe
    remote_probe="$(remote_ssh_raw "${check_script}" 2>/dev/null || true)"

    while IFS= read -r line; do
        if [[ "${line}" =~ ^TOOL:([^:]+):OK:(.*)$ ]]; then
            log_success "  -> Remote binary: ${BASH_REMATCH[1]} (${BASH_REMATCH[2]})"
        elif [[ "${line}" =~ ^TOOL:([^:]+):MISSING$ ]]; then
            log_warn "  -> Missing remote binary: ${BASH_REMATCH[1]}"
        elif [[ "${line}" == "SUDO:PASSWORDLESS" ]]; then
            log_success "  -> Remote Sudo: Passwordless sudo enabled (ideal for automated test suite)"
        elif [[ "${line}" == "SUDO:NEEDS_PASSWORD" ]]; then
            log_warn "  -> Remote Sudo: Interactive password required (sudo without password recommended)"
        fi
    done <<< "${remote_probe}"

    # 4. Check remote Wi-Fi hardware
    log_info "Probing remote Wi-Fi adapters..."
    local wifi_info
    wifi_info="$(remote_ssh_raw 'iw dev 2>/dev/null | awk "/Interface/ {print \$2}" | tr "\n" " " || true')"
    if [[ -n "${wifi_info// /}" ]]; then
        log_success "Remote Wi-Fi interface(s) detected: ${wifi_info}"
    else
        log_warn "No physical wireless interfaces detected via iw on remote PC."
    fi

    print_section "REMOTE PROBE COMPLETE"
    return 0
}

cmd_sync() {
    print_header "SYNCHRONIZING CODEBASE TO REMOTE CLIENT"
    log_info "Source      : ${LAB_DIR}/"
    log_info "Destination : ${TARGET_USER}@${TARGET_HOST}:${TARGET_DIR}/"

    # Ensure remote directory exists
    remote_ssh_raw "mkdir -p \"${TARGET_DIR}\""

    local -a rsync_cmd=(
        "rsync" "-avz" "--delete"
        "--exclude=.git"
        "--exclude=logs/*"
        "--exclude=captures/*"
        "--exclude=state/*"
        "--exclude=.venv"
        "--exclude=__pycache__"
        "--exclude=*.pyc"
    )

    if (( WITH_CONFIG == 0 )); then
        rsync_cmd+=("--exclude=config.env")
    else
        log_info "Including config.env in sync (--with-config set)"
    fi

    local ssh_r_opt
    ssh_r_opt="$(get_ssh_transport_opt)"

    rsync_cmd+=("-e" "${ssh_r_opt}")
    rsync_cmd+=("${LAB_DIR}/" "${TARGET_USER}@${TARGET_HOST}:${TARGET_DIR}/")

    log_info "Executing rsync..."
    "${rsync_cmd[@]}"

    # Ensure remote script permissions
    remote_ssh_raw "chmod +x \"${TARGET_DIR}\"/scripts/*.sh \"${TARGET_DIR}\"/tools/*.py 2>/dev/null || true"
    log_success "Codebase synchronized successfully to ${TARGET_HOST}:${TARGET_DIR}."
}

cmd_status() {
    print_header "REMOTE CLIENT SYSTEM & WI-FI STATUS"
    log_info "Target Endpoint: ${TARGET_USER}@${TARGET_HOST}"

    if remote_ssh_raw "[[ -f \"${TARGET_DIR}/scripts/show_state.sh\" ]]"; then
        remote_ssh_exec "./scripts/show_state.sh || true"
    else
        log_warn "Remote show_state.sh not found. Running basic hardware inspection..."
        remote_ssh_raw "
            echo '--- Host Interfaces ---'
            ip -brief addr show
            echo '--- Wi-Fi Interfaces ---'
            iw dev 2>/dev/null || echo 'iw not available'
        "
    fi
}

cmd_wifi_connect() {
    local band="${1:-}"
    if [[ -z "${band}" ]]; then
        die "Subcommand 'wifi-connect' requires band argument: 2g, 5g, or 6g"
    fi

    print_header "CONNECTING REMOTE CLIENT WI-FI TO BAND [${band^^}]"
    log_info "Target Endpoint : ${TARGET_USER}@${TARGET_HOST}"
    log_info "Remote Command  : ./scripts/wifi_connect.sh connect ${band} --force"

    remote_ssh_exec "./scripts/wifi_connect.sh connect \"${band}\" --force"
    log_success "Remote Wi-Fi connection triggered successfully."
}

cmd_run_iperf() {
    local -a iperf_args=("$@")
    if (( ${#iperf_args[@]} == 0 )); then
        iperf_args=("-c" "${WAN_SERVER_IP:-10.10.0.1}" "-p" "5202" "-t" "5")
    fi

    # Detect if a specific interface was requested via --bind-dev or -B
    local target_dev=""
    for (( i=0; i<${#iperf_args[@]}; i++ )); do
        if [[ "${iperf_args[i]}" == "--bind-dev" && $(( i + 1 )) -lt ${#iperf_args[@]} ]]; then
            target_dev="${iperf_args[i+1]}"
            break
        elif [[ "${iperf_args[i]}" =~ %([a-zA-Z0-9._-]+)$ ]]; then
            target_dev="${BASH_REMATCH[1]}"
            break
        fi
    done

    local wan_ip="${WAN_SERVER_IP:-10.10.0.1}"
    local remote_gw="${DUT_LAN_IP:-192.168.1.1}"

    if [[ -z "${target_dev}" ]]; then
        if [[ "${REMOTE_CLIENT_ROLE:-}" == "lan_client" && -n "${REMOTE_CLIENT_LAN_IF:-${REMOTE_LAN_IF:-}}" ]]; then
            target_dev="${REMOTE_CLIENT_LAN_IF:-${REMOTE_LAN_IF:-}}"
        else
            # Default fallback to Wi-Fi if no bind dev specified
            local env_dump
            env_dump="$(cmd_get_wifi_env 2>/dev/null || true)"
            eval "${env_dump}"
            target_dev="${REMOTE_WIFI_IF:-}"
            remote_gw="${REMOTE_WIFI_GATEWAY:-${remote_gw}}"
        fi
    fi

    if [[ -n "${target_dev}" && -n "${remote_gw}" ]]; then
        remote_ssh_raw "sudo -n ip route replace '${wan_ip}' via '${remote_gw}' dev '${target_dev}' 2>/dev/null || true"
    fi

    # Join arguments with spaces to prevent IFS newline splitting
    local iperf_cmd
    iperf_cmd="iperf3 $(IFS=' '; echo "${iperf_args[*]}")"
    remote_ssh_raw "${iperf_cmd}"
}

cmd_get_wifi_env() {
    local -a extra_args=("$@")
    local remote_cmd="python3 tools/wifi_inspector.py export-env --prefix REMOTE_"
    if (( ${#extra_args[@]} > 0 )); then
        remote_cmd+=" $(IFS=' '; echo "${extra_args[*]}")"
    fi
    remote_ssh_exec "${remote_cmd}"
}

cmd_wifi_status() {
    print_header "REMOTE CLIENT WI-FI CONNECTION STATUS"
    log_info "Target Endpoint : ${TARGET_USER}@${TARGET_HOST}"

    local env_dump
    env_dump="$(cmd_get_wifi_env --check-ping "${DUT_LAN_IP:-192.168.1.1}" 2>/dev/null || true)"
    eval "${env_dump}"

    local status_label="${REMOTE_WIFI_STATUS:-DISCONNECTED}"
    log_info "  -> Remote Interface : ${REMOTE_WIFI_IF:-none} [${status_label}] (MAC: ${REMOTE_WIFI_MAC:-none})"
    log_info "  -> Target SSID      : '${REMOTE_WIFI_SSID:-none}' (BSSID: ${REMOTE_WIFI_BSSID:-none})"
    log_info "  -> Band & Frequency : ${REMOTE_WIFI_BAND:-none} (Ch: ${REMOTE_WIFI_CHANNEL:-none}, Width: ${REMOTE_WIFI_WIDTH:-none})"
    log_info "  -> Signal & Bitrate : ${REMOTE_WIFI_SIGNAL:-none} (Tx: ${REMOTE_WIFI_BITRATE:-none})"
    log_info "  -> Station IP (DHCP): ${REMOTE_WIFI_IP:-none} (Gateway: ${REMOTE_WIFI_GATEWAY:-none})"
    if [[ "${REMOTE_WIFI_PING_OK:-0}" == "1" ]]; then
        log_success "  -> DUT Reachability : REACHABLE (Ping RTT: ${REMOTE_WIFI_PING_RTT:-<1ms})"
    else
        log_warn "  -> DUT Reachability : UNREACHABLE (Failed ping to ${DUT_LAN_IP:-192.168.1.1})"
    fi
    print_section "STATUS QUERY COMPLETE"
}

cmd_get_wifi_ip() {
    local env_dump
    env_dump="$(cmd_get_wifi_env 2>/dev/null || true)"
    eval "${env_dump}"
    echo "${REMOTE_WIFI_IP:-}"
}

cmd_run_voip() {
    local engine="auto"
    local server_ip="${WAN_SERVER_IP:-10.10.0.1}"
    local server_port=5060
    local local_port=5064
    local rtp_port=10002
    local duration="${VOIP_CALL_DURATION_SEC:-20}"
    local phone_id="phone-2"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --engine|-E) engine="$2"; shift 2 ;;
            --server-ip) server_ip="$2"; shift 2 ;;
            --server-port) server_port="$2"; shift 2 ;;
            --local-port) local_port="$2"; shift 2 ;;
            --rtp-port) rtp_port="$2"; shift 2 ;;
            --duration|-d) duration="$2"; shift 2 ;;
            --phone-id) phone_id="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Probe remote Wi-Fi status & IP
    local env_dump
    env_dump="$(cmd_get_wifi_env 2>/dev/null || true)"
    eval "${env_dump}"
    local remote_wifi_ip="${REMOTE_WIFI_IP:-}"
    local remote_wifi_if="${REMOTE_WIFI_IF:-wlan0}"
    local remote_ssid="${REMOTE_WIFI_SSID:-none}"
    local remote_status="${REMOTE_WIFI_STATUS:-DISCONNECTED}"
    local remote_gw="${REMOTE_WIFI_GATEWAY:-${DUT_LAN_IP:-192.168.1.1}}"

    # Ensure remote host routes traffic for server_ip via Wi-Fi interface (DUT)
    # and mark outgoing VoIP packets with DSCP 46 (EF) for 802.11 WMM Voice (AC_VO)
    if [[ -n "${remote_wifi_if}" && -n "${remote_gw}" ]]; then
        remote_ssh_raw "sudo -n ip route replace '${server_ip}' via '${remote_gw}' dev '${remote_wifi_if}' 2>/dev/null || true"
        remote_ssh_raw "sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp -m multiport --dports 5060,5062,5064,10000,10002,10004 -j DSCP --set-dscp 46 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp -m multiport --dports 5060,5062,5064,10000,10002,10004 -j DSCP --set-dscp 46 2>/dev/null || true; sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp -m multiport --sports 5060,5062,5064,10000,10002,10004 -j DSCP --set-dscp 46 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp -m multiport --sports 5060,5062,5064,10000,10002,10004 -j DSCP --set-dscp 46 2>/dev/null || true"
    fi

    local remote_cmd=""
    if [[ "${engine}" == "pjsua" || "${engine}" == "auto" ]]; then
        local has_pjsua
        has_pjsua="$(remote_ssh_raw "export PATH=\"${TARGET_DIR}/tools/bin:\$PATH\"; command -v pjsua >/dev/null && echo 1 || echo 0" 2>/dev/null | tr -d '\r\n ')"
        if [[ "${has_pjsua}" == "1" ]]; then
            engine="pjsua"
        elif [[ "${engine}" == "auto" ]]; then
            local has_sipp
            has_sipp="$(remote_ssh_raw "export PATH=\"${TARGET_DIR}/tools/bin:\$PATH\"; command -v sipp >/dev/null && echo 1 || echo 0" 2>/dev/null | tr -d '\r\n ')"
            if [[ "${has_sipp}" == "1" ]]; then
                engine="sipp"
            else
                engine="python"
            fi
        fi
    fi

    local log_file="/tmp/voip_${phone_id}.log"
    local env_prefix="export PATH=\"./tools/bin:\$PATH\"; export LD_LIBRARY_PATH=\"\${PWD}/tools/lib:\$LD_LIBRARY_PATH\";"
    if [[ "${engine}" == "pjsua" ]]; then
        local ip_opt=""
        if [[ -n "${remote_wifi_ip}" ]]; then
            ip_opt="--ip-addr=${remote_wifi_ip} --bound-addr=${remote_wifi_ip}"
        fi
        remote_cmd="${env_prefix} nohup pjsua --local-port=${local_port} --rtp-port=${rtp_port} --null-audio --no-vad ${ip_opt} --duration=${duration} --set-qos --use-cli --no-cli-console --app-log-level=0 'sip:${server_ip}:${server_port}' > \"${log_file}\" 2>&1 < /dev/null & echo \$!"

    elif [[ "${engine}" == "sipp" ]]; then
        local ip_opt=""
        if [[ -n "${remote_wifi_ip}" ]]; then
            ip_opt="-i ${remote_wifi_ip} -mi ${remote_wifi_ip}"
        fi
        local sipp_dur_ms=$(( duration * 1000 ))
        local tpl="templates/sipp_uac_pcap.xml"
        local pcap="templates/g711a_voice.pcap"
        local pcap_abs="${TARGET_DIR}/${pcap}"
        local has_tpl
        has_tpl="$(remote_ssh_raw "[[ -f '${TARGET_DIR}/${tpl}' && -f '${pcap_abs}' ]] && echo 1 || echo 0" 2>/dev/null | tr -d '\r\n ')"
        if [[ "${has_tpl}" == "1" ]]; then
            # Substitute absolute pcap path into temporary XML and ensure root symlink
            remote_ssh_exec "sed \"s|__PCAP_FILE__|${pcap_abs}|g\" \"${TARGET_DIR}/${tpl}\" > /tmp/sipp_uac_pcap_${phone_id}.xml && ln -sf \"${pcap_abs}\" \"${TARGET_DIR}/g711a_voice.pcap\" 2>/dev/null || true"
            remote_cmd="${env_prefix} nohup sudo -n sipp -sf /tmp/sipp_uac_pcap_${phone_id}.xml '${server_ip}:${server_port}' ${ip_opt} -p ${local_port} -mp ${rtp_port} -m 1 -d ${sipp_dur_ms} -nostdin > \"${log_file}\" 2>&1 < /dev/null & echo \$!"
        else
            remote_cmd="${env_prefix} nohup sipp -sn uac '${server_ip}:${server_port}' ${ip_opt} -p ${local_port} -mp ${rtp_port} -m 1 -d ${sipp_dur_ms} -nostdin > \"${log_file}\" 2>&1 < /dev/null & echo \$!"
        fi

    else
        local ip_opt=""
        if [[ -n "${remote_wifi_ip}" ]]; then
            ip_opt="--bind-ip ${remote_wifi_ip}"
        fi
        remote_cmd="${env_prefix} nohup python3 tools/voip_call_simulator.py client --server-ip ${server_ip} --server-port ${rtp_port} ${ip_opt} --duration ${duration} --phone-id ${phone_id} > \"${log_file}\" 2>&1 < /dev/null & echo \$!"
    fi

    log_info "Launching remote [${phone_id}] VoIP client on ${TARGET_HOST}..."
    log_info "  -> Remote Wi-Fi Link : ${remote_wifi_if} [${remote_status}] (SSID: '${remote_ssid}', IP: ${remote_wifi_ip:-unknown})"
    log_info "  -> Remote Route      : ${server_ip} via ${remote_gw} dev ${remote_wifi_if}"
    log_info "  -> VoIP Engine       : [${engine^^}] | Server: ${server_ip}:${server_port} | RTP: ${rtp_port} | Duration: ${duration}s"

    local spawned_pid
    spawned_pid="$(remote_ssh_exec "${remote_cmd}" 2>/dev/null | tr -d '\r\n ' || true)"
    if [[ -n "${spawned_pid}" && "${spawned_pid}" =~ ^[0-9]+$ ]]; then
        remote_ssh_raw "echo ${spawned_pid} > /tmp/voip_${phone_id}.pid"
    fi

    # Verify process actually started and is running
    local is_alive=0
    local log_snippet=""
    if [[ -n "${spawned_pid}" && "${spawned_pid}" =~ ^[0-9]+$ ]]; then
        sleep 0.5
        is_alive="$(remote_ssh_raw "kill -0 ${spawned_pid} 2>/dev/null || sudo -n kill -0 ${spawned_pid} 2>/dev/null && echo 1 || echo 0" 2>/dev/null | tr -d '\r\n ' || true)"
    fi

    if [[ "${is_alive}" == "1" ]]; then
        log_success "Remote VoIP client [${phone_id}] active on ${TARGET_HOST} (PID: ${spawned_pid}, Log: ${log_file})."
        return 0
    else
        log_snippet="$(remote_ssh_raw "cat ${log_file} 2>/dev/null | tr '\n' ' ' | head -c 200" 2>/dev/null || true)"
        log_error "Remote VoIP client [${phone_id}] FAILED to run on ${TARGET_HOST}!"
        if [[ -n "${log_snippet}" ]]; then
            log_error "  Remote error log: ${log_snippet}"
        fi
        return 1
    fi
}

cmd_is_voip_running() {
    local phone_id="${1:-phone-2}"
    local check_cmd='
        pid=""
        pid_file="/tmp/voip_'"${phone_id}"'.pid"
        if [[ -f "${pid_file}" ]]; then
            pid="$(cat "${pid_file}" 2>/dev/null | tr -d "[:space:]")"
        fi
        if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
            if kill -0 "${pid}" 2>/dev/null || sudo -n kill -0 "${pid}" 2>/dev/null; then
                echo 1
                exit 0
            else
                echo 0
                exit 0
            fi
        fi
        if pgrep -f "voip_'"${phone_id}"'" >/dev/null 2>&1; then
            echo 1
            exit 0
        fi
        echo 0
    '
    remote_ssh_raw "${check_cmd}" | tr -d '\r\n '
}

cmd_run_vod() {
    local server_ip="${WAN_SERVER_IP:-10.10.0.1}"
    local server_port=5005
    local bind_port=5005
    local duration=10
    local dscp=34
    local output_json="/tmp/wqos_vod.json"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server-ip) server_ip="$2"; shift 2 ;;
            --server-port) server_port="$2"; shift 2 ;;
            --bind-port) bind_port="$2"; shift 2 ;;
            --duration|-d) duration="$2"; shift 2 ;;
            --dscp) dscp="$2"; shift 2 ;;
            --output-json) output_json="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    local env_dump
    env_dump="$(cmd_get_wifi_env 2>/dev/null || true)"
    eval "${env_dump}"
    local remote_wifi_ip="${REMOTE_WIFI_IP:-}"
    local remote_wifi_if="${REMOTE_WIFI_IF:-wlan0}"
    local remote_gw="${REMOTE_WIFI_GATEWAY:-${DUT_LAN_IP:-192.168.1.1}}"

    if [[ -n "${remote_wifi_if}" && -n "${remote_gw}" ]]; then
        remote_ssh_raw "sudo -n ip route replace '${server_ip}' via '${remote_gw}' dev '${remote_wifi_if}' 2>/dev/null || true"
        remote_ssh_raw "sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp --dport ${bind_port} -j DSCP --set-dscp ${dscp} 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp --dport ${bind_port} -j DSCP --set-dscp ${dscp} 2>/dev/null || true; sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp --sport ${bind_port} -j DSCP --set-dscp ${dscp} 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp --sport ${bind_port} -j DSCP --set-dscp ${dscp} 2>/dev/null || true"
    fi

    local ip_opt=""
    if [[ -n "${remote_wifi_ip}" ]]; then
        ip_opt="--bind-ip ${remote_wifi_ip}"
    fi

    local env_prefix="export PATH=\"./tools/bin:\$PATH\"; export LD_LIBRARY_PATH=\"\${PWD}/tools/lib:\$LD_LIBRARY_PATH\";"
    local remote_cmd="${env_prefix} nohup python3 tools/vod_stream_tester.py client --server-ip ${server_ip} --server-port ${server_port} --bind-port ${bind_port} ${ip_opt} --dscp ${dscp} --duration ${duration} --output-json ${output_json} > /tmp/wqos_vod.log 2>&1 < /dev/null & echo \$!"

    local spawned_pid
    spawned_pid="$(remote_ssh_exec "${remote_cmd}" 2>/dev/null | tr -d '\r\n ' || true)"
    if [[ -n "${spawned_pid}" && "${spawned_pid}" =~ ^[0-9]+$ ]]; then
        remote_ssh_raw "echo ${spawned_pid} > /tmp/wqos_vod.pid"
        log_success "Remote VOD client active on ${TARGET_HOST} (PID: ${spawned_pid})."
    else
        log_error "Remote VOD client FAILED to start on ${TARGET_HOST}!"
        return 1
    fi
}

cmd_run_wireless_qos() {
    local server_ip="${WAN_SERVER_IP:-10.10.0.1}"
    local duration=10
    local voice_dscp=46
    local video_dscp=34
    local voice_port=10000
    local video_port=5005

    # Never reuse metrics from an earlier invocation when a client fails to start.
    remote_ssh_raw "rm -f /tmp/wqos_vod.json /tmp/wqos_voice.json"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --server-ip) server_ip="$2"; shift 2 ;;
            --duration|-d) duration="$2"; shift 2 ;;
            --voice-dscp) voice_dscp="$2"; shift 2 ;;
            --video-dscp) video_dscp="$2"; shift 2 ;;
            --voice-port) voice_port="$2"; shift 2 ;;
            --video-port) video_port="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    # Probe remote Wi-Fi status & IP
    local env_dump
    env_dump="$(cmd_get_wifi_env 2>/dev/null || true)"
    eval "${env_dump}"
    local remote_wifi_ip="${REMOTE_WIFI_IP:-}"
    local remote_wifi_if="${REMOTE_WIFI_IF:-wlan0}"
    local remote_gw="${REMOTE_WIFI_GATEWAY:-${DUT_LAN_IP:-192.168.1.1}}"

    if [[ -z "${remote_wifi_ip}" ]]; then
        log_error "No active Wi-Fi IP detected on remote PC ${TARGET_HOST}!"
        return 1
    fi

    # Ensure remote host routes traffic for server_ip via Wi-Fi interface (DUT)
    if [[ -n "${remote_wifi_if}" && -n "${remote_gw}" ]]; then
        remote_ssh_raw "sudo -n ip route replace '${server_ip}' via '${remote_gw}' dev '${remote_wifi_if}' 2>/dev/null || true"
        # Mangle rules for Voice (DSCP 46) and Video (DSCP 34)
        remote_ssh_raw "sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp --dport ${voice_port} -j DSCP --set-dscp ${voice_dscp} 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp --dport ${voice_port} -j DSCP --set-dscp ${voice_dscp} 2>/dev/null || true; sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp --sport ${voice_port} -j DSCP --set-dscp ${voice_dscp} 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp --sport ${voice_port} -j DSCP --set-dscp ${voice_dscp} 2>/dev/null || true"
        remote_ssh_raw "sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp --dport ${video_port} -j DSCP --set-dscp ${video_dscp} 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp --dport ${video_port} -j DSCP --set-dscp ${video_dscp} 2>/dev/null || true; sudo -n iptables -t mangle -C POSTROUTING -o '${remote_wifi_if}' -p udp --sport ${video_port} -j DSCP --set-dscp ${video_dscp} 2>/dev/null || sudo -n iptables -t mangle -A POSTROUTING -o '${remote_wifi_if}' -p udp --sport ${video_port} -j DSCP --set-dscp ${video_dscp} 2>/dev/null || true"
    fi

    local env_prefix="export PATH=\"./tools/bin:\$PATH\"; export LD_LIBRARY_PATH=\"\${PWD}/tools/lib:\$LD_LIBRARY_PATH\";"

    # Start VOD Client
    local vod_cmd="${env_prefix} nohup python3 tools/vod_stream_tester.py client --server-ip ${server_ip} --server-port ${video_port} --bind-ip ${remote_wifi_ip} --bind-port ${video_port} --dscp ${video_dscp} --duration ${duration} --min-throughput-mbps 0 --max-loss-pct 1.0 --output-json /tmp/wqos_vod.json > /tmp/wqos_vod.log 2>&1 < /dev/null & echo \$!"
    local vod_pid
    vod_pid="$(remote_ssh_exec "${vod_cmd}" 2>/dev/null | tr -d '\r\n ' || true)"
    if [[ -n "${vod_pid}" && "${vod_pid}" =~ ^[0-9]+$ ]]; then
        remote_ssh_raw "echo ${vod_pid} > /tmp/wqos_vod.pid"
    fi

    # Start Voice Client
    local voice_cmd="${env_prefix} nohup python3 tools/voip_call_simulator.py client --server-ip ${server_ip} --server-port ${voice_port} --bind-ip ${remote_wifi_ip} --bind-port ${voice_port} --dscp ${voice_dscp} --duration ${duration} --phone-id wqos-voice --output-json /tmp/wqos_voice.json > /tmp/wqos_voice.log 2>&1 < /dev/null & echo \$!"
    local voice_pid
    voice_pid="$(remote_ssh_exec "${voice_cmd}" 2>/dev/null | tr -d '\r\n ' || true)"
    if [[ -n "${voice_pid}" && "${voice_pid}" =~ ^[0-9]+$ ]]; then
        remote_ssh_raw "echo ${voice_pid} > /tmp/wqos_voice.pid"
    fi

    log_success "Remote Wireless QoS clients launched on ${TARGET_HOST} (VOD PID: ${vod_pid:-fail}, Voice PID: ${voice_pid:-fail})."
}

cmd_is_wireless_qos_running() {
    local check_cmd='
        alive=0
        for svc in vod voice; do
            if [[ -f "/tmp/wqos_${svc}.pid" ]]; then
                pid="$(cat "/tmp/wqos_${svc}.pid" 2>/dev/null | tr -d "[:space:]")"
                if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
                    if kill -0 "${pid}" 2>/dev/null || sudo -n kill -0 "${pid}" 2>/dev/null; then
                        alive=$(( alive + 1 ))
                    fi
                fi
            fi
        done
        echo "${alive}"
    '
    remote_ssh_raw "${check_cmd}" | tr -d '\r\n '
}

cmd_stop_wireless_qos() {
    local stop_script='
        for svc in vod voice; do
            if [[ -f "/tmp/wqos_${svc}.pid" ]]; then
                pid="$(cat "/tmp/wqos_${svc}.pid" 2>/dev/null | tr -d "[:space:]")"
                if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
                    kill -TERM "${pid}" 2>/dev/null || sudo -n kill -TERM "${pid}" 2>/dev/null || true
                    sleep 0.1
                    kill -KILL "${pid}" 2>/dev/null || sudo -n kill -KILL "${pid}" 2>/dev/null || true
                fi
                rm -f "/tmp/wqos_${svc}.pid" 2>/dev/null || true
            fi
        done
        pkill -TERM -f "[v]od_stream_tester.py" 2>/dev/null || true
        pkill -TERM -f "[v]oip_call_simulator.py" 2>/dev/null || true
    '
    remote_ssh_raw "${stop_script}"
}

cmd_clean() {
    print_header "CLEANING LINGERING PROCESSES ON REMOTE CLIENT"
    log_info "Target Endpoint: ${TARGET_USER}@${TARGET_HOST}"

    local wan_ip="${WAN_SERVER_IP:-10.10.0.1}"
    local clean_script='
        for proc in iperf3 pjsua sipp; do
            sudo -n pkill -TERM -x "${proc}" 2>/dev/null || pkill -TERM -x "${proc}" 2>/dev/null || true
        done
        pkill -TERM -f "[t]raffic_generator.py" 2>/dev/null || true
        pkill -TERM -f "[v]oip_call_simulator.py" 2>/dev/null || true
        pkill -TERM -f "[v]od_stream_tester.py" 2>/dev/null || true
        pkill -TERM -f "[t]cpdump -i" 2>/dev/null || true
        sleep 0.2
        for proc in iperf3 pjsua sipp; do
            sudo -n pkill -KILL -x "${proc}" 2>/dev/null || pkill -KILL -x "${proc}" 2>/dev/null || true
        done
        pkill -KILL -f "[t]raffic_generator.py" 2>/dev/null || true
        pkill -KILL -f "[v]oip_call_simulator.py" 2>/dev/null || true
        pkill -KILL -f "[v]od_stream_tester.py" 2>/dev/null || true
        sudo -n pkill -KILL -f "[t]cpdump.*mon" 2>/dev/null || true
        sudo -n ip link set mon0 down 2>/dev/null || true
        sudo -n iw dev mon0 del 2>/dev/null || true
        sudo -n ip link set wlp3s0 up 2>/dev/null || true
        sudo -n nmcli dev set wlp3s0 managed yes 2>/dev/null || true
        rm -f /tmp/voip_*.pid /tmp/voip_*.log /tmp/sipp_uac_pcap*.xml /tmp/wqos_*.pid /tmp/wqos_*.log /tmp/wqos_*.json /tmp/ota_*.pid /tmp/ota_*.state /tmp/ota_*.log 2>/dev/null || true
        sudo -n ip route del "'"${wan_ip}"'" 2>/dev/null || true
        sudo -n iptables -t mangle -D POSTROUTING -p udp -m multiport --dports 5060,5062,5064,10000,10002,10004 -j DSCP --set-dscp 46 2>/dev/null || true
        sudo -n iptables -t mangle -D POSTROUTING -p udp -m multiport --sports 5060,5062,5064,10000,10002,10004 -j DSCP --set-dscp 46 2>/dev/null || true
        sudo -n iptables -t mangle -D POSTROUTING -p udp --dport 5005 -j DSCP --set-dscp 34 2>/dev/null || true
        sudo -n iptables -t mangle -D POSTROUTING -p udp --sport 5005 -j DSCP --set-dscp 34 2>/dev/null || true
        sudo -n iptables -t mangle -D POSTROUTING -p udp --dport 10000 -j DSCP --set-dscp 46 2>/dev/null || true
        sudo -n iptables -t mangle -D POSTROUTING -p udp --sport 10000 -j DSCP --set-dscp 46 2>/dev/null || true
        echo "Remote processes cleaned."
    '
    remote_ssh_raw "${clean_script}"
    log_success "Cleanup complete on remote client."
}

cmd_start_capture() {
    local iface="${1:-wlp3s0}"
    local bpf_filter="${2:-udp port 5060 or udp port 5064 or udp port 10002}"
    local pcap_path="${3:-captures/remote_wifi.pcap}"
    local snaplen="${4:-${CAPTURE_SNAPLEN:-96}}"

    local target_pcap="${pcap_path}"
    if [[ "${target_pcap}" != /* ]]; then
        if [[ "${target_pcap}" != captures/* ]]; then
            target_pcap="captures/${target_pcap}"
        fi
        target_pcap="${TARGET_DIR}/${target_pcap}"
    fi

    remote_ssh_raw "
        mkdir -p \"\$(dirname '${target_pcap}')\" 2>/dev/null || true
        chmod 0777 \"\$(dirname '${target_pcap}')\" 2>/dev/null || true
        sudo -n pkill -KILL -f \"[t]cpdump.*${target_pcap}\" 2>/dev/null || true
        sudo -n rm -f '${target_pcap}' 2>/dev/null || true
        touch '${target_pcap}' 2>/dev/null || sudo -n touch '${target_pcap}' 2>/dev/null || true
        chmod 0666 '${target_pcap}' 2>/dev/null || sudo -n chmod 0666 '${target_pcap}' 2>/dev/null || true
        nohup sudo -n tcpdump -ni '${iface}' -s ${snaplen} -U -w '${target_pcap}' ${bpf_filter} >/dev/null 2>&1 < /dev/null &
    "
    sleep 0.4
    local is_alive
    is_alive="$(remote_ssh_raw "sudo -n pgrep -f \"[t]cpdump.*${target_pcap}\" >/dev/null && echo 1 || echo 0" | tr -d '\r\n ')"
    if [[ "${is_alive}" == "1" ]]; then
        log_success "Remote Wi-Fi capture active on ${TARGET_HOST}:${iface} -> ${target_pcap}"
    else
        log_warn "Failed to start remote Wi-Fi capture on ${TARGET_HOST}:${iface}"
    fi
}

cmd_stop_capture() {
    local pcap_path="${1:-captures/remote_wifi.pcap}"
    local target_pcap="${pcap_path}"
    if [[ "${target_pcap}" != /* ]]; then
        if [[ "${target_pcap}" != captures/* ]]; then
            target_pcap="captures/${target_pcap}"
        fi
        target_pcap="${TARGET_DIR}/${target_pcap}"
    fi
    remote_ssh_raw "
        sudo -n pkill -TERM -f \"[t]cpdump.*${target_pcap}\" 2>/dev/null || true
        sleep 0.2
        sudo -n pkill -KILL -f \"[t]cpdump.*${target_pcap}\" 2>/dev/null || true
        sudo -n chmod 0666 '${target_pcap}' 2>/dev/null || true
    "
    log_success "Remote Wi-Fi capture stopped: ${target_pcap}"
}

cmd_start_ota_monitor() {
    local iface=""
    local mon_if="mon0"
    local freq=""
    local channel=""
    local band=""
    local width="40"
    local center_freq=""
    local bpf_filter=""
    local bssid=""
    local pcap_path=""
    local snaplen=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iface|-i)
                iface="$2"
                shift 2
                ;;
            --mon-if|--mon-iface|-m)
                mon_if="$2"
                shift 2
                ;;
            --freq|-f)
                freq="$2"
                shift 2
                ;;
            --channel|-c)
                channel="$2"
                shift 2
                ;;
            --band|-b)
                band="$2"
                shift 2
                ;;
            --width|-w)
                width="$2"
                shift 2
                ;;
            --center-freq)
                center_freq="$2"
                shift 2
                ;;
            --bpf|--filter)
                bpf_filter="$2"
                shift 2
                ;;
            --bssid)
                bssid="$2"
                shift 2
                ;;
            --pcap)
                pcap_path="$2"
                shift 2
                ;;
            --snaplen|-s)
                snaplen="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    # 1. Resolve remote physical Wi-Fi interface
    if [[ -z "${iface}" ]]; then
        iface="${REMOTE_CLIENT_WIFI_IF:-auto}"
        if [[ "${iface}" == "auto" || -z "${iface}" ]]; then
            iface="$(remote_ssh_raw 'iw dev 2>/dev/null | awk "/Interface/ && \$2 !~ /mon/ {print \$2; exit}"' | tr -d '\r\n ')"
        fi
    fi
    if [[ -z "${iface}" ]]; then
        iface="wlp3s0"
    fi

    # 2. Derive frequency from channel if specified
    if [[ -n "${channel}" && -z "${freq}" ]]; then
        if (( channel >= 1 && channel <= 14 )); then
            if (( channel == 14 )); then
                freq=2484
            else
                freq=$(( 2407 + channel * 5 ))
            fi
            if [[ -z "${center_freq}" && "${width}" == "20" ]]; then
                center_freq="${freq}"
            fi
        elif (( channel >= 36 && channel <= 165 )); then
            freq=$(( 5000 + channel * 5 ))
        fi
    fi

    # 3. Auto-detect frequency and width from active remote Wi-Fi connection if not provided
    if [[ -z "${freq}" ]]; then
        local link_info
        link_info="$(remote_ssh_raw "iw dev '${iface}' link 2>/dev/null || true")"
        if [[ "${link_info}" =~ freq:[[:space:]]*([0-9]+) ]]; then
            freq="${BASH_REMATCH[1]}"
            local dev_info
            dev_info="$(remote_ssh_raw "iw dev '${iface}' info 2>/dev/null || true")"
            if [[ "${dev_info}" =~ width:[[:space:]]*([0-9]+)[[:space:]]*MHz ]]; then
                width="${BASH_REMATCH[1]}"
            fi
            if [[ "${dev_info}" =~ center1:[[:space:]]*([0-9]+)[[:space:]]*MHz ]]; then
                center_freq="${BASH_REMATCH[1]}"
            fi
        fi
    fi

    # Fallback default if still unassigned (default 5GHz Ch 36 40MHz)
    if [[ -z "${freq}" ]]; then
        freq="5180"
        width="40"
        center_freq="5190"
    fi

    # 4. Resolve center frequency for HT40 if not given
    if [[ -z "${center_freq}" ]]; then
        if [[ "${width}" == "20" ]]; then
            center_freq="${freq}"
        elif [[ "${width}" == "40" ]]; then
            if (( freq >= 5180 && freq <= 5320 )) || (( freq >= 5500 && freq <= 5720 )); then
                if (( (freq / 20) % 2 == 1 )); then
                    center_freq=$(( freq + 10 ))
                else
                    center_freq=$(( freq - 10 ))
                fi
            elif (( freq == 5745 || freq == 5785 )); then
                center_freq=$(( freq + 10 ))
            elif (( freq == 5765 || freq == 5805 )); then
                center_freq=$(( freq - 10 ))
            elif (( freq >= 2412 && freq <= 2442 )); then
                center_freq=$(( freq + 10 ))
            elif (( freq >= 2447 && freq <= 2472 )); then
                center_freq=$(( freq - 10 ))
            else
                center_freq="${freq}"
            fi
        fi
    fi

    # 5. Resolve BPF filter from BSSID if provided
    if [[ -n "${bssid}" && -z "${bpf_filter}" ]]; then
        bpf_filter="wlan addr1 ${bssid} or wlan addr2 ${bssid} or wlan addr3 ${bssid}"
    fi

    # 6. Resolve target pcap path
    if [[ -z "${pcap_path}" ]]; then
        local ts
        ts="$(date +%Y%m%d_%H%M%S)"
        pcap_path="captures/remote_ota_${ts}.pcap"
    fi
    local target_pcap="${pcap_path}"
    if [[ "${target_pcap}" != /* ]]; then
        if [[ "${target_pcap}" != captures/* && "${target_pcap}" != tmp/* ]]; then
            target_pcap="captures/${target_pcap}"
        fi
        target_pcap="${TARGET_DIR}/${target_pcap}"
    fi

    print_header "STARTING REMOTE OTA MONITOR CAPTURE"
    log_info "Target Endpoint  : ${TARGET_USER}@${TARGET_HOST}"
    log_info "Base Interface   : ${iface}"
    log_info "Monitor Dev      : ${mon_if}"
    log_info "Tuning Target    : ${freq} MHz (Width: ${width} MHz${center_freq:+, Center: ${center_freq} MHz})"
    log_info "Capture Dest     : ${target_pcap}"
    if [[ -n "${bpf_filter}" ]]; then
        log_info "BPF Filter       : ${bpf_filter}"
    else
        log_info "BPF Filter       : [None - Capture All 802.11 Frames]"
    fi

    # 7. Execute remote initialization and capture
    local remote_start_cmd
    remote_start_cmd="
        mkdir -p \"\$(dirname '${target_pcap}')\" 2>/dev/null || true
        chmod 0777 \"\$(dirname '${target_pcap}')\" 2>/dev/null || true

        # Clean lingering monitor capture
        sudo -n pkill -KILL -f \"[t]cpdump.*${mon_if}\" 2>/dev/null || true
        if [[ -f /tmp/ota_capture.pid ]]; then
            old_pid=\"\$(cat /tmp/ota_capture.pid 2>/dev/null | tr -d '[:space:]')\"
            if [[ -n \"\${old_pid}\" ]]; then
                sudo -n kill -KILL \"\${old_pid}\" 2>/dev/null || true
            fi
            rm -f /tmp/ota_capture.pid
        fi

        # Clean lingering monitor interface
        sudo -n ip link set '${mon_if}' down 2>/dev/null || true
        sudo -n iw dev '${mon_if}' del 2>/dev/null || true

        # Save monitor state
        {
            echo "BASE_IFACE='${iface}'"
            echo "MON_IFACE='${mon_if}'"
            echo "FREQ='${freq}'"
            echo "WIDTH='${width}'"
            echo "CENTER_FREQ='${center_freq}'"
            echo "PCAP_PATH='${target_pcap}'"
        } > /tmp/ota_monitor.state

        sudo -n nmcli dev set '${mon_if}' managed no 2>/dev/null || true
        sudo -n ip link set '${iface}' down 2>/dev/null || true
        sudo -n iw dev '${iface}' interface add '${mon_if}' type monitor
        sudo -n ip link set '${mon_if}' up
    "

    if [[ -n "${center_freq}" && "${width}" != "20" ]]; then
        remote_start_cmd+="
        sudo -n iw dev '${mon_if}' set freq '${freq}' '${width}' '${center_freq}'
        "
    else
        remote_start_cmd+="
        sudo -n iw dev '${mon_if}' set freq '${freq}'
        "
    fi

    remote_start_cmd+="
        sudo -n rm -f '${target_pcap}' 2>/dev/null || true
        touch '${target_pcap}' 2>/dev/null || sudo -n touch '${target_pcap}' 2>/dev/null || true
        sudo -n chmod 0666 '${target_pcap}' 2>/dev/null || true

        nohup sudo -n tcpdump -ni '${mon_if}' -s ${snaplen} -U -w '${target_pcap}' ${bpf_filter} > /tmp/ota_capture.log 2>&1 < /dev/null &
        echo \$! > /tmp/ota_capture.pid
    "

    remote_ssh_raw "${remote_start_cmd}"
    sleep 0.5

    # 8. Verify running state
    local is_alive
    is_alive="$(remote_ssh_raw '
        if [[ -f /tmp/ota_capture.pid ]]; then
            pid="$(cat /tmp/ota_capture.pid 2>/dev/null | tr -d "[:space:]")"
            if [[ -n "${pid}" ]] && sudo -n kill -0 "${pid}" 2>/dev/null; then
                echo "1"
            else
                echo "0"
            fi
        else
            echo "0"
        fi
    ' | tr -d '\r\n ')"

    if [[ "${is_alive}" == "1" ]]; then
        log_success "Remote OTA Monitor capture active on ${TARGET_HOST}:${mon_if} -> ${target_pcap}"
        echo "${target_pcap}"
        return 0
    else
        log_error "Failed to start remote OTA Monitor capture on ${TARGET_HOST}:${mon_if}!"
        remote_ssh_raw "cat /tmp/ota_capture.log 2>/dev/null || true"
        return 1
    fi
}

cmd_stop_ota_monitor() {
    local target_pcap=""
    local do_fetch=0
    local local_dst=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --pcap)
                target_pcap="$2"
                shift 2
                ;;
            --fetch)
                do_fetch=1
                shift
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    local_dst="$1"
                    shift
                fi
                ;;
            *)
                shift
                ;;
        esac
    done

    print_header "STOPPING REMOTE OTA MONITOR CAPTURE"
    log_info "Target Endpoint: ${TARGET_USER}@${TARGET_HOST}"

    local remote_stop_script='
        # 1. Terminate tcpdump
        if [[ -f /tmp/ota_capture.pid ]]; then
            pid="$(cat /tmp/ota_capture.pid 2>/dev/null | tr -d "[:space:]")"
            if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
                sudo -n kill -TERM "${pid}" 2>/dev/null || true
                sleep 0.2
                sudo -n kill -KILL "${pid}" 2>/dev/null || true
            fi
            rm -f /tmp/ota_capture.pid 2>/dev/null || true
        fi
        sudo -n pkill -TERM -f "[t]cpdump.*mon" 2>/dev/null || true

        # 2. Extract recorded state
        if [[ -f /tmp/ota_monitor.state ]]; then
            # shellcheck disable=SC1091
            source /tmp/ota_monitor.state 2>/dev/null || true
        fi
        base_iface="${BASE_IFACE:-wlp3s0}"
        mon_if="${MON_IFACE:-mon0}"
        pcap_path="${PCAP_PATH:-'"${target_pcap}"'}"

        # 3. Teardown monitor interface
        sudo -n ip link set "${mon_if}" down 2>/dev/null || true
        sudo -n iw dev "${mon_if}" del 2>/dev/null || true

        # 4. Restore base Wi-Fi interface
        sudo -n ip link set "${base_iface}" up 2>/dev/null || true
        sudo -n nmcli dev set "${base_iface}" managed yes 2>/dev/null || true
        sudo -n nmcli dev connect "${base_iface}" 2>/dev/null || true

        # 5. Fix permissions and report
        if [[ -n "${pcap_path}" && -f "${pcap_path}" ]]; then
            sudo -n chmod 0666 "${pcap_path}" 2>/dev/null || true
            size="$(ls -lh "${pcap_path}" 2>/dev/null | awk "{print \$5}")"
            echo "STATUS:STOPPED:${pcap_path}:${size}"
        else
            echo "STATUS:STOPPED:${pcap_path}:0"
        fi
        rm -f /tmp/ota_monitor.state /tmp/ota_capture.log 2>/dev/null || true
    '

    local stop_result
    stop_result="$(remote_ssh_raw "${remote_stop_script}")"
    local reported_pcap=""
    local reported_size="0"

    while IFS= read -r line; do
        if [[ "${line}" =~ ^STATUS:STOPPED:([^:]*):(.*)$ ]]; then
            reported_pcap="${BASH_REMATCH[1]}"
            reported_size="${BASH_REMATCH[2]}"
            break
        fi
    done <<< "${stop_result}"

    if [[ -z "${target_pcap}" ]]; then
        target_pcap="${reported_pcap}"
    fi

    log_success "Remote OTA Monitor capture stopped: ${target_pcap} (Size: ${reported_size})"

    if (( do_fetch == 1 )) && [[ -n "${target_pcap}" ]]; then
        if [[ -z "${local_dst}" ]]; then
            local_dst="./captures/$(basename "${target_pcap}")"
        fi
        cmd_fetch_capture "${target_pcap}" "${local_dst}"
    fi
}

cmd_status_ota_monitor() {
    print_header "REMOTE OTA MONITOR STATUS"
    log_info "Target Endpoint: ${TARGET_USER}@${TARGET_HOST}"

    local status_script='
        state_file="/tmp/ota_monitor.state"
        pid_file="/tmp/ota_capture.pid"
        if [[ -f "${state_file}" ]]; then
            source "${state_file}" 2>/dev/null || true
        fi
        mon_if="${MON_IFACE:-mon0}"
        pcap_path="${PCAP_PATH:-}"

        mon_exists=0
        mon_freq=""
        if iw dev "${mon_if}" info >/dev/null 2>&1; then
            mon_exists=1
            mon_freq="$(iw dev "${mon_if}" info 2>/dev/null | grep -E "channel" | tr -d "\t\r\n" || true)"
        fi

        is_running=0
        pid=""
        if [[ -f "${pid_file}" ]]; then
            pid="$(cat "${pid_file}" 2>/dev/null | tr -d "[:space:]")"
            if [[ -n "${pid}" ]] && sudo -n kill -0 "${pid}" 2>/dev/null; then
                is_running=1
            fi
        fi

        pcap_size="0"
        if [[ -n "${pcap_path}" && -f "${pcap_path}" ]]; then
            pcap_size="$(ls -lh "${pcap_path}" 2>/dev/null | awk "{print \$5}")"
        fi

        echo "STATUS_MON_EXISTS=\"${mon_exists}\""
        echo "STATUS_MON_DEV=\"${mon_if}\""
        echo "STATUS_MON_FREQ=\"${mon_freq}\""
        echo "STATUS_IS_RUNNING=\"${is_running}\""
        echo "STATUS_PID=\"${pid}\""
        echo "STATUS_PCAP_PATH=\"${pcap_path}\""
        echo "STATUS_PCAP_SIZE=\"${pcap_size}\""
    '
    local status_out
    status_out="$(remote_ssh_raw "${status_script}")"
    eval "${status_out}"

    if [[ "${STATUS_MON_EXISTS:-0}" == "1" ]]; then
        log_success "  -> Monitor Device : ${STATUS_MON_DEV:-mon0} [ACTIVE] (${STATUS_MON_FREQ:-unknown})"
    else
        log_info "  -> Monitor Device : ${STATUS_MON_DEV:-mon0} [INACTIVE]"
    fi

    if [[ "${STATUS_IS_RUNNING:-0}" == "1" ]]; then
        log_success "  -> Capture Daemon : RUNNING (PID: ${STATUS_PID:-unknown})"
        log_info    "  -> Capture File   : ${STATUS_PCAP_PATH:-none} (${STATUS_PCAP_SIZE:-0B})"
    else
        log_info    "  -> Capture Daemon : STOPPED"
    fi
    print_section "STATUS QUERY COMPLETE"
}

cmd_audit_ota_wmm() {
    local duration=3
    local freq=""
    local channel=""
    local width="40"
    local bssid=""
    local ap_edca_json="${LAB_DIR}/logs/ap_edca.json"
    local out_pcap=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --duration|-d)
                duration="$2"
                shift 2
                ;;
            --freq|-f)
                freq="$2"
                shift 2
                ;;
            --channel|-c)
                channel="$2"
                shift 2
                ;;
            --width|-w)
                width="$2"
                shift 2
                ;;
            --bssid|-b)
                bssid="$2"
                shift 2
                ;;
            --ap-edca-json)
                ap_edca_json="$2"
                shift 2
                ;;
            --out-pcap|-o)
                out_pcap="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done

    print_header "STANDALONE OVER-THE-AIR (OTA) WMM EDCA AUDIT"
    log_info "Target Endpoint  : ${TARGET_USER}@${TARGET_HOST}"
    log_info "Sniff Duration   : ${duration}s"

    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local rem_pcap="captures/ota_wmm_audit_${ts}.pcap"
    local local_pcap="${out_pcap:-${LAB_DIR}/captures/ota_wmm_audit_${ts}.pcap}"

    mkdir -p "$(dirname "${local_pcap}")" 2>/dev/null || true

    local -a start_args=(
        --pcap "${rem_pcap}"
        --width "${width}"
    )
    if [[ -n "${freq}" ]]; then start_args+=(--freq "${freq}"); fi
    if [[ -n "${channel}" ]]; then start_args+=(--channel "${channel}"); fi
    if [[ -n "${bssid}" ]]; then start_args+=(--bssid "${bssid}"); fi

    log_step "1. Starting temporary OTA sniffer on remote client..."
    cmd_start_ota_monitor "${start_args[@]}" >/dev/null

    log_step "2. Sniffing 802.11 management frames (${duration}s)..."
    sleep "${duration}"

    log_step "3. Stopping OTA sniffer and retrieving capture..."
    cmd_stop_ota_monitor --pcap "${rem_pcap}" --fetch "${local_pcap}" >/dev/null

    log_step "4. Auditing WMM Parameter Element from over-the-air capture..."
    local -a audit_cmd=(
        python3 "${LAB_DIR}/tools/wireless_qos_audit.py"
        --audit-wmm
        --ota-pcap "${local_pcap}"
    )
    if [[ -n "${bssid}" ]]; then audit_cmd+=(--bssid "${bssid}"); fi
    if [[ -f "${ap_edca_json}" ]]; then audit_cmd+=(--ap-edca-json "${ap_edca_json}"); fi

    "${audit_cmd[@]}"
}

cmd_fetch_capture() {
    local remote_src="${1:-captures/remote_wifi.pcap}"
    local local_dst="${2:-./captures/remote_voice.pcap}"
    local target_src="${remote_src}"
    if [[ "${target_src}" != /* ]]; then
        if [[ "${target_src}" != captures/* && "${target_src}" != tmp/* ]]; then
            target_src="captures/${target_src}"
        fi
        target_src="${TARGET_DIR}/${target_src}"
    fi
    local ssh_r_opt
    ssh_r_opt="$(get_ssh_transport_opt)"

    mkdir -p "$(dirname "${local_dst}")" 2>/dev/null || true

    # Attempt rsync first using key-authenticated transport
    if ! rsync -avz -e "${ssh_r_opt}" "${TARGET_USER}@${TARGET_HOST}:${target_src}" "${local_dst}" >/dev/null 2>&1; then
        # Fallback to scp if rsync fails
        local -a scp_cmd=("scp")
        if [[ -n "${TARGET_PORT}" && "${TARGET_PORT}" != "22" ]]; then
            scp_cmd+=("-P" "${TARGET_PORT}")
        fi
        if [[ -n "${TARGET_KEY}" && -f "${TARGET_KEY}" ]]; then
            scp_cmd+=("-i" "${TARGET_KEY}")
        fi
        if [[ -n "${SSH_OPTS_STR}" ]]; then
            local -a parsed_opts=()
            IFS=" " read -r -a parsed_opts <<< "${SSH_OPTS_STR}"
            scp_cmd+=("${parsed_opts[@]}")
        fi
        scp_cmd+=("${TARGET_USER}@${TARGET_HOST}:${target_src}" "${local_dst}")
        "${scp_cmd[@]}" >/dev/null 2>&1 || true
    fi

    chmod 0666 "${local_dst}" 2>/dev/null || true
    if [[ -f "${local_dst}" ]]; then
        log_success "Fetched remote capture to ${local_dst}"
    else
        log_warn "Failed to fetch remote capture from ${TARGET_HOST}:${target_src}"
    fi
}

cmd_exec() {
    local remote_cmd
    remote_cmd="$(IFS=' '; echo "$*")"
    if [[ -z "${remote_cmd}" ]]; then
        die "Subcommand 'exec' requires a command string to execute."
    fi
    remote_ssh_exec "${remote_cmd}"
}

main() {
    local action=""
    local -a extra_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -H|--host)
                [[ $# -ge 2 ]] || die "Option $1 requires a host argument"
                CLI_HOST="$2"
                shift 2
                ;;
            -u|--user)
                [[ $# -ge 2 ]] || die "Option $1 requires a username argument"
                CLI_USER="$2"
                shift 2
                ;;
            -p|--port)
                [[ $# -ge 2 ]] || die "Option $1 requires a port argument"
                CLI_PORT="$2"
                shift 2
                ;;
            -i|--key)
                [[ $# -ge 2 ]] || die "Option $1 requires a key path argument"
                CLI_KEY="$2"
                shift 2
                ;;
            -d|--dir)
                [[ $# -ge 2 ]] || die "Option $1 requires a path argument"
                CLI_DIR="$2"
                shift 2
                ;;
            --with-config)
                WITH_CONFIG=1
                shift
                ;;
            -s|--silent)
                SILENT=1
                shift
                ;;
            test|ping|probe|test-connection)
                action="test"
                shift
                ;;
            sync|deploy)
                action="sync"
                shift
                ;;
            status|show)
                action="status"
                shift
                ;;
            wifi-connect)
                action="wifi-connect"
                shift
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    extra_args+=("$1")
                    shift
                fi
                ;;
            wifi-status|status-wifi|wifi-info)
                action="wifi-status"
                shift
                ;;
            wifi-env)
                action="wifi-env"
                shift
                extra_args+=("$@")
                break
                ;;
            wifi-ip|get-wifi-ip)
                action="wifi-ip"
                shift
                ;;
            run-iperf)
                action="run-iperf"
                shift
                extra_args+=("$@")
                break
                ;;
            run-voip|voip)
                action="run-voip"
                shift
                extra_args+=("$@")
                break
                ;;
            is-voip-running|is-alive|check-voip)
                action="is-voip-running"
                shift
                if [[ $# -gt 0 && ! "$1" =~ ^- ]]; then
                    extra_args+=("$1")
                    shift
                fi
                ;;
            run-vod|vod)
                action="run-vod"
                shift
                extra_args+=("$@")
                break
                ;;
            run-wireless-qos|run-wqos|wireless-qos)
                action="run-wireless-qos"
                shift
                extra_args+=("$@")
                break
                ;;
            is-wireless-qos-running|is-wqos-running)
                action="is-wireless-qos-running"
                shift
                ;;
            stop-wireless-qos|stop-wqos)
                action="stop-wireless-qos"
                shift
                ;;
            clean|stop)
                action="clean"
                shift
                ;;
            start-capture|capture-start)
                action="start-capture"
                shift
                extra_args+=("$@")
                break
                ;;
            stop-capture|capture-stop)
                action="stop-capture"
                shift
                extra_args+=("$@")
                break
                ;;
            start-ota-monitor|ota-start)
                action="start-ota-monitor"
                shift
                extra_args+=("$@")
                break
                ;;
            stop-ota-monitor|ota-stop)
                action="stop-ota-monitor"
                shift
                extra_args+=("$@")
                break
                ;;
            status-ota-monitor|ota-status)
                action="status-ota-monitor"
                shift
                ;;
            audit-ota-wmm|ota-wmm-audit)
                action="audit-ota-wmm"
                shift
                extra_args+=("$@")
                break
                ;;
            fetch-capture|fetch-file|get-file)
                action="fetch-capture"
                shift
                extra_args+=("$@")
                break
                ;;
            exec)
                action="exec"
                shift
                extra_args+=("$@")
                break
                ;;
            *)
                die "Unknown option or command: $1 (Run with --help for usage)"
                ;;
        esac
    done

    resolve_config

    case "${action:-test}" in
        test)
            cmd_test
            ;;
        sync)
            cmd_sync
            ;;
        status)
            cmd_status
            ;;
        wifi-connect)
            cmd_wifi_connect "${extra_args[@]:-}"
            ;;
        wifi-status)
            cmd_wifi_status
            ;;
        wifi-env)
            cmd_get_wifi_env "${extra_args[@]:-}"
            ;;
        wifi-ip)
            cmd_get_wifi_ip
            ;;
        run-iperf)
            cmd_run_iperf "${extra_args[@]}"
            ;;
        run-voip)
            cmd_run_voip "${extra_args[@]}"
            ;;
        is-voip-running)
            cmd_is_voip_running "${extra_args[@]:-}"
            ;;
        run-vod)
            cmd_run_vod "${extra_args[@]}"
            ;;
        run-wireless-qos)
            cmd_run_wireless_qos "${extra_args[@]}"
            ;;
        is-wireless-qos-running)
            cmd_is_wireless_qos_running
            ;;
        stop-wireless-qos)
            cmd_stop_wireless_qos
            ;;
        start-capture)
            cmd_start_capture "${extra_args[@]}"
            ;;
        stop-capture)
            cmd_stop_capture "${extra_args[@]:-}"
            ;;
        start-ota-monitor)
            cmd_start_ota_monitor "${extra_args[@]}"
            ;;
        stop-ota-monitor)
            cmd_stop_ota_monitor "${extra_args[@]}"
            ;;
        status-ota-monitor)
            cmd_status_ota_monitor
            ;;
        audit-ota-wmm|ota-wmm-audit)
            cmd_audit_ota_wmm "${extra_args[@]}"
            ;;
        fetch-capture)
            cmd_fetch_capture "${extra_args[@]}"
            ;;
        clean)
            cmd_clean
            ;;
        exec)
            cmd_exec "${extra_args[@]}"
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"

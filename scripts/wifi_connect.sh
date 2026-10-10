#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - WI-FI CONNECTION MANAGER
# Manages Over-The-Air (OTA) Wi-Fi connections to DUT SSIDs (2.4GHz / 5GHz / 6GHz)
# Protects active SSH management sessions from accidental disconnection
# Adheres to the 13 Golden Principles of the Linux Network Test Lab Framework
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

FORCE=0
TIMEOUT_SEC=10

usage() {
    cat <<'EOF'
==================================================================
  Gateway Performance Lab - Wi-Fi Connection Manager
==================================================================

Name:
  wifi_connect.sh - Physical Wi-Fi Connection & State Manager

Synopsis:
  ./scripts/wifi_connect.sh [COMMAND] [OPTIONS]

Description:
  Inspects, audits, connects, disconnects, and restores the host's
  physical Wi-Fi interface to DUT target wireless SSIDs across
  2.4 GHz, 5 GHz, and 6 GHz bands configured in config.env
  (DUT_SSID_2G, DUT_SSID_5G, DUT_SSID_6G). Protects active SSH
  management sessions from accidental link termination.

Commands:
  status, show       (Default) Comprehensive Wi-Fi hardware, active link,
                     signal quality, and DUT SSID visibility audit.
  connect [2g|5g|6g] Connect physical Wi-Fi card to the target DUT band.
  disconnect         Disconnect physical Wi-Fi from the current network.
  restore            Reconnect to the dynamically saved pre-test network
                     or BASELINE_WIFI_SSID configured in config.env.
  scan               Trigger an active wireless rescan and list visible networks.

Options:
  --force, -f        Force reconnection even if already connected or if an
                     active SSH session is detected on the Wi-Fi interface.
  --timeout, -t <s > Maximum wait time in seconds for IP lease (default: 10).
  -h, --help         Show this canonical CLI help message and exit (code 0).

Examples:
  ./scripts/wifi_connect.sh status
  ./scripts/wifi_connect.sh connect 5g
  ./scripts/wifi_connect.sh connect 2g --force
  ./scripts/wifi_connect.sh restore
  ./scripts/wifi_connect.sh scan
==================================================================
EOF
}

detect_wifi_interface() {
    local iface="${PHYSICAL_WIFI_IF:-auto}"
    if [[ "${iface}" == "auto" || -z "${iface}" ]]; then
        iface="$( ( (iw dev 2>/dev/null || true) | awk '/Interface/ {print $2}' || true) | head -n1 )"
    fi
    echo "${iface}"
}

check_ssh_on_wifi() {
    local iface="$1"
    [[ -n "${iface}" ]] || return 1

    local all_wifi_ips=()
    while IFS= read -r ip_entry; do
        [[ -n "${ip_entry}" ]] && all_wifi_ips+=("${ip_entry}")
    done < <(ip addr show dev "${iface}" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 || true)

    (( ${#all_wifi_ips[@]} > 0 )) || return 1

    local ssh_conn="${SSH_CONNECTION:-${SSH_CLIENT:-}}"
    if [[ -n "${ssh_conn}" ]]; then
        local ssh_server_ip
        ssh_server_ip="$(echo "${ssh_conn}" | awk '{print $3}')"
        for w_ip in "${all_wifi_ips[@]}"; do
            if [[ "${ssh_server_ip}" == "${w_ip}" ]]; then
                return 0 # Active SSH connection is established on this Wi-Fi card!
            fi
        done
    fi
    return 1 # Safe: SSH is not running on Wi-Fi
}

save_current_wifi_state() {
    local iface="$1"
    local cur_con
    cur_con="$( (nmcli -t -f NAME,TYPE,DEVICE con show --active 2>/dev/null || true) | awk -F: -v dev="${iface}" '$2=="802-11-wireless" && $3==dev {print $1}' | head -n1 || true )"
    local cur_ssid
    cur_ssid="$( (iw dev "${iface}" link 2>/dev/null || true) | awk -F'SSID: ' '/SSID:/ {print $2}' | head -n1 || echo "" )"
    local cur_ip
    cur_ip="$( (ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || true )"

    if [[ -n "${cur_con}" || -n "${cur_ssid}" ]]; then
        write_state_env "${STATE_DIR}/wifi_last_network.env" \
            PREVIOUS_WIFI_CON_NAME="${cur_con}" \
            PREVIOUS_WIFI_SSID="${cur_ssid}" \
            PREVIOUS_WIFI_IP="${cur_ip}" \
            PREVIOUS_WIFI_TIMESTAMP="$(date -Iseconds)"
        log_info "Saved pre-test Wi-Fi state: Profile='${cur_con}', SSID='${cur_ssid}'"
    fi
}

wait_for_wifi_ip() {
    local iface="$1"
    local max_wait="${2:-${TIMEOUT_SEC}}"
    local max_attempts=$(( max_wait * 2 ))
    local attempt=0

    log_info "Waiting for DHCP address lease on ${iface} (timeout: ${max_wait}s)..." >&2
    while (( attempt < max_attempts )); do
        local ip_addr
        ip_addr="$( (ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || true )"
        if [[ -n "${ip_addr}" && "${ip_addr}" != "None" ]]; then
            echo "${ip_addr}"
            return 0
        fi
        sleep 0.5
        (( attempt++ ))
    done
    return 1
}

wait_for_gateway_ping() {
    local iface="$1"
    local gw_ip="$2"
    local max_wait="${3:-5}"
    local max_attempts=$(( max_wait * 2 ))
    local attempt=0

    while (( attempt < max_attempts )); do
        if ping -I "${iface}" -c 1 -W 1 "${gw_ip}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
        (( attempt++ ))
    done
    return 1
}

show_status() {
    load_config "${LAB_DIR}/config.env"
    local iface
    iface="$(detect_wifi_interface)"

    print_header "WI-FI HARDWARE & CONNECTION AUDIT"

    if [[ -z "${iface}" ]]; then
        log_error "No wireless interface detected on this machine."
        return 1
    fi

    # Hardware & Driver Audit
    local drv_info mac_addr
    drv_info="$( (ethtool -i "${iface}" 2>/dev/null || true) | awk -F': ' '/driver:/ {printf "%s", $2}' )"
    mac_addr="$( (ip link show dev "${iface}" 2>/dev/null || true) | awk '/link\/ether/ {print $2}' | head -n1 || echo "unknown" )"
    log_info "Wireless Interface: [${iface}] (MAC: ${mac_addr}, Driver: ${drv_info:-generic})"

    # Active Link Details
    local link_out active_ssid active_bssid active_freq active_sig active_tx_rate active_rx_rate
    link_out="$(iw dev "${iface}" link 2>/dev/null || true)"
    active_ssid="$(echo "${link_out}" | awk -F'SSID: ' '/SSID:/ {print $2}' | head -n1 || echo "")"
    active_bssid="$(echo "${link_out}" | awk '/Connected to/ {print $3}' | head -n1 || echo "")"
    active_freq="$(echo "${link_out}" | awk '/freq:/ {print $2}' | head -n1 || echo "")"
    active_sig="$(echo "${link_out}" | awk -F': ' '/signal:/ {print $2}' | head -n1 || echo "")"
    active_tx_rate="$(echo "${link_out}" | awk -F': ' '/tx bitrate:/ {print $2}' | head -n1 || echo "")"
    active_rx_rate="$(echo "${link_out}" | awk -F': ' '/rx bitrate:/ {print $2}' | head -n1 || echo "")"

    local active_chan active_ip active_gw
    active_chan="$( (iw dev "${iface}" info 2>/dev/null || true) | awk '/channel/ {print $2}' | head -n1 || echo "" )"
    active_ip="$( (ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "None" )"
    active_gw="$( (ip -4 route show dev "${iface}" 2>/dev/null || true) | awk '/default/ {print $3}' | head -n1 || echo "None" )"

    if [[ -n "${active_ssid}" ]]; then
        log_success "Current Link   : CONNECTED to SSID '${active_ssid}'"
        printf '  -> BSSID      : %s\n' "${active_bssid:-N/A}"
        printf '  -> IP Address : %s\n' "${active_ip}"
        printf '  -> Gateway    : %s\n' "${active_gw}"
        printf '  -> Channel    : %s (%s MHz)\n' "${active_chan:-N/A}" "${active_freq:-N/A}"
        printf '  -> Signal     : %s\n' "${active_sig:-N/A}"
        printf '  -> Bitrates   : TX: %s | RX: %s\n' "${active_tx_rate:-N/A}" "${active_rx_rate:-N/A}"

        # Live ping latency to gateway
        if [[ -n "${active_gw}" && "${active_gw}" != "None" ]]; then
            local rtt
            rtt="$( (ping -I "${iface}" -c 1 -W 1 "${active_gw}" 2>/dev/null || true) | awk -F'/' '/rtt/ {print $5}' )"
            if [[ -n "${rtt}" ]]; then
                printf '  -> Gateway RTT: %s ms\n' "${rtt}"
            fi
        fi
    else
        log_warn "Current Link   : DISCONNECTED (Interface is idle)"
    fi

    # Check for active SSH session
    if check_ssh_on_wifi "${iface}"; then
        printf '\n\e[1;31m  [CRITICAL SSH SAFETY WARNING]\e[0m\n'
        printf '  Your current SSH terminal session is connecting via this Wi-Fi card (IP: %s)!\n' "${active_ip}"
        printf '  Switching Wi-Fi to DUT will IMMEDIATELY TERMINATE your current SSH session.\n'
        printf '  Remediation: Connect via wired Ethernet (e.g. eno1: %s) or physical console before switching.\n\n' \
            "$( (ip -4 -o addr show dev eno1 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo 'N/A' )"
    fi

    # Scan for DUT SSIDs configured in config.env
    print_section "SCANNING FOR DUT TARGET SSIDs"
    printf '  Target 2.4 GHz SSID : %s\n' "${DUT_SSID_2G:-Not configured}"
    printf '  Target 5.0 GHz SSID : %s\n' "${DUT_SSID_5G:-Not configured}"
    printf '  Target 6.0 GHz SSID : %s\n\n' "${DUT_SSID_6G:-Not configured}"

    if check_command nmcli; then
        local scan_out
        scan_out="$(nmcli -t -f IN-USE,BSSID,SSID,CHAN,SIGNAL,SECURITY dev wifi list 2>/dev/null || true)"

        check_dut_ssid() {
            local band="$1"
            local target_ssid="$2"
            [[ -n "${target_ssid}" ]] || return 0

            local match
            match="$( (grep -F ":${target_ssid}:" <<< "${scan_out}" 2>/dev/null || true) | head -n1 )"
            if [[ -n "${match}" ]]; then
                "${LAB_DIR}/tools/wifi_scan_formatter.py" "${match}" "${band}" "${target_ssid}"
            else
                printf '  \e[1;33m%-12s\e[0m %-6s SSID: %-20s | (Check if DUT Wi-Fi is enabled and broadcasting)\n' \
                    "[NOT SEEN]" "${band}" "${target_ssid}"
            fi
        }

        check_dut_ssid "2.4GHz" "${DUT_SSID_2G:-}"
        check_dut_ssid "5.0GHz" "${DUT_SSID_5G:-}"
        check_dut_ssid "6.0GHz" "${DUT_SSID_6G:-}"
    fi

    printf '\n==================================================================\n'
}

connect_wifi() {
    local target_band="${1:-5g}"
    load_config "${LAB_DIR}/config.env"
    local iface
    iface="$(detect_wifi_interface)"

    [[ -n "${iface}" ]] || die "No wireless interface detected."

    local target_ssid=""
    local target_pass=""

    case "${target_band,,}" in
        2g|2.4g|2.4ghz)
            target_ssid="${DUT_SSID_2G:-}"
            target_pass="${DUT_PASS_2G:-}"
            ;;
        5g|5ghz)
            target_ssid="${DUT_SSID_5G:-}"
            target_pass="${DUT_PASS_5G:-}"
            ;;
        6g|6ghz)
            target_ssid="${DUT_SSID_6G:-}"
            target_pass="${DUT_PASS_6G:-}"
            ;;
        *)
            die "Unknown band: ${target_band}. Use 2g, 5g, or 6g."
            ;;
    esac

    [[ -n "${target_ssid}" ]] || die "Target SSID for ${target_band^^} is not configured in config.env."

    # Idempotent Fast-Path: check if already connected with healthy link
    local current_ssid
    current_ssid="$( (iw dev "${iface}" link 2>/dev/null || true) | awk -F'SSID: ' '/SSID:/ {print $2}' | head -n1 || echo "" )"
    if [[ "${current_ssid}" == "${target_ssid}" && ${FORCE} -eq 0 ]]; then
        local cur_ip
        cur_ip="$( (ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || true )"
        if [[ -n "${cur_ip}" && "${cur_ip}" != "None" ]]; then
            log_success "Already connected to [${target_ssid}] (${target_band^^}) on ${iface} (IP: ${cur_ip})."
            if ping -I "${iface}" -c 1 -W 1 "${DUT_LAN_IP:-192.168.1.1}" >/dev/null 2>&1; then
                log_pass "DUT Gateway (${DUT_LAN_IP:-192.168.1.1}) is healthy and reachable. Fast-path skip (use --force to reconnect)."
                return 0
            fi
        fi
    fi

    # Check for SSH session on Wi-Fi interface
    if check_ssh_on_wifi "${iface}"; then
        if (( FORCE == 0 )); then
            printf '\n\e[1;31m[REFUSING DANGEROUS ACTION]\e[0m\n'
            printf 'Your current SSH connection is established over Wi-Fi interface [%s]!\n' "${iface}"
            printf 'Connecting to SSID "%s" will DROP your current SSH shell immediately.\n\n' "${target_ssid}"
            printf 'To proceed safely, either:\n'
            printf '  1. Connect SSH via wired Ethernet (e.g. eno1: %s)\n' \
                "$( (ip -4 -o addr show dev eno1 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo 'N/A' )"
            printf '  2. Work directly from the local physical console\n'
            printf '  3. Pass --force to connect anyway if you have alternative access\n\n'
            exit 1
        else
            log_warn "FORCE flag provided. Connecting to ${target_ssid} despite active SSH on Wi-Fi..."
        fi
    fi

    # Save current Wi-Fi state for smart restoration later
    save_current_wifi_state "${iface}"

    log_info "Connecting interface [${iface}] to DUT SSID: [${target_ssid}] (${target_band^^})..."

    if check_command nmcli; then
        # Ensure radio is enabled and interface is managed
        nmcli radio wifi on 2>/dev/null || true
        nmcli dev set "${iface}" managed yes 2>/dev/null || true

        # Trigger a fresh wireless scan
        log_info "Triggering fresh wireless scan on ${iface}..."
        nmcli dev wifi rescan ifname "${iface}" 2>/dev/null || true

        local connect_cmd=("nmcli" "dev" "wifi" "connect" "${target_ssid}")
        if [[ -n "${target_pass}" ]]; then
            connect_cmd+=("password" "${target_pass}")
        fi
        connect_cmd+=("ifname" "${iface}")

        local connect_ok=0
        if "${connect_cmd[@]}"; then
            connect_ok=1
        else
            log_warn "Connection by SSID failed. Searching for BSSID of '${target_ssid}' in scan cache..."
            local target_bssid
            target_bssid="$( (nmcli -t -f BSSID,SSID dev wifi list 2>/dev/null || true) | grep -F ":${target_ssid}" | head -n1 | cut -d: -f1-6 | tr -d '\\' || true )"
            if [[ -n "${target_bssid}" ]]; then
                log_info "Found BSSID: ${target_bssid}. Retrying connection by BSSID..."
                local bssid_cmd=("nmcli" "dev" "wifi" "connect" "${target_bssid}")
                if [[ -n "${target_pass}" ]]; then
                    bssid_cmd+=("password" "${target_pass}")
                fi
                bssid_cmd+=("ifname" "${iface}")
                if "${bssid_cmd[@]}"; then
                    connect_ok=1
                fi
            fi
        fi

        # Fallback: Direct NetworkManager connection profile with WPA2/WPA3 support
        if (( connect_ok == 0 )); then
            log_info "Attempting direct NetworkManager profile connection for '${target_ssid}'..."
            local sudo_pfx=()
            if (( EUID != 0 )) && sudo -n true 2>/dev/null; then
                sudo_pfx=("sudo")
            fi
            local con_name="DUT_${target_band^^}"
            "${sudo_pfx[@]}" nmcli connection delete "${con_name}" 2>/dev/null || true
            local add_cmd=("${sudo_pfx[@]}" "nmcli" "connection" "add" "type" "wifi" "ifname" "${iface}" "con-name" "${con_name}" "ssid" "${target_ssid}")
            if [[ -n "${target_pass}" ]]; then
                if [[ "${target_band,,}" == "6g"* ]]; then
                    add_cmd+=("wifi-sec.key-mgmt" "sae" "wifi-sec.psk" "${target_pass}")
                else
                    add_cmd+=("wifi-sec.key-mgmt" "wpa-psk" "wifi-sec.psk" "${target_pass}")
                fi
            fi
            if "${add_cmd[@]}" >/dev/null 2>&1 && "${sudo_pfx[@]}" nmcli connection up "${con_name}" >/dev/null 2>&1; then
                connect_ok=1
            fi
        fi

        if (( connect_ok == 1 )); then
            log_success "Successfully associated with ${target_ssid}!"
            local new_ip
            if new_ip="$(wait_for_wifi_ip "${iface}" "${TIMEOUT_SEC}")"; then
                log_success "Obtained IP from DUT: ${new_ip}"
            else
                log_warn "Associated to SSID '${target_ssid}' but IP lease timed out after ${TIMEOUT_SEC}s."
            fi

            # Check gateway ping
            if wait_for_gateway_ping "${iface}" "${DUT_LAN_IP:-192.168.1.1}" 3; then
                log_pass "DUT gateway (${DUT_LAN_IP:-192.168.1.1}) responded to ping successfully."
            else
                log_warn "DUT gateway (${DUT_LAN_IP:-192.168.1.1}) did not respond to ping."
            fi
        else
            die "Failed to connect to ${target_ssid}. Check SSID, password, and signal strength."
        fi
    else
        die "nmcli command is required to manage Wi-Fi connections."
    fi
}

disconnect_wifi() {
    load_config "${LAB_DIR}/config.env"
    local iface
    iface="$(detect_wifi_interface)"
    [[ -n "${iface}" ]] || die "No wireless interface detected."

    log_info "Disconnecting wireless interface [${iface}]..."
    nmcli dev disconnect "${iface}" || true
    log_success "Interface [${iface}] disconnected."
}

restore_wifi() {
    load_config "${LAB_DIR}/config.env"
    local iface
    iface="$(detect_wifi_interface)"
    [[ -n "${iface}" ]] || die "No wireless interface detected."

    local target_profile=""
    local target_ssid=""

    # 1. Check saved dynamic state
    local state_file="${STATE_DIR}/wifi_last_network.env"
    if [[ -f "${state_file}" ]]; then
        # shellcheck disable=SC1090
        source "${state_file}"
        target_profile="${PREVIOUS_WIFI_CON_NAME:-}"
        target_ssid="${PREVIOUS_WIFI_SSID:-}"
    fi

    # 2. Check baseline Wi-Fi in config.env
    if [[ -z "${target_profile}" && -n "${BASELINE_WIFI_SSID:-}" ]]; then
        target_ssid="${BASELINE_WIFI_SSID}"
        target_profile="${BASELINE_WIFI_SSID}"
    fi

    if [[ -n "${target_profile}" ]]; then
        log_info "Restoring Wi-Fi connection to: '${target_profile}' (SSID: '${target_ssid:-same}')..."
        if nmcli connection up "${target_profile}" 2>/dev/null || nmcli dev wifi connect "${target_ssid}" ifname "${iface}" 2>/dev/null; then
            log_success "Successfully restored Wi-Fi to '${target_profile}'."
            rm -f "${state_file}" 2>/dev/null || true
            return 0
        else
            log_warn "Failed to reconnect to '${target_profile}'."
        fi
    fi

    # 3. Fallback: list available saved profiles
    log_info "Available saved Wi-Fi connections:"
    nmcli -t -f NAME,TYPE connection show | awk -F: '$2=="802-11-wireless"{printf "  - %s\n", $1}' || true
    log_info "Run: nmcli connection up <PROFILE_NAME> to restore manually."
}

scan_wifi() {
    load_config "${LAB_DIR}/config.env"
    local iface
    iface="$(detect_wifi_interface)"
    [[ -n "${iface}" ]] || die "No wireless interface detected."

    print_header "ACTIVE WI-FI RESCAN ON ${iface}"
    log_info "Triggering fresh wireless rescan..."
    nmcli dev wifi rescan ifname "${iface}" 2>/dev/null || true
    nmcli -f IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,SECURITY dev wifi list ifname "${iface}" || true
}

main() {
    local cmd="status"
    local band="5g"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            status|show)
                cmd="status"
                shift
                ;;
            connect)
                cmd="connect"
                if [[ $# -ge 2 && "$2" != -* ]]; then
                    band="$2"
                    shift 2
                else
                    band="5g"
                    shift
                fi
                ;;
            disconnect)
                cmd="disconnect"
                shift
                ;;
            restore)
                cmd="restore"
                shift
                ;;
            scan)
                cmd="scan"
                shift
                ;;
            --force|-f)
                FORCE=1
                shift
                ;;
            --timeout|-t)
                [[ $# -ge 2 ]] || die "Option --timeout requires a seconds argument."
                TIMEOUT_SEC="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
    done

    case "${cmd}" in
        status)
            show_status
            ;;
        connect)
            connect_wifi "${band}"
            ;;
        disconnect)
            disconnect_wifi
            ;;
        restore)
            restore_wifi
            ;;
        scan)
            scan_wifi
            ;;
    esac
}

main "$@"

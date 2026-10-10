#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - LAN CLIENT DHCP MANAGER
# Controls dynamic DHCP client daemons inside LAN namespaces (PC, STB, Phones)
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
  Gateway Performance Lab - LAN Client DHCP Manager
==================================================================

Description:
  Manages DHCP client lifecycle (udhcpc / dhclient) inside LAN namespaces
  (ns-pc, ns-stb, ns-wlan*, ns-phone*) to acquire dynamic IP addressing
  and default routes from the Gateway DUT LAN DHCP server.

Usage:
  sudo ./scripts/client_dhcp.sh start [target]
  sudo ./scripts/client_dhcp.sh renew [target]
  sudo ./scripts/client_dhcp.sh stop [target]
  sudo ./scripts/client_dhcp.sh release [target]
  ./scripts/client_dhcp.sh status
  ./scripts/client_dhcp.sh -h | --help

Targets:
  all               All active LAN namespaces (PC, STB, Wi-Fi, Phones) [Default]
  pc                Gigabit Wired PC (ns-pc)
  stb               IPTV Set-Top Box (ns-stb)
  phone             Both Wi-Fi Phones (ns-phone1, ns-phone2)
  wlan              Simulated Wireless Clients (ns-wlan2g, ns-wlan5g, ns-wlan6g)
  <namespace>       Explicit namespace name (e.g. ns-pc, ns-stb)

Commands:
  start [target]    Start non-blocking background DHCP client daemons (asynchronous)
  renew [target]    Signal running daemons to renew or query lease immediately
  stop [target]     Stop running DHCP client daemons
  release [target]  Release DHCP leases and stop client daemons
  status            Display LAN client IP addresses, gateways, and daemon status
  -h, --help        Show this help message and exit

Examples:
  ./scripts/client_dhcp.sh -h
  sudo ./scripts/client_dhcp.sh start
  sudo ./scripts/client_dhcp.sh start pc
  sudo ./scripts/client_dhcp.sh renew pc
  ./scripts/client_dhcp.sh status
  sudo ./scripts/client_dhcp.sh stop

Suggested Next Steps:
  1. Verify LAN status:        ./scripts/client_dhcp.sh status
  2. Run test scenario:        sudo ./scripts/scenario.sh all
  3. Verify compliance:        ./scripts/verify_compliance.sh
==================================================================
USAGE
}

# Resolve list of (namespace:target_key:static_ip:hostname:vendor_id) tuples
resolve_targets() {
    local target="${1:-all}"
    local list=()

    case "${target}" in
        pc)
            list+=("${PC_NS:-ns-pc}:pc:${PC_IP:-192.168.1.10}:LAN-PC-Giga:PC_x86_64")
            ;;
        stb)
            list+=("${STB_NS:-ns-stb}:stb:${STB_IP:-192.168.1.20}:IPTV-STB-LivingRoom:IPTV_STB_4K")
            ;;
        phone)
            list+=("${PHONE1_NS:-ns-phone1}:phone1:${PHONE1_IP:-192.168.1.41}:VoIP-Phone-1:VoIP_SIP_G711")
            list+=("${PHONE2_NS:-ns-phone2}:phone2:${PHONE2_IP:-192.168.1.42}:VoIP-Phone-2:VoIP_SIP_G711")
            ;;
        wlan)
            list+=("${WLAN2G_NS:-ns-wlan2g}:wlan2g:${WLAN2G_IP:-192.168.1.31}:WiFi-Client-2G:WiFi_80211")
            list+=("${WLAN5G_NS:-ns-wlan5g}:wlan5g:${WLAN5G_IP:-192.168.1.32}:WiFi-Client-5G:WiFi_80211")
            list+=("${WLAN6G_NS:-ns-wlan6g}:wlan6g:${WLAN6G_IP:-192.168.1.33}:WiFi-Client-6G:WiFi_80211")
            ;;
        all)
            list+=(
                "${PC_NS:-ns-pc}:pc:${PC_IP:-192.168.1.10}:LAN-PC-Giga:PC_x86_64"
                "${STB_NS:-ns-stb}:stb:${STB_IP:-192.168.1.20}:IPTV-STB-LivingRoom:IPTV_STB_4K"
                "${WLAN2G_NS:-ns-wlan2g}:wlan2g:${WLAN2G_IP:-192.168.1.31}:WiFi-Client-2G:WiFi_80211"
                "${WLAN5G_NS:-ns-wlan5g}:wlan5g:${WLAN5G_IP:-192.168.1.32}:WiFi-Client-5G:WiFi_80211"
                "${WLAN6G_NS:-ns-wlan6g}:wlan6g:${WLAN6G_IP:-192.168.1.33}:WiFi-Client-6G:WiFi_80211"
                "${PHONE1_NS:-ns-phone1}:phone1:${PHONE1_IP:-192.168.1.41}:VoIP-Phone-1:VoIP_SIP_G711"
                "${PHONE2_NS:-ns-phone2}:phone2:${PHONE2_IP:-192.168.1.42}:VoIP-Phone-2:VoIP_SIP_G711"
            )
            ;;
        *)
            list+=("${target}:custom:192.168.1.100:Generic-Client:Client_Generic")
            ;;
    esac

    printf '%s\n' "${list[@]}"
}

get_ns_interface() {
    local ns="$1"
    local iface="eth0"
    if ns_exists "${ns}"; then
        if ip -n "${ns}" link show dev eth0 >/dev/null 2>&1; then
            iface="eth0"
        else
            iface="$(ip -n "${ns}" -o link show 2>/dev/null | awk -F': ' '$2 != "lo" {print $2; exit}' || echo "eth0")"
        fi
    fi
    printf '%s' "${iface}"
}

start_client() {
    local target="${1:-all}"
    require_root
    load_config
    ensure_runtime_dirs

    local udhcpc_script="${SCRIPT_DIR}/lib/udhcpc.script"
    if [[ ! -x "${udhcpc_script}" ]]; then
        chmod +x "${udhcpc_script}" 2>/dev/null || true
    fi

    local lines=()
    mapfile -t lines < <(resolve_targets "${target}")

    log_info "Starting non-blocking DHCP client daemons for target: [${target}]..."

    local entry ns key static_ip hostname vendor_id iface pidfile logfile
    for entry in "${lines[@]}"; do
        IFS=':' read -r ns key static_ip hostname vendor_id <<< "${entry}"

        if ! ns_exists "${ns}"; then
            continue
        fi

        iface="$(get_ns_interface "${ns}")"
        pidfile="${STATE_DIR}/udhcpc-${ns}.pid"
        logfile="${LOG_DIR}/udhcpc-${ns}.log"

        # Ensure interface is up
        ip -n "${ns}" link set "${iface}" up 2>/dev/null || true

        # Enable IPv6 SLAAC autoconf & RA reception inside client namespace
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.accept_ra=2" 2>/dev/null || true
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.autoconf=1" 2>/dev/null || true
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.all.forwarding=0" 2>/dev/null || true

        # Check if daemon is already running
        if is_pidfile_running "${pidfile}"; then
            log_info "DHCP client (udhcpc) already active on ${ns}:${iface} [PID: $(cat "${pidfile}")]"
            continue
        fi
        if [[ -f "${STATE_DIR}/dhclient-${ns}.pid" ]] && is_pidfile_running "${STATE_DIR}/dhclient-${ns}.pid"; then
            log_info "DHCP client (dhclient) already active on ${ns}:${iface} [PID: $(cat "${STATE_DIR}/dhclient-${ns}.pid")]"
            continue
        fi

        local started=0

        # Launch BusyBox udhcpc as persistent background daemon (-f in background via &)
        if command -v udhcpc >/dev/null 2>&1; then
            nohup ip netns exec "${ns}" udhcpc \
                -f \
                -i "${iface}" \
                -p "${pidfile}" \
                -s "${udhcpc_script}" \
                -x "hostname:${hostname}" -F "${hostname}" \
                -V "${vendor_id}" \
                -S </dev/null > "${logfile}" 2>&1 &
            local bg_pid=$!
            sleep 0.1
            if [[ ! -f "${pidfile}" ]]; then
                printf '%s\n' "${bg_pid}" > "${pidfile}"
            fi

            if is_pidfile_running "${pidfile}"; then
                log_success "DHCP client daemon active on ${ns}:${iface} [PID: $(cat "${pidfile}")] (Hostname: ${hostname})"
                started=1
            fi
        fi

        # Fallback to ISC dhclient if udhcpc is unavailable
        if (( started == 0 )) && command -v dhclient >/dev/null 2>&1; then
            local dhclient_pid="${STATE_DIR}/dhclient-${ns}.pid"
            local leasefile="${STATE_DIR}/dhclient-${ns}.leases"
            local dhclient_log="${LOG_DIR}/dhclient-${ns}.log"
            nohup ip netns exec "${ns}" dhclient -4 -nw \
                -lf "${leasefile}" \
                -pf "${dhclient_pid}" \
                "${iface}" </dev/null > "${dhclient_log}" 2>&1 &
            sleep 0.1
            if is_pidfile_running "${dhclient_pid}"; then
                log_success "DHCP client daemon (dhclient) active on ${ns}:${iface} [PID: $(cat "${dhclient_pid}")]"
                started=1
            fi
        fi

        # Optional IPv6 DHCP client daemon
        local ip_ver="${IP_VERSION:-dual}"
        if [[ "${ip_ver}" != "4" && "${ip_ver}" != "v4" && "${ip_ver}" != "ipv4" ]]; then
            if command -v dhclient >/dev/null 2>&1; then
                local dhclient6_pid="${STATE_DIR}/dhclient6-${ns}.pid"
                local leasefile6="${STATE_DIR}/dhclient6-${ns}.leases"
                if ! is_pidfile_running "${dhclient6_pid}"; then
                    nohup ip netns exec "${ns}" dhclient -6 -nw \
                        -lf "${leasefile6}" \
                        -pf "${dhclient6_pid}" \
                        "${iface}" </dev/null > "${LOG_DIR}/dhclient6-${ns}.log" 2>&1 &
                fi
            fi
        fi

        if (( started == 0 )); then
            log_warn "Neither udhcpc nor dhclient could be started on ${ns}:${iface}."
        fi
    done

    log_success "LAN DHCP client daemons initialized in background (non-blocking)."
}

renew_client() {
    local target="${1:-all}"
    require_root
    load_config
    ensure_runtime_dirs

    local lines=()
    mapfile -t lines < <(resolve_targets "${target}")

    log_info "Requesting / renewing DHCP leases for target: [${target}]..."

    local entry ns key static_ip hostname vendor_id iface pidfile
    for entry in "${lines[@]}"; do
        IFS=':' read -r ns key static_ip hostname vendor_id <<< "${entry}"

        if ! ns_exists "${ns}"; then
            continue
        fi

        iface="$(get_ns_interface "${ns}")"
        pidfile="${STATE_DIR}/udhcpc-${ns}.pid"

        if is_pidfile_running "${pidfile}"; then
            local pid
            pid="$(cat "${pidfile}")"
            log_info "Signaling DHCP renewal (SIGUSR1) to udhcpc [PID: ${pid}] on ${ns}:${iface}..."
            kill -USR1 "${pid}" 2>/dev/null || true
        elif [[ -f "${STATE_DIR}/dhclient-${ns}.pid" ]] && is_pidfile_running "${STATE_DIR}/dhclient-${ns}.pid"; then
            log_info "Triggering DHCP renew on dhclient for ${ns}:${iface}..."
            ip netns exec "${ns}" dhclient -4 -r "${iface}" 2>/dev/null || true
            local dhclient_pid="${STATE_DIR}/dhclient-${ns}.pid"
            local leasefile="${STATE_DIR}/dhclient-${ns}.leases"
            nohup ip netns exec "${ns}" dhclient -4 -nw -lf "${leasefile}" -pf "${dhclient_pid}" "${iface}" </dev/null >/dev/null 2>&1 &
        else
            log_info "No daemon active on ${ns}:${iface}; launching DHCP client..."
            start_client "${key}"
        fi
    done

    # Brief 1.5s check for immediate lease reporting
    sleep 1.5

    for entry in "${lines[@]}"; do
        IFS=':' read -r ns key static_ip hostname vendor_id <<< "${entry}"
        if ! ns_exists "${ns}"; then
            continue
        fi

        iface="$(get_ns_interface "${ns}")"
        local cur_ip cur_v6 cur_gw
        cur_ip="$(ip netns exec "${ns}" ip -4 -o addr show dev "${iface}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
        cur_v6="$(ip netns exec "${ns}" ip -6 -o addr show dev "${iface}" scope global 2>/dev/null | awk '{print $4}' | head -n1 || echo "")"
        cur_gw="$(ip netns exec "${ns}" ip -4 route show default 2>/dev/null | awk '{print $3}' | head -n1 || echo "")"

        if [[ -n "${cur_ip}" ]]; then
            log_success "Active lease on ${ns}:${iface} -> IPv4: ${cur_ip} (Gateway: ${cur_gw:-none})"
        else
            log_info "No IPv4 lease acquired yet on ${ns}:${iface}. Daemon continues listening in background."
        fi

        if [[ -n "${cur_v6}" ]]; then
            log_success "Active IPv6 on ${ns}:${iface} -> ${cur_v6}"
        fi
    done
}

stop_client() {
    local target="${1:-all}"
    require_root
    load_config

    local lines=()
    mapfile -t lines < <(resolve_targets "${target}")

    log_info "Stopping DHCP client daemons for target: [${target}]..."

    local entry ns key static_ip hostname vendor_id iface pidfile
    for entry in "${lines[@]}"; do
        IFS=':' read -r ns key static_ip hostname vendor_id <<< "${entry}"

        if ! ns_exists "${ns}"; then
            continue
        fi

        iface="$(get_ns_interface "${ns}")"
        pidfile="${STATE_DIR}/udhcpc-${ns}.pid"

        if is_pidfile_running "${pidfile}"; then
            local pid
            pid="$(cat "${pidfile}")"
            kill -TERM "${pid}" 2>/dev/null || true
            stop_pidfile "${pidfile}"
        fi
        ip netns exec "${ns}" pkill -TERM udhcpc 2>/dev/null || true

        stop_pidfile "${STATE_DIR}/dhclient-${ns}.pid"
        stop_pidfile "${STATE_DIR}/dhclient6-${ns}.pid"
        ip netns exec "${ns}" pkill -TERM dhclient 2>/dev/null || true

        log_info "Stopped DHCP client on ${ns}:${iface}"
    done

    log_success "DHCP client stop completed."
}

release_client() {
    local target="${1:-all}"
    require_root
    load_config

    local lines=()
    mapfile -t lines < <(resolve_targets "${target}")

    log_info "Releasing DHCP leases and stopping daemons for target: [${target}]..."

    local entry ns key static_ip hostname vendor_id iface pidfile
    for entry in "${lines[@]}"; do
        IFS=':' read -r ns key static_ip hostname vendor_id <<< "${entry}"

        if ! ns_exists "${ns}"; then
            continue
        fi

        iface="$(get_ns_interface "${ns}")"
        pidfile="${STATE_DIR}/udhcpc-${ns}.pid"

        if is_pidfile_running "${pidfile}"; then
            local pid
            pid="$(cat "${pidfile}")"
            kill -USR2 "${pid}" 2>/dev/null || true
            kill -TERM "${pid}" 2>/dev/null || true
            stop_pidfile "${pidfile}"
        fi
        ip netns exec "${ns}" pkill -TERM udhcpc 2>/dev/null || true

        stop_pidfile "${STATE_DIR}/dhclient-${ns}.pid"
        stop_pidfile "${STATE_DIR}/dhclient6-${ns}.pid"
        ip netns exec "${ns}" pkill -TERM dhclient 2>/dev/null || true

        # Flush IP addresses and routes on release
        ip netns exec "${ns}" ip -4 addr flush dev "${iface}" 2>/dev/null || true
        ip netns exec "${ns}" ip -4 route flush dev "${iface}" 2>/dev/null || true

        log_info "Released DHCP on ${ns}:${iface}"
    done

    log_success "DHCP client release completed."
}

show_status() {
    load_config
    print_header "LAN CLIENT NETWORK & DHCP STATUS"

    local targets=(
        "${PC_NS:-ns-pc}:Gigabit PC"
        "${STB_NS:-ns-stb}:IPTV Set-Top Box"
        "${WLAN2G_NS:-ns-wlan2g}:Wi-Fi 2.4G Client"
        "${WLAN5G_NS:-ns-wlan5g}:Wi-Fi 5G Client"
        "${WLAN6G_NS:-ns-wlan6g}:Wi-Fi 6G Client"
        "${PHONE1_NS:-ns-phone1}:VoIP Phone 1"
        "${PHONE2_NS:-ns-phone2}:VoIP Phone 2"
    )

    printf '%-12s %-18s %-6s %-16s %-26s %-16s\n' "Namespace" "Role / Device" "IFace" "IPv4 Address" "IPv6 Address (SLAAC/DHCP)" "DHCP State"
    printf '%s\n' "----------------------------------------------------------------------------------------------------------------------"

    local entry ns desc iface cur_ip4 cur_v6 cur_gw pidfile dhcp_mode
    for entry in "${targets[@]}"; do
        ns="${entry%%:*}"
        desc="${entry#*:}"

        if ! ns_exists "${ns}"; then
            printf '%-12s %-18s %-6s %-16s %-26s %-16s\n' "${ns}" "${desc}" "-" "[NOT FOUND]" "-" "INACTIVE"
            continue
        fi

        pidfile="${STATE_DIR}/udhcpc-${ns}.pid"
        local dhclient_pid="${STATE_DIR}/dhclient-${ns}.pid"
        local daemon_running=0

        if is_pidfile_running "${pidfile}" || { [[ -f "${dhclient_pid}" ]] && is_pidfile_running "${dhclient_pid}"; }; then
            daemon_running=1
        fi

        if ! is_root; then
            if (( daemon_running == 1 )); then
                dhcp_mode="DAEMON_ACTIVE"
            else
                dhcp_mode="STOPPED"
            fi
            printf '%-12s %-18s %-6s %-16s %-26s %-16s\n' "${ns}" "${desc}" "-" "[Run with sudo]" "-" "${dhcp_mode}"
            continue
        fi

        iface="$(get_ns_interface "${ns}")"
        cur_ip4="$(ip netns exec "${ns}" ip -4 -o addr show dev "${iface}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
        cur_v6="$(ip netns exec "${ns}" ip -6 -o addr show dev "${iface}" scope global 2>/dev/null | awk '{print $4}' | head -n1 || echo "")"
        cur_gw="$(ip netns exec "${ns}" ip -4 route show default 2>/dev/null | awk '{print $3}' | head -n1 || echo "")"

        [[ -z "${cur_ip4}" ]] && cur_ip4="-"
        [[ -z "${cur_v6}" ]] && cur_v6="-"

        if (( daemon_running == 1 )) && [[ "${cur_ip4}" != "-" ]]; then
            dhcp_mode="BOUND (${cur_ip4})"
        elif (( daemon_running == 1 )); then
            dhcp_mode="AWAITING_LEASE"
        elif [[ "${cur_ip4}" != "-" ]]; then
            dhcp_mode="STATIC"
        else
            dhcp_mode="STOPPED"
        fi

        printf '%-12s %-18s %-6s %-16s %-26s %-16s\n' "${ns}" "${desc}" "${iface}" "${cur_ip4}" "${cur_v6}" "${dhcp_mode}"
    done
}

request_once_v4() {
    local target="${1:-pc}"
    local custom_mac="${2:-}"
    local custom_host="${3:-LAN-PC-Giga}"
    local custom_vendor="${4:-PC_x86_64}"
    require_root
    load_config
    ensure_runtime_dirs

    local ns="${PC_NS:-ns-pc}"
    case "${target}" in
        pc) ns="${PC_NS:-ns-pc}" ;;
        stb) ns="${STB_NS:-ns-stb}" ;;
        *) ns="${target}" ;;
    esac

    if ! ns_exists "${ns}"; then
        fatal "Namespace '${ns}' does not exist"
    fi

    local iface
    iface="$(get_ns_interface "${ns}")"

    # Stop any background daemon first
    local pidfile="${STATE_DIR}/udhcpc-${ns}.pid"
    stop_pidfile "${pidfile}"
    ip netns exec "${ns}" pkill -TERM udhcpc 2>/dev/null || true
    ip netns exec "${ns}" pkill -TERM dhclient 2>/dev/null || true

    # Optionally change MAC address
    if [[ -n "${custom_mac}" ]]; then
        ip -n "${ns}" link set "${iface}" down
        ip -n "${ns}" link set "${iface}" address "${custom_mac}"
        ip -n "${ns}" link set "${iface}" up
    fi

    # Flush current addresses
    ip -n "${ns}" -4 addr flush dev "${iface}" 2>/dev/null || true
    ip -n "${ns}" -4 route flush dev "${iface}" 2>/dev/null || true

    local udhcpc_script="${SCRIPT_DIR}/lib/udhcpc.script"
    log_info "Triggering synchronous DHCPv4 request on ${ns}:${iface} (Host: ${custom_host}, Vendor: ${custom_vendor})..."

    if ip netns exec "${ns}" udhcpc \
        -i "${iface}" \
        -n -q \
        -t 4 -T 2 \
        -s "${udhcpc_script}" \
        -x "hostname:${custom_host}" -F "${custom_host}" \
        -V "${custom_vendor}"; then
        local ip4
        ip4="$(ip netns exec "${ns}" ip -4 -o addr show dev "${iface}" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
        log_success "Lease successfully acquired in ${ns}: ${ip4}"
        return 0
    else
        log_error "udhcpc failed to acquire lease in ${ns}"
        return 1
    fi
}

request_once_v6() {
    local target="${1:-pc}"
    local mode="${2:-stateless}" # stateless or stateful
    require_root
    load_config
    ensure_runtime_dirs

    local ns="${PC_NS:-ns-pc}"
    case "${target}" in
        pc) ns="${PC_NS:-ns-pc}" ;;
        stb) ns="${STB_NS:-ns-stb}" ;;
        *) ns="${target}" ;;
    esac

    if ! ns_exists "${ns}"; then
        fatal "Namespace '${ns}' does not exist"
    fi

    local iface
    iface="$(get_ns_interface "${ns}")"

    ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.disable_ipv6=0" 2>/dev/null || true
    ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.all.forwarding=0" 2>/dev/null || true
    # Flush existing global IPv6 addresses to avoid stale false-positives
    ip netns exec "${ns}" ip -6 addr flush dev "${iface}" scope global 2>/dev/null || true

    if [[ "${mode}" == "stateless" ]]; then
        log_info "Triggering SLAAC & Stateless DHCPv6 on ${ns}:${iface}..."
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.accept_ra=2" 2>/dev/null || true
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.autoconf=1" 2>/dev/null || true
        ip netns exec "${ns}" ping -6 -c 2 -W 1 ff02::2%"${iface}" >/dev/null 2>&1 || true
        if command -v dhclient >/dev/null 2>&1; then
            timeout 6s ip netns exec "${ns}" dhclient -6 -S -1 -v "${iface}" 2>/dev/null || true
        fi
    else
        log_info "Triggering Stateful DHCPv6 (IA_NA) on ${ns}:${iface}..."
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.accept_ra=2" 2>/dev/null || true
        ip netns exec "${ns}" sysctl -q -w "net.ipv6.conf.${iface}.autoconf=0" 2>/dev/null || true
        local leasefile="${STATE_DIR}/dhclient6-${ns}.leases"
        local cfgfile="${STATE_DIR}/dhclient6-${ns}.conf"
        cat <<EOF > "${cfgfile}"
timeout 6;
retry 2;
initial-interval 1;
EOF
        if command -v dhclient >/dev/null 2>&1; then
            local dhclient_out
            dhclient_out="$(timeout 8s ip netns exec "${ns}" dhclient -6 -1 -v -cf "${cfgfile}" -lf "${leasefile}" "${iface}" 2>&1 || true)"
            if grep -qi "NoAddrsAvail" <<< "${dhclient_out}"; then
                log_warn "DUT Gateway replied with status 'NoAddrsAvail' (no IPv6 addresses available in pool)."
            elif grep -qi "bound to" <<< "${dhclient_out}"; then
                log_pass "Stateful DHCPv6 lease acquired."
            fi
        fi
    fi

    sleep 1
    local cur_v6
    cur_v6="$(ip netns exec "${ns}" ip -6 -o addr show dev "${iface}" scope global 2>/dev/null | awk '{print $4}' | head -n1 || echo "")"
    if [[ -n "${cur_v6}" ]]; then
        log_success "IPv6 configured on ${ns}:${iface}: ${cur_v6}"
        return 0
    else
        log_warn "No global IPv6 configured on ${ns}:${iface}"
        return 1
    fi
}

main() {
    local arg
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    load_config

    local cmd="${1:-status}"
    local target="${2:-all}"

    case "${cmd}" in
        start|run|up)
            start_client "${target}"
            ;;
        renew|request)
            renew_client "${target}"
            ;;
        request-v4)
            shift 2 2>/dev/null || true
            request_once_v4 "${target}" "$@"
            ;;
        request-v6)
            shift 2 2>/dev/null || true
            request_once_v6 "${target}" "$@"
            ;;
        stop)
            stop_client "${target}"
            ;;
        release)
            release_client "${target}"
            ;;
        status)
            show_status
            ;;
        *)
            log_error "Unknown command: ${cmd}"
            usage
            exit 1
            ;;
    esac
}

main "$@"

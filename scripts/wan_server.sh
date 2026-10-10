#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - UPSTREAM WAN SERVER EMULATOR
# Complete WAN service management: Kea Triad (DHCPv4, DHCPv6, radvd) & dnsmasq
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

readonly NS_WAN="${WAN_NS:-ns-wan}"

usage() {
    cat <<'USAGE'
==================================================================
  Gateway Performance Lab - Upstream WAN Server Emulator
==================================================================

Description:
  Manages upstream WAN services inside the ns-wan network namespace.
  Supports dual-stack Kea Triad (Kea DHCPv4, Kea DHCPv6, radvd) with
  automated lightweight dnsmasq fallback to provide public IP addressing
  and WAN core services to the physical or virtual Gateway DUT.

Usage:
  sudo ./scripts/wan_server.sh start [backend]
  sudo ./scripts/wan_server.sh stop
  ./scripts/wan_server.sh status
  ./scripts/wan_server.sh -h | --help

Commands:
  start [backend]   Start WAN services ('auto', 'kea', 'dnsmasq') [Default: auto]
  stop              Stop all running WAN daemons (Kea, dnsmasq, radvd)
  status            Inspect status of WAN emulator daemons and DHCP leases
  -h, --help        Show this help message and exit

Backends:
  auto              Try Kea Triad first; automatically fallback to dnsmasq [Default]
  kea               Force dual-stack Kea DHCPv4 / DHCPv6 + radvd
  dnsmasq           Force lightweight single-daemon dnsmasq

Examples:
  ./scripts/wan_server.sh -h
  sudo ./scripts/wan_server.sh start
  sudo ./scripts/wan_server.sh start dnsmasq
  ./scripts/wan_server.sh status
  sudo ./scripts/wan_server.sh stop

Suggested Next Steps:
  1. Inspect running leases:   ./scripts/wan_server.sh status
  2. Request LAN DHCP leases:  sudo ./scripts/client_dhcp.sh renew all
  3. Run test scenarios:       sudo ./scripts/scenario.sh all
  4. Verify compliance:        ./scripts/verify_compliance.sh
==================================================================
USAGE
}

get_wan_if() {
    local iface="eth0"
    if ns_exists "${NS_WAN}"; then
        if ip -n "${NS_WAN}" link show dev eth0 >/dev/null 2>&1; then
            iface="eth0"
        elif ip -n "${NS_WAN}" link show dev eth-wan >/dev/null 2>&1; then
            iface="eth-wan"
        fi
    fi
    printf '%s' "${iface}"
}

prepare_kea_runtime() {
    if command -v apparmor_parser >/dev/null 2>&1; then
        apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp4 2>/dev/null || true
        apparmor_parser -R /etc/apparmor.d/usr.sbin.kea-dhcp6 2>/dev/null || true
    fi

    install -d -m 0777 /run/kea /run/lock/kea "${STATE_DIR}/kea"
    chmod 0777 /run/kea /run/lock/kea "${STATE_DIR}/kea" 2>/dev/null || true
    rm -f /run/kea/logger_lockfile /var/run/kea/logger_lockfile /run/lock/kea/logger_lockfile 2>/dev/null || true
    rm -f /run/kea/*.pid /run/lock/kea/*.pid 2>/dev/null || true
}

render_wan_template() {
    local src="$1"
    local dst="$2"
    local iface="${3:-eth0}"

    local v4_dns_list="${WAN_IPV4_DNS:-${WAN_SERVER_IP:-203.0.113.1}}"
    if [[ -n "${WAN_IPV4_DNS2:-}" ]]; then
        v4_dns_list="${v4_dns_list}, ${WAN_IPV4_DNS2}"
    fi

    local v6_dns_list="${WAN_IPV6_DNS:-2001:db8:10::1}"
    local v6_radvd_dns="${WAN_IPV6_DNS:-2001:db8:10::1}"
    if [[ -n "${WAN_IPV6_DNS2:-}" ]]; then
        v6_dns_list="${WAN_IPV6_DNS}, ${WAN_IPV6_DNS2}"
        v6_radvd_dns="${WAN_IPV6_DNS} ${WAN_IPV6_DNS2}"
    fi

    local v6_mode="${WAN_IPV6_MODE:-dual-stack}"
    local ra_managed="${RA_MANAGED_FLAG:-}"
    local ra_other="${RA_OTHER_CONFIG_FLAG:-}"
    local ra_autonomous="${RA_AUTONOMOUS_FLAG:-}"

    if [[ -z "${ra_managed}" || -z "${ra_other}" || -z "${ra_autonomous}" ]]; then
        case "${v6_mode}" in
            slaac)
                [[ -z "${ra_managed}" ]] && ra_managed="off"
                [[ -z "${ra_other}" ]] && ra_other="off"
                [[ -z "${ra_autonomous}" ]] && ra_autonomous="on"
                ;;
            stateless)
                [[ -z "${ra_managed}" ]] && ra_managed="off"
                [[ -z "${ra_other}" ]] && ra_other="on"
                [[ -z "${ra_autonomous}" ]] && ra_autonomous="on"
                ;;
            stateful|stateful-pd)
                [[ -z "${ra_managed}" ]] && ra_managed="on"
                [[ -z "${ra_other}" ]] && ra_other="on"
                [[ -z "${ra_autonomous}" ]] && ra_autonomous="off"
                ;;
            pd-only)
                [[ -z "${ra_managed}" ]] && ra_managed="off"
                [[ -z "${ra_other}" ]] && ra_other="on"
                [[ -z "${ra_autonomous}" ]] && ra_autonomous="on"
                ;;
            ds-lite)
                [[ -z "${ra_managed}" ]] && ra_managed="on"
                [[ -z "${ra_other}" ]] && ra_other="on"
                [[ -z "${ra_autonomous}" ]] && ra_autonomous="off"
                ;;
            dual-stack|*)
                [[ -z "${ra_managed}" ]] && ra_managed="on"
                [[ -z "${ra_other}" ]] && ra_other="on"
                [[ -z "${ra_autonomous}" ]] && ra_autonomous="on"
                ;;
        esac
    fi

    local v4_gw="${WAN_SERVER_IP:-203.0.113.1}"
    local v4_subnet="${v4_gw%.*}.0/24"
    local v4_start="${WAN_DHCP_RANGE_START:-${WAN_DHCP_POOL_START:-203.0.113.100}}"
    local v4_end="${WAN_DHCP_RANGE_END:-${WAN_DHCP_POOL_END:-203.0.113.200}}"

    sed \
        -e "s|@DUT_IF@|${iface}|g" \
        -e "s|@WAN_IPV4_SUBNET@|${WAN_IPV4_SUBNET:-${v4_subnet}}|g" \
        -e "s|@WAN_IPV4_POOL_START@|${v4_start}|g" \
        -e "s|@WAN_IPV4_POOL_END@|${v4_end}|g" \
        -e "s|@WAN_IPV4_ROUTER@|${WAN_IPV4_ROUTER:-${v4_gw}}|g" \
        -e "s|@WAN_IPV4_DNS@|${v4_dns_list}|g" \
        -e "s|@WAN_IPV4_DNS1@|${WAN_IPV4_DNS:-${v4_gw}}|g" \
        -e "s|@WAN_IPV4_DNS2@|${WAN_IPV4_DNS2:-8.8.8.8}|g" \
        -e "s|@WAN_IPV6_PREFIX@|${WAN_IPV6_PREFIX:-2001:db8:10::/64}|g" \
        -e "s|@WAN_IPV6_POOL_START@|${WAN_IPV6_POOL_START:-2001:db8:10::1000}|g" \
        -e "s|@WAN_IPV6_POOL_END@|${WAN_IPV6_POOL_END:-2001:db8:10::1fff}|g" \
        -e "s|@PD_PREFIX@|${PD_PREFIX:-2001:db8:100::}|g" \
        -e "s|@PD_PREFIX_LEN@|${PD_PREFIX_LEN:-56}|g" \
        -e "s|@PD_DELEGATED_LEN@|${PD_DELEGATED_LEN:-60}|g" \
        -e "s|@WAN_IPV6_DNS@|${v6_dns_list}|g" \
        -e "s|@WAN_IPV6_RDNSS@|${v6_radvd_dns}|g" \
        -e "s|@RA_MANAGED_FLAG@|${ra_managed}|g" \
        -e "s|@RA_OTHER_CONFIG_FLAG@|${ra_other}|g" \
        -e "s|@RA_AUTONOMOUS_FLAG@|${ra_autonomous}|g" \
        -e "s|@AFTR_NAME@|${AFTR_NAME:-aftr.example.com}|g" \
        -e "s|@DHCP_VALID_LIFETIME_SEC@|${DHCP_VALID_LIFETIME_SEC:-43200}|g" \
        -e "s|@DHCP_RENEW_TIMER_SEC@|${DHCP_RENEW_TIMER_SEC:-21600}|g" \
        -e "s|@DHCP_REBIND_TIMER_SEC@|${DHCP_REBIND_TIMER_SEC:-34560}|g" \
        -e "s|@DHCP6_PREFERRED_LIFETIME_SEC@|${DHCP6_PREFERRED_LIFETIME_SEC:-28800}|g" \
        -e "s|@RA_LIFETIME_SEC@|${RA_LIFETIME_SEC:-1800}|g" \
        -e "s|@RA_MIN_INTERVAL_SEC@|${RA_MIN_INTERVAL_SEC:-3}|g" \
        -e "s|@RA_MAX_INTERVAL_SEC@|${RA_MAX_INTERVAL_SEC:-10}|g" \
        "${src}" > "${dst}"
}

start_dnsmasq_fallback() {
    local ns_if="${1:-$(get_wan_if)}"
    local is_v4="${2:-1}"
    local is_v6="${3:-1}"

    require_command dnsmasq
    local pidfile="${STATE_DIR}/dnsmasq-wan.pid"
    local conffile="${STATE_DIR}/dnsmasq-wan.conf"
    local leasefile="${STATE_DIR}/dnsmasq-wan.leases"
    local logfile="${LOG_DIR}/dnsmasq-wan.log"

    stop_pidfile "${pidfile}"

    local pool_start="${WAN_DHCP_RANGE_START:-${WAN_DHCP_POOL_START:-203.0.113.100}}"
    local pool_end="${WAN_DHCP_RANGE_END:-${WAN_DHCP_POOL_END:-203.0.113.200}}"
    local gw_ip="${WAN_SERVER_IP:-203.0.113.1}"
    local lease_sec="${DHCP_VALID_LIFETIME_SEC:-43200}"

    {
        printf 'port=0\n'
        printf 'no-resolv\n'
        printf 'no-hosts\n'
        printf 'bind-interfaces\n'
        printf 'interface=%s\n' "${ns_if}"

        if (( is_v4 == 1 )); then
            printf 'dhcp-range=%s,%s,255.255.255.0,%ss\n' \
                "${pool_start}" \
                "${pool_end}" \
                "${lease_sec}"
            printf 'dhcp-option=option:router,%s\n' "${gw_ip}"
            printf 'dhcp-option=option:dns-server,%s,8.8.8.8\n' "${gw_ip}"
            if [[ -n "${DUT_WAN_IP:-}" && -n "${DUT_WAN_MAC:-}" ]]; then
                printf 'dhcp-host=%s,%s\n' "${DUT_WAN_MAC}" "${DUT_WAN_IP}"
            fi
        fi

        if (( is_v6 == 1 )); then
            printf 'enable-ra\n'
            local v6_mode="${WAN_IPV6_MODE:-dual-stack}"
            case "${v6_mode}" in
                slaac)
                    printf 'dhcp-range=2001:db8:10::1000,2001:db8:10::1fff,slaac,64,%ss\n' "${lease_sec}"
                    ;;
                stateless)
                    printf 'dhcp-range=2001:db8:10::,ra-stateless,64,%ss\n' "${lease_sec}"
                    ;;
                *)
                    printf 'dhcp-range=2001:db8:10::1000,2001:db8:10::1fff,64,%ss\n' "${lease_sec}"
                    ;;
            esac
            printf 'dhcp-option=option6:dns-server,[2001:db8:10::1]\n'
        fi

        # Relayed subnet pools for DHCP Relay testing (RFC 3046 Option 82 & RFC 8415)
        # Allows ns-wan to act as Central DHCP Server when Gateway DUT relays requests
        printf 'dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,%ss\n' "${lease_sec}"
        printf 'dhcp-range=2001:db8:100::1000,2001:db8:100::2000,64,%ss\n' "${lease_sec}"

        printf 'dhcp-authoritative\n'
        printf 'dhcp-leasefile=%s\n' "${leasefile}"
        printf 'log-facility=%s\n' "${logfile}"
        printf 'log-dhcp\n'
    } > "${conffile}"

    touch "${leasefile}"
    chmod 0666 "${leasefile}" 2>/dev/null || true

    nohup ip netns exec "${NS_WAN}" dnsmasq --conf-file="${conffile}" --pid-file="${pidfile}" > "${logfile}" 2>&1 &
    sleep 0.5

    if ! is_pidfile_running "${pidfile}"; then
        log_error "dnsmasq fallback failed to start. Check ${logfile}"
        tail -n 20 "${logfile}" >&2 || true
        return 1
    fi
    log_success "dnsmasq fallback active on ${NS_WAN}:${ns_if} [PID: $(cat "${pidfile}")]"
    return 0
}

start_dhcp4_kea() {
    prepare_kea_runtime

    local ns_if="${1:-$(get_wan_if)}"
    local src="${PROJECT_ROOT}/config/kea/kea-dhcp4.conf.in"
    local dst="${STATE_DIR}/kea-dhcp4.conf"
    local pidfile="${STATE_DIR}/kea-dhcp4.pid"
    local logfile="${LOG_DIR}/kea-dhcp4.log"

    if ! command -v kea-dhcp4 >/dev/null 2>&1; then
        log_warn "kea-dhcp4 binary not found."
        return 1
    fi

    if [[ ! -f "${src}" ]]; then
        log_warn "Kea DHCPv4 template ${src} not found."
        return 1
    fi

    render_wan_template "${src}" "${dst}" "${ns_if}"
    stop_pidfile "${pidfile}"

    nohup ip netns exec "${NS_WAN}" \
        env KEA_PIDFILE_DIR="/run/kea" KEA_LOCKFILE_DIR="/run/lock/kea" \
        kea-dhcp4 -c "${dst}" > "${logfile}" 2>&1 &
    printf '%s\n' "$!" > "${pidfile}"
    sleep 0.5

    if is_pidfile_running "${pidfile}"; then
        log_success "kea-dhcp4 server active on ${NS_WAN}:${ns_if} [PID: $(cat "${pidfile}")]"
        return 0
    fi

    log_warn "kea-dhcp4 failed to start. Check ${logfile}"
    stop_pidfile "${pidfile}"
    return 1
}

start_radvd() {
    local ns_if="${1:-$(get_wan_if)}"
    local src="${PROJECT_ROOT}/config/radvd/radvd.conf.in"
    local dst="${STATE_DIR}/radvd.conf"
    local pidfile="${STATE_DIR}/radvd.pid"
    local logfile="${LOG_DIR}/radvd.log"

    if ! command -v radvd >/dev/null 2>&1; then
        log_warn "radvd binary not found; skipping IPv6 Router Advertisement."
        return 1
    fi

    if [[ ! -f "${src}" ]]; then
        log_warn "radvd template ${src} not found; skipping Router Advertisement."
        return 1
    fi

    # radvd requires IPv6 forwarding enabled in namespace
    ip netns exec "${NS_WAN}" sysctl -q -w net.ipv6.conf.all.forwarding=1 2>/dev/null || true
    ip netns exec "${NS_WAN}" sysctl -q -w net.ipv6.conf.default.forwarding=1 2>/dev/null || true
    ip netns exec "${NS_WAN}" sysctl -q -w "net.ipv6.conf.${ns_if}.forwarding=1" 2>/dev/null || true

    render_wan_template "${src}" "${dst}" "${ns_if}"
    chmod 0644 "${dst}" 2>/dev/null || true
    stop_pidfile "${pidfile}"

    ip netns exec "${NS_WAN}" radvd -C "${dst}" -p "${pidfile}" -m logfile -l "${logfile}" 2>/dev/null || true
    sleep 0.3

    if is_pidfile_running "${pidfile}"; then
        log_success "radvd active on ${NS_WAN}:${ns_if} [PID: $(cat "${pidfile}")] (Mode: ${WAN_IPV6_MODE:-dual-stack})"
        return 0
    else
        log_warn "radvd failed to start. Check ${logfile}"
        return 1
    fi
}

start_dhcp6_kea() {
    prepare_kea_runtime

    local ns_if="${1:-$(get_wan_if)}"
    local src="${PROJECT_ROOT}/config/kea/kea-dhcp6.conf.in"
    local dst="${STATE_DIR}/kea-dhcp6.conf"
    local pidfile="${STATE_DIR}/kea-dhcp6.pid"
    local logfile="${LOG_DIR}/kea-dhcp6.log"

    if ! command -v kea-dhcp6 >/dev/null 2>&1; then
        log_warn "kea-dhcp6 binary not found."
        return 1
    fi

    if [[ ! -f "${src}" ]]; then
        log_warn "Kea DHCPv6 template ${src} not found."
        return 1
    fi

    # Disable DAD and ensure link-local exists on interface for raw socket binding
    ip netns exec "${NS_WAN}" sysctl -q -w net.ipv6.conf.all.dad_transmits=0 2>/dev/null || true
    ip netns exec "${NS_WAN}" sysctl -q -w net.ipv6.conf.default.dad_transmits=0 2>/dev/null || true
    ip netns exec "${NS_WAN}" sysctl -q -w "net.ipv6.conf.${ns_if}.dad_transmits=0" 2>/dev/null || true

    if ! ip netns exec "${NS_WAN}" ip -6 -o addr show dev "${ns_if}" scope link 2>/dev/null | grep -q 'inet6 '; then
        ip -n "${NS_WAN}" -6 addr add "fe80::254/64" dev "${ns_if}" nodad 2>/dev/null || true
    fi

    # Ensure static global WAN IPv6 address exists on interface
    local wan_v6_addr="${WAN_IPV6_CIDR:-2001:db8:10::1/64}"
    if ! ip netns exec "${NS_WAN}" ip -6 -o addr show dev "${ns_if}" scope global 2>/dev/null | grep -q 'inet6 '; then
        ip -n "${NS_WAN}" -6 addr add "${wan_v6_addr}" dev "${ns_if}" nodad 2>/dev/null || true
    fi

    # Wait briefly if any address is still resolving DAD (prevents EADDRNOTAVAIL socket bind error)
    local dad_wait=0
    while ip netns exec "${NS_WAN}" ip -6 -o addr show dev "${ns_if}" 2>/dev/null | grep -q 'tentative'; do
        sleep 0.1
        dad_wait=$((dad_wait + 1))
        if (( dad_wait >= 10 )); then break; fi
    done

    render_wan_template "${src}" "${dst}" "${ns_if}"
    stop_pidfile "${pidfile}"

    nohup ip netns exec "${NS_WAN}" \
        env KEA_PIDFILE_DIR="/run/kea" KEA_LOCKFILE_DIR="/run/lock/kea" \
        kea-dhcp6 -c "${dst}" > "${logfile}" 2>&1 &
    printf '%s\n' "$!" > "${pidfile}"
    sleep 0.5

    if is_pidfile_running "${pidfile}" && ! grep -q "DHCPSRV_NO_SOCKETS_OPEN" "${logfile}" 2>/dev/null; then
        local pd_prefix="${PD_PREFIX:-2001:db8:100::}"
        local pd_len="${PD_PREFIX_LEN:-56}"
        local pd_deg="${PD_DELEGATED_LEN:-60}"
        log_success "kea-dhcp6 server active on ${NS_WAN}:${ns_if} [PID: $(cat "${pidfile}")] (IA_NA + IA_PD: ${pd_prefix}/${pd_len} -> /${pd_deg})"
        return 0
    fi

    log_warn "kea-dhcp6 failed to start or bind sockets. Check ${logfile}"
    stop_pidfile "${pidfile}"
    return 1
}

start_services() {
    local backend="${1:-auto}"
    require_root
    load_config
    ensure_runtime_dirs

    if ! ns_exists "${NS_WAN}"; then
        die "Namespace ${NS_WAN} does not exist. Please run sudo ./scripts/setup.sh first."
    fi

    stop_services >/dev/null 2>&1 || true

    local ns_if
    ns_if="$(get_wan_if)"

    local ip_ver="${IP_VERSION:-dual}"
    local is_v4=0
    local is_v6=0

    case "${ip_ver}" in
        dual|dual-stack|ds) is_v4=1; is_v6=1 ;;
        4|v4|ipv4)          is_v4=1; is_v6=0 ;;
        6|v6|ipv6)          is_v4=0; is_v6=1 ;;
        *)                  is_v4=1; is_v6=1 ;;
    esac

    log_info "Starting WAN DHCP services in ${NS_WAN} (IP_VERSION: ${ip_ver}, Backend: ${backend})..."

    local v6_mode="${WAN_IPV6_MODE:-dual-stack}"
    local kea_v4_ok=0
    local kea_v6_ok=0

    if [[ "${backend}" == "kea" || "${backend}" == "auto" ]]; then
        # 1. Start IPv4 Kea DHCP
        if (( is_v4 == 1 )); then
            if start_dhcp4_kea "${ns_if}"; then
                kea_v4_ok=1
            fi
        fi

        # 2. Start IPv6 Router Advertisement (radvd) & Kea DHCPv6
        if (( is_v6 == 1 )); then
            start_radvd "${ns_if}" || true
            if [[ "${v6_mode}" == "slaac" ]]; then
                kea_v6_ok=1
            else
                if start_dhcp6_kea "${ns_if}"; then
                    kea_v6_ok=1
                fi
            fi
        fi
    fi

    # Fallback to dnsmasq if Kea failed or backend was explicitly dnsmasq
    local need_fallback_v4=0
    local need_fallback_v6=0

    if (( is_v4 == 1 && kea_v4_ok == 0 )); then
        need_fallback_v4=1
    fi
    if (( is_v6 == 1 && kea_v6_ok == 0 )); then
        need_fallback_v6=1
    fi

    if (( need_fallback_v4 == 1 || need_fallback_v6 == 1 )); then
        log_warn "Activating dnsmasq fallback (v4=${need_fallback_v4}, v6=${need_fallback_v6})..."
        start_dnsmasq_fallback "${ns_if}" "${need_fallback_v4}" "${need_fallback_v6}"
    fi
}

stop_services() {
    require_root
    load_config
    log_info "Stopping WAN server daemons in ${NS_WAN}..."

    stop_pidfile "${STATE_DIR}/kea-dhcp4.pid"
    stop_pidfile "${STATE_DIR}/kea-dhcp6.pid"
    stop_pidfile "${STATE_DIR}/radvd.pid"
    stop_pidfile "${STATE_DIR}/dnsmasq-dhcp4.pid"
    stop_pidfile "${STATE_DIR}/dnsmasq-wan.pid"
    stop_pidfile "${STATE_DIR}/dnsmasq-wan-v4.pid"
    stop_pidfile "${STATE_DIR}/wan_dnsmasq.pid"

    if ns_exists "${NS_WAN}"; then
        ip netns exec "${NS_WAN}" pkill -TERM kea-dhcp4 2>/dev/null || true
        ip netns exec "${NS_WAN}" pkill -TERM kea-dhcp6 2>/dev/null || true
        ip netns exec "${NS_WAN}" pkill -TERM radvd 2>/dev/null || true
        ip netns exec "${NS_WAN}" pkill -TERM dnsmasq 2>/dev/null || true
    fi

    rm -f "${STATE_DIR}"/dnsmasq-*.conf "${STATE_DIR}"/kea-dhcp*.conf "${STATE_DIR}/radvd.conf" 2>/dev/null || true
    log_success "WAN server daemons stopped."
}

show_status() {
    load_config
    print_header "UPSTREAM WAN SERVER STATUS"
    local ns_if
    ns_if="$(get_wan_if)"
    printf 'Namespace: %s (Interface: %s)\n\n' "${NS_WAN}" "${ns_if}"

    local daemons=(
        "kea-dhcp4:Kea DHCPv4 Server"
        "kea-dhcp6:Kea DHCPv6 Server"
        "radvd:Router Advertisement Daemon (radvd)"
        "dnsmasq-dhcp4:dnsmasq DHCPv4 Server"
        "dnsmasq-wan:dnsmasq Fallback Server"
    )

    local entry name desc pidfile
    for entry in "${daemons[@]}"; do
        name="${entry%%:*}"
        desc="${entry#*:}"
        pidfile="${STATE_DIR}/${name}.pid"

        if is_pidfile_running "${pidfile}"; then
            printf '  \e[1;32m[RUNNING]\e[0m %-40s (PID: %s)\n' "${desc}" "$(cat "${pidfile}")"
        else
            printf '  \e[1;30m[STOPPED]\e[0m %-40s\n' "${desc}"
        fi
    done

    # Show active leases if available
    printf '\n--- [ACTIVE WAN DHCP LEASES] ---\n'
    local leasefile="${STATE_DIR}/dnsmasq-dhcp4.leases"
    [[ ! -f "${leasefile}" ]] && leasefile="${STATE_DIR}/dnsmasq-wan.leases"
    if [[ -f "${leasefile}" && -s "${leasefile}" ]]; then
        printf '%-18s %-16s %-20s\n' "MAC Address" "Leased IP" "Hostname"
        printf '%s\n' "------------------------------------------------------------"
        awk '{printf "%-18s %-16s %-20s\n", $2, $3, $4}' "${leasefile}"
    else
        printf 'No active DHCP leases recorded yet.\n'
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

    local cmd="${1:-start}"
    case "${cmd}" in
        start)
            local backend="${2:-${WAN_DHCP_BACKEND:-auto}}"
            start_services "${backend}"
            ;;
        stop)
            stop_services
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

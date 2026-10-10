#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - DUT EMULATOR & DHCP CONTROLLER
# Manages DHCPv4 Server, DHCPv6 Server, and DHCP Relay inside ns-dut
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

readonly DUT_NS_NAME="${DUT_NS:-ns-dut}"
readonly DUT_LAN_IF="br-lan"
readonly DUT_WAN_IF="eth-wan"

usage() {
    cat <<'EOF'
==================================================================
  Gateway Test Lab - DUT Emulator & DHCP Controller
==================================================================

Description:
  Controls the DHCP server, DHCPv6 server, and DHCP Relay modes
  running on the Home Gateway (ns-dut in virtual simulation, or
  coordinates with hardware DUT).

Usage:
  sudo ./scripts/dut_emulator.sh <command> [options]
  ./scripts/dut_emulator.sh status
  ./scripts/dut_emulator.sh -h | --help

Commands:
  server-v4            Start DHCPv4 Server on LAN (Pool, Options 1/3/6/15, Static Lease)
  server-v6-stateless  Start Stateless DHCPv6 + SLAAC (RA M=0, O=1, RDNSS Option 23)
  server-v6-stateful   Start Stateful DHCPv6 (RA M=1, IA_NA non-temporary pool)
  relay-v4 [server_ip] Start DHCPv4 Relay Agent (Option 82, giaddr forwarding)
  relay-v6 [server_ip] Start DHCPv6 Relay Agent (Relay-Forward / Relay-Reply encapsulation)
  stop                 Stop all running DUT DHCP and RA daemons
  status               Display active DUT DHCP daemons and lease table
  -h, --help           Show this help message and exit

Examples:
  sudo ./scripts/dut_emulator.sh server-v4
  sudo ./scripts/dut_emulator.sh server-v6-stateless
  sudo ./scripts/dut_emulator.sh server-v6-stateful
  sudo ./scripts/dut_emulator.sh relay-v4 10.10.0.1
  sudo ./scripts/dut_emulator.sh relay-v6 2001:db8:10::1
  ./scripts/dut_emulator.sh status
  sudo ./scripts/dut_emulator.sh stop
==================================================================
EOF
}

stop_dut_daemons() {
    require_root
    load_config
    ensure_runtime_dirs

    if [[ "${TOPOLOGY_MODE:-virtual}" == "physical" ]]; then
        log_info "Physical topology mode active: skipping virtual DUT daemons stop."
        return 0
    fi

    log_info "Stopping active DUT DHCP / RA daemons..."
    local pidfiles=(
        "${STATE_DIR}/dut-dnsmasq.pid"
        "${STATE_DIR}/dut-radvd.pid"
        "${STATE_DIR}/dut-relay.pid"
    )

    for pf in "${pidfiles[@]}"; do
        if [[ -f "${pf}" ]]; then
            stop_pidfile "${pf}"
            rm -f "${pf}"
        fi
    done

    # Cleanup potential zombie processes inside ns-dut
    if ns_exists "${DUT_NS_NAME}"; then
        ip netns exec "${DUT_NS_NAME}" pkill -f "dnsmasq.*${DUT_LAN_IF}" 2>/dev/null || true
        ip netns exec "${DUT_NS_NAME}" pkill -f "radvd.*dut" 2>/dev/null || true
    fi

    log_success "DUT daemons stopped."
}

start_server_v4() {
    require_root
    load_config
    ensure_runtime_dirs
    stop_dut_daemons

    if [[ "${TOPOLOGY_MODE:-virtual}" == "physical" ]]; then
        log_info "Physical topology mode active: external gateway DUT in use."
        return 0
    fi

    if ! ns_exists "${DUT_NS_NAME}"; then
        fatal "DUT namespace '${DUT_NS_NAME}' does not exist. Run './scripts/setup.sh --virtual' first."
    fi

    local pool_start="${DUT_DHCPV4_POOL_START:-192.168.1.100}"
    local pool_end="${DUT_DHCPV4_POOL_END:-192.168.1.200}"
    local lease_time="${DUT_DHCPV4_LEASE_TIME:-7200}s"
    local router="${DUT_DHCPV4_ROUTER:-192.168.1.1}"
    local dns="${DUT_DHCPV4_DNS:-192.168.1.1,8.8.8.8}"
    local domain="${DUT_DHCPV4_DOMAIN:-home.gateway}"
    local static_mac="${DUT_DHCPV4_STATIC_MAC:-02:00:00:00:01:99}"
    local static_ip="${DUT_DHCPV4_STATIC_IP:-192.168.1.99}"
    local static_host="${DUT_DHCPV4_STATIC_HOSTNAME:-reserved-test-host}"

    local pidfile="${STATE_DIR}/dut-dnsmasq.pid"
    local leasefile="${STATE_DIR}/dut-dnsmasq.leases"
    local logfile="${LOG_DIR}/dut-dnsmasq.log"

    log_info "Starting DHCPv4 Server in ${DUT_NS_NAME} on ${DUT_LAN_IF} (Pool: ${pool_start} - ${pool_end})..."

    # Ensure IP address is configured on br-lan
    if ! ip -n "${DUT_NS_NAME}" -4 addr show dev "${DUT_LAN_IF}" | grep -q "${router}"; then
        ip -n "${DUT_NS_NAME}" addr add "${router}/24" dev "${DUT_LAN_IF}" 2>/dev/null || true
    fi

    nohup ip netns exec "${DUT_NS_NAME}" dnsmasq \
        --conf-file=/dev/null \
        --no-daemon \
        --interface="${DUT_LAN_IF}" \
        --bind-interfaces \
        --listen-address="${router}" \
        --dhcp-range="${pool_start},${pool_end},255.255.255.0,${lease_time}" \
        --dhcp-option="option:router,${router}" \
        --dhcp-option="option:dns-server,${dns}" \
        --dhcp-option="option:domain-name,${domain}" \
        --dhcp-host="${static_mac},${static_ip},${static_host}" \
        --dhcp-leasefile="${leasefile}" \
        --pid-file="${pidfile}" \
        --log-dhcp \
        --log-queries </dev/null > "${logfile}" 2>&1 &

    local bg_pid=$!
    sleep 0.2
    if [[ ! -f "${pidfile}" ]]; then
        printf '%s\n' "${bg_pid}" > "${pidfile}"
    fi

    if is_pidfile_running "${pidfile}"; then
        log_success "DHCPv4 Server active in ${DUT_NS_NAME} [PID: $(cat "${pidfile}")]"
    else
        log_error "Failed to start DHCPv4 Server in ${DUT_NS_NAME}. Check ${logfile}"
        return 1
    fi
}

start_server_v6_stateless() {
    require_root
    load_config
    ensure_runtime_dirs
    stop_dut_daemons

    if [[ "${TOPOLOGY_MODE:-virtual}" == "physical" ]]; then
        log_info "Physical topology mode active: external gateway DUT in use."
        return 0
    fi

    if ! ns_exists "${DUT_NS_NAME}"; then
        fatal "DUT namespace '${DUT_NS_NAME}' does not exist. Run './scripts/setup.sh --virtual' first."
    fi

    local lan_prefix="2001:db8:100::/64"
    local lan_ip="2001:db8:100::1"
    local dns_v6="2001:db8:100::1"

    local radvd_conf="${STATE_DIR}/dut-radvd.conf"
    local radvd_pid="${STATE_DIR}/dut-radvd.pid"
    local radvd_log="${LOG_DIR}/dut-radvd.log"

    local dnsmasq_pid="${STATE_DIR}/dut-dnsmasq.pid"
    local dnsmasq_log="${LOG_DIR}/dut-dnsmasq.log"

    log_info "Configuring Stateless DHCPv6 + SLAAC in ${DUT_NS_NAME} on ${DUT_LAN_IF}..."

    # Ensure IPv6 address on br-lan
    ip -n "${DUT_NS_NAME}" -6 addr replace "${lan_ip}/64" dev "${DUT_LAN_IF}" nodad 2>/dev/null || true
    ip netns exec "${DUT_NS_NAME}" sysctl -q -w "net.ipv6.conf.${DUT_LAN_IF}.disable_ipv6=0" 2>/dev/null || true
    ip netns exec "${DUT_NS_NAME}" sysctl -q -w "net.ipv6.conf.all.forwarding=1" 2>/dev/null || true

    # Generate radvd configuration for Stateless mode:
    # AdvManagedFlag off (No stateful address)
    # AdvOtherConfigFlag on (Other config like DNS via Information-Request)
    # AdvAutonomous on (SLAAC enabled)
    cat <<EOF > "${radvd_conf}"
interface ${DUT_LAN_IF} {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 5;
    AdvManagedFlag off;
    AdvOtherConfigFlag on;
    prefix ${lan_prefix} {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
    };
    RDNSS ${dns_v6} {
        AdvRDNSSLifetime 3600;
    };
};
EOF
    chmod 0644 "${radvd_conf}"

    # Launch radvd in ns-dut
    nohup ip netns exec "${DUT_NS_NAME}" radvd \
        -C "${radvd_conf}" \
        -p "${radvd_pid}" \
        -m stderr </dev/null > "${radvd_log}" 2>&1 &

    # Launch dnsmasq to answer DHCPv6 Information-Request with Option 23 (DNS)
    nohup ip netns exec "${DUT_NS_NAME}" dnsmasq \
        --conf-file=/dev/null \
        --no-daemon \
        --interface="${DUT_LAN_IF}" \
        --bind-interfaces \
        --dhcp-range="::,constructor:${DUT_LAN_IF},ra-stateless" \
        --dhcp-option="option6:dns-server,[${dns_v6}]" \
        --dhcp-option="option6:domain-search,home.gateway" \
        --pid-file="${dnsmasq_pid}" \
        --log-dhcp </dev/null > "${dnsmasq_log}" 2>&1 &

    sleep 0.2
    log_success "Stateless DHCPv6 (SLAAC + RDNSS) active in ${DUT_NS_NAME}."
}

start_server_v6_stateful() {
    require_root
    load_config
    ensure_runtime_dirs
    stop_dut_daemons

    if [[ "${TOPOLOGY_MODE:-virtual}" == "physical" ]]; then
        log_info "Physical topology mode active: external gateway DUT in use."
        return 0
    fi

    if ! ns_exists "${DUT_NS_NAME}"; then
        fatal "DUT namespace '${DUT_NS_NAME}' does not exist. Run './scripts/setup.sh --virtual' first."
    fi

    local pool_start="${DUT_DHCPV6_POOL_START:-2001:db8:100:1::1000}"
    local pool_end="${DUT_DHCPV6_POOL_END:-2001:db8:100:1::2000}"
    local lease_time="${DUT_DHCPV6_LEASE_TIME:-3600}s"
    local lan_prefix="2001:db8:100:1::/64"
    local lan_ip="2001:db8:100:1::1"
    local dns_v6="2001:db8:100:1::1"

    local radvd_conf="${STATE_DIR}/dut-radvd.conf"
    local radvd_pid="${STATE_DIR}/dut-radvd.pid"
    local radvd_log="${LOG_DIR}/dut-radvd.log"

    local dnsmasq_pid="${STATE_DIR}/dut-dnsmasq.pid"
    local dnsmasq_log="${LOG_DIR}/dut-dnsmasq.log"

    log_info "Configuring Stateful DHCPv6 (IA_NA) in ${DUT_NS_NAME} on ${DUT_LAN_IF}..."

    # Ensure IPv6 address on br-lan
    ip -n "${DUT_NS_NAME}" -6 addr replace "${lan_ip}/64" dev "${DUT_LAN_IF}" nodad 2>/dev/null || true
    ip netns exec "${DUT_NS_NAME}" sysctl -q -w "net.ipv6.conf.${DUT_LAN_IF}.disable_ipv6=0" 2>/dev/null || true
    ip netns exec "${DUT_NS_NAME}" sysctl -q -w "net.ipv6.conf.all.forwarding=1" 2>/dev/null || true

    # Generate radvd config for Stateful mode:
    # AdvManagedFlag on (Clients must query DHCPv6 server for IA_NA addresses)
    # AdvAutonomous off (SLAAC disabled)
    cat <<EOF > "${radvd_conf}"
interface ${DUT_LAN_IF} {
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 5;
    AdvManagedFlag on;
    AdvOtherConfigFlag on;
    prefix ${lan_prefix} {
        AdvOnLink on;
        AdvAutonomous off;
        AdvRouterAddr on;
    };
    RDNSS ${dns_v6} {
        AdvRDNSSLifetime 3600;
    };
};
EOF
    chmod 0644 "${radvd_conf}"

    nohup ip netns exec "${DUT_NS_NAME}" radvd \
        -C "${radvd_conf}" \
        -p "${radvd_pid}" \
        -m stderr </dev/null > "${radvd_log}" 2>&1 &

    # Launch dnsmasq to handle Stateful Solicit/Advertise/Request/Reply for IA_NA
    nohup ip netns exec "${DUT_NS_NAME}" dnsmasq \
        --conf-file=/dev/null \
        --no-daemon \
        --interface="${DUT_LAN_IF}" \
        --bind-interfaces \
        --dhcp-range="${pool_start},${pool_end},64,${lease_time}" \
        --dhcp-option="option6:dns-server,[${dns_v6}]" \
        --dhcp-option="option6:domain-search,home.gateway" \
        --pid-file="${dnsmasq_pid}" \
        --log-dhcp </dev/null > "${dnsmasq_log}" 2>&1 &

    sleep 0.2
    log_success "Stateful DHCPv6 (IA_NA Pool: ${pool_start} - ${pool_end}) active in ${DUT_NS_NAME}."
}

start_relay_v4() {
    local server_ip="${1:-${DHCP_RELAY_SERVER_V4:-10.10.0.1}}"
    require_root
    load_config
    ensure_runtime_dirs
    stop_dut_daemons

    if [[ "${TOPOLOGY_MODE:-virtual}" == "physical" ]]; then
        log_info "Physical topology mode active: external gateway DUT in use."
        return 0
    fi

    if ! ns_exists "${DUT_NS_NAME}"; then
        fatal "DUT namespace '${DUT_NS_NAME}' does not exist. Run './scripts/setup.sh --virtual' first."
    fi

    local gateway_ip="${DUT_LAN_IP:-192.168.1.1}"
    local pidfile="${STATE_DIR}/dut-dnsmasq.pid"
    local logfile="${LOG_DIR}/dut-dnsmasq.log"

    log_info "Configuring DHCPv4 Relay Agent in ${DUT_NS_NAME} (${DUT_LAN_IF} -> ${server_ip} via ${DUT_WAN_IF})..."

    # Launch dnsmasq in Relay mode:
    # --dhcp-relay=<local-addr>,<server-addr>[,<interface>]
    # Relays incoming requests on br-lan to server_ip, inserting giaddr = local-addr
    nohup ip netns exec "${DUT_NS_NAME}" dnsmasq \
        --conf-file=/dev/null \
        --no-daemon \
        --interface="${DUT_LAN_IF}" \
        --interface="${DUT_WAN_IF}" \
        --bind-interfaces \
        --dhcp-relay="${gateway_ip},${server_ip},${DUT_WAN_IF}" \
        --pid-file="${pidfile}" \
        --log-dhcp </dev/null > "${logfile}" 2>&1 &

    local bg_pid=$!
    sleep 0.2
    if [[ ! -f "${pidfile}" ]]; then
        printf '%s\n' "${bg_pid}" > "${pidfile}"
    fi

    if is_pidfile_running "${pidfile}"; then
        log_success "DHCPv4 Relay Agent active in ${DUT_NS_NAME} [PID: $(cat "${pidfile}")] (Server: ${server_ip}, giaddr: ${gateway_ip})"
    else
        log_error "Failed to start DHCPv4 Relay Agent. Check ${logfile}"
        return 1
    fi
}

start_relay_v6() {
    local server_v6="${1:-${DHCP_RELAY_SERVER_V6:-2001:db8:10::1}}"
    require_root
    load_config
    ensure_runtime_dirs
    stop_dut_daemons

    if [[ "${TOPOLOGY_MODE:-virtual}" == "physical" ]]; then
        log_info "Physical topology mode active: external gateway DUT in use."
        return 0
    fi

    if ! ns_exists "${DUT_NS_NAME}"; then
        fatal "DUT namespace '${DUT_NS_NAME}' does not exist. Run './scripts/setup.sh --virtual' first."
    fi

    local gateway_v6="${DUT_LAN_IPV6:-2001:db8:100::1}"
    local pidfile="${STATE_DIR}/dut-dnsmasq.pid"
    local logfile="${LOG_DIR}/dut-dnsmasq.log"

    log_info "Configuring DHCPv6 Relay Agent in ${DUT_NS_NAME} (${DUT_LAN_IF} -> [${server_v6}] via ${DUT_WAN_IF})..."

    # Launch dnsmasq in IPv6 Relay mode
    nohup ip netns exec "${DUT_NS_NAME}" dnsmasq \
        --conf-file=/dev/null \
        --no-daemon \
        --interface="${DUT_LAN_IF}" \
        --interface="${DUT_WAN_IF}" \
        --bind-interfaces \
        --dhcp-relay="${gateway_v6},${server_v6},${DUT_WAN_IF}" \
        --pid-file="${pidfile}" \
        --log-dhcp </dev/null > "${logfile}" 2>&1 &

    local bg_pid=$!
    sleep 0.2
    if [[ ! -f "${pidfile}" ]]; then
        printf '%s\n' "${bg_pid}" > "${pidfile}"
    fi

    if is_pidfile_running "${pidfile}"; then
        log_success "DHCPv6 Relay Agent active in ${DUT_NS_NAME} [PID: $(cat "${pidfile}")] (Server: ${server_v6})"
    else
        log_error "Failed to start DHCPv6 Relay Agent. Check ${logfile}"
        return 1
    fi
}

show_status() {
    load_config
    printf '\n==================================================================\n'
    printf '  DUT DHCP / RELAY RUNTIME STATUS\n'
    printf '==================================================================\n'

    local pidfile="${STATE_DIR}/dut-dnsmasq.pid"
    local radvd_pid="${STATE_DIR}/dut-radvd.pid"
    local leasefile="${STATE_DIR}/dut-dnsmasq.leases"

    if [[ -f "${pidfile}" ]] && is_pidfile_running "${pidfile}"; then
        printf '  [RUNNING] DUT dnsmasq Daemon (PID: %s)\n' "$(cat "${pidfile}")"
    else
        printf '  [STOPPED] DUT dnsmasq Daemon\n'
    fi

    if [[ -f "${radvd_pid}" ]] && is_pidfile_running "${radvd_pid}"; then
        printf '  [RUNNING] DUT radvd Daemon    (PID: %s)\n' "$(cat "${radvd_pid}")"
    else
        printf '  [STOPPED] DUT radvd Daemon\n'
    fi

    if [[ -f "${leasefile}" ]]; then
        printf '\n--- [ACTIVE DUT DHCP LEASES] ---\n'
        cat "${leasefile}"
    fi

    if ns_exists "${DUT_NS_NAME}"; then
        printf '\n--- [DUT INTERFACE ADDRESSES] ---\n'
        ip -n "${DUT_NS_NAME}" -br addr show dev "${DUT_LAN_IF}" 2>/dev/null || true
        ip -n "${DUT_NS_NAME}" -br addr show dev "${DUT_WAN_IF}" 2>/dev/null || true
    fi
    printf '==================================================================\n\n'
}

main() {
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    if [[ $# -lt 1 ]]; then
        usage
        exit 1
    fi

    local cmd="$1"; shift

    case "${cmd}" in
        server-v4)
            start_server_v4 "$@"
            ;;
        server-v6-stateless)
            start_server_v6_stateless "$@"
            ;;
        server-v6-stateful)
            start_server_v6_stateful "$@"
            ;;
        relay-v4)
            start_relay_v4 "$@"
            ;;
        relay-v6)
            start_relay_v6 "$@"
            ;;
        stop)
            stop_dut_daemons
            ;;
        status)
            show_status
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown command: ${cmd}" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"

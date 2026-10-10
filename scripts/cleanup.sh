#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - CLEANUP SCRIPT BOILERPLATE
# Idempotently tears down netns, veths, bridges, daemons,
# and restores physical interfaces to UP state with DHCP.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
    cat <<'USAGE'
Description:
  Gracefully stops daemons, tears down network namespaces, bridges,
  and virtual interfaces, and restores physical network adapters.
  Supports selective, non-destructive cleaning of logs and captures.

Usage:
  sudo ./scripts/cleanup.sh [options]
  ./scripts/cleanup.sh [command]

Options:
  -r, --restore, --dhcp    Restore physical interfaces (WAN_IF, LAN_IF) to UP, re-enable NetworkManager,
                           and trigger DHCP [Default]
  -d, --down, --no-restore Keep physical interfaces DOWN and flushed (isolated test mode)
  --logs                   Purge all test logs in logs/
  --captures               Purge all PCAP captures in captures/
  -a, --all                Teardown topology and purge state, logs, and captures
  -h, --help               Show this help message

Subcommands (Non-destructive to running topology):
  logs                     Purge logs/ without tearing down lab
  captures                 Purge captures/ without tearing down lab
  data                     Purge both logs/ and captures/ without tearing down lab

Examples:
  sudo ./scripts/cleanup.sh
  sudo ./scripts/cleanup.sh --all
  sudo ./scripts/cleanup.sh --down
  ./scripts/cleanup.sh logs
  ./scripts/cleanup.sh data

Suggested Next Steps:
  - Verify clean state:    ./scripts/show_state.sh
  - Deploy virtual lab:    sudo ./scripts/setup.sh --virtual
  - Deploy physical lab:   sudo ./scripts/setup.sh --single
USAGE
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

    # Non-destructive subcommands (Run without requiring root)
    case "${1:-}" in
        logs)     clean_logs; exit 0 ;;
        captures) clean_captures; exit 0 ;;
        data)     clean_logs; clean_captures; exit 0 ;;
    esac

    require_root
    require_command ip

    local restore="${RESTORE_INTERFACES_ON_CLEANUP:-1}"
    local clean_logs_flag=0
    local clean_captures_flag=0

    while (( $# > 0 )); do
        case "$1" in
            -r|--restore|--dhcp)    restore=1; shift ;;
            -d|--down|--no-restore) restore=0; shift ;;
            --logs)                 clean_logs_flag=1; shift ;;
            --captures)             clean_captures_flag=1; shift ;;
            -a|--all)               clean_logs_flag=1; clean_captures_flag=1; shift ;;
            *)                      usage; exit 2 ;;
        esac
    done

    print_header "CLEANING UP TEST LAB ENVIRONMENT"
    log_info "Initiating cleanup (restore_interfaces=${restore})..."

    # 1. Stop packet captures and client daemons
    if [[ -x "${SCRIPT_DIR}/capture.sh" ]]; then
        "${SCRIPT_DIR}/capture.sh" stop 2>/dev/null || true
    fi
    if [[ -x "${SCRIPT_DIR}/client_dhcp.sh" ]]; then
        "${SCRIPT_DIR}/client_dhcp.sh" release 2>/dev/null || true
    fi
    if [[ -x "${SCRIPT_DIR}/wan_server.sh" ]]; then
        "${SCRIPT_DIR}/wan_server.sh" stop 2>/dev/null || true
    fi
    if [[ -x "${SCRIPT_DIR}/dut_emulator.sh" ]]; then
        "${SCRIPT_DIR}/dut_emulator.sh" stop 2>/dev/null || true
    fi

    # 2. Stop daemons recorded in PID files
    local pidfile
    for pidfile in "${STATE_DIR}"/*.pid; do
        [[ -f "${pidfile}" ]] && stop_pidfile "${pidfile}"
    done

    # 3. Terminate background processes inside namespaces
    local ns
    local all_ns=(
        "${WAN_NS:-ns-wan}"
        "${DUT_NS:-ns-dut}"
        "${PC_NS:-ns-pc}"
        "${STB_NS:-ns-stb}"
        "${WLAN2G_NS:-ns-wlan2g}"
        "${WLAN5G_NS:-ns-wlan5g}"
        "${WLAN6G_NS:-ns-wlan6g}"
        "${PHONE1_NS:-ns-phone1}"
        "${PHONE2_NS:-ns-phone2}"
    )

    for ns in "${all_ns[@]}"; do
        if ns_exists "${ns}"; then
            ip netns exec "${ns}" pkill -TERM tcpdump 2>/dev/null || true
            ip netns exec "${ns}" pkill -TERM iperf3 2>/dev/null || true
            ip netns exec "${ns}" pkill -TERM python3 2>/dev/null || true
            ip netns exec "${ns}" pkill -TERM udhcpc 2>/dev/null || true
            ip netns exec "${ns}" pkill -TERM dnsmasq 2>/dev/null || true
        fi
    done

    # 4. Delete virtual interfaces (host-side veth ends)
    local veth
    for veth in v-wan-h v-pc-h v-stb-h v-w2g-h v-w5g-h v-w6g-h v-ph1-h v-ph2-h \
                veth-wan veth-dutwan veth-dut-pc veth-dut-stb veth-dut-w2g veth-dut-w5g veth-dut-w6g veth-dut-ph1 veth-dut-ph2; do
        if ip link show dev "${veth}" >/dev/null 2>&1; then
            ip link del dev "${veth}" 2>/dev/null || true
        fi
    done

    # 5. Restore physical interface names inside namespaces before deletion
    if ns_exists "${WAN_NS:-ns-wan}" && [[ -n "${WAN_IF:-}" ]]; then
        ip -n "${WAN_NS:-ns-wan}" link set "eth-raw" name "${WAN_IF}" 2>/dev/null || \
        ip -n "${WAN_NS:-ns-wan}" link set "eth0" name "${WAN_IF}" 2>/dev/null || true
    fi
    if ns_exists "${PC_NS:-ns-pc}" && [[ -n "${PC_IF:-${LAN_IF:-}}" ]]; then
        local pc_dev="${PC_IF:-${LAN_IF:-}}"
        ip -n "${PC_NS:-ns-pc}" link set "eth0" name "${pc_dev}" 2>/dev/null || true
    fi
    if ns_exists "${STB_NS:-ns-stb}" && [[ -n "${STB_IF:-}" ]]; then
        ip -n "${STB_NS:-ns-stb}" link set "eth0" name "${STB_IF}" 2>/dev/null || true
    fi

    for ns in "${all_ns[@]}"; do
        if ns_exists "${ns}"; then
            ip netns del "${ns}" 2>/dev/null || true
        fi
    done

    # 6. Delete test bridges
    local br
    for br in "${WAN_BRIDGE:-br-test-wan}" "${LAN_BRIDGE:-br-test-lan}"; do
        if bridge_exists "${br}"; then
            ip link set dev "${br}" down 2>/dev/null || true
            ip link del dev "${br}" 2>/dev/null || true
        fi
    done

    # 6.1 Clean up any 802.1Q VLAN trunk sub-interfaces
    if [[ -n "${VLAN_TRUNK_IF:-}" ]]; then
        local vlan_id
        for vlan_id in "${VLAN_ID_PC:-10}" "${VLAN_ID_STB:-20}" "${VLAN_ID_WLAN2G:-31}" "${VLAN_ID_WLAN5G:-32}" "${VLAN_ID_WLAN6G:-33}"; do
            ip link del dev "${VLAN_TRUNK_IF}.${vlan_id}" 2>/dev/null || true
        done
    fi

    # 7. Restore physical interfaces to UP + DHCP (or keep DOWN if requested)
    local ifaces=()
    local ifname
    for ifname in "${WAN_IF:-}" "${LAN_IF:-}" "${PC_IF:-}" "${STB_IF:-}" "${WLAN2G_IF:-}" "${WLAN5G_IF:-}" "${WLAN6G_IF:-}" "${PHONE1_IF:-}" "${PHONE2_IF:-}" "${VLAN_TRUNK_IF:-}" "${TEST_IF:-}"; do
        if [[ -n "${ifname}" ]] && iface_exists_root "${ifname}"; then
            if [[ ! " ${ifaces[*]:-} " =~ [[:space:]]${ifname}[[:space:]] ]]; then
                ifaces+=("${ifname}")
            fi
        fi
    done

    for ifname in "${ifaces[@]:-}"; do
        if (( restore == 1 )); then
            restore_physical_interface "${ifname}"
        else
            tear_down_physical_interface "${ifname}"
        fi
    done

    # 8. Clean runtime state files
    rm -f "${STATE_DIR}/topology_state.env" "${STATE_DIR}/last_capture.env" 2>/dev/null || true
    rm -f "${STATE_DIR}"/*.pid "${STATE_DIR}"/*.leases "${STATE_DIR}"/*.conf "${STATE_DIR}"/*.state 2>/dev/null || true
    rm -f /run/kea/*.pid /run/lock/kea/*.pid /run/kea/logger_lockfile /run/lock/kea/logger_lockfile 2>/dev/null || true

    if (( clean_logs_flag == 1 )); then clean_logs; fi
    if (( clean_captures_flag == 1 )); then clean_captures; fi

    log_success "Cleanup completed successfully!"
    printf '\nSuggested next steps:\n'
    printf '  - Check lab state:     ./scripts/show_state.sh\n'
    printf '  - Deploy virtual lab:  sudo ./scripts/setup.sh --virtual\n'
}

main "$@"

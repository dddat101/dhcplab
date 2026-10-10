#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - POLYMORPHIC STATION ADAPTER HIERARCHY
# Module: station_adapter.sh
# Provides a polymorphic abstraction for wireless station endpoints across
# local namespaces (LocalStationAdapter: netns/veth/wlan) and remote SSH hosts
# (RemoteStationAdapter), unifying command execution, routing seams, and QoS marking.
# ==============================================================================

# Guard against duplicate inclusion
if [[ -n "${_NWLAB_STATION_ADAPTER_LOADED:-}" ]]; then
    return 0
fi
readonly _NWLAB_STATION_ADAPTER_LOADED=1

_SA_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "${_SA_DIR}/common.sh" ]]; then
    # shellcheck source=lib/common.sh
    source "${_SA_DIR}/common.sh"
fi
unset _SA_DIR

# ------------------------------------------------------------------------------
# Station Adapter State
# ------------------------------------------------------------------------------
STATION_TYPE="local"          # "local" or "remote"
STATION_TARGET=""             # netns name, dev name, or remote host
STATION_ROUTE_ACTIVE=0
STATION_MANGLE_ACTIVE=0
STATION_ACTIVE_DEV=""
STATION_ACTIVE_PORTS=""
STATION_ACTIVE_DSCP=""
CLEANUP_WIFI_ROUTE=""
CLEANUP_IPTABLES_MANGLE=""

# ------------------------------------------------------------------------------
# Polymorphic Initialization
# ------------------------------------------------------------------------------

station_init() {
    local stype="${1:-local}"
    local target="${2:-}"

    STATION_TYPE="${stype,,}"
    STATION_TARGET="${target}"

    if [[ "${STATION_TYPE}" == "local" ]]; then
        if [[ -n "${STATION_TARGET}" ]] && ! ns_exists "${STATION_TARGET}"; then
            STATION_ACTIVE_DEV="${STATION_TARGET}"
        fi
    fi

    log_info "Station Adapter initialized: [Type: ${STATION_TYPE^^}] [Target: ${STATION_TARGET:-default}]"
}

# ------------------------------------------------------------------------------
# Polymorphic Command Execution Seam
# ------------------------------------------------------------------------------

station_exec() {
    if (( $# == 0 )); then
        return 0
    fi

    if [[ "${STATION_TYPE}" == "remote" ]]; then
        local remote_runner="${SCRIPT_DIR:-.}/remote_client.sh"
        if [[ -f "${remote_runner}" ]]; then
            "${remote_runner}" run "$@"
        else
            ssh ${REMOTE_CLIENT_SSH_OPTS:-} "${STATION_TARGET:-${REMOTE_CLIENT_HOST:-}}" "$@"
        fi
    else
        # Local adapter
        if [[ -n "${STATION_TARGET}" ]] && ns_exists "${STATION_TARGET}"; then
            ip netns exec "${STATION_TARGET}" "$@"
        else
            "$@"
        fi
    fi
}

# ------------------------------------------------------------------------------
# Polymorphic Host Route Binding Seam
# ------------------------------------------------------------------------------

station_bind_route() {
    local wan_ip="${1:-${WAN_SERVER_IP:-10.10.0.1}}"
    local dut_ip="${2:-${DUT_LAN_IP:-192.168.1.1}}"
    local dev="${3:-${STATION_ACTIVE_DEV:-${STATION_TARGET}}}"

    if (( DRY_RUN == 1 )); then
        log_info "[DRY-RUN] Would bind route ${wan_ip} via ${dut_ip} on station [${STATION_TYPE}:${STATION_TARGET}]"
        return 0
    fi

    if [[ "${STATION_TYPE}" == "remote" ]]; then
        log_cmd "[REMOTE] ip route replace ${wan_ip} via ${dut_ip}"
        station_exec "sudo ip route replace ${wan_ip} via ${dut_ip} 2>/dev/null || true"
        STATION_ROUTE_ACTIVE=1
    else
        # Local adapter
        if [[ -n "${STATION_TARGET}" ]] && ns_exists "${STATION_TARGET}"; then
            log_cmd "ip netns exec ${STATION_TARGET} ip route replace ${wan_ip} via ${dut_ip}"
            ip netns exec "${STATION_TARGET}" ip route replace "${wan_ip}" via "${dut_ip}" 2>/dev/null || true
            CLEANUP_WIFI_ROUTE="${wan_ip} via ${dut_ip}"
            STATION_ROUTE_ACTIVE=1
        elif [[ -n "${dev}" ]]; then
            log_cmd "ip route replace ${wan_ip} via ${dut_ip} dev ${dev}"
            ip route replace "${wan_ip}" via "${dut_ip}" dev "${dev}" 2>/dev/null || true
            CLEANUP_WIFI_ROUTE="${wan_ip} via ${dut_ip} dev ${dev}"
            STATION_ROUTE_ACTIVE=1
            STATION_ACTIVE_DEV="${dev}"
        fi
    fi

    return 0
}

station_unbind_route() {
    if (( STATION_ROUTE_ACTIVE == 0 )); then
        return 0
    fi

    if [[ "${STATION_TYPE}" == "remote" ]]; then
        log_cmd "[REMOTE] ip route del ${CLEANUP_WIFI_ROUTE:-${WAN_SERVER_IP:-10.10.0.1}}"
        station_exec "sudo ip route del ${WAN_SERVER_IP:-10.10.0.1} 2>/dev/null || true"
    else
        if [[ -n "${STATION_TARGET}" ]] && ns_exists "${STATION_TARGET}"; then
            if [[ -n "${CLEANUP_WIFI_ROUTE:-}" ]]; then
                log_cmd "ip netns exec ${STATION_TARGET} ip route del ${CLEANUP_WIFI_ROUTE}"
                ip netns exec "${STATION_TARGET}" ip route del ${CLEANUP_WIFI_ROUTE} 2>/dev/null || true
            fi
        elif [[ -n "${CLEANUP_WIFI_ROUTE:-}" ]]; then
            log_cmd "ip route del ${CLEANUP_WIFI_ROUTE}"
            ip route del ${CLEANUP_WIFI_ROUTE} 2>/dev/null || true
        fi
    fi

    CLEANUP_WIFI_ROUTE=""
    STATION_ROUTE_ACTIVE=0
    return 0
}

# ------------------------------------------------------------------------------
# Polymorphic QoS DSCP Mangle Seam
# ------------------------------------------------------------------------------

station_apply_qos() {
    local ports_list="${1:-}"
    local dscp_mark="${2:-}"
    local dev="${3:-${STATION_ACTIVE_DEV:-${STATION_TARGET}}}"

    if [[ -z "${ports_list}" || -z "${dscp_mark}" ]]; then
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        log_info "[DRY-RUN] Would apply DSCP ${dscp_mark} mangle rules on station [${STATION_TYPE}:${STATION_TARGET}]"
        return 0
    fi

    if [[ "${STATION_TYPE}" == "remote" ]]; then
        log_cmd "[REMOTE] iptables mangle DSCP ${dscp_mark} for ports ${ports_list}"
        station_exec "sudo iptables -t mangle -A POSTROUTING -p udp -m multiport --dports ${ports_list} -j DSCP --set-dscp ${dscp_mark} 2>/dev/null || true"
        station_exec "sudo iptables -t mangle -A POSTROUTING -p udp -m multiport --sports ${ports_list} -j DSCP --set-dscp ${dscp_mark} 2>/dev/null || true"
        STATION_MANGLE_ACTIVE=1
        STATION_ACTIVE_PORTS="${ports_list}"
        STATION_ACTIVE_DSCP="${dscp_mark}"
    else
        local dev_flag=""
        if [[ -n "${dev}" ]]; then
            dev_flag="-o ${dev}"
        fi

        local ipt_cmd=("iptables" "-t" "mangle")
        if [[ -n "${STATION_TARGET}" ]] && ns_exists "${STATION_TARGET}"; then
            ipt_cmd=("ip" "netns" "exec" "${STATION_TARGET}" "iptables" "-t" "mangle")
        fi

        log_cmd "${ipt_cmd[*]} -A POSTROUTING ${dev_flag} -p udp -m multiport --dports ${ports_list} -j DSCP --set-dscp ${dscp_mark}"
        "${ipt_cmd[@]}" -A POSTROUTING ${dev_flag} -p udp -m multiport --dports "${ports_list}" -j DSCP --set-dscp "${dscp_mark}" 2>/dev/null || true

        log_cmd "${ipt_cmd[*]} -A POSTROUTING ${dev_flag} -p udp -m multiport --sports ${ports_list} -j DSCP --set-dscp ${dscp_mark}"
        "${ipt_cmd[@]}" -A POSTROUTING ${dev_flag} -p udp -m multiport --sports "${ports_list}" -j DSCP --set-dscp "${dscp_mark}" 2>/dev/null || true

        STATION_MANGLE_ACTIVE=1
        STATION_ACTIVE_PORTS="${ports_list}"
        STATION_ACTIVE_DSCP="${dscp_mark}"
    fi

    return 0
}

station_revert_qos() {
    if (( STATION_MANGLE_ACTIVE == 0 )); then
        return 0
    fi

    local ports="${STATION_ACTIVE_PORTS}"
    local dscp="${STATION_ACTIVE_DSCP}"
    local dev="${STATION_ACTIVE_DEV}"

    if [[ -z "${ports}" || -z "${dscp}" ]]; then
        return 0
    fi

    if [[ "${STATION_TYPE}" == "remote" ]]; then
        log_cmd "[REMOTE] revert iptables mangle DSCP ${dscp}"
        station_exec "sudo iptables -t mangle -D POSTROUTING -p udp -m multiport --dports ${ports} -j DSCP --set-dscp ${dscp} 2>/dev/null || true"
        station_exec "sudo iptables -t mangle -D POSTROUTING -p udp -m multiport --sports ${ports} -j DSCP --set-dscp ${dscp} 2>/dev/null || true"
    else
        local dev_flag=""
        if [[ -n "${dev}" ]]; then
            dev_flag="-o ${dev}"
        fi

        local ipt_cmd=("iptables" "-t" "mangle")
        if [[ -n "${STATION_TARGET}" ]] && ns_exists "${STATION_TARGET}"; then
            ipt_cmd=("ip" "netns" "exec" "${STATION_TARGET}" "iptables" "-t" "mangle")
        fi

        log_cmd "${ipt_cmd[*]} -D POSTROUTING ${dev_flag} -p udp -m multiport --dports ${ports} -j DSCP --set-dscp ${dscp}"
        "${ipt_cmd[@]}" -D POSTROUTING ${dev_flag} -p udp -m multiport --dports "${ports}" -j DSCP --set-dscp "${dscp}" 2>/dev/null || true
        "${ipt_cmd[@]}" -D POSTROUTING ${dev_flag} -p udp -m multiport --sports "${ports}" -j DSCP --set-dscp "${dscp}" 2>/dev/null || true
    fi

    STATION_MANGLE_ACTIVE=0
    STATION_ACTIVE_PORTS=""
    STATION_ACTIVE_DSCP=""
    return 0
}

# ------------------------------------------------------------------------------
# Centralized Cleanup Seam
# ------------------------------------------------------------------------------

station_cleanup() {
    station_revert_qos
    station_unbind_route
    STATION_ACTIVE_DEV=""
    STATION_TARGET=""
    STATION_TYPE="local"
    return 0
}

# ------------------------------------------------------------------------------
# Backwards Compatibility Wrappers
# ------------------------------------------------------------------------------

station_adapter_bind_route() {
    local dev="${1:-}"
    local wan_ip="${2:-${WAN_SERVER_IP:-10.10.0.1}}"
    local dut_ip="${3:-${DUT_LAN_IP:-192.168.1.1}}"

    STATION_ACTIVE_DEV="${dev}"
    station_bind_route "${wan_ip}" "${dut_ip}" "${dev}"
}

station_adapter_unbind_route() {
    station_unbind_route
}

station_adapter_apply_mangle() {
    local dev="${1:-}"
    local ports="${2:-}"
    local dscp="${3:-}"

    STATION_ACTIVE_DEV="${dev}"
    station_apply_qos "${ports}" "${dscp}" "${dev}"
}

station_adapter_revert_mangle() {
    station_revert_qos
}

station_adapter_acquire() {
    local target_dev="${PLAN_PRIMARY_WIFI_IF:-}"
    local req_route="${PLAN_REQUIRES_HOST_ROUTE:-0}"

    if (( req_route == 1 )) && [[ -n "${target_dev}" ]]; then
        station_adapter_bind_route "${target_dev}" "${WAN_SERVER_IP:-10.10.0.1}" "${DUT_LAN_IP:-192.168.1.1}"
    fi

    return 0
}

station_adapter_release() {
    station_cleanup
}

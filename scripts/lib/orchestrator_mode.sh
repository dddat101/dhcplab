#!/usr/bin/env bash
# ==============================================================================
# DHCPLAB - RUNNING MODE ORCHESTRATOR
# Module: orchestrator_mode.sh
# Bridge between scenario runners and RunningContextResolver.
# Evaluates invariants, exports the Execution Plan, and prepares Station Adapters.
# ==============================================================================

# Guard against duplicate inclusion
if [[ -n "${_DHCPLAB_ORCHESTRATOR_MODE_LOADED:-}" ]]; then
    return 0
fi
readonly _DHCPLAB_ORCHESTRATOR_MODE_LOADED=1

_ORCH_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "${_ORCH_DIR}/common.sh" ]]; then
    # shellcheck source=lib/common.sh
    source "${_ORCH_DIR}/common.sh"
fi
if [[ -f "${_ORCH_DIR}/station_adapter.sh" ]]; then
    # shellcheck source=lib/station_adapter.sh
    source "${_ORCH_DIR}/station_adapter.sh"
fi
unset _ORCH_DIR

orchestrator_resolve_context() {
    local script_dir="${SCRIPT_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
    local lab_dir="${LAB_DIR:-$(cd -- "${script_dir}/.." && pwd -P)}"
    local tools_dir="${lab_dir}/tools"
    local resolver_script="${tools_dir}/running_context.py"

    if [[ ! -f "${resolver_script}" ]]; then
        log_warn "orchestrator_resolve_context: resolver script not found at ${resolver_script}; fallback to emulated"
        PLAN_TOPOLOGY_MODE="${TOPOLOGY_MODE:-virtual}"
        PLAN_EXECUTION_MODE="emulated_virtual"
        PLAN_IS_VIRTUAL="1"
        PLAN_REQUIRES_HOST_ROUTE="0"
        PLAN_REQUIRES_REMOTE_CLIENT="0"
        PLAN_REQUIRES_IPTABLES_MANGLE="0"
        PLAN_PRIMARY_WIFI_IF="eth0"
        PLAN_PRIMARY_WIFI_NS="ns-wlan5g"
        PLAN_SIM_MODE="emulated"
        PLAN_VOIP_MODE="virtual"
        PLAN_WQOS_MODE="virtual"
        PLAN_IS_FORCED_OVERRIDE="0"
        PLAN_REASON="Default fallback to emulated execution"
        return 0
    fi

    # 1. Inspect hardware state once if not already available
    if [[ -z "${DETECTED_WIFI_STATUS:-}" ]] && [[ -x "${tools_dir}/wifi_inspector.py" ]]; then
        local env_dump
        env_dump="$("${tools_dir}/wifi_inspector.py" export-env --check-ping "${DUT_LAN_IP:-192.168.1.1}" 2>/dev/null || true)"
        eval "${env_dump}"
    fi

    # 2. Check remote client Wi-Fi state if configured
    local rem_ok=0
    if [[ -n "${REMOTE_CLIENT_HOST:-}" ]] && [[ -x "${script_dir}/remote_client.sh" ]]; then
        if [[ -z "${REMOTE_WIFI_STATUS:-}" ]]; then
            local rem_dump
            rem_dump="$("${script_dir}/remote_client.sh" wifi-env --check-ping "${DUT_LAN_IP:-192.168.1.1}" 2>/dev/null || true)"
            eval "${rem_dump}"
        fi
        if [[ "${REMOTE_WIFI_PING_OK:-0}" == "1" ]]; then
            rem_ok=1
        fi
    fi

    # 3. Invoke deep domain resolver to generate Execution Plan
    local plan_env
    plan_env="$("${PYTHON_BIN:-python3}" "${resolver_script}" export-env \
        --topology-mode "${TOPOLOGY_MODE:-virtual}" \
        --cli-wifi-mode "${CUSTOM_WIFI_MODE:-}" \
        --config-wifi-mode "${WIFI_TEST_MODE:-auto}" \
        --wifi-card-count "${WIFI_CARD_COUNT:-0}" \
        --wifi-if "${DETECTED_WIFI_IF:-}" \
        --wifi-ssid "${DETECTED_WIFI_SSID:-}" \
        --wifi-band "${DETECTED_WIFI_BAND:-}" \
        --wifi-ip "${DETECTED_WIFI_IP:-}" \
        --remote-host "${REMOTE_CLIENT_HOST:-}" \
        $( (( rem_ok == 1 )) && echo "--remote-wifi-ok" ) \
        --remote-wifi-if "${REMOTE_WIFI_IF:-}" \
        --remote-wifi-ip "${REMOTE_WIFI_IP:-}" \
        --remote-wifi-ssid "${REMOTE_WIFI_SSID:-}" \
        --remote-wifi-band "${REMOTE_WIFI_BAND:-}" \
        2>/dev/null || true)"

    if [[ -n "${plan_env}" ]]; then
        eval "${plan_env}"
    fi

    return 0
}

orchestrator_show_plan() {
    local scenario_title="${1:-PERFORMANCE BENCHMARK}"
    log_info "Execution Plan for [${scenario_title}]:"
    log_info "  -> Topology Mode    : [${PLAN_TOPOLOGY_MODE:-virtual^^}]"
    log_info "  -> Canonical Mode   : [${PLAN_EXECUTION_MODE:-unknown^^}]"
    log_info "  -> Virtual Emulated : $( (( ${PLAN_IS_VIRTUAL:-1} == 1 )) && echo 'YES (Software namespaces)' || echo 'NO (Over-The-Air Hardware)' )"
    if (( ${PLAN_REQUIRES_REMOTE_CLIENT:-0} == 1 )); then
        log_info "  -> Remote Station   : ${REMOTE_CLIENT_HOST:-not_configured} (Dev: ${REMOTE_WIFI_IF:-wlan0})"
    fi
    if (( ${PLAN_REQUIRES_HOST_ROUTE:-0} == 1 )); then
        log_info "  -> Physical Wi-Fi   : ${PLAN_PRIMARY_WIFI_IF:-wlan0} (Host route to ${WAN_SERVER_IP:-10.10.0.1} required)"
    elif [[ -n "${PLAN_PRIMARY_WIFI_NS:-}" ]]; then
        log_info "  -> Emulated Station : ${PLAN_PRIMARY_WIFI_NS} (${PLAN_PRIMARY_WIFI_IF:-eth0})"
    fi
    if (( ${PLAN_IS_FORCED_OVERRIDE:-0} == 1 )); then
        log_warn "  -> FORCED OVERRIDE  : Physical hardware requested inside virtual topology."
    fi
    log_info "  -> Reason           : ${PLAN_REASON:-None}"
}

#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - SCENARIO PLUGIN & REGISTRATION FRAMEWORK
# Module: scenario_framework.sh
# Provides dynamic scenario discovery, declarative lifecycle hooks,
# canonical CLI dispatching, and pluggable verification integration.
# ==============================================================================

# Guard against duplicate inclusion
if [[ -n "${_NWLAB_SCENARIO_FRAMEWORK_LOADED:-}" ]]; then
    return 0
fi
readonly _NWLAB_SCENARIO_FRAMEWORK_LOADED=1

# Ensure common library dependencies are sourced
_SCN_FW_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -f "${_SCN_FW_DIR}/common.sh" ]]; then
    # shellcheck source=lib/common.sh
    source "${_SCN_FW_DIR}/common.sh"
fi
if [[ -f "${_SCN_FW_DIR}/scenario_common.sh" ]]; then
    # shellcheck source=lib/scenario_common.sh
    source "${_SCN_FW_DIR}/scenario_common.sh"
fi
unset _SCN_FW_DIR

# ------------------------------------------------------------------------------
# Global Scenario Registry State
# ------------------------------------------------------------------------------
declare -ga SCENARIO_REGISTRY_ORDER=()
declare -gA SCENARIO_REGISTRY_NAME=()
declare -gA SCENARIO_REGISTRY_DESC=()
declare -gA SCENARIO_REGISTRY_ALIASES=()
declare -gA SCENARIO_REGISTRY_LAN_NS=()
declare -gA SCENARIO_REGISTRY_BPF=()
declare -gA SCENARIO_REGISTRY_DURATION=()
declare -gA SCENARIO_REGISTRY_RUN_FN=()
declare -gA SCENARIO_REGISTRY_VALIDATE_FN=()
declare -gA SCENARIO_REGISTRY_SETUP_FN=()
declare -gA SCENARIO_REGISTRY_VERIFY_FN=()
declare -gA SCENARIO_REGISTRY_TEARDOWN_FN=()
declare -gA SCENARIO_REGISTRY_HELP_FN=()
declare -gA SCENARIO_REGISTRY_OPTIONS_FN=()
declare -gA SCENARIO_REGISTRY_FILE=()

# ------------------------------------------------------------------------------
# Scenario Registration API
# ------------------------------------------------------------------------------
scenario_register() {
    local id=""
    local name=""
    local desc=""
    local aliases=""
    local lan_ns="${PC_NS:-ns-pc}"
    local bpf=""
    local duration=10
    local run_fn=""
    local validate_fn=""
    local setup_fn=""
    local verify_fn=""
    local teardown_fn=""
    local help_fn=""
    local options_fn=""
    local scn_file="${BASH_SOURCE[1]:-}"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --id)
                [[ $# -ge 2 ]] || die "scenario_register: --id requires a value"
                id="${2,,}"
                shift 2
                ;;
            --name)
                [[ $# -ge 2 ]] || die "scenario_register: --name requires a value"
                name="$2"
                shift 2
                ;;
            --desc|--description)
                [[ $# -ge 2 ]] || die "scenario_register: --desc requires a value"
                desc="$2"
                shift 2
                ;;
            --aliases|--alias)
                [[ $# -ge 2 ]] || die "scenario_register: --aliases requires a value"
                aliases="$2"
                shift 2
                ;;
            --lan-ns|--netns)
                [[ $# -ge 2 ]] || die "scenario_register: --lan-ns requires a value"
                lan_ns="$2"
                shift 2
                ;;
            --bpf|--capture-filter)
                [[ $# -ge 2 ]] || die "scenario_register: --bpf requires a value"
                bpf="$2"
                shift 2
                ;;
            --duration)
                [[ $# -ge 2 ]] || die "scenario_register: --duration requires a value"
                duration="$2"
                shift 2
                ;;
            --run-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --run-fn requires a value"
                run_fn="$2"
                shift 2
                ;;
            --validate-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --validate-fn requires a value"
                validate_fn="$2"
                shift 2
                ;;
            --setup-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --setup-fn requires a value"
                setup_fn="$2"
                shift 2
                ;;
            --verify-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --verify-fn requires a value"
                verify_fn="$2"
                shift 2
                ;;
            --teardown-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --teardown-fn requires a value"
                teardown_fn="$2"
                shift 2
                ;;
            --help-fn|--usage-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --help-fn requires a value"
                help_fn="$2"
                shift 2
                ;;
            --options-fn)
                [[ $# -ge 2 ]] || die "scenario_register: --options-fn requires a value"
                options_fn="$2"
                shift 2
                ;;
            *)
                die "scenario_register: unrecognized option: $1"
                ;;
        esac
    done

    [[ -n "${id}" ]] || die "scenario_register: scenario ID cannot be empty"
    [[ -n "${run_fn}" ]] || die "scenario_register: scenario [${id}] must provide --run-fn"

    # Track registration order
    local exists=0
    for existing_id in "${SCENARIO_REGISTRY_ORDER[@]:-}"; do
        if [[ "${existing_id}" == "${id}" ]]; then
            exists=1
            break
        fi
    done
    if (( exists == 0 )); then
        SCENARIO_REGISTRY_ORDER+=("${id}")
    fi

    SCENARIO_REGISTRY_NAME["${id}"]="${name:-${id}}"
    SCENARIO_REGISTRY_DESC["${id}"]="${desc:-No description provided}"
    SCENARIO_REGISTRY_ALIASES["${id}"]="${aliases}"
    SCENARIO_REGISTRY_LAN_NS["${id}"]="${lan_ns}"
    SCENARIO_REGISTRY_BPF["${id}"]="${bpf}"
    SCENARIO_REGISTRY_DURATION["${id}"]="${duration}"
    SCENARIO_REGISTRY_RUN_FN["${id}"]="${run_fn}"
    SCENARIO_REGISTRY_VALIDATE_FN["${id}"]="${validate_fn}"
    SCENARIO_REGISTRY_SETUP_FN["${id}"]="${setup_fn}"
    SCENARIO_REGISTRY_VERIFY_FN["${id}"]="${verify_fn}"
    SCENARIO_REGISTRY_TEARDOWN_FN["${id}"]="${teardown_fn}"
    SCENARIO_REGISTRY_HELP_FN["${id}"]="${help_fn}"
    SCENARIO_REGISTRY_OPTIONS_FN["${id}"]="${options_fn}"
    SCENARIO_REGISTRY_FILE["${id}"]="${scn_file}"

    log_debug "Registered scenario: ${id} (${name:-${id}}) from ${scn_file}"
}

# ------------------------------------------------------------------------------
# Dynamic Scenario Discovery
# ------------------------------------------------------------------------------
scenario_load_all() {
    local scenarios_dir="${1:-${LAB_DIR:-${PROJECT_ROOT}}/scripts/scenarios}"

    if [[ ! -d "${scenarios_dir}" ]]; then
        log_debug "No scenarios directory found at: ${scenarios_dir}"
        return 0
    fi

    for scn_file in "${scenarios_dir}"/*.sh; do
        if [[ -f "${scn_file}" && ! "${scn_file}" =~ \.(example|bak|disabled)\.sh$ ]]; then
            # Source defensively
            # shellcheck source=/dev/null
            source "${scn_file}" || {
                log_warn "Failed to source scenario module: ${scn_file}"
            }
        fi
    done
}

# ------------------------------------------------------------------------------
# Query & Resolution Utilities
# ------------------------------------------------------------------------------
scenario_resolve() {
    local query="${1,,}"
    if [[ -z "${query}" ]]; then
        echo ""
        return 1
    fi

    # 1. Exact ID match
    if [[ -n "${SCENARIO_REGISTRY_NAME[${query}]+x}" ]]; then
        echo "${query}"
        return 0
    fi

    # 2. Match aliases
    for id in "${SCENARIO_REGISTRY_ORDER[@]:-}"; do
        local raw_aliases="${SCENARIO_REGISTRY_ALIASES[${id}]:-}"
        IFS=',' read -r -a alias_arr <<< "${raw_aliases}"
        for a in "${alias_arr[@]}"; do
            local clean_a="${a// /}"
            if [[ "${clean_a,,}" == "${query}" ]]; then
                echo "${id}"
                return 0
            fi
        done
    done

    echo ""
    return 1
}

scenario_list() {
    if (( ${#SCENARIO_REGISTRY_ORDER[@]} == 0 )); then
        printf '  No scenario modules currently registered.\n'
        printf '  Place scenario scripts in scripts/scenarios/ conforming to scenario_template.sh\n\n'
        return 0
    fi

    printf 'Available Test Scenarios:\n'
    printf '%-18s | %-28s | %-12s | %s\n' "Scenario ID" "Scenario Title" "Target Netns" "Aliases / BPF Filter"
    printf '%s\n' "-------------------+------------------------------+--------------+---------------------------------------"

    for id in "${SCENARIO_REGISTRY_ORDER[@]}"; do
        local name="${SCENARIO_REGISTRY_NAME[${id}]}"
        local ns="${SCENARIO_REGISTRY_LAN_NS[${id}]}"
        local aliases="${SCENARIO_REGISTRY_ALIASES[${id}]}"
        local bpf="${SCENARIO_REGISTRY_BPF[${id}]}"
        local info="${aliases:-none}"
        if [[ -n "${bpf}" ]]; then
            info+=" (BPF: ${bpf})"
        fi
        printf '%-18s | %-28s | %-12s | %s\n' "${id}" "${name}" "${ns}" "${info}"
    done
    printf '\n'
}

# ------------------------------------------------------------------------------
# Help Dispatcher
# ------------------------------------------------------------------------------
scenario_show_help() {
    local target="${1:-}"

    if [[ -n "${target}" && "${target}" != "all" ]]; then
        local resolved_id
        resolved_id="$(scenario_resolve "${target}" || true)"
        if [[ -n "${resolved_id}" ]]; then
            local custom_help="${SCENARIO_REGISTRY_HELP_FN[${resolved_id}]:-}"
            if [[ -n "${custom_help}" ]] && declare -F "${custom_help}" >/dev/null 2>&1; then
                "${custom_help}"
                return 0
            else
                cat <<EOF
+------------------------------------------------------------------+
| SCENARIO: ${SCENARIO_REGISTRY_NAME[${resolved_id}]}
+------------------------------------------------------------------+
  ID          : ${resolved_id}
  Aliases     : ${SCENARIO_REGISTRY_ALIASES[${resolved_id}]:-none}
  Description : ${SCENARIO_REGISTRY_DESC[${resolved_id}]}
  LAN Target  : ${SCENARIO_REGISTRY_LAN_NS[${resolved_id}]}
  Capture BPF : ${SCENARIO_REGISTRY_BPF[${resolved_id}]:-none}
  Duration    : ${SCENARIO_REGISTRY_DURATION[${resolved_id}]}s
  Source File : ${SCENARIO_REGISTRY_FILE[${resolved_id}]}

  Execute:
    sudo ./scripts/scenario.sh ${resolved_id}
EOF
                return 0
            fi
        else
            log_warn "Scenario '${target}' not found in registry."
        fi
    fi

    # Default list of all scenarios
    scenario_list
}

# ------------------------------------------------------------------------------
# Scenario Execution Engine
# ------------------------------------------------------------------------------
scenario_run_single() {
    local scn_id="$1"
    shift
    local resolved_id
    resolved_id="$(scenario_resolve "${scn_id}" || true)"
    if [[ -z "${resolved_id}" ]]; then
        die "Unknown scenario: '${scn_id}'. Run './scripts/scenario.sh list' to inspect available scenarios."
    fi

    local title="${SCENARIO_REGISTRY_NAME[${resolved_id}]}"
    local lan_ns="${SCENARIO_REGISTRY_LAN_NS[${resolved_id}]}"
    local bpf_filter="${SCENARIO_REGISTRY_BPF[${resolved_id}]}"
    local run_fn="${SCENARIO_REGISTRY_RUN_FN[${resolved_id}]}"
    local val_fn="${SCENARIO_REGISTRY_VALIDATE_FN[${resolved_id}]:-}"
    local setup_fn="${SCENARIO_REGISTRY_SETUP_FN[${resolved_id}]:-}"
    local verify_fn="${SCENARIO_REGISTRY_VERIFY_FN[${resolved_id}]:-}"
    local teardown_fn="${SCENARIO_REGISTRY_TEARDOWN_FN[${resolved_id}]:-}"
    local options_fn="${SCENARIO_REGISTRY_OPTIONS_FN[${resolved_id}]:-}"

    printf '\n==================================================================\n'
    printf '  STARTING DHCPLAB TEST: [%s] %s\n' "${resolved_id}" "${title}"
    printf '==================================================================\n'
    log_step "Executing Scenario: [${resolved_id}] ${title}"

    # 1. Parse scenario-specific options if hook is provided
    if [[ -n "${options_fn}" ]] && declare -F "${options_fn}" >/dev/null 2>&1; then
        "${options_fn}" "$@"
    fi

    # 2. Resolve Running Context & Display Execution Plan via Orchestrator Mode
    if declare -F orchestrator_resolve_context >/dev/null 2>&1; then
        orchestrator_resolve_context
        orchestrator_show_plan "${title}"
    fi

    # 3. Validation Hook
    if [[ -n "${val_fn}" ]] && declare -F "${val_fn}" >/dev/null 2>&1; then
        if ! "${val_fn}"; then
            log_error "Validation failed for scenario [${resolved_id}]."
            return 1
        fi
    fi

    # 4. Pre-test Setup Hook & Station Adapter Acquisition
    if declare -F station_adapter_acquire >/dev/null 2>&1; then
        station_adapter_acquire
    fi
    if [[ -n "${setup_fn}" ]] && declare -F "${setup_fn}" >/dev/null 2>&1; then
        "${setup_fn}"
    fi

    # 5. Execute Main Traffic Routine wrapped in Dual-Sided Capture
    local run_status=0
    if [[ -n "${run_fn}" ]] && declare -F "${run_fn}" >/dev/null 2>&1; then
        run_with_dual_capture "${resolved_id}" "${lan_ns}" "${bpf_filter}" "${run_fn}" || {
            run_status=$?
            log_error "Execution of scenario [${resolved_id}] failed with code ${run_status}."
        }
    else
        die "Registered run function '${run_fn}' for [${resolved_id}] is missing."
    fi

    # 6. Verification Hook (Auto-verifies upon completion)
    if [[ -n "${verify_fn}" ]] && declare -F "${verify_fn}" >/dev/null 2>&1; then
        log_info "Evaluating acceptance assertions for [${resolved_id}]..."
        "${verify_fn}" || {
            log_warn "Scenario [${resolved_id}] assertions reported failures."
        }
    fi

    # 7. Post-test Teardown Hook & Station Adapter Release
    if [[ -n "${teardown_fn}" ]] && declare -F "${teardown_fn}" >/dev/null 2>&1; then
        "${teardown_fn}"
    fi
    if declare -F station_adapter_release >/dev/null 2>&1; then
        station_adapter_release
    fi

    return "${run_status}"
}

scenario_run_all() {
    if (( ${#SCENARIO_REGISTRY_ORDER[@]} == 0 )); then
        die "No scenarios registered to execute."
    fi

    log_step "Beginning execution of complete test suite (${#SCENARIO_REGISTRY_ORDER[@]} scenarios)..."

    local total_count=0
    local pass_count=0
    local fail_count=0

    for id in "${SCENARIO_REGISTRY_ORDER[@]}"; do
        total_count=$(( total_count + 1 ))
        if scenario_run_single "${id}"; then
            pass_count=$(( pass_count + 1 ))
        else
            fail_count=$(( fail_count + 1 ))
        fi
    done

    printf '\n==================================================================\n'
    printf '  TEST SUITE EXECUTION SUMMARY\n'
    printf '==================================================================\n'
    printf '  Total Scenarios Executed : %d\n' "${total_count}"
    printf '  Passed                   : %d\n' "${pass_count}"
    printf '  Failed                   : %d\n' "${fail_count}"
    printf '==================================================================\n\n'

    if (( fail_count > 0 )); then
        return 1
    fi
    return 0
}

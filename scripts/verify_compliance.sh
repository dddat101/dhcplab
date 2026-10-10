#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - PLUGGABLE COMPLIANCE & VERIFICATION ENGINE
# Dual-layer verification: Pluggable metric assertions + Wire-level PCAP inspection
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/scenario_framework.sh
source "${SCRIPT_DIR}/lib/scenario_framework.sh"

TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

# Dynamically discover and load all scenario modules
scenario_load_all "${SCRIPT_DIR}/scenarios"

usage() {
    cat <<'EOF'
==================================================================
  Network Test Lab - Pluggable Compliance Verifier
==================================================================

Description:
  Evaluates test results against quantitative acceptance criteria:
  - Executes registered scenario verification hooks dynamically
  - Inspects evaluated JSON metrics in logs/
  - Performs dual-sided PCAP timeline inspection via tshark

Usage:
  ./scripts/verify_compliance.sh [options] [scenario_id] [pcap_file]

Options:
  -h, --help       Show this help message and exit
  --no-timeline    Skip tshark packet timeline printing
  --pcap <file>    Explicitly specify PCAP evidence capture to audit

Examples:
  ./scripts/verify_compliance.sh
  ./scripts/verify_compliance.sh template
  ./scripts/verify_compliance.sh --pcap captures/wan.pcap
==================================================================
EOF
}

check_assertion() {
    local test_id="$1"
    local title="$2"
    local status="$3"
    local detail="$4"

    TOTAL_TESTS=$(( TOTAL_TESTS + 1 ))
    if [[ "${status}" == "PASS" ]]; then
        PASSED_TESTS=$(( PASSED_TESTS + 1 ))
        printf '  \e[1;32m[PASS]\e[0m    [%s] %s\n            Detail: %s\n' "${test_id}" "${title}" "${detail}"
    elif [[ "${status}" == "INVALID" || "${status}" == "INCONCLUSIVE" ]]; then
        SKIPPED_TESTS=$(( SKIPPED_TESTS + 1 ))
        printf '  \e[1;33m[%s]\e[0m [%s] %s\n            Detail: %s\n' "${status}" "${test_id}" "${title}" "${detail}"
    elif [[ "${status}" == "NOT_RUN" || "${status}" == "SKIP" ]]; then
        SKIPPED_TESTS=$(( SKIPPED_TESTS + 1 ))
        printf '  \e[1;33m[NOT RUN]\e[0m [%s] %s\n            Detail: %s\n' "${test_id}" "${title}" "${detail}"
    else
        FAILED_TESTS=$(( FAILED_TESTS + 1 ))
        printf '  \e[1;31m[FAIL]\e[0m    [%s] %s\n            Detail: %s\n' "${test_id}" "${title}" "${detail}"
    fi
}

parse_json_field() {
    local file="$1"
    local field="$2"
    if [[ ! -f "${file}" || ! -r "${file}" ]]; then
        printf 'MISSING\n'
        return 0
    fi
    if [[ -f "${LAB_DIR}/tools/metric_parser.py" ]]; then
        "${PYTHON_BIN:-python3}" "${LAB_DIR}/tools/metric_parser.py" get-field --file "${file}" --field "${field}" --default "MISSING" 2>/dev/null || printf 'MISSING\n'
    else
        printf 'MISSING\n'
    fi
}

print_pcap_timeline() {
    local pcap_file="$1"
    if ! check_command "${TSHARK_BIN:-tshark}"; then
        log_info "tshark not installed; skipping packet timeline table."
        return 0
    fi
    if [[ ! -f "${pcap_file}" || ! -s "${pcap_file}" ]]; then
        log_warn "PCAP file is empty or missing: ${pcap_file}"
        return 0
    fi

    printf '\n========================================================================================\n'
    printf '                          PACKET TIMELINE EVIDENCE                               \n'
    printf '========================================================================================\n'
    printf '%-6s | %-12s | %-24s | %-24s | %-20s\n' "Frame" "Time (s)" "Source IP" "Destination IP" "Protocol / Info"
    printf '%s\n' "----------------------------------------------------------------------------------------"

    ( (cat "${pcap_file}" 2>/dev/null | tshark -r - \
        -T fields \
        -e frame.number -e frame.time_relative -e _ws.col.Source -e _ws.col.Destination -e _ws.col.Protocol -e _ws.col.Info 2>/dev/null | \
        awk -F '\t' '{ printf "%-6s | %-12.4f | %-24s | %-24s | %-10s %s\n", $1, $2, $3, $4, $5, $6 }') 2>/dev/null || true ) | head -n 35

    printf '========================================================================================\n\n'
}

verify_scenario_result() {
    local id="$1"
    local name="${SCENARIO_REGISTRY_NAME[${id}]:-${id}}"
    local verify_fn="${SCENARIO_REGISTRY_VERIFY_FN[${id}]:-}"
    local result_json="${LOG_DIR}/${id}_result.json"
    if [[ ! -f "${result_json}" ]]; then
        local alt_json
        alt_json="$(ls -t "${LOG_DIR}"/*"${id}"*_result.json 2>/dev/null | head -n1 || echo "")"
        if [[ -n "${alt_json}" && -f "${alt_json}" ]]; then
            result_json="${alt_json}"
        fi
    fi

    # 1. If scenario defines its own verification hook, execute it
    if [[ -n "${verify_fn}" ]] && declare -F "${verify_fn}" >/dev/null 2>&1; then
        if "${verify_fn}"; then
            check_assertion "${id}" "${name}" "PASS" "Scenario verification hook passed."
        else
            check_assertion "${id}" "${name}" "FAIL" "Scenario verification hook failed."
        fi
        return 0
    fi

    # 2. If result file is missing, report NOT_RUN
    if [[ ! -f "${result_json}" ]]; then
        check_assertion "${id}" "${name}" "NOT_RUN" "Result JSON not found: ${result_json}"
        return 0
    fi

    # 2. Otherwise check for JSON result in LOG_DIR
    if [[ -f "${result_json}" ]]; then
        local verdict
        verdict="$(parse_json_field "${result_json}" "verdict")"
        if [[ "${verdict}" == "MISSING" ]]; then
            verdict="$(parse_json_field "${result_json}" "status")"
        fi

        local details="Evaluated metrics from ${result_json}"
        if [[ "${verdict}" == "PASS" ]]; then
            check_assertion "${id}" "${name}" "PASS" "${details}"
        elif [[ "${verdict}" == "MISSING" ]]; then
            check_assertion "${id}" "${name}" "INCONCLUSIVE" "Result JSON exists but no verdict field present."
        else
            check_assertion "${id}" "${name}" "FAIL" "${details} (Verdict: ${verdict})"
        fi
    else
        check_assertion "${id}" "${name}" "NOT_RUN" "Result JSON not found: ${result_json}"
    fi
}

main() {
    local target_id=""
    local pcap_file=""
    local show_timeline=1

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --no-timeline)
                show_timeline=0
                shift
                ;;
            --pcap)
                [[ $# -ge 2 ]] || die "Option --pcap requires a file path"
                pcap_file="$2"
                shift 2
                ;;
            *)
                if [[ -z "${target_id}" ]]; then
                    local resolved
                    resolved="$(scenario_resolve "$1" || true)"
                    if [[ -n "${resolved}" ]]; then
                        target_id="${resolved}"
                    elif [[ -f "$1" ]]; then
                        pcap_file="$1"
                    else
                        target_id="$1"
                    fi
                elif [[ -z "${pcap_file}" && -f "$1" ]]; then
                    pcap_file="$1"
                fi
                shift
                ;;
        esac
    done

    load_config "${LAB_DIR}/config.env"

    if [[ -z "${pcap_file}" ]]; then
        if [[ -f "${STATE_DIR}/latest_wan_pcap.txt" ]]; then
            pcap_file="$(cat "${STATE_DIR}/latest_wan_pcap.txt" 2>/dev/null || true)"
        fi
        if [[ -z "${pcap_file}" ]]; then
            pcap_file="$(get_latest_pcap || true)"
        fi
    fi

    print_header "NETWORK TEST LAB - COMPLIANCE VERIFICATION REPORT"

    if [[ -n "${pcap_file}" && -f "${pcap_file}" ]]; then
        local pcap_size
        pcap_size="$(du -h "${pcap_file}" 2>/dev/null | cut -f1 || echo "unknown")"
        log_info "Primary Evidence Capture : ${pcap_file} (${pcap_size})"
    fi

    # Execute verification
    if [[ -n "${target_id}" ]]; then
        verify_scenario_result "${target_id}"
    elif (( ${#SCENARIO_REGISTRY_ORDER[@]} > 0 )); then
        for id in "${SCENARIO_REGISTRY_ORDER[@]}"; do
            verify_scenario_result "${id}"
        done
    else
        log_warn "No scenario modules registered in scripts/scenarios/."
    fi

    # Print PCAP timeline if available and requested
    if (( show_timeline == 1 )) && [[ -n "${pcap_file}" && -f "${pcap_file}" ]]; then
        print_pcap_timeline "${pcap_file}"
    fi

    # Print summary scoreboard
    printf '\n========================================================================================\n'
    printf '                                COMPLIANCE SCORECARD                                     \n'
    printf '========================================================================================\n'
    printf '  Total Assertions Evaluated : %d\n' "${TOTAL_TESTS}"
    printf '  Passed                     : \e[1;32m%d\e[0m\n' "${PASSED_TESTS}"
    printf '  Failed                     : \e[1;31m%d\e[0m\n' "${FAILED_TESTS}"
    printf '  Skipped / Not Run          : \e[1;33m%d\e[0m\n' "${SKIPPED_TESTS}"
    printf '========================================================================================\n\n'

    if (( FAILED_TESTS > 0 )); then
        return 1
    fi
    return 0
}

main "$@"

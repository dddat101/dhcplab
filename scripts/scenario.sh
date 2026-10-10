#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - AUTOMATED SCENARIO RUNNER & FRAMEWORK ENGINE
# Supports dynamic scenario discovery, declarative lifecycle hooks,
# dual-sided (WAN/LAN) captures, and pluggable verification integration.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck source=lib/scenario_common.sh
source "${SCRIPT_DIR}/lib/scenario_common.sh"
# shellcheck source=lib/scenario_framework.sh
source "${SCRIPT_DIR}/lib/scenario_framework.sh"

DEBUG="${DEBUG:-0}"
VERBOSE="${VERBOSE:-0}"
DRY_RUN=0
NO_CAPTURE=0
CUSTOM_DURATION=""
CUSTOM_BITRATE=""
CAPTURE_SNAPLEN="${CAPTURE_SNAPLEN:-0}"
SCENARIO_TMP_DIR=""
ACTIVE_BG_PIDS=()
ENABLE_LOG_TEE=0
CUSTOM_LOG_FILE=""
COLLECT_ARTIFACTS=0

# Backward compatibility parameters
AUTO_ADAPT_BURST_SPEED="${AUTO_ADAPT_BURST_SPEED:-1}"
ADAPTED_NIC=""
ORIGINAL_NIC_SPEED=""

# ------------------------------------------------------------------------------
# Dynamically Discover and Load Scenario Modules
# ------------------------------------------------------------------------------
scenario_load_all "${SCRIPT_DIR}/scenarios"

usage() {
    local target="${1:-}"

    if [[ -n "${target}" && "${target}" != "all" && "${target}" != "-h" && "${target}" != "--help" ]]; then
        scenario_show_help "${target}"
        return 0
    fi

    cat <<'EOF'
==================================================================
  Network Test Lab - Automated Scenario Runner & Framework Engine
==================================================================

Usage:
  sudo ./scripts/scenario.sh [OPTIONS] <SCENARIO> [SCENARIO_OPTIONS]
  ./scripts/scenario.sh list                 (List all discovered test scenarios)
  ./scripts/scenario.sh plan [SCENARIO]      (Resolve and view Execution Plan for a scenario)
  ./scripts/scenario.sh -h [SCENARIO]        (View options for a specific scenario)

Global Options (Supported across all scenarios):
  --debug, -v              Enable detailed debug logging and command tracing
  --snaplen, -s <bytes>    Packet capture snaplen in bytes (default: 96, 0 = full packet)
  --no-capture, -C         Disable background PCAP capture during test
  --duration, -d <sec>     Override test stream duration in seconds
  --bitrate, -b <rate>     Override target test bitrate (e.g. 500M, 950M, 1G)
  --wifi-mode <mode>       Override Wi-Fi mode (emulated, real_single_band, hybrid, physical)
  --collect-artifacts, -A  Bundle PCAPs, logs, JSON metrics & state into artifacts/
  --log, -l [file]         Mirror console output to log file (default: logs/scenario_*.log)
  --dry-run, -n            Dry-run mode (validate configs/parameters without traffic)
  -h, --help [scenario]    Show this help menu (or details for a specific scenario)

Suite Execution:
  sudo ./scripts/scenario.sh all             (Execute all registered scenarios in order)

EOF

    scenario_list

    cat <<'EOF'
Examples:
  ./scripts/scenario.sh list
  ./scripts/scenario.sh plan dhcpv6_stateful
  ./scripts/scenario.sh -h template
  sudo ./scripts/scenario.sh template
  sudo ./scripts/scenario.sh -b 950M -d 15 template
  sudo ./scripts/scenario.sh -C -A all
==================================================================
EOF
}

main() {
    # If no arguments provided, display help and scenario catalog
    if [[ $# -eq 0 ]]; then
        usage
        exit 0
    fi

    # Handle quick subcommands
    case "$1" in
        list)
            scenario_list
            exit 0
            ;;
        plan)
            shift
            load_config "${LAB_DIR}/config.env"
            ensure_runtime_dirs
            local target="${1:-all}"
            if declare -F orchestrator_resolve_context >/dev/null 2>&1; then
                orchestrator_resolve_context
                orchestrator_show_plan "${target}"
            fi
            exit 0
            ;;
        -h|--help)
            shift
            usage "${1:-}"
            exit 0
            ;;
    esac

    load_config "${LAB_DIR}/config.env"
    ensure_runtime_dirs

    local target_scenario=""
    local -a scenario_extra_args=()

    # Parse CLI flags
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --debug|-v|--verbose)
                DEBUG=1
                VERBOSE=1
                export DEBUG VERBOSE
                shift
                ;;
            --dry-run|-n)
                DRY_RUN=1
                shift
                ;;
            --no-capture|-C)
                NO_CAPTURE=1
                shift
                ;;
            --snaplen|-s)
                [[ $# -ge 2 ]] || die "Option --snaplen requires a length argument (e.g. 96, 128, 0)"
                CAPTURE_SNAPLEN="$2"
                shift 2
                ;;
            --duration|-d)
                [[ $# -ge 2 ]] || die "Option --duration requires a seconds argument"
                CUSTOM_DURATION="$2"
                export CUSTOM_DURATION
                shift 2
                ;;
            --bitrate|-b)
                [[ $# -ge 2 ]] || die "Option --bitrate requires a rate argument (e.g. 500M, 950M)"
                CUSTOM_BITRATE="$2"
                export CUSTOM_BITRATE
                shift 2
                ;;
            --wifi-mode)
                [[ $# -ge 2 ]] || die "Option --wifi-mode requires a mode argument (e.g. emulated, real_single_band, hybrid, physical)"
                CUSTOM_WIFI_MODE="$2"
                export CUSTOM_WIFI_MODE
                shift 2
                ;;
            --collect-artifacts|-A)
                COLLECT_ARTIFACTS=1
                shift
                ;;
            --log|-l)
                ENABLE_LOG_TEE=1
                if [[ $# -ge 2 && ! "$2" =~ ^- ]]; then
                    CUSTOM_LOG_FILE="$2"
                    shift 2
                else
                    shift
                fi
                ;;
            -h|--help)
                shift
                usage "${1:-${target_scenario}}"
                exit 0
                ;;
            list)
                scenario_list
                exit 0
                ;;
            *)
                if [[ -z "${target_scenario}" ]]; then
                    target_scenario="$1"
                else
                    scenario_extra_args+=("$1")
                fi
                shift
                ;;
        esac
    done

    [[ -n "${target_scenario}" ]] || die "No scenario specified. Run './scripts/scenario.sh list' to view scenarios."

    # Setup console mirroring if requested
    if (( ENABLE_LOG_TEE == 1 )); then
        local ts
        ts="$(date +%Y%m%d_%H%M%S)"
        local log_dest="${CUSTOM_LOG_FILE:-${LOG_DIR}/scenario_${target_scenario}_${ts}.log}"
        mkdir -p "$(dirname "${log_dest}")" 2>/dev/null || true
        touch "${log_dest}" 2>/dev/null || true
        chmod 0666 "${log_dest}" 2>/dev/null || true
        exec > >(tee -a "${log_dest}") 2>&1
        log_info "Console logging mirrored to: ${log_dest}"
    fi

    # Set up scenario workspace temp directory
    SCENARIO_TMP_DIR="$(mktemp -d -p "${LAB_DIR}/state" scn_run_XXXXXX 2>/dev/null || mktemp -d)"
    chmod 0777 "${SCENARIO_TMP_DIR}" 2>/dev/null || true

    # Arm defensive scenario trap
    trap 'cleanup_scenario_trap' EXIT INT TERM ERR

    # Execution logic: 'all' vs specific scenario
    local exit_code=0
    if [[ "${target_scenario}" == "all" ]]; then
        scenario_run_all || exit_code=$?
    else
        local resolved_id
        resolved_id="$(scenario_resolve "${target_scenario}" || true)"
        if [[ -z "${resolved_id}" ]]; then
            log_error "Unknown scenario: '${target_scenario}'"
            scenario_list
            exit 1
        fi
        scenario_run_single "${resolved_id}" "${scenario_extra_args[@]}" || exit_code=$?
    fi

    # Package artifacts if requested
    if (( COLLECT_ARTIFACTS == 1 )) && [[ -x "${SCRIPT_DIR}/collect_artifacts.sh" ]]; then
        log_step "Collecting test artifacts bundle into artifacts/..."
        "${SCRIPT_DIR}/collect_artifacts.sh" --latest || true
    fi

    return "${exit_code}"
}

main "$@"

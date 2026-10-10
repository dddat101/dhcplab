#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - TRAFFIC PROCESS SUPERVISOR
# Centralized Background Process Lifecycle, Process Registry & Clean Reaping
# ==============================================================================

# Defensive bootstrap for logging & utilities if running standalone
if ! declare -F log_info >/dev/null 2>&1; then
    log_info()    { printf '\e[1;32m[INFO]\e[0m    %s\n' "$*"; }
    log_warn()    { printf '\e[1;33m[WARN]\e[0m    %s\n' "$*" >&2; }
    log_error()   { printf '\e[1;31m[ERROR]\e[0m   %s\n' "$*" >&2; }
    log_debug()   { if [[ "${DEBUG:-0}" == "1" || "${VERBOSE:-0}" == "1" ]]; then printf '\e[1;34m[DEBUG]\e[0m   %s\n' "$*" >&2; fi; }
    log_cmd()     { if [[ "${DEBUG:-0}" == "1" || "${VERBOSE:-0}" == "1" ]]; then printf '\e[1;34m[DEBUG]\e[0m   CMD: %s\n' "$*" >&2; fi; }
fi

if ! declare -F ns_exists >/dev/null 2>&1; then
    ns_exists() {
        local ns="$1"
        [[ -n "${ns}" ]] && ip netns list 2>/dev/null | awk '{print $1}' | grep -qw -- "${ns}"
    }
fi

if ! declare -F is_root >/dev/null 2>&1; then
    is_root() { (( EUID == 0 )); }
fi

# ------------------------------------------------------------------------------
# Process Registry State
# ------------------------------------------------------------------------------
declare -A TRAFFIC_JOB_PID=()
declare -A TRAFFIC_JOB_NS=()
declare -A TRAFFIC_JOB_LOG=()
declare -A TRAFFIC_JOB_CMD=()
declare -g TRAFFIC_LAST_PID=""
declare -g TRAFFIC_LAST_JOB=""

if [[ -z "${ACTIVE_BG_PIDS+x}" ]]; then
    declare -a ACTIVE_BG_PIDS=()
fi

# ------------------------------------------------------------------------------
# Internal Helpers: PID Resolution & Unregistration
# ------------------------------------------------------------------------------
_traffic_resolve_pid() {
    local target="$1"
    if [[ -n "${target}" && -n "${TRAFFIC_JOB_PID[${target}]+x}" ]]; then
        echo "${TRAFFIC_JOB_PID[${target}]}"
    elif [[ "${target}" =~ ^[0-9]+$ ]]; then
        echo "${target}"
    else
        echo ""
    fi
}

_traffic_unregister_pids() {
    local -a pids=("$@")
    if (( ${#pids[@]} == 0 )); then
        return 0
    fi

    # 1. Remove from TRAFFIC_JOB_* maps
    for pid in "${pids[@]}"; do
        if [[ -z "${pid}" ]]; then continue; fi
        for job in "${!TRAFFIC_JOB_PID[@]}"; do
            if [[ "${TRAFFIC_JOB_PID[${job}]}" == "${pid}" ]]; then
                unset "TRAFFIC_JOB_PID[${job}]"
                unset "TRAFFIC_JOB_NS[${job}]"
                unset "TRAFFIC_JOB_LOG[${job}]"
                unset "TRAFFIC_JOB_CMD[${job}]"
            fi
        done
    done

    # 2. Prune from ACTIVE_BG_PIDS
    if (( ${#ACTIVE_BG_PIDS[@]} > 0 )); then
        local -a remaining_pids=()
        for active in "${ACTIVE_BG_PIDS[@]}"; do
            local matched=0
            for terminated in "${pids[@]}"; do
                if [[ "${active}" == "${terminated}" ]]; then
                    matched=1
                    break
                fi
            done
            if (( matched == 0 )); then
                remaining_pids+=("${active}")
            fi
        done
        if (( ${#remaining_pids[@]} > 0 )); then
            ACTIVE_BG_PIDS=("${remaining_pids[@]}")
        else
            ACTIVE_BG_PIDS=()
        fi
    fi
}

# ------------------------------------------------------------------------------
# Low-level Escalated Process Termination (TERM -> KILL -> wait)
# ------------------------------------------------------------------------------
terminate_bg_pids() {
    local -a pids=("$@")
    if (( ${#pids[@]} == 0 )); then
        return 0
    fi

    # 1. Send SIGTERM to allow graceful socket & state cleanup
    for pid in "${pids[@]}"; do
        if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" 2>/dev/null; then
            kill -TERM "${pid}" 2>/dev/null || true
        fi
    done

    # 2. Poll briefly (up to 0.6s) to allow processes to terminate cleanly
    local count=0
    while (( count < 6 )); do
        local any_alive=0
        for pid in "${pids[@]}"; do
            if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]] && kill -0 "${pid}" 2>/dev/null; then
                any_alive=1
                break
            fi
        done
        if (( any_alive == 0 )); then
            break
        fi
        sleep 0.1
        count=$(( count + 1 ))
    done

    # 3. Escalate to SIGKILL for any stubborn process and reap immediately with wait
    for pid in "${pids[@]}"; do
        if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
            if kill -0 "${pid}" 2>/dev/null; then
                kill -KILL "${pid}" 2>/dev/null || true
            fi
            # CRITICAL DEFENSIVE PATTERN: Reap child process so Bash suppresses job control "Killed" output
            wait "${pid}" 2>/dev/null || true
        fi
    done

    # 4. Synchronize ACTIVE_BG_PIDS and TRAFFIC_JOB_* maps
    _traffic_unregister_pids "${pids[@]}"
}

# ------------------------------------------------------------------------------
# High-leverage Orchestrator APIs
# ------------------------------------------------------------------------------

# Launch command in background with automatic PID registration and namespace fallback
# Usage: traffic_run_bg [--job <id>] [--netns <ns>] [--out <logfile>] [--append] [--check] <cmd...>
traffic_run_bg() {
    local job_id=""
    local ns=""
    local out_file="/dev/null"
    local append=0
    local check_alive=0

    while (( $# > 0 )); do
        case "$1" in
            --job)
                job_id="$2"
                shift 2
                ;;
            --netns)
                ns="$2"
                shift 2
                ;;
            --out)
                out_file="$2"
                shift 2
                ;;
            --append)
                append=1
                shift 1
                ;;
            --check)
                check_alive=1
                shift 1
                ;;
            --)
                shift
                break
                ;;
            *)
                break
                ;;
        esac
    done

    if (( $# == 0 )); then
        log_error "traffic_run_bg: No command specified."
        return 1
    fi

    local cmd=("$@")

    # Ensure parent log directory exists
    if [[ "${out_file}" != "/dev/null" ]]; then
        local out_dir
        out_dir="$(dirname "${out_file}")"
        if [[ ! -d "${out_dir}" ]]; then
            mkdir -p "${out_dir}" 2>/dev/null || true
        fi
    fi

    # Determine command execution context (netns vs host fallback)
    local -a run_cmd=()
    if [[ -n "${ns}" ]] && ns_exists "${ns}" && is_root; then
        run_cmd=(ip netns exec "${ns}" "${cmd[@]}")
    else
        if [[ -n "${ns}" ]]; then
            log_debug "traffic_run_bg: Netns '${ns}' not active or unprivileged; executing on host"
        fi
        run_cmd=("${cmd[@]}")
    fi

    if (( append == 1 )); then
        log_cmd "${run_cmd[*]} >> ${out_file} 2>&1 &"
        "${run_cmd[@]}" >> "${out_file}" 2>&1 &
    else
        log_cmd "${run_cmd[*]} > ${out_file} 2>&1 &"
        "${run_cmd[@]}" > "${out_file}" 2>&1 &
    fi

    local pid=$!
    TRAFFIC_LAST_PID="${pid}"
    local effective_job="${job_id:-${pid}}"
    TRAFFIC_LAST_JOB="${effective_job}"

    TRAFFIC_JOB_PID["${effective_job}"]="${pid}"
    TRAFFIC_JOB_NS["${effective_job}"]="${ns:-host}"
    TRAFFIC_JOB_LOG["${effective_job}"]="${out_file}"
    TRAFFIC_JOB_CMD["${effective_job}"]="${cmd[*]}"

    ACTIVE_BG_PIDS+=("${pid}")

    if (( check_alive == 1 )); then
        sleep 0.05
        if ! kill -0 "${pid}" 2>/dev/null; then
            log_warn "traffic_run_bg: Process for job '${effective_job}' (PID ${pid}) exited prematurely!"
            return 1
        fi
    fi

    return 0
}

# Convenience wrapper matching framework specification
# Usage: orchestrator_start_ns_bg <job_id> <netns> <stdout_log> [stderr_log] <cmd...>
orchestrator_start_ns_bg() {
    local job_id="$1"
    local ns="$2"
    local stdout_log="$3"
    shift 3
    if [[ $# -gt 0 && ( "$1" == *.log || "$1" == /dev/null || "$1" == *err* ) ]]; then
        shift 1
    fi
    traffic_run_bg --job "${job_id}" --netns "${ns}" --out "${stdout_log}" "$@"
}

# Start background server daemon with optional port readiness polling
# Usage: traffic_start_server [--job <id>] [--netns <ns>] [--port <port>] [--out <logfile>] [--ready-timeout <sec>] <cmd...>
traffic_start_server() {
    local port=""
    local ready_timeout=2
    local -a passthrough_args=()

    while (( $# > 0 )); do
        case "$1" in
            --port)
                port="$2"
                shift 2
                ;;
            --ready-timeout)
                ready_timeout="$2"
                shift 2
                ;;
            --job|--netns|--out)
                passthrough_args+=("$1" "$2")
                shift 2
                ;;
            --append|--check)
                passthrough_args+=("$1")
                shift 1
                ;;
            --)
                shift
                break
                ;;
            *)
                break
                ;;
        esac
    done

    traffic_run_bg "${passthrough_args[@]}" "$@"

    if [[ -n "${port}" ]]; then
        if declare -F wait_for_port >/dev/null 2>&1; then
            local ns="${TRAFFIC_JOB_NS[${TRAFFIC_LAST_JOB}]:-}"
            if [[ "${ns}" == "host" ]]; then ns=""; fi
            wait_for_port "${port}" "127.0.0.1" "${ready_timeout}" "${ns}" || log_warn "Server on port ${port} did not respond within ${ready_timeout}s"
        else
            sleep 0.2
        fi
    else
        sleep 0.1
    fi
}

# Wait for one or more jobs with optional defensive timeout and automatic child reaping
# Usage: traffic_wait_all [--timeout <sec>] [--strict] <job_ids_or_pids...>
traffic_wait_all() {
    local timeout=0
    local strict=0

    while (( $# > 0 )); do
        case "$1" in
            --timeout)
                timeout="$2"
                shift 2
                ;;
            --strict)
                strict=1
                shift 1
                ;;
            *)
                break
                ;;
        esac
    done

    local -a targets=("$@")
    if (( ${#targets[@]} == 0 )); then
        return 0
    fi

    local -a pids=()
    for t in "${targets[@]}"; do
        local p
        p="$(_traffic_resolve_pid "${t}")"
        if [[ -n "${p}" ]]; then
            pids+=("${p}")
        fi
    done

    if (( ${#pids[@]} == 0 )); then
        return 0
    fi

    local timed_out=0
    if (( timeout > 0 )); then
        local start_ts
        start_ts=$(date +%s)
        while true; do
            local all_done=1
            for p in "${pids[@]}"; do
                if kill -0 "${p}" 2>/dev/null; then
                    all_done=0
                    break
                fi
            done
            if (( all_done == 1 )); then
                break
            fi
            local now_ts
            now_ts=$(date +%s)
            if (( now_ts - start_ts >= timeout )); then
                timed_out=1
                break
            fi
            sleep 0.1
        done
    fi

    if (( timed_out == 1 )); then
        local -a lingering=()
        for p in "${pids[@]}"; do
            if kill -0 "${p}" 2>/dev/null; then
                lingering+=("${p}")
            fi
        done
        if (( ${#lingering[@]} > 0 )); then
            log_warn "traffic_wait_all: Timeout (${timeout}s) exceeded. Escalating termination for lingering PIDs: ${lingering[*]}"
            terminate_bg_pids "${lingering[@]}"
        fi
    fi

    # Defensively reap all PIDs to suppress Bash job control "Killed" leakage
    local wait_exit=0
    for p in "${pids[@]}"; do
        wait "${p}" 2>/dev/null || wait_exit=$?
    done

    # Clean up from registry & ACTIVE_BG_PIDS
    _traffic_unregister_pids "${pids[@]}"

    TRAFFIC_LAST_EXIT="${wait_exit}"

    if (( timed_out == 1 )); then
        return 124
    fi

    if (( strict == 1 )); then
        return "${wait_exit}"
    fi

    return 0
}

# Stop group of jobs or PIDs with graceful escalation (TERM -> KILL)
# Usage: traffic_stop_group <job_ids_or_pids...>
traffic_stop_group() {
    local -a targets=("$@")
    if (( ${#targets[@]} == 0 )); then
        return 0
    fi

    local -a pids=()
    for t in "${targets[@]}"; do
        local p
        p="$(_traffic_resolve_pid "${t}")"
        if [[ -n "${p}" ]]; then
            pids+=("${p}")
        fi
    done

    if (( ${#pids[@]} > 0 )); then
        terminate_bg_pids "${pids[@]}"
        _traffic_unregister_pids "${pids[@]}"
    fi
    return 0
}

# Clean stale lingering processes matching a pattern across lab namespaces or host
# Defensively excludes current shell ($$ and $BASHPID) to avoid self-termination
# Usage: traffic_clean_stale [--netns <ns>] <process_pattern>
traffic_clean_stale() {
    local ns=""
    if [[ "${1:-}" == "--netns" ]]; then
        ns="$2"
        shift 2
    fi
    local pattern="${1:-}"
    if [[ -z "${pattern}" ]]; then
        return 0
    fi

    if [[ -n "${ns}" ]]; then
        if ns_exists "${ns}"; then
            ip netns exec "${ns}" pkill -TERM -x "${pattern}" 2>/dev/null || ip netns exec "${ns}" pkill -TERM -f "${pattern}" 2>/dev/null || true
        else
            _traffic_clean_host_stale "${pattern}"
        fi
    else
        # Clean across standard lab namespaces
        for test_ns in "${WAN_NS:-ns-wan}" "${STB_NS:-ns-stb}" "${PC_NS:-ns-pc}" "${DUT_NS:-ns-dut}" "${WLAN2G_NS:-ns-wlan2g}" "${WLAN5G_NS:-ns-wlan5g}" "${WLAN6G_NS:-ns-wlan6g}"; do
            if ns_exists "${test_ns}"; then
                ip netns exec "${test_ns}" pkill -TERM -x "${pattern}" 2>/dev/null || ip netns exec "${test_ns}" pkill -TERM -f "${pattern}" 2>/dev/null || true
            fi
        done
        _traffic_clean_host_stale "${pattern}"
    fi
}

_traffic_clean_host_stale() {
    local pattern="$1"
    local curr_pid="$$"
    local bash_pid="${BASHPID:-$$}"
    local pids_raw
    pids_raw=$(pgrep -x "${pattern}" 2>/dev/null || pgrep -f "${pattern}" 2>/dev/null || true)
    if [[ -z "${pids_raw}" ]]; then
        return 0
    fi

    local -a safe_pids=()
    while IFS= read -r pid; do
        if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ && "${pid}" != "${curr_pid}" && "${pid}" != "${bash_pid}" ]]; then
            safe_pids+=("${pid}")
        fi
    done <<< "${pids_raw}"

    if (( ${#safe_pids[@]} > 0 )); then
        kill -TERM "${safe_pids[@]}" 2>/dev/null || true
    fi
}

# Query PID associated with a symbolic job name
traffic_get_pid() {
    local target="$1"
    _traffic_resolve_pid "${target}"
}

# Query execution status of a job (RUNNING, TERMINATED, or NOT_FOUND)
traffic_get_status() {
    local target="$1"
    local pid
    pid="$(_traffic_resolve_pid "${target}")"
    if [[ -z "${pid}" ]]; then
        echo "NOT_FOUND"
        return 1
    fi
    if kill -0 "${pid}" 2>/dev/null; then
        echo "RUNNING"
        return 0
    else
        echo "TERMINATED"
        return 0
    fi
}

# Reset process registry state (useful in test suites and scenario boundaries)
traffic_reset_registry() {
    TRAFFIC_JOB_PID=()
    TRAFFIC_JOB_NS=()
    TRAFFIC_JOB_LOG=()
    TRAFFIC_JOB_CMD=()
    TRAFFIC_LAST_PID=""
    TRAFFIC_LAST_JOB=""
}

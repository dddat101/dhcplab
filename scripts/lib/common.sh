#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - PRODUCTION COMMON HELPER LIBRARY
# Reusable utilities for lifecycle, namespaces, socket polling & network safety
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

# Guard against duplicate inclusion
if [[ -n "${_NWLAB_COMMON_LIB_LOADED:-}" ]]; then
    return 0
fi
readonly _NWLAB_COMMON_LIB_LOADED=1

readonly SCRIPT_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROJECT_ROOT="$(cd -- "${SCRIPT_LIB_DIR}/../.." && pwd -P)"
readonly CONFIG_FILE="${PROJECT_ROOT}/config.env"
readonly LOG_TAG="LAB-FRAMEWORK"

# 1. Logging & Terminal Output
# Formats timestamp string (e.g. 2026-10-10 17:15:00)
# Centralized dedicated function to maintain and customize time format cleanly.
format_log_time() {
    local fmt="${1:-${LOG_TIME_FORMAT:-%Y-%m-%d %H:%M:%S}}"
    printf "%(${fmt})T" -1 2>/dev/null || date "+${fmt}"
}

# Prefix helper incorporating the formatted timestamp [YYYY-MM-DD HH:MM:SS]
log_time() {
    if [[ "${LOG_TIME_ENABLE:-1}" == "0" || "${NO_LOG_TIME:-0}" == "1" ]]; then
        return 0
    fi
    printf '[%s] ' "$(format_log_time "$@")"
}

log_info()    { printf '%s\e[1;32m[INFO]\e[0m    %s\n' "$(log_time)" "$*"; }
log_success() { printf '%s\e[1;32m[PASS]\e[0m    %s\n' "$(log_time)" "$*"; }
log_pass()    { log_success "$*"; }
log_warn()    { printf '%s\e[1;33m[WARN]\e[0m    %s\n' "$(log_time)" "$*" >&2; }
log_error()   { printf '%s\e[1;31m[ERROR]\e[0m   %s\n' "$(log_time)" "$*" >&2; }
log_step()    { printf '%s\e[1;36m===> %s\e[0m\n' "$(log_time)" "$*"; }
die()         { log_error "$*"; exit 1; }
fatal()       { die "$@"; }

log_debug() {
    if [[ "${DEBUG:-0}" == "1" || "${VERBOSE:-0}" == "1" ]]; then
        printf '%s\e[1;34m[DEBUG]\e[0m   %s\n' "$(log_time)" "$*" >&2
    fi
}

log_cmd() {
    if [[ "${DEBUG:-0}" == "1" || "${VERBOSE:-0}" == "1" ]]; then
        local IFS=' '
        printf '%s\e[1;34m[DEBUG]\e[0m   CMD: %s\n' "$(log_time)" "$*" >&2
    fi
}

run_cmd() {
    log_cmd "$*"
    "$@"
}

print_header() {
    local title="$1"
    printf '==================================================================\n'
    printf '  %s\n' "${title}"
    printf '==================================================================\n'
}

print_section() {
    local section="$1"
    printf '\n--- [%s] ---\n' "${section}"
}

# 2. Privileges & Tool Availability
require_root() {
    if (( EUID != 0 )); then
        die "This command requires root/sudo privileges. Please run with sudo."
    fi
}
is_root() { (( EUID == 0 )); }

require_command() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        die "Required command is not installed: ${cmd}"
    fi
}
require_cmd() { require_command "$@"; }

check_command() {
    local cmd="$1"
    command -v "${cmd}" >/dev/null 2>&1
}

# 3. Config & Runtime Dirs
load_config() {
    local config_path="${1:-${CONFIG_FILE}}"
    if [[ ! -f "${config_path}" ]]; then
        if [[ -f "${PROJECT_ROOT}/config.env.example" ]]; then
            log_warn "config.env not found. Auto-generating from config.env.example..."
            cp "${PROJECT_ROOT}/config.env.example" "${config_path}"
        else
            die "Missing configuration file: ${config_path}. Create it from config.env.example."
        fi
    fi

    # shellcheck disable=SC1090
    source "${config_path}"

    # Defaults
    : "${LAB_ROLE:=single}"
    : "${TOPOLOGY_MODE:=virtual}"
    : "${RESTORE_INTERFACES_ON_CLEANUP:=1}"
    : "${CAPTURE_DIR:=${PROJECT_ROOT}/captures}"
    : "${LOG_DIR:=${PROJECT_ROOT}/logs}"
    : "${STATE_DIR:=${PROJECT_ROOT}/state}"
    : "${NS_IF:=eth-wan}"
    : "${LOG_TIME_FORMAT:=%Y-%m-%d %H:%M:%S}"
    : "${LOG_TIME_ENABLE:=1}"

    # Auto-detect Python Virtualenv
    if [[ -z "${PYTHON_BIN:-}" ]]; then
        if [[ -x "${PROJECT_ROOT}/.venv/bin/python3" ]]; then
            PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python3"
        else
            PYTHON_BIN="python3"
        fi
    fi

    if [[ "${CAPTURE_DIR}" != /* ]]; then CAPTURE_DIR="${PROJECT_ROOT}/${CAPTURE_DIR}"; fi
    if [[ "${LOG_DIR}" != /* ]]; then LOG_DIR="${PROJECT_ROOT}/${LOG_DIR}"; fi
    if [[ "${STATE_DIR}" != /* ]]; then STATE_DIR="${PROJECT_ROOT}/${STATE_DIR}"; fi

    # Sourcing active runtime topology state if established
    if [[ -f "${STATE_DIR}/topology_state.env" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_DIR}/topology_state.env"
    fi

    ensure_runtime_dirs
}

ensure_runtime_dirs() {
    : "${CAPTURE_DIR:=${PROJECT_ROOT}/captures}"
    : "${LOG_DIR:=${PROJECT_ROOT}/logs}"
    : "${STATE_DIR:=${PROJECT_ROOT}/state}"
    install -d -m 0777 "${CAPTURE_DIR}" "${LOG_DIR}" "${STATE_DIR}"
    chmod 0777 "${CAPTURE_DIR}" "${LOG_DIR}" "${STATE_DIR}" 2>/dev/null || true
    chmod -R a+rw "${CAPTURE_DIR}" "${LOG_DIR}" "${STATE_DIR}" 2>/dev/null || true
}

init_runtime_dirs() {
    ensure_runtime_dirs "$@"
}

clean_logs() {
    ensure_runtime_dirs
    log_info "Cleaning log files in ${LOG_DIR}..."
    find "${LOG_DIR}" -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
    log_info "Logs directory cleaned."
}

clean_captures() {
    ensure_runtime_dirs
    log_info "Cleaning PCAP capture files in ${CAPTURE_DIR}..."
    find "${CAPTURE_DIR}" -mindepth 1 ! -name '.gitkeep' -delete 2>/dev/null || true
    rm -f "${STATE_DIR}/last_capture.env" "${STATE_DIR}/latest_capture.txt" 2>/dev/null || true
    log_info "Captures directory cleaned."
}

# 4. Network Safety & Namespaces
iface_exists_root() { ip link show dev "$1" >/dev/null 2>&1; }
iface_exists_ns()   { ip netns exec "$1" ip link show dev "$2" >/dev/null 2>&1; }
ns_exists()         { ip netns list 2>/dev/null | awk '{print $1}' | grep -Fxq "$1"; }
bridge_exists()     { ip link show dev "$1" >/dev/null 2>&1; }

get_host_primary_uplink() {
    local primary=""
    primary="$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' || true)"
    if [[ -z "${primary}" ]]; then
        primary="$(ip -4 route show default 2>/dev/null | sort -k7 -n | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' | head -n1 || true)"
    fi
    echo "${primary}"
}

assert_safe_test_if() {
    local iface="$1"
    [[ -n "${iface}" ]] || die "Interface name cannot be empty."
    [[ "${iface}" != "lo" ]] || die "Refusing to use loopback interface."
    iface_exists_root "${iface}" || die "Interface not found in root namespace: ${iface}"

    # Protect host primary default route (active uplink)
    local primary_uplink
    primary_uplink="$(get_host_primary_uplink)"
    if [[ -n "${primary_uplink}" && "${iface}" == "${primary_uplink}" ]]; then
        die "Interface ${iface} is the host primary internet interface! Refusing to use primary uplink."
    fi

    # NetworkManager smart unmanage & flush
    if ip -4 addr show dev "${iface}" 2>/dev/null | grep -q 'inet ' || ip route show default 2>/dev/null | grep -Eq "dev[[:space:]]+${iface}([[:space:]]|$)"; then
        log_warn "Interface ${iface} has host IPv4 address or route. Flushing and setting unmanaged..."
        command -v nmcli >/dev/null 2>&1 && nmcli device set "${iface}" managed no 2>/dev/null || true
        ip route del default dev "${iface}" 2>/dev/null || true
        ip addr flush dev "${iface}" 2>/dev/null || true
    fi
}

unmanage_interface() {
    local iface="$1"
    [[ -n "${iface}" ]] || return 0
    require_root
    assert_safe_test_if "${iface}"
    log_info "Unmanaging test interface ${iface} from NetworkManager..."
    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "${iface}" managed no 2>/dev/null || true
    fi
    ip route del default dev "${iface}" 2>/dev/null || true
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" down 2>/dev/null || true
}

namespace_ip() {
    local ns="${1:-ns-wan}"
    local iface="${2:-${NS_IF:-eth-wan}}"
    if ns_exists "${ns}"; then
        (ip netns exec "${ns}" ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    else
        (ip -4 -o addr show dev "${iface}" 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    fi
}

namespace_mac() {
    local ns="${1:-ns-wan}"
    local iface="${2:-${NS_IF:-eth-wan}}"
    if ns_exists "${ns}"; then
        (ip netns exec "${ns}" cat "/sys/class/net/${iface}/address" 2>/dev/null || true) | head -n1 || echo ""
    else
        (cat "/sys/class/net/${iface}/address" 2>/dev/null || true) | head -n1 || echo ""
    fi
}

exec_in_ns() {
    local ns="$1"
    shift
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        ip netns exec "${ns}" "$@"
    else
        "$@"
    fi
}

is_ip_reachable() {
    local target="$1"
    local timeout="${2:-1}"
    local ns="${3:-}"
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        ip netns exec "${ns}" ping -c 1 -W "${timeout}" "${target}" >/dev/null 2>&1
    else
        ping -c 1 -W "${timeout}" "${target}" >/dev/null 2>&1
    fi
}

wait_for_ping() {
    local target="$1"
    local timeout="${2:-10}"
    local ns="${3:-}"
    local elapsed=0
    while ! is_ip_reachable "${target}" 1 "${ns}"; do
        sleep 1
        elapsed=$((elapsed + 1))
        if (( elapsed >= timeout )); then
            log_warn "Timeout waiting for ping response from ${target} after ${timeout}s"
            return 1
        fi
    done
    return 0
}

# 5. Bridges & Interface Recovery
bridge_create() {
    local bridge="$1"
    if ! bridge_exists "${bridge}"; then
        ip link add name "${bridge}" type bridge
    fi
    ip addr flush dev "${bridge}" 2>/dev/null || true
    sysctl -q -w "net.ipv6.conf.${bridge}.disable_ipv6=1" 2>/dev/null || true
    ip link set dev "${bridge}" type bridge stp_state 0 mcast_snooping 0 2>/dev/null || true
    ip link set dev "${bridge}" up
}

attach_physical_to_bridge() {
    local iface="$1"
    local bridge="$2"
    assert_safe_test_if "${iface}"
    command -v nmcli >/dev/null 2>&1 && nmcli device set "${iface}" managed no 2>/dev/null || true
    ip link set dev "${iface}" down
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" master "${bridge}"
    ip link set dev "${iface}" up
}

restore_physical_interface() {
    local iface="$1"
    require_root
    [[ -n "${iface}" ]] || return 0
    iface_exists_root "${iface}" || return 0

    log_info "Restoring interface ${iface} to UP state with DHCP..."
    ip link set dev "${iface}" nomaster 2>/dev/null || true
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" up

    if command -v nmcli >/dev/null 2>&1; then
        nmcli device set "${iface}" managed yes 2>/dev/null || true
        nmcli device set "${iface}" autoconnect yes 2>/dev/null || true
        nmcli device connect "${iface}" >/dev/null 2>&1 || true
    fi

    if ip link show dev "${iface}" 2>/dev/null | grep -q "LOWER_UP"; then
        local got_ip=0
        for (( i=0; i<4; i++ )); do
            if ip -4 -o addr show dev "${iface}" 2>/dev/null | grep -q 'inet '; then
                got_ip=1; break
            fi
            sleep 0.5
        done
        if (( got_ip == 0 )) && command -v dhclient >/dev/null 2>&1; then
            dhclient -4 -nw "${iface}" 2>/dev/null || true
        fi
    fi
}

tear_down_physical_interface() {
    local iface="$1"
    require_root
    [[ -n "${iface}" ]] || return 0
    iface_exists_root "${iface}" || return 0
    command -v dhclient >/dev/null 2>&1 && dhclient -x "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" nomaster 2>/dev/null || true
    ip addr flush dev "${iface}" 2>/dev/null || true
    ip link set dev "${iface}" down 2>/dev/null || true
    command -v nmcli >/dev/null 2>&1 && nmcli device set "${iface}" managed yes 2>/dev/null || true
}

cleanup_bridge_and_nic() {
    local bridge="$1"
    local iface="${2:-}"
    local restore="${3:-${RESTORE_INTERFACES_ON_CLEANUP:-1}}"

    if [[ -n "${iface}" ]] && iface_exists_root "${iface}"; then
        if (( restore == 1 )); then
            restore_physical_interface "${iface}"
        else
            tear_down_physical_interface "${iface}"
        fi
    fi
    if bridge_exists "${bridge}"; then
        ip link set dev "${bridge}" down 2>/dev/null || true
        ip link del dev "${bridge}" 2>/dev/null || true
    fi
}

ns_create() {
    local ns="$1"
    if ! ns_exists "${ns}"; then ip netns add "${ns}"; fi
    ip -n "${ns}" link set lo up
}

create_veth_to_ns() {
    local ns="$1" host_if="$2" ns_if="$3" bridge="$4" cidr="$5" gateway="${6:-}"
    ns_create "${ns}"
    if ! iface_exists_ns "${ns}" "${ns_if}"; then
        ip link del dev "${host_if}" 2>/dev/null || true
        ip link add "${host_if}" type veth peer name "${ns_if}" netns "${ns}"
    fi
    ip link set dev "${host_if}" master "${bridge}"
    ip link set dev "${host_if}" up
    ip -n "${ns}" link set dev "${ns_if}" up
    ip -n "${ns}" -4 addr flush dev "${ns_if}" 2>/dev/null || true
    ip -n "${ns}" addr add "${cidr}" dev "${ns_if}"
    if [[ -n "${gateway}" ]]; then
        ip -n "${ns}" route replace default via "${gateway}" dev "${ns_if}" 2>/dev/null || true
    fi
}

# 6. Upstream WAN Services & DHCP Management (Delegated to scripts/wan_server.sh)

wait_for_ipv6_dad() {
    local ns="${1:-}"
    local iface="${2:-eth0}"
    local max_wait="${3:-5}"
    local prefix=()
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        prefix=("ip" "netns" "exec" "${ns}")
    fi

    local i
    for (( i=0; i<max_wait*10; i++ )); do
        if ! "${prefix[@]}" ip -6 addr show dev "${iface}" 2>/dev/null | grep -q "tentative"; then
            return 0
        fi
        sleep 0.1
    done
    return 0
}

namespace_ipv6() {
    local ns="${1:-ns-wan}"
    local iface="${2:-eth0}"
    if ns_exists "${ns}"; then
        (ip netns exec "${ns}" ip -6 -o addr show dev "${iface}" scope global 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    else
        (ip -6 -o addr show dev "${iface}" scope global 2>/dev/null || true) | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo ""
    fi
}

wan_dhcp_server() {
    local script="${PROJECT_ROOT}/scripts/wan_server.sh"
    if [[ -x "${script}" ]]; then
        "${script}" "$@"
    else
        log_warn "wan_server.sh not found at ${script}"
        return 1
    fi
}


# 7. Process & Daemon Management
is_pidfile_running() {
    local pidfile="$1" pid=""
    if [[ ! -f "${pidfile}" ]]; then return 1; fi
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -z "${pid}" || "${pid}" =~ [^0-9] ]]; then return 1; fi
    kill -0 "${pid}" 2>/dev/null || [[ -d "/proc/${pid}" ]]
}

start_daemon() {
    local pid_file="$1" log_file="$2" service_name="$3" exec_ns="${4:-}"
    shift 4 || true
    local cmd=("$@")

    if is_pidfile_running "${pid_file}"; then
        log_warn "${service_name} is already running (PID: $(cat "${pid_file}"))."
        return 0
    fi
    log_info "Starting ${service_name}..."
    local prefix=()
    if [[ -n "${exec_ns}" ]] && ns_exists "${exec_ns}"; then
        prefix=("ip" "netns" "exec" "${exec_ns}")
    fi
    "${prefix[@]}" nohup "${cmd[@]}" > "${log_file}" 2>&1 &
    local daemon_pid=$!
    echo "${daemon_pid}" > "${pid_file}"
    chmod 0666 "${pid_file}" "${log_file}" 2>/dev/null || true
    sleep 0.2
    if kill -0 "${daemon_pid}" 2>/dev/null; then
        log_info "${service_name} running (PID: ${daemon_pid}, Log: ${log_file})"
        return 0
    else
        log_error "Failed to start ${service_name}! Check log: ${log_file}"
        return 1
    fi
}

stop_pidfile() {
    local pidfile="$1" name="${2:-process}" pid="" attempt
    if [[ ! -f "${pidfile}" ]]; then return 0; fi
    pid="$(cat "${pidfile}" 2>/dev/null || true)"
    if [[ -n "${pid}" && "${pid}" =~ ^[0-9]+$ ]]; then
        if kill -0 "${pid}" 2>/dev/null; then
            log_info "Stopping ${name} (PID: ${pid})..."
            kill -INT "${pid}" 2>/dev/null || kill -TERM "${pid}" 2>/dev/null || true
            for attempt in {1..15}; do
                if ! kill -0 "${pid}" 2>/dev/null; then break; fi
                sleep 0.1
            done
            if kill -0 "${pid}" 2>/dev/null; then kill -9 "${pid}" 2>/dev/null || true; fi
            log_info "${name} stopped."
        fi
    fi
    rm -f "${pidfile}"
}

stop_process_by_pattern() {
    local pattern="$1" name="${2:-processes matching '${pattern}'}"
    if pgrep -f "${pattern}" >/dev/null 2>&1; then
        log_info "Terminating ${name}..."
        pkill -INT -f "${pattern}" 2>/dev/null || true
        sleep 0.3
        pgrep -f "${pattern}" >/dev/null 2>&1 && pkill -TERM -f "${pattern}" 2>/dev/null || true
        sleep 0.5
        pgrep -f "${pattern}" >/dev/null 2>&1 && pkill -9 -f "${pattern}" 2>/dev/null || true
    fi
}

# 7. Socket & Port Synchronization
is_port_listening() {
    local port="$1" host="${2:-127.0.0.1}" ns="${3:-}"

    # Try passive ss check first to avoid disrupting one-off servers
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        if ip netns exec "${ns}" ss -H -lutn "sport = :${port}" 2>/dev/null | grep -qw -- "${port}"; then
            return 0
        fi
        ip netns exec "${ns}" bash -c "timeout 0.5 bash -c '(echo >/dev/tcp/${host}/${port}) 2>/dev/null'" 2>/dev/null
    else
        if [[ "${host}" == "127.0.0.1" || "${host}" == "localhost" || "${host}" == "::1" ]]; then
            if ss -H -lutn "sport = :${port}" 2>/dev/null | grep -qw -- "${port}"; then
                return 0
            fi
        fi
        bash -c "timeout 0.5 bash -c '(echo >/dev/tcp/${host}/${port}) 2>/dev/null'" 2>/dev/null
    fi
}

wait_for_port() {
    local port="$1" host="${2:-127.0.0.1}" timeout="${3:-10}" ns="${4:-}" elapsed=0
    while ! is_port_listening "${port}" "${host}" "${ns}"; do
        sleep 0.5
        elapsed=$((elapsed + 1))
        if (( elapsed >= timeout * 2 )); then
            log_warn "Timeout waiting for port ${port} on ${host} after ${timeout}s"
            return 1
        fi
    done
    return 0
}

wait_for_http() {
    local url="$1" expected_code="${2:-200}" timeout="${3:-10}" ns="${4:-}" elapsed=0
    local curl_cmd=("curl" "-sk" "-o" "/dev/null" "-w" "%{http_code}" "--max-time" "1" "${url}")
    if [[ -n "${ns}" ]] && ns_exists "${ns}"; then
        curl_cmd=("ip" "netns" "exec" "${ns}" "${curl_cmd[@]}")
    fi
    while true; do
        local code
        code="$("${curl_cmd[@]}" 2>/dev/null || echo "000")"
        if [[ "${code}" == "${expected_code}" || ("${expected_code}" == "any" && "${code}" != "000") ]]; then return 0; fi
        sleep 0.5
        elapsed=$((elapsed + 1))
        if (( elapsed >= timeout * 2 )); then
            log_warn "Timeout waiting for HTTP URL ${url} (code: ${code}) after ${timeout}s"
            return 1
        fi
    done
}

# 8. DUT SSH Command Execution
run_dut_cmd() {
    local cmd="$1" timeout="${2:-10}"
    if [[ -z "${DUT_SSH_HOST:-}" || -z "${cmd}" ]]; then return 0; fi
    require_command ssh
    local ssh_opts=(-o ConnectTimeout="${timeout}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR)
    [[ -n "${DUT_SSH_PORT:-}" ]] && ssh_opts+=(-p "${DUT_SSH_PORT}")
    [[ -n "${DUT_SSH_KEY:-}" && -f "${DUT_SSH_KEY}" ]] && ssh_opts+=(-i "${DUT_SSH_KEY}")
    ssh "${ssh_opts[@]}" "${DUT_SSH_USER:-root}@${DUT_SSH_HOST}" "${cmd}"
}
is_dut_ssh_ready() {
    [[ -z "${DUT_SSH_HOST:-}" ]] && return 1
    run_dut_cmd "echo ok" 3 >/dev/null 2>&1
}

# 9. PCAP & Certificate Utilities
get_latest_pcap() {
    if [[ -f "${STATE_DIR}/last_capture.env" ]]; then
        local pcap_from_env
        pcap_from_env="$(grep '^LAST_PCAP=' "${STATE_DIR}/last_capture.env" 2>/dev/null | cut -d= -f2- | tr -d "'\"" || true)"
        if [[ -n "${pcap_from_env}" && -f "${pcap_from_env}" ]]; then
            printf '%s\n' "${pcap_from_env}"; return 0
        fi
    fi
    if [[ -d "${CAPTURE_DIR}" ]]; then
        local newest
        newest="$( (find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | awk '{print $2}') || true)"
        if [[ -n "${newest}" && -f "${newest}" ]]; then
            printf '%s\n' "${newest}"; return 0
        fi
    fi
    return 1
}

format_bytes() {
    local bytes="${1:-0}"
    bytes="${bytes//[^0-9]/}"
    [[ -n "${bytes}" ]] || bytes=0
    if (( bytes < 1024 )); then printf '%d B' "${bytes}"
    elif (( bytes < 1048576 )); then printf '%.1f KB' "$((bytes * 10 / 1024))e-1"
    elif (( bytes < 1073741824 )); then printf '%.1f MB' "$((bytes * 10 / 1048576))e-1"
    else printf '%.1f GB' "$((bytes * 10 / 1073741824))e-1"; fi
}

detect_tshark_field() {
    local fields_cache="$1"; shift; local candidate
    for candidate in "$@"; do
        if grep -Fxq "${candidate}" <<< "${fields_cache}"; then
            printf '%s\n' "${candidate}"; return 0
        fi
    done
    return 1
}

validate_cert_expiry() {
    local cert_file="$1" days_check="${2:-7}"
    [[ -f "${cert_file}" ]] || return 1
    require_command openssl
    local seconds=$(( days_check * 86400 ))
    openssl x509 -checkend "${seconds}" -noout -in "${cert_file}" >/dev/null 2>&1
}

# 10. Atomic State Persistence Utility
write_state_env() {
    local target_file="$1"; shift
    local temp_file="${target_file}.tmp.$$"
    mkdir -p "$(dirname "${target_file}")"

    {
        for item in "$@"; do
            local key="${item%%=*}"
            local val="${item#*=}"
            printf '%s="%s"\n' "${key}" "${val}"
        done
    } > "${temp_file}"

    chmod 0666 "${temp_file}" 2>/dev/null || true
    mv -f "${temp_file}" "${target_file}"
}

# 11. BPF to Wireshark Display Filter Converter
bpf_to_display_filter() {
    local f="${1:-}"
    if [[ -z "${f}" ]]; then
        return 0
    fi
    # Always normalize BPF 'icmp6' to Wireshark 'icmpv6'
    f="$(sed -E 's/\bicmp6\b/icmpv6/g' <<< "${f}")"

    # If already a Wireshark display filter (contains field dots, or comparison operators)
    if [[ "${f}" =~ (\.(port|addr|dst|src|proto|len)|==|!=|<=|>=) ]]; then
        printf '%s' "${f}"
        return 0
    fi

    # 1. 'udp port <N>' or 'tcp port <N>' -> 'udp.port == <N>' or 'tcp.port == <N>'
    f="$(sed -E 's/\b(udp|tcp)\s+port\s+([0-9]+)/\1.port == \2/g' <<< "${f}")"
    # 2. generic 'port <N>' -> '(tcp.port == <N> || udp.port == <N>)'
    f="$(sed -E 's/\bport\s+([0-9]+)/(tcp.port == \1 || udp.port == \1)/g' <<< "${f}")"
    # 3. 'host <ip>' -> 'ip.addr == <ip>'
    f="$(sed -E 's/\bhost\s+([0-9.]+)/ip.addr == \1/g' <<< "${f}")"
    # 4. 'src <ip>' -> 'ip.src == <ip>', 'dst <ip>' -> 'ip.dst == <ip>'
    f="$(sed -E 's/\bsrc\s+([0-9.]+)/ip.src == \1/g; s/\bdst\s+([0-9.]+)/ip.dst == \1/g' <<< "${f}")"
    # 5. Logical operators: 'or' -> '||', 'and' -> '&&'
    f="$(sed -E 's/\bor\b/||/g; s/\band\b/\&\&/g' <<< "${f}")"

    printf '%s' "${f}"
}


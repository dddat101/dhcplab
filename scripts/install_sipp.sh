#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - SIPP AUTOMATED BUILDER & INSTALLER
# Installs or compiles the native SIPp traffic generator and benchmarking tool.
# Supports system package manager (sip-tester / sipp) or building from source.
# Adheres to the Linux Network Test Lab Framework & Bash Defensive Patterns.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration constants
readonly TARGET_BIN="${LAB_DIR}/tools/bin/sipp"
readonly TARGET_DIR="${LAB_DIR}/tools/bin"
readonly SIPP_DEFAULT_REPO="https://github.com/SIPp/sipp.git"
readonly DEBIAN_PKG="sip-tester"
readonly REDHAT_PKG="sipp"
readonly REQUIRED_SOURCE_TOOLS=(git g++ make cmake)
readonly MIN_FREE_DISK_MB=300

# Mutable options
INSTALL_MODE="auto"    # "auto", "package", "source"
FORCE_REBUILD=0
DRY_RUN=0
CHECK_ONLY=0
BUILD_JOBS="$(nproc 2>/dev/null || echo 2)"
REPO_URL="${SIPP_DEFAULT_REPO}"
GIT_TAG=""
BUILD_TMP_DIR=""

usage() {
    cat <<'EOF'
==================================================================
  Gateway Performance Lab - SIPp Builder & Installer
==================================================================

Description:
  Automates the installation and compilation of the native SIPp
  traffic generator and performance benchmarking tool. Supports both
  system package manager installation (sip-tester on Debian/Ubuntu,
  sipp on Fedora/RHEL) and building headless/PCAP-enabled SIPp from source.
  Provides native SIP/RTP voice call emulation for VoIP QoS benchmarks (TC-QOS-01).

Usage:
  ./scripts/install_sipp.sh [OPTIONS]

Options:
  --check, -c        Inspect status, version, and capability flags of installed sipp.
  --dry-run, -n      Preview installation plan without modifying files or system packages.
  --force, -f        Force fresh installation or re-compilation even if already installed.
  --package, -p      Force installation via system package manager (requires root/sudo).
  --source, -s       Force compilation from GitHub source repository.
  --jobs, -j <num>   Number of parallel compilation workers [Default: $(nproc)].
  --tag, -t <tag>    Target git release tag or branch when building from source.
  --repo <url>       Custom git repository URL for SIPp source.
  -h, --help         Show this canonical CLI help message and exit (code 0).

Output:
  Installs executable binary or link to: tools/bin/sipp

Prerequisites:
  - Package mode : sudo / root privileges for apt-get or dnf
  - Source mode  : git, g++, make, cmake, libpcap-dev, libssl-dev, libncurses-dev

Examples:
  ./scripts/install_sipp.sh --check
  ./scripts/install_sipp.sh --dry-run
  ./scripts/install_sipp.sh
  ./scripts/install_sipp.sh --package
  ./scripts/install_sipp.sh --source --jobs 4

Suggested Next Steps:
  - Inspect Wi-Fi link status : ./scripts/wifi_connect.sh status
  - Run VoIP QoS benchmark    : sudo ./scripts/scenario.sh voice_qos -E sipp
==================================================================
EOF
}

cleanup_build_trap() {
    local rc=$?
    trap - EXIT INT TERM ERR
    if [[ -n "${BUILD_TMP_DIR}" && -d "${BUILD_TMP_DIR}" ]]; then
        rm -rf "${BUILD_TMP_DIR}" 2>/dev/null || true
    fi
    exit "${rc}"
}

check_sipp_status() {
    print_header "SIPP (SIP TESTER) INSTALLATION AUDIT"

    local active_bin=""
    if [[ -x "${TARGET_BIN}" ]]; then
        active_bin="${TARGET_BIN}"
    elif command -v sipp >/dev/null 2>&1; then
        active_bin="$(command -v sipp)"
    fi

    if [[ -n "${active_bin}" ]]; then
        local bin_desc="${active_bin}"
        if [[ -L "${TARGET_BIN}" ]]; then
            bin_desc="${TARGET_BIN} -> $(readlink -f "${TARGET_BIN}")"
        fi

        log_success "SIPp binary is INSTALLED: ${bin_desc}"

        printf '\n--- [BINARY VERSION & CAPABILITIES] ---\n'
        # SIPp exits with code 99 on -v flag; protect pipeline
        ( "${active_bin}" -v 2>&1 || true ) | head -n 6 || true
        printf '%s\n\n' '---------------------------------------'
        return 0
    else
        log_warn "SIPp is NOT INSTALLED at: ${TARGET_BIN}"
        log_info "Run './scripts/install_sipp.sh' to install via package manager or build from source."
        return 1
    fi
}

check_source_dependencies() {
    log_info "Validating source build toolchain..."
    local missing=()

    for cmd in "${REQUIRED_SOURCE_TOOLS[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        local missing_raw="${missing[*]}"
        local missing_str="${missing_raw//$'\n'/, }"
        die "Missing required source build tool(s): ${missing_str}. Install via: sudo apt-get install -y cmake build-essential git libpcap-dev libssl-dev libncurses-dev"
    fi

    # Check available disk space in temp directory
    local temp_base="${TMPDIR:-/tmp}"
    local free_mb
    free_mb="$(df -Pm "${temp_base}" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")"
    if (( free_mb > 0 && free_mb < MIN_FREE_DISK_MB )); then
        log_warn "Low temporary disk space in ${temp_base}: ${free_mb}MB available (recommended: >= ${MIN_FREE_DISK_MB}MB)."
    fi

    local tools_raw="${REQUIRED_SOURCE_TOOLS[*]}"
    local tools_str="${tools_raw//$'\n'/, }"
    log_pass "All build dependencies (${tools_str}) are verified."
}

log_build_error() {
    local phase="$1"
    local log_file="$2"
    log_error "Build failed during: ${phase}"
    if [[ -f "${log_file}" ]]; then
        printf '\n\e[1;31m--- [LAST 35 LINES OF BUILD LOG: %s] ---\e[0m\n' "${log_file}" >&2
        tail -n 35 "${log_file}" >&2
        printf '\e[1;31m------------------------------------------------------------------\e[0m\n\n' >&2
    fi
}

install_from_package() {
    require_root
    log_step "Installing SIPp via system package manager..."

    if command -v apt-get >/dev/null 2>&1; then
        log_info "Detected Debian/Ubuntu APT. Installing '${DEBIAN_PKG}'..."
        DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${DEBIAN_PKG}"
    elif command -v dnf >/dev/null 2>&1; then
        log_info "Detected RedHat/Fedora DNF. Installing '${REDHAT_PKG}'..."
        dnf install -y "${REDHAT_PKG}"
    elif command -v yum >/dev/null 2>&1; then
        log_info "Detected YUM. Installing '${REDHAT_PKG}'..."
        yum install -y "${REDHAT_PKG}"
    elif command -v pacman >/dev/null 2>&1; then
        log_info "Detected Pacman. Installing 'sipp'..."
        pacman -Sy --noconfirm sipp
    else
        die "No supported package manager found (apt-get, dnf, yum, pacman). Please use --source to build from source."
    fi

    local sys_bin
    sys_bin="$(command -v sipp || echo "")"
    if [[ -z "${sys_bin}" || ! -x "${sys_bin}" ]]; then
        die "Package installation completed, but 'sipp' binary is not accessible in PATH."
    fi

    link_binary "${sys_bin}"
}

build_from_source() {
    check_source_dependencies

    BUILD_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/sipp_build.XXXXXX")"
    trap cleanup_build_trap EXIT INT TERM ERR

    local build_log="${BUILD_TMP_DIR}/build.log"
    touch "${build_log}"

    local repo_dir="${BUILD_TMP_DIR}/sipp"
    local clone_args=("--depth" "1")
    if [[ -n "${GIT_TAG}" ]]; then
        clone_args+=("--branch" "${GIT_TAG}")
    fi
    clone_args+=("${REPO_URL}" "${repo_dir}")

    log_step "Cloning SIPp repository from ${REPO_URL}..."
    if ! git clone "${clone_args[@]}" >> "${build_log}" 2>&1; then
        log_build_error "Git clone" "${build_log}"
        die "Failed to clone SIPp repository."
    fi

    cd "${repo_dir}"

    log_step "Configuring SIPp with CMake (PCAP and SSL support enabled)..."
    local cmake_args=(
        "-B" "build"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DUSE_PCAP=1"
        "-DUSE_SSL=1"
    )
    if ! cmake "${cmake_args[@]}" >> "${build_log}" 2>&1; then
        log_build_error "CMake configuration" "${build_log}"
        die "Failed to configure SIPp with CMake."
    fi

    log_step "Compiling SIPp (parallel jobs: ${BUILD_JOBS})..."
    if ! cmake --build build -j"${BUILD_JOBS}" >> "${build_log}" 2>&1; then
        log_build_error "CMake compilation" "${build_log}"
        die "Failed during SIPp compilation."
    fi

    local built_bin="${repo_dir}/build/sipp"
    if [[ ! -x "${built_bin}" ]]; then
        built_bin="$(find "${repo_dir}/build" -name "sipp" -type f -perm /111 2>/dev/null | head -n1 || true)"
    fi

    if [[ -z "${built_bin}" || ! -x "${built_bin}" ]]; then
        log_build_error "Locating sipp binary" "${build_log}"
        die "Compilation completed, but failed to locate compiled 'sipp' binary."
    fi

    install_binary "${built_bin}"
}

link_binary() {
    local source_bin="$1"
    mkdir -p "${TARGET_DIR}"

    log_step "Linking system SIPp binary to ${TARGET_BIN}..."
    ln -sfn "${source_bin}" "${TARGET_BIN}"

    log_success "Successfully linked SIPp: ${TARGET_BIN} -> ${source_bin}"
    printf '\n--- [INSTALLED SIPP VERIFICATION] ---\n'
    ( "${TARGET_BIN}" -v 2>&1 || true ) | head -n 6 || true
    printf '%s\n' '-------------------------------------'
}

install_binary() {
    local source_bin="$1"
    mkdir -p "${TARGET_DIR}"

    log_step "Installing native compiled SIPp to ${TARGET_BIN}..."
    local tmp_bin="${TARGET_BIN}.tmp.$$"
    cp -f "${source_bin}" "${tmp_bin}"
    chmod 0755 "${tmp_bin}"
    mv -f "${tmp_bin}" "${TARGET_BIN}"

    ensure_runtime_dirs
    if [[ -n "${BUILD_TMP_DIR}" && -f "${BUILD_TMP_DIR}/build.log" ]]; then
        cp -f "${BUILD_TMP_DIR}/build.log" "${LOG_DIR}/sipp_build.log" 2>/dev/null || true
    fi

    log_success "Successfully compiled and installed SIPp: ${TARGET_BIN}"
    printf '\n--- [INSTALLED SIPP VERIFICATION] ---\n'
    ( "${TARGET_BIN}" -v 2>&1 || true ) | head -n 6 || true
    printf '%s\n' '-------------------------------------'
}

main() {
    # 1. Graceful degradation: Check help flags first (always exit 0)
    for arg in "$@"; do
        if [[ "${arg}" == "-h" || "${arg}" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    # 2. Argument parsing
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check|-c)
                CHECK_ONLY=1
                shift
                ;;
            --dry-run|-n)
                DRY_RUN=1
                shift
                ;;
            --force|-f)
                FORCE_REBUILD=1
                shift
                ;;
            --package|-p)
                INSTALL_MODE="package"
                shift
                ;;
            --source|-s)
                INSTALL_MODE="source"
                shift
                ;;
            --jobs|-j)
                shift
                [[ $# -gt 0 ]] || die "Option --jobs requires an integer argument."
                [[ "$1" =~ ^[0-9]+$ ]] || die "Invalid jobs count: $1 (must be an integer)."
                BUILD_JOBS="$1"
                shift
                ;;
            --tag|-t)
                shift
                [[ $# -gt 0 ]] || die "Option --tag requires a release tag or branch name."
                GIT_TAG="$1"
                shift
                ;;
            --repo)
                shift
                [[ $# -gt 0 ]] || die "Option --repo requires a git URL."
                REPO_URL="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # 3. Check-only mode
    if (( CHECK_ONLY == 1 )); then
        check_sipp_status
        exit $?
    fi

    print_header "SIPP AUTOMATED BUILDER & INSTALLER"

    # 4. Check existing installation
    if [[ -x "${TARGET_BIN}" && ${FORCE_REBUILD} -eq 0 && ${DRY_RUN} -eq 0 ]]; then
        log_success "SIPp binary is already installed at: ${TARGET_BIN}"
        printf '  Use --force to trigger a re-install or re-compilation.\n'
        printf '  Use --check to audit installed build options.\n\n'
        exit 0
    fi

    # 5. Determine strategy in auto mode
    local plan="link"
    local sys_sipp
    sys_sipp="$(command -v sipp 2>/dev/null || echo "")"

    if [[ "${INSTALL_MODE}" == "source" ]]; then
        plan="source"
    elif [[ "${INSTALL_MODE}" == "package" ]]; then
        plan="package"
    else
        # Auto mode
        if [[ -n "${sys_sipp}" && -x "${sys_sipp}" ]]; then
            plan="link"
        elif command -v apt-get >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1; then
            plan="package"
        else
            plan="source"
        fi
    fi

    # 6. Dry-run preview mode
    if (( DRY_RUN == 1 )); then
        print_section "DRY RUN PLAN (NO MUTATIONS PERFORMED)"
        printf '  Target Binary       : %s\n' "${TARGET_BIN}"
        printf '  Resolved Strategy   : %s\n' "${plan^^}"
        if [[ "${plan}" == "link" ]]; then
            printf '  System Binary       : %s\n' "${sys_sipp}"
            printf '  Action              : Link existing system binary into %s\n' "${TARGET_BIN}"
        elif [[ "${plan}" == "package" ]]; then
            printf '  Package Manager     : %s\n' "$(command -v apt-get >/dev/null 2>&1 && echo "APT (package: ${DEBIAN_PKG})" || echo "DNF (package: ${REDHAT_PKG})")"
            printf '  Action              : Install via package manager and link into %s\n' "${TARGET_BIN}"
        else
            printf '  Repository URL      : %s\n' "${REPO_URL}"
            printf '  Target Git Tag      : %s\n' "${GIT_TAG:-(default branch)}"
            printf '  Parallel Build Jobs : %s\n' "${BUILD_JOBS}"
            printf '  Build Engine        : CMake (Release, USE_PCAP=1, USE_SSL=1)\n'
            printf '  Action              : Compile from source and atomically install to %s\n' "${TARGET_BIN}"
        fi
        printf '  Force Rebuild       : %s\n\n' "$(( FORCE_REBUILD ))"
        exit 0
    fi

    # 7. Execute planned installation
    case "${plan}" in
        link)
            link_binary "${sys_sipp}"
            ;;
        package)
            install_from_package
            ;;
        source)
            build_from_source
            ;;
    esac
}

main "$@"

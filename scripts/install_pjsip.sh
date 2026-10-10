#!/usr/bin/env bash
# ==============================================================================
# GATEWAY PERFORMANCE LAB - PJSIP (PJSUA) AUTOMATED BUILDER & INSTALLER
# Builds headless PJSIP user-agent (pjsua) from source for VoIP QoS testing.
# Zero sound/video card dependency, optimized for automated test labs.
# Adheres to the Linux Network Test Lab Framework & Bash Defensive Patterns.
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration constants
readonly TARGET_BIN="${LAB_DIR}/tools/bin/pjsua"
readonly TARGET_DIR="${LAB_DIR}/tools/bin"
readonly PJPROJECT_DEFAULT_REPO="https://github.com/pjsip/pjproject.git"
readonly REQUIRED_BUILD_TOOLS=(git gcc make g++)
readonly MIN_FREE_DISK_MB=300

# Mutable options
FORCE_REBUILD=0
DRY_RUN=0
CHECK_ONLY=0
BUILD_JOBS="$(nproc 2>/dev/null || echo 2)"
REPO_URL="${PJPROJECT_DEFAULT_REPO}"
GIT_TAG=""
BUILD_TMP_DIR=""

usage() {
    cat <<'EOF'
==================================================================
  Gateway Performance Lab - PJSIP (pjsua) Builder & Installer
==================================================================

Description:
  Automates fetching, configuring, and compiling the native headless
  PJSIP (pjproject) command-line user-agent (pjsua) from GitHub.
  Provides native SIP/RTP voice call emulation with DSCP marking for
  VoIP QoS benchmarks (TC-QOS-01) without sound or video hardware.

Usage:
  ./scripts/install_pjsip.sh [OPTIONS]

Options:
  --check, -c        Inspect status and version of installed pjsua binary.
  --dry-run, -n      Preview build and installation plan without modifying files.
  --force, -f        Force fresh shallow clone and compilation even if installed.
  --jobs, -j <num>   Number of parallel compilation workers [Default: $(nproc)].
  --tag, -t <tag>    Target git release tag or branch to clone [Default: latest].
  --repo <url>       Custom git repository URL for pjproject.
  -h, --help         Show this canonical CLI help message and exit (code 0).

Output:
  Installs executable binary to: tools/bin/pjsua

Prerequisites:
  - Standard Linux toolchain: git, gcc, make, g++
  - Recommended minimum free disk space in temp directory: 300 MB

Examples:
  ./scripts/install_pjsip.sh --check
  ./scripts/install_pjsip.sh --dry-run
  ./scripts/install_pjsip.sh
  ./scripts/install_pjsip.sh --force --jobs 4
  ./scripts/install_pjsip.sh --tag 2.14.1

Suggested Next Steps:
  - Inspect Wi-Fi link status : ./scripts/wifi_connect.sh status
  - Run VoIP QoS benchmark    : sudo ./scripts/scenario.sh voice_qos
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

check_pjsip_status() {
    print_header "PJSIP (PJSUA) INSTALLATION AUDIT"

    if [[ -x "${TARGET_BIN}" ]]; then
        local bin_size
        bin_size="$(du -h "${TARGET_BIN}" 2>/dev/null | awk '{print $1}' || echo "N/A")"
        log_success "PJSIP user-agent is INSTALLED: ${TARGET_BIN} (${bin_size})"

        printf '\n--- [BINARY CONFIGURATION SUMMARY] ---\n'
        ( "${TARGET_BIN}" --version 2>&1 || true ) | head -n 12 || true
        printf '%s\n\n' '--------------------------------------'
        return 0
    else
        log_warn "PJSIP user-agent is NOT INSTALLED at: ${TARGET_BIN}"
        log_info "Run './scripts/install_pjsip.sh' to compile and install headless pjsua."
        return 1
    fi
}

check_dependencies() {
    log_info "Validating build toolchain..."
    local missing=()

    for cmd in "${REQUIRED_BUILD_TOOLS[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        local missing_raw="${missing[*]}"
        local missing_str="${missing_raw//$'\n'/, }"
        die "Missing required build tool(s): ${missing_str}. Please install via: sudo apt-get install -y build-essential git"
    fi

    # Check available disk space in temp directory
    local temp_base="${TMPDIR:-/tmp}"
    local free_mb
    free_mb="$(df -Pm "${temp_base}" 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")"
    if (( free_mb > 0 && free_mb < MIN_FREE_DISK_MB )); then
        log_warn "Low temporary disk space in ${temp_base}: ${free_mb}MB available (recommended: >= ${MIN_FREE_DISK_MB}MB)."
    fi

    local tools_raw="${REQUIRED_BUILD_TOOLS[*]}"
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

build_pjsip() {
    BUILD_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pjproject_build.XXXXXX")"
    trap cleanup_build_trap EXIT INT TERM ERR

    local build_log="${BUILD_TMP_DIR}/build.log"
    touch "${build_log}"

    local repo_dir="${BUILD_TMP_DIR}/pjproject"
    local clone_args=("--depth" "1")
    if [[ -n "${GIT_TAG}" ]]; then
        clone_args+=("--branch" "${GIT_TAG}")
    fi
    clone_args+=("${REPO_URL}" "${repo_dir}")

    log_step "Cloning PJSIP repository from ${REPO_URL}..."
    if ! git clone "${clone_args[@]}" >> "${build_log}" 2>&1; then
        log_build_error "Git clone" "${build_log}"
        die "Failed to clone PJSIP repository."
    fi

    cd "${repo_dir}"

    log_step "Configuring PJSIP (headless: --disable-sound --disable-video)..."
    if ! ./configure --disable-sound --disable-video CFLAGS="-O2" >> "${build_log}" 2>&1; then
        log_build_error "Configure" "${build_log}"
        die "Failed to configure PJSIP."
    fi

    log_step "Compiling PJSIP core libraries (parallel jobs: ${BUILD_JOBS})..."
    if ! make dep >> "${build_log}" 2>&1; then
        log_build_error "Make dependencies" "${build_log}"
        die "Failed during 'make dep'."
    fi

    if ! make -j"${BUILD_JOBS}" >> "${build_log}" 2>&1; then
        log_build_error "Make core libraries" "${build_log}"
        die "Failed during 'make'."
    fi

    log_step "Compiling pjsua application (parallel jobs: ${BUILD_JOBS})..."
    cd "${repo_dir}/pjsip-apps/build"
    if ! make -j"${BUILD_JOBS}" >> "${build_log}" 2>&1; then
        log_build_error "Make pjsua application" "${build_log}"
        die "Failed during 'make' for pjsua application."
    fi

    # Locate compiled binary
    local built_bin
    built_bin="$(find "${repo_dir}/pjsip-apps/bin" -name "pjsua-*" -type f -perm /111 2>/dev/null | head -n1 || true)"
    if [[ -z "${built_bin}" || ! -x "${built_bin}" ]]; then
        log_build_error "Locating pjsua executable" "${build_log}"
        die "Compilation completed, but failed to locate built 'pjsua' binary."
    fi

    install_binary "${built_bin}"
}

install_binary() {
    local source_bin="$1"

    log_step "Installing pjsua to ${TARGET_BIN}..."
    mkdir -p "${TARGET_DIR}"

    # Atomic install pattern: copy to temp file, set permissions, atomic move
    local tmp_bin="${TARGET_BIN}.tmp.$$"
    cp -f "${source_bin}" "${tmp_bin}"
    chmod 0755 "${tmp_bin}"
    mv -f "${tmp_bin}" "${TARGET_BIN}"

    # Copy build log to project logs directory for historical audit
    ensure_runtime_dirs
    if [[ -n "${BUILD_TMP_DIR}" && -f "${BUILD_TMP_DIR}/build.log" ]]; then
        cp -f "${BUILD_TMP_DIR}/build.log" "${LOG_DIR}/pjsip_build.log" 2>/dev/null || true
    fi

    log_success "Successfully installed pjsua: ${TARGET_BIN}"
    printf '\n--- [INSTALLED PJSUA VERIFICATION] ---\n'
    ( "${TARGET_BIN}" --version 2>&1 || true ) | head -n 12 || true
    printf '%s\n' '--------------------------------------'
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
        check_pjsip_status
        exit $?
    fi

    print_header "PJSIP (PJSUA) AUTOMATED BUILDER & INSTALLER"

    # 4. Check existing installation
    if [[ -x "${TARGET_BIN}" && ${FORCE_REBUILD} -eq 0 && ${DRY_RUN} -eq 0 ]]; then
        log_success "PJSIP user-agent is already installed at: ${TARGET_BIN}"
        printf '  Use --force to trigger a clean shallow re-clone and rebuild.\n'
        printf '  Use --check to audit installed build options.\n\n'
        exit 0
    fi

    # 5. Dependency check
    check_dependencies

    # 6. Dry-run preview mode
    if (( DRY_RUN == 1 )); then
        print_section "DRY RUN PLAN (NO MUTATIONS PERFORMED)"
        printf '  Target Binary       : %s\n' "${TARGET_BIN}"
        printf '  Repository URL      : %s\n' "${REPO_URL}"
        printf '  Target Git Tag      : %s\n' "${GIT_TAG:-(default branch)}"
        printf '  Parallel Build Jobs : %s\n' "${BUILD_JOBS}"
        printf '  Configure Flags     : --disable-sound --disable-video CFLAGS="-O2"\n'
        printf '  Force Rebuild       : %s\n' "$(( FORCE_REBUILD ))"
        printf '  Installation Mode   : Atomic (.tmp.$$ -> rename)\n'
        printf '  Action              : Preview completed successfully.\n\n'
        exit 0
    fi

    # 7. Execute build & installation
    build_pjsip
}

main "$@"

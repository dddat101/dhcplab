#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - HOST DEPENDENCY INSTALLER
# Installs required host packages (Kea, dnsmasq, radvd, udhcpc, iperf3, tcpdump, etc.)
# Disables default host-level systemd services for isolated network namespace operation
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

readonly DEBIAN_PACKAGES=(
    ca-certificates
    curl
    dnsmasq
    ethtool
    iperf3
    iproute2
    iptables
    iputils-ping
    isc-dhcp-client
    kea-dhcp4-server
    kea-dhcp6-server
    openssh-client
    openssl
    procps
    python3
    python3-venv
    radvd
    tcpdump
    tshark
    udhcpc
)

readonly REDHAT_PACKAGES=(
    ca-certificates
    curl
    dhcp-client
    dnsmasq
    ethtool
    iperf3
    iproute
    iptables
    iputils
    kea
    openssh-clients
    openssl
    procps-ng
    python3
    radvd
    tcpdump
    wireshark-cli
)

usage() {
    cat <<'USAGE'
==================================================================
  Gateway Performance Lab - Host Dependency Installer
==================================================================

Description:
  Installs required system packages and network daemons for the
  performance test lab (Kea DHCPv4/v6, radvd, dnsmasq, udhcpc,
  dhclient, iperf3, tcpdump, tshark, python3, ethtool, iproute2, etc.).
  Automatically detects APT (Debian/Ubuntu/Mint) and DNF (Fedora/RHEL).
  Disables default host-level systemd services to guarantee netns isolation.

Usage:
  sudo ./scripts/install_deps.sh [options]
  ./scripts/install_deps.sh --check-only
  ./scripts/install_deps.sh -h | --help

Options:
  --check-only   Check missing packages without installing (can run as non-root)
  -y, --yes      Automatic yes to package manager prompts
  -h, --help     Show this help message and exit

Examples:
  ./scripts/install_deps.sh -h
  ./scripts/install_deps.sh --check-only
  sudo ./scripts/install_deps.sh
  sudo ./scripts/install_deps.sh -y

Suggested Next Steps:
  1. Verify environment readiness: ./scripts/diagnose.sh
  2. Deploy virtual topology:      sudo ./scripts/setup.sh --virtual
  3. Deploy physical topology:     sudo ./scripts/setup.sh --single
==================================================================
USAGE
}

check_dependencies() {
    print_header "CHECKING LAB TOOLCHAIN DEPENDENCIES"
    local required_commands=(
        ip
        tc
        iptables
        iperf3
        tcpdump
        tshark
        python3
        openssl
        curl
        ethtool
        kea-dhcp4
        kea-dhcp6
        radvd
        dnsmasq
        udhcpc
    )

    local missing=()
    local cmd
    for cmd in "${required_commands[@]}"; do
        if command -v "${cmd}" >/dev/null 2>&1; then
            printf '  \e[1;32m[INSTALLED]\e[0m %-20s (%s)\n' "${cmd}" "$(command -v "${cmd}")"
        else
            printf '  \e[1;31m[MISSING]\e[0m   %-20s (Not found in PATH)\n' "${cmd}"
            missing+=("${cmd}")
        fi
    done

    printf '\n'
    if (( ${#missing[@]} == 0 )); then
        log_success "All essential lab tools and daemons are already installed!"
        return 0
    else
        log_warn "Missing tools: ${missing[*]}"
        printf 'Run: sudo ./scripts/install_deps.sh to install missing dependencies.\n'
        return 1
    fi
}

disable_host_services() {
    log_info "Ensuring netns isolation by disabling default host-level system services..."
    local services=(
        kea-dhcp4-server
        kea-dhcp6-server
        kea-dhcp4
        kea-dhcp6
        radvd
        dnsmasq
    )

    local svc
    for svc in "${services[@]}"; do
        if command -v systemctl >/dev/null 2>&1; then
            if systemctl is-enabled "${svc}" >/dev/null 2>&1 || systemctl is-active "${svc}" >/dev/null 2>&1; then
                log_info "Stopping and disabling host-level daemon: ${svc}"
                systemctl disable --now "${svc}" 2>/dev/null || true
            fi
        fi
    done
}

configure_tshark_permissions() {
    # On Ubuntu 24.04+, AppArmor restricts tshark from reading files outside /tmp.
    # Add generic pcap read permission to local override.
    if [[ -d /etc/apparmor.d/local ]] && [[ -f /etc/apparmor.d/tshark ]]; then
        if ! grep -q '\.pcap' /etc/apparmor.d/local/tshark 2>/dev/null; then
            log_info "Configuring AppArmor to allow tshark to read .pcap files..."
            echo 'file r /**.pcap{,ng}{,.gz},' >> /etc/apparmor.d/local/tshark 2>/dev/null || true
            if command -v apparmor_parser >/dev/null 2>&1; then
                apparmor_parser -r /etc/apparmor.d/tshark 2>/dev/null || true
            fi
        fi
    fi
}

wait_for_dpkg_lock() {
    local timeout="${1:-300}"
    local lock_files=(
        "/var/lib/dpkg/lock-frontend"
        "/var/lib/dpkg/lock"
        "/var/lib/apt/lists/lock"
    )
    local elapsed=0
    local warned=0

    while (( elapsed < timeout )); do
        local is_locked=0
        local holder_info=""

        for lf in "${lock_files[@]}"; do
            if [[ -f "${lf}" ]]; then
                if command -v fuser >/dev/null 2>&1; then
                    local pids
                    pids="$(fuser "${lf}" 2>/dev/null || true)"
                    if [[ -n "${pids// }" ]]; then
                        is_locked=1
                        holder_info="held on ${lf} by PID(s): ${pids// }"
                        break
                    fi
                elif command -v lsof >/dev/null 2>&1; then
                    if lsof "${lf}" >/dev/null 2>&1; then
                        is_locked=1
                        holder_info="held on ${lf}"
                        break
                    fi
                fi
            fi
        done

        if (( is_locked == 0 )); then
            if (( warned == 1 )); then
                log_success "Package manager lock released. Continuing with installation..."
            fi
            return 0
        fi

        if (( warned == 0 )); then
            log_info "Package manager lock detected (${holder_info})."
            log_info "Waiting for background process (e.g. unattended-upgrades) to release lock (timeout: ${timeout}s)..."
            warned=1
        fi

        sleep 3
        elapsed=$(( elapsed + 3 ))
    done

    log_warn "Wait timeout (${timeout}s) exceeded. Attempting installation with APT Lock Timeout..."
    return 0
}

install_packages() {
    local auto_yes="$1"
    require_root

    print_header "INSTALLING LAB DEPENDENCIES"

    if command -v apt-get >/dev/null 2>&1; then
        log_info "Detected Debian/Ubuntu APT package manager."
        wait_for_dpkg_lock 300

        log_info "Updating package lists..."
        apt-get -o DPkg::Lock::Timeout=300 update -y

        log_info "Installing required packages..."
        local apt_opts=("-y" "--no-install-recommends" "-o" "DPkg::Lock::Timeout=300")
        DEBIAN_FRONTEND=noninteractive apt-get install "${apt_opts[@]}" "${DEBIAN_PACKAGES[@]}"

        disable_host_services
        configure_tshark_permissions
        log_success "All Debian/Ubuntu packages successfully installed and configured."

    elif command -v dnf >/dev/null 2>&1; then
        log_info "Detected Fedora/RHEL DNF package manager."
        local dnf_opts=("-y")
        dnf install "${dnf_opts[@]}" "${REDHAT_PACKAGES[@]}"

        disable_host_services
        log_success "All Fedora/RHEL packages successfully installed and configured."

    else
        die "Unsupported package manager. Please manually install: ${DEBIAN_PACKAGES[*]}"
    fi
}

main() {
    local check_only=0
    local auto_yes=0

    local arg
    for arg in "$@"; do
        case "${arg}" in
            -h|--help)
                usage
                exit 0
                ;;
            --check-only)
                check_only=1
                ;;
            -y|--yes)
                auto_yes=1
                ;;
            *)
                log_error "Unknown option: ${arg}"
                usage
                exit 1
                ;;
        esac
    done

    if (( check_only == 1 )); then
        check_dependencies || true
        exit 0
    fi

    install_packages "${auto_yes}"

    printf '\n'
    print_header "DEPENDENCY INSTALLATION COMPLETE"
    printf 'Recommended next steps:\n'
    printf '  1. Verify pre-flight readiness:  ./scripts/diagnose.sh\n'
    printf '  2. Deploy virtual simulation:    sudo ./scripts/setup.sh --virtual\n'
    printf '  3. Deploy physical testbed:      sudo ./scripts/setup.sh --single\n'
    printf '==================================================================\n'
}

main "$@"

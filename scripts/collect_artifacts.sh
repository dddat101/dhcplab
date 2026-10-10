#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - ARTIFACT COLLECTOR
# Gathers all test metrics, raw iperf3 trials, PCAPs, logs, and system states
# into a structured, timestamped bundle (directory and compressed archive).
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
LAB_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# Source common library if available
if [[ -f "${SCRIPT_DIR}/lib/common.sh" ]]; then
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/lib/common.sh"
fi

# Fallback loggers if not defined
type log_info >/dev/null 2>&1 || log_info() { printf '\e[1;32m[INFO]\e[0m    %s\n' "$*"; }
type log_success >/dev/null 2>&1 || log_success() { printf '\e[1;32m[PASS]\e[0m    %s\n' "$*"; }
type log_warn >/dev/null 2>&1 || log_warn() { printf '\e[1;33m[WARN]\e[0m    %s\n' "$*" >&2; }
type log_error >/dev/null 2>&1 || log_error() { printf '\e[1;31m[ERROR]\e[0m   %s\n' "$*" >&2; }
type print_header >/dev/null 2>&1 || print_header() {
    printf '==================================================================\n'
    printf '  %s\n' "$1"
    printf '==================================================================\n'
}

LOG_DIR="${LAB_DIR}/logs"
CAPTURES_DIR="${LAB_DIR}/captures"
STATE_DIR="${LAB_DIR}/state"
ARTIFACTS_ROOT="${LAB_DIR}/artifacts"
RAW_IPERF_DIR="${LOG_DIR}/raw_iperf"

usage() {
    cat << 'EOF'
==================================================================
  Gateway Performance Lab - Artifact Collector
==================================================================

Description:
  Collects all test deliverables and diagnostic data into a single
  structured bundle (directory and compressed .tar.gz archive):
  - Evaluated JSON results (Unicast, Multicast, Bursts, Apps, Multi-band, QoS)
  - Raw per-trial iperf3 JSON outputs (intervals, CWND, retransmits)
  - Packet captures (*.pcap) across WAN, LAN, and Wi-Fi
  - Execution console logs (*.log)
  - Network state, topology, and routing tables
  - Generated manifest.json & SUMMARY.md report

Usage:
  ./scripts/collect_artifacts.sh [OPTIONS]

Options:
  -o, --output <path>      Specify custom output archive or directory path
  --latest                 Collect only the most recent test run artifacts
  --no-pcap                Exclude PCAP capture files (reduces bundle size)
  --no-tar                 Do not compress into .tar.gz; keep as directory
  --clean                  Remove older artifacts from artifacts/ directory
  -h, --help               Show this help message and exit

Examples:
  ./scripts/collect_artifacts.sh
  ./scripts/collect_artifacts.sh --latest
  ./scripts/collect_artifacts.sh --no-pcap -o /tmp/report.tar.gz
  ./scripts/collect_artifacts.sh --no-tar
==================================================================
EOF
}

clean_artifacts() {
    print_header "CLEANING OLD ARTIFACTS"
    if [[ -d "${ARTIFACTS_ROOT}" ]]; then
        local count
        count="$(find "${ARTIFACTS_ROOT}" -mindepth 1 -maxdepth 1 ! -name ".gitkeep" 2>/dev/null | wc -l || echo "0")"
        find "${ARTIFACTS_ROOT}" -mindepth 1 -maxdepth 1 ! -name ".gitkeep" -exec rm -rf {} + 2>/dev/null || true
        log_success "Cleaned ${count} previous artifact item(s) from ${ARTIFACTS_ROOT}/."
    else
        log_info "Artifacts directory is already clean."
    fi
}

main() {
    local opt_output=""
    local opt_latest=0
    local opt_no_pcap=0
    local opt_no_tar=0
    local opt_clean=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            -o|--output)
                [[ $# -ge 2 ]] || { log_error "Option --output requires a path argument"; exit 2; }
                opt_output="$2"
                shift 2
                ;;
            --latest)
                opt_latest=1
                shift
                ;;
            --no-pcap)
                opt_no_pcap=1
                shift
                ;;
            --no-tar)
                opt_no_tar=1
                shift
                ;;
            --clean)
                opt_clean=1
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 2
                ;;
        esac
    done

    if (( opt_clean == 1 )); then
        clean_artifacts
        exit 0
    fi

    # Load configuration if present
    if [[ -f "${LAB_DIR}/config.env" ]]; then
        # shellcheck disable=SC1091
        source "${LAB_DIR}/config.env" 2>/dev/null || true
    fi

    mkdir -p "${ARTIFACTS_ROOT}" "${LOG_DIR}" "${STATE_DIR}" "${CAPTURES_DIR}" "${RAW_IPERF_DIR}" 2>/dev/null || true

    local ts
    ts="$(date +%Y%m%d_%H%M%S)"
    local bundle_name="gw_perf_artifact_${ts}"
    local bundle_dir="${ARTIFACTS_ROOT}/${bundle_name}"

    if [[ -n "${opt_output}" ]]; then
        if [[ "${opt_output}" == *.tar.gz || "${opt_output}" == *.tgz ]]; then
            bundle_dir="${ARTIFACTS_ROOT}/tmp_${bundle_name}"
        else
            bundle_dir="${opt_output}"
        fi
    fi

    mkdir -p "${bundle_dir}"
    local dir_metrics="${bundle_dir}/metrics"
    local dir_raw_iperf="${bundle_dir}/raw_iperf"
    local dir_logs="${bundle_dir}/logs"
    local dir_captures="${bundle_dir}/captures"
    local dir_state="${bundle_dir}/system_state"

    mkdir -p "${dir_metrics}" "${dir_raw_iperf}" "${dir_logs}" "${dir_captures}" "${dir_state}"

    print_header "COLLECTING TEST ARTIFACTS"
    log_info "Artifact Destination : ${bundle_dir}"

    # 1. Collect Evaluated JSON Metrics
    local cnt_metrics=0
    if compgen -G "${LOG_DIR}/*.json" >/dev/null 2>&1; then
        for f in "${LOG_DIR}"/*.json; do
            if [[ -f "${f}" ]]; then
                cp -f "${f}" "${dir_metrics}/"
                cnt_metrics=$(( cnt_metrics + 1 ))
            fi
        done
    fi
    log_info "  -> Evaluated Metrics : ${cnt_metrics} JSON files collected"

    # 2. Collect Raw iperf3 Trial JSONs
    local cnt_raw=0
    if compgen -G "${RAW_IPERF_DIR}/*.json" >/dev/null 2>&1; then
        for f in "${RAW_IPERF_DIR}"/*.json; do
            if [[ -f "${f}" ]]; then
                cp -f "${f}" "${dir_raw_iperf}/"
                cnt_raw=$(( cnt_raw + 1 ))
            fi
        done
    fi
    # Also check /tmp for any active/uncleaned scenario iperf files
    local tmp_iperf_found
    tmp_iperf_found="$(find /tmp -maxdepth 2 -name "iperf_*.json" 2>/dev/null || true)"
    if [[ -n "${tmp_iperf_found}" ]]; then
        while IFS= read -r f; do
            if [[ -f "${f}" ]]; then
                cp -f "${f}" "${dir_raw_iperf}/" 2>/dev/null || true
                cnt_raw=$(( cnt_raw + 1 ))
            fi
        done <<< "${tmp_iperf_found}"
    fi
    log_info "  -> Raw iperf3 Trials : ${cnt_raw} JSON trial outputs collected"

    # 3. Collect Execution Logs
    local cnt_logs=0
    if compgen -G "${LOG_DIR}/*.log" >/dev/null 2>&1; then
        if (( opt_latest == 1 )); then
            local latest_log
            latest_log="$(ls -t "${LOG_DIR}"/*.log 2>/dev/null | head -n1 || true)"
            if [[ -n "${latest_log}" && -f "${latest_log}" ]]; then
                cp -f "${latest_log}" "${dir_logs}/"
                cnt_logs=1
            fi
        else
            for f in "${LOG_DIR}"/*.log; do
                if [[ -f "${f}" ]]; then
                    cp -f "${f}" "${dir_logs}/"
                    cnt_logs=$(( cnt_logs + 1 ))
                fi
            done
        fi
    fi
    log_info "  -> Execution Logs    : ${cnt_logs} log file(s) collected"

    # 4. Collect Packet Captures (PCAPs)
    local cnt_pcap=0
    local pcap_bytes=0
    if (( opt_no_pcap == 0 )); then
        if compgen -G "${CAPTURES_DIR}/*.pcap" >/dev/null 2>&1; then
            if (( opt_latest == 1 )); then
                # Find PCAPs matching the latest test tag or newest files
                local latest_env="${STATE_DIR}/last_capture_dual.env"
                if [[ -f "${latest_env}" ]]; then
                    # shellcheck disable=SC1090
                    source "${latest_env}" 2>/dev/null || true
                    if [[ -n "${LAST_PCAP_WAN:-}" && -f "${LAST_PCAP_WAN}" ]]; then
                        cp -f "${LAST_PCAP_WAN}" "${dir_captures}/"
                        cnt_pcap=$(( cnt_pcap + 1 ))
                    fi
                    if [[ -n "${LAST_PCAP_LAN:-}" && -f "${LAST_PCAP_LAN}" ]]; then
                        cp -f "${LAST_PCAP_LAN}" "${dir_captures}/"
                        cnt_pcap=$(( cnt_pcap + 1 ))
                    fi
                    if [[ -n "${LAST_PCAP_WIFI:-}" && -f "${LAST_PCAP_WIFI}" ]]; then
                        cp -f "${LAST_PCAP_WIFI}" "${dir_captures}/"
                        cnt_pcap=$(( cnt_pcap + 1 ))
                    fi
                    if [[ -f "${STATE_DIR}/latest_lan_merged_pcap.txt" ]]; then
                        local merged_f
                        merged_f="$(cat "${STATE_DIR}/latest_lan_merged_pcap.txt" 2>/dev/null || true)"
                        if [[ -n "${merged_f}" && -f "${merged_f}" ]]; then
                            cp -f "${merged_f}" "${dir_captures}/"
                            cnt_pcap=$(( cnt_pcap + 1 ))
                        fi
                    fi
                else
                    # Fallback to newest 3 pcaps
                    while IFS= read -r f; do
                        if [[ -n "${f}" && -f "${f}" ]]; then
                            cp -f "${f}" "${dir_captures}/"
                            cnt_pcap=$(( cnt_pcap + 1 ))
                        fi
                    done < <(ls -t "${CAPTURES_DIR}"/*.pcap 2>/dev/null | head -n 3)
                fi
            else
                for f in "${CAPTURES_DIR}"/*.pcap; do
                    if [[ -f "${f}" ]]; then
                        cp -f "${f}" "${dir_captures}/"
                        cnt_pcap=$(( cnt_pcap + 1 ))
                    fi
                done
            fi
        fi
        if compgen -G "${dir_captures}/*.pcap" >/dev/null 2>&1; then
            pcap_bytes="$(du -cb "${dir_captures}"/*.pcap 2>/dev/null | awk 'END{print $1}' || echo "0")"
        fi
        local pcap_size_str
        pcap_size_str="$(du -sh "${dir_captures}" 2>/dev/null | cut -f1 || echo "0B")"
        log_info "  -> Packet Captures   : ${cnt_pcap} PCAP(s) (${pcap_size_str})"
    else
        log_info "  -> Packet Captures   : Excluded (--no-pcap specified)"
    fi

    # 5. Collect System & Topology State
    local cnt_state=0
    if compgen -G "${STATE_DIR}/*" >/dev/null 2>&1; then
        for f in "${STATE_DIR}"/*; do
            if [[ -f "${f}" && ! "${f}" =~ \.pid$ ]]; then
                cp -f "${f}" "${dir_state}/"
                cnt_state=$(( cnt_state + 1 ))
            fi
        done
    fi

    # Snapshot host networking & system diagnostics
    {
        printf "==================================================================\n"
        printf "  SYSTEM & DUT ENVIRONMENT SNAPSHOT\n"
        printf "==================================================================\n"
        printf "Timestamp   : %s\n" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
        printf "Hostname    : %s\n" "$(hostname 2>/dev/null || echo "unknown")"
        printf "Kernel      : %s\n" "$(uname -a 2>/dev/null || echo "unknown")"
        printf "DUT LAN IP  : %s\n" "${DUT_LAN_IP:-192.168.1.1}"
        printf "DUT WAN IP  : %s\n" "${DUT_WAN_IP:-10.10.0.100}"
        printf "\n--- [IP ADDRESSES & LINKS] ---\n"
        ip -br addr show 2>/dev/null || true
        printf "\n--- [ROUTING TABLE] ---\n"
        ip route show 2>/dev/null || true
        printf "\n--- [WIRELESS INTERFACES] ---\n"
        iw dev 2>/dev/null || true
    } > "${dir_state}/system_environment.txt"
    cnt_state=$(( cnt_state + 1 ))

    # Git snapshot info
    if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
        {
            printf "Commit  : %s\n" "$(git rev-parse HEAD 2>/dev/null || echo "N/A")"
            printf "Branch  : %s\n" "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "N/A")"
            printf "Date    : %s\n" "$(git log -1 --format=%cd 2>/dev/null || echo "N/A")"
            printf "Author  : %s\n" "$(git log -1 --format='%an <%ae>' 2>/dev/null || echo "N/A")"
            printf "Subject : %s\n" "$(git log -1 --format=%s 2>/dev/null || echo "N/A")"
            printf "\n--- Status ---\n"
            git status -s 2>/dev/null || true
        } > "${dir_state}/git_info.txt"
        cnt_state=$(( cnt_state + 1 ))
    fi
    log_info "  -> System State      : ${cnt_state} diagnostics snapshot(s)"

    # 6. Collect DUT Diagnostic Artifacts (if DUT collector enabled and reachable)
    local cnt_dut=0
    local dir_dut="${bundle_dir}/dut_diagnostics"
    if [[ "${DUT_COLLECTOR_ENABLED:-1}" == "1" && -x "${SCRIPT_DIR}/dut_collector.sh" ]]; then
        if "${SCRIPT_DIR}/dut_collector.sh" test >/dev/null 2>&1; then
            log_info "Collecting live DUT diagnostic artifact bundle..."
            "${SCRIPT_DIR}/dut_collector.sh" collect --out-dir "${dir_dut}" >/dev/null 2>&1 || true
            if [[ -d "${dir_dut}" ]]; then
                cnt_dut="$(find "${dir_dut}" -type f | wc -l || echo "0")"
                local dut_size
                dut_size="$(du -sh "${dir_dut}" 2>/dev/null | cut -f1 || echo "0B")"
                log_info "  -> DUT Diagnostics   : ${cnt_dut} artifact(s) (${dut_size})"
            fi
        else
            log_info "  -> DUT Diagnostics   : Skipped (DUT not reachable or SSH auth unconfigured)"
        fi
    fi

    # 7. Generate Manifest JSON
    local total_files
    total_files="$(find "${bundle_dir}" -type f | wc -l || echo "0")"
    local total_bytes
    total_bytes="$(du -sb "${bundle_dir}" 2>/dev/null | awk '{print $1}' || echo "0")"

    local git_rev git_br
    git_rev="$(git rev-parse HEAD 2>/dev/null || echo "N/A")"
    git_br="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "N/A")"
    local metric_tool="${LAB_DIR}/tools/metric_parser.py"

    if [[ -f "${metric_tool}" ]]; then
        "${PYTHON_BIN:-python3}" "${metric_tool}" write-bundle-manifest \
            --output "${bundle_dir}/manifest.json" \
            --bundle-name "${bundle_name}" \
            --git-commit "${git_rev}" \
            --git-branch "${git_br}" \
            --dut-lan-ip "${DUT_LAN_IP:-192.168.1.1}" \
            --dut-wan-ip "${DUT_WAN_IP:-10.10.0.100}" \
            --total-files "${total_files}" \
            --total-bytes "${total_bytes}" \
            --counts \
                "metrics_json=${cnt_metrics}" \
                "raw_iperf_json=${cnt_raw}" \
                "logs=${cnt_logs}" \
                "captures_pcap=${cnt_pcap}" \
                "state_files=${cnt_state}" \
                "dut_artifacts=${cnt_dut}" \
                "total_files=${total_files}" 2>/dev/null || true
    fi

    # 8. Generate Summary Markdown Report
    {
        printf "# Gateway Performance Lab - Artifact Evidence Bundle\n\n"
        printf "* **Bundle Name:** \`%s\`\n" "${bundle_name}"
        printf "* **Generated At:** %s\n" "$(date +'%Y-%m-%d %H:%M:%S %Z')"
        printf "* **Git Revision:** \`%s\` (branch: \`%s\`)\n" \
            "$(git rev-parse --short HEAD 2>/dev/null || echo "N/A")" \
            "$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "N/A")"
        printf "* **DUT Gateway IP:** \`%s\` | **WAN IP:** \`%s\`\n\n" "${DUT_LAN_IP:-192.168.1.1}" "${DUT_WAN_IP:-10.10.0.100}"

        printf "## 1. Bundle Contents Summary\n\n"
        printf "| Component | Path | File Count | Description |\n"
        printf "| :--- | :--- | :---: | :--- |\n"
        printf "| **Evaluated Metrics** | \`metrics/\` | %d | Consolidate JSON evaluations (Unicast, Multicast, Apps, QoS) |\n" "${cnt_metrics}"
        printf "| **Raw iperf3 Trials** | \`raw_iperf/\` | %d | Second-by-second interval & CWND stats from iperf3 runs |\n" "${cnt_raw}"
        printf "| **Execution Logs** | \`logs/\` | %d | Full console output logs for test scenarios |\n" "${cnt_logs}"
        printf "| **Packet Captures** | \`captures/\` | %d | Dual/Multi-point PCAP evidence files (%s) |\n" "${cnt_pcap}" "${pcap_size_str:-0B}"
        printf "| **System State** | \`system_state/\` | %d | Interface configurations, routes, and diagnostic snapshots |\n" "${cnt_state}"
        if (( cnt_dut > 0 )); then
            printf "| **DUT Diagnostics** | \`dut_diagnostics/\` | %d | Kernel dmesg, hardware drop counters, QoS qdisc, WMM EDCA |\n" "${cnt_dut}"
        fi
        printf "\n"

        printf "## 2. Benchmark Metrics Overview\n\n"
        printf "| Test ID | Scenario Name | Output File | Verdict |\n"
        printf "| :--- | :--- | :--- | :---: |\n"

        for jf in "${dir_metrics}"/*.json; do
            if [[ -f "${jf}" ]]; then
                local bname test_tag verdict
                bname="$(basename "${jf}")"
                test_tag="$(grep -o '"test": *"[^"]*"' "${jf}" 2>/dev/null | head -n1 | cut -d'"' -f4 || echo "${bname}")"
                verdict="$(grep -o '"verdict": *"[^"]*"' "${jf}" 2>/dev/null | head -n1 | cut -d'"' -f4 || echo "")"
                if [[ -z "${verdict}" ]]; then
                    verdict="$(grep -o '"status": *"[^"]*"' "${jf}" 2>/dev/null | head -n1 | cut -d'"' -f4 || echo "RECORDED")"
                fi
                printf "| \`%s\` | %s | \`metrics/%s\` | **%s** |\n" "${bname}" "${test_tag}" "${bname}" "${verdict}"
            fi
        done
    } > "${bundle_dir}/SUMMARY.md"

    # Set permissions so non-root can access
    chmod -R 0777 "${bundle_dir}" 2>/dev/null || true

    local final_target="${bundle_dir}"

    # 8. Compress into .tar.gz unless --no-tar
    if (( opt_no_tar == 0 )); then
        local tar_file="${ARTIFACTS_ROOT}/${bundle_name}.tar.gz"
        if [[ -n "${opt_output}" && ( "${opt_output}" == *.tar.gz || "${opt_output}" == *.tgz ) ]]; then
            tar_file="${opt_output}"
        fi

        log_info "Compressing artifact archive..."
        tar -czf "${tar_file}" -C "${ARTIFACTS_ROOT}" "${bundle_name}" 2>/dev/null || {
            # Fallback if custom path
            tar -czf "${tar_file}" -C "$(dirname "${bundle_dir}")" "$(basename "${bundle_dir}")"
        }
        chmod 0666 "${tar_file}" 2>/dev/null || true

        # Symlink latest.tar.gz
        ln -sf "${tar_file}" "${ARTIFACTS_ROOT}/latest.tar.gz" 2>/dev/null || true
        final_target="${tar_file}"
    fi

    # Symlink latest directory
    ln -sfn "${bundle_dir}" "${ARTIFACTS_ROOT}/latest" 2>/dev/null || true

    local final_size
    final_size="$(du -sh "${final_target}" 2>/dev/null | cut -f1 || echo "0B")"

    printf '\n==================================================================\n'
    printf '  ARTIFACT COLLECTION COMPLETE\n'
    printf '==================================================================\n'
    printf '  Archive / Bundle  : %s\n' "${final_target}"
    printf '  Bundle Size       : %s\n' "${final_size}"
    printf '  Metrics JSONs     : %d files in metrics/\n' "${cnt_metrics}"
    printf '  Raw iperf3 Trials : %d files in raw_iperf/\n' "${cnt_raw}"
    printf '  Execution Logs    : %d files in logs/\n' "${cnt_logs}"
    printf '  PCAP Captures     : %d files in captures/\n' "${cnt_pcap}"
    printf '  System Diagnostics: %d files in system_state/\n' "${cnt_state}"
    printf '  Quick Access Link : %s\n' "${ARTIFACTS_ROOT}/latest"
    printf '==================================================================\n\n'
}

main "$@"

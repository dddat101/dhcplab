#!/usr/bin/env bash
# ==============================================================================
# NETWORK TEST LAB - RUNTIME STATE OBSERVER
# Non-root graceful degradation, stale PID detection & topology inspection
# Enhanced with unified Physical & Virtual Network Namespaces & Wi-Fi Analysis
# ==============================================================================

set -Eeuo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

usage() {
    cat <<'USAGE'
Description:
  Inspects and reports current runtime state of the network test lab,
  including active namespaces, bridges, interface addresses, daemons,
  packet captures, and unified Physical vs. Virtual Wi-Fi status.

Usage:
  ./scripts/show_state.sh [options]
  ./scripts/show_state.sh -h | --help

Options:
  -w, --wifi   Display only Wi-Fi & wireless interface state (Physical & Virtual)
  -h, --help   Show this help message and exit

Suggested Next Steps:
  - Connect Wi-Fi:         sudo ./scripts/wifi_connect.sh connect 5g
  - Run test scenarios:    sudo ./scripts/scenario.sh all
  - Verify compliance:     ./scripts/verify_compliance.sh
  - Teardown when done:    sudo ./scripts/cleanup.sh
USAGE
}

print_namespaces_section() {
    local filter_wifi="${1:-0}"

    if (( filter_wifi == 1 )); then
        print_section "WI-FI & WIRELESS INTERFACES (PHYSICAL & VIRTUAL NETNS)"
    else
        print_section "ALL NETWORK NAMESPACES & INTERFACES"
    fi

    # 1. Discover Physical Wi-Fi Adapters on Host
    local phy_devs=()
    if command -v iw >/dev/null 2>&1; then
        mapfile -t phy_devs < <(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}')
    fi

    # 2. Define All Testbed Endpoints
    # Format: namespace:role:type:veth_host:target_ssid:band:is_wifi
    local all_endpoints=(
        "${WAN_NS:-ns-wan}:WAN Simulator:VIRTUAL:v-wan-h:-:-:0"
        "${DUT_NS:-ns-dut}:Virtual DUT Gateway:VIRTUAL:-:-:-:0"
        "${PC_NS:-ns-pc}:Gigabit Wired PC:VIRTUAL:v-pc-h:-:-:0"
        "${STB_NS:-ns-stb}:IPTV STB (100M):VIRTUAL:v-stb-h:-:-:0"
        "${WLAN2G_NS:-ns-wlan2g}:Wi-Fi 2.4G Station:VIRTUAL:v-w2g-h:${DUT_SSID_2G:-DUT_2.4G}:2.4GHz:1"
        "${WLAN5G_NS:-ns-wlan5g}:Wi-Fi 5G Station:VIRTUAL:v-w5g-h:${DUT_SSID_5G:-DUT_5G}:5GHz:1"
        "${WLAN6G_NS:-ns-wlan6g}:Wi-Fi 6G Station:VIRTUAL:v-w6g-h:${DUT_SSID_6G:-DUT_6G}:6GHz:1"
        "${PHONE1_NS:-ns-phone1}:Wi-Fi Phone 1 (VoIP):VIRTUAL:v-ph1-h:${DUT_SSID_VOIP:-${DUT_SSID_5G:-DUT_5G}}:5GHz VoIP:1"
        "${PHONE2_NS:-ns-phone2}:Wi-Fi Phone 2 (VoIP):VIRTUAL:v-ph2-h:${DUT_SSID_VOIP:-${DUT_SSID_5G:-DUT_5G}}:5GHz VoIP:1"
    )

    # Dynamic Discovery: Append any active custom netns created by user scenarios
    if command -v ip >/dev/null 2>&1; then
        local discovered_ns
        discovered_ns="$(ip netns list 2>/dev/null | awk '{print $1}' || true)"
        for dns in ${discovered_ns}; do
            local already=0
            for ep in "${all_endpoints[@]}"; do
                local ep_ns="${ep%%:*}"
                if [[ "${ep_ns}" == "${dns}" ]]; then
                    already=1
                    break
                fi
            done
            if (( already == 0 )); then
                all_endpoints+=("${dns}:Custom Endpoint:VIRTUAL:-:-:-:0")
            fi
        done
    fi

    # 3. Print Unified Summary Table
    printf '%-19s %-20s %-10s %-22s %-24s %-15s %-14s %-12s\n' \
        "Target / Namespace" "Role" "Type" "Medium" "SSID (Target/Connected)" "IPv4 Address" "Gateway" "Status"
    printf '%s\n' "----------------------------------------------------------------------------------------------------------------------------------------------------------------"

    # --- Physical Wi-Fi Rows ---
    for wif in "${phy_devs[@]}"; do
        local w_link w_ssid="(None)" w_status="DISCONNECTED" w_band="-" w_freq=""
        w_link="$(iw dev "${wif}" link 2>/dev/null || true)"
        if [[ -n "${w_link}" && "${w_link}" != *"Not connected"* ]]; then
            w_status="CONNECTED"
            w_ssid="$(printf '%s\n' "${w_link}" | awk -F'SSID: ' '/SSID:/{print $2}' | xargs || true)"
            w_freq="$(printf '%s\n' "${w_link}" | awk '/freq:/{print $2}' || true)"
            local w_freq_int="${w_freq//[!0-9.]/}"
            w_freq_int="${w_freq_int%%.*}"
            if [[ -n "${w_freq_int}" && "${w_freq_int}" =~ ^[0-9]+$ ]]; then
                if (( w_freq_int >= 2400 && w_freq_int <= 2500 )); then w_band="2.4GHz"
                elif (( w_freq_int >= 5150 && w_freq_int <= 5895 )); then w_band="5GHz"
                elif (( w_freq_int >= 5925 && w_freq_int <= 7125 )); then w_band="6GHz"
                fi
            fi
        fi

        local w_ip w_gw
        w_ip="$(ip -4 -o addr show dev "${wif}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
        w_gw="$(ip -4 route show dev "${wif}" 2>/dev/null | awk '/default via/{print $3}' | head -n1 || echo "")"
        [[ -z "${w_ip}" ]] && w_ip="-"
        [[ -z "${w_gw}" ]] && w_gw="-"

        local status_colored
        if [[ "${w_status}" == "CONNECTED" ]]; then
            status_colored="\e[1;32mCONNECTED\e[0m"
        else
            status_colored="\e[1;33mDISCONNECTED\e[0m"
        fi

        local ssid_disp="${w_ssid}"
        if [[ "${w_status}" == "CONNECTED" && "${w_band}" != "-" ]]; then
            ssid_disp="${w_ssid} (${w_band})"
        fi

        printf '%-19s %-20s \e[1;36m%-10s\e[0m %-22s %-24s %-15s %-14s %b\n' \
            "[Host] ${wif}" "Physical OTA Wi-Fi" "PHYSICAL" "OTA Hardware (RF)" "${ssid_disp}" "${w_ip}" "${w_gw}" "${status_colored}"
    done

    # --- Remote Wi-Fi Station Row ---
    if [[ -n "${REMOTE_CLIENT_HOST:-}" ]] && [[ -x "${SCRIPT_DIR}/remote_client.sh" ]]; then
        local r_env
        r_env="$("${SCRIPT_DIR}/remote_client.sh" wifi-env 2>/dev/null || true)"
        if [[ -n "${r_env}" ]]; then
            eval "${r_env}"
            local r_status="${REMOTE_WIFI_STATUS:-DISCONNECTED}"
            local r_colored
            if [[ "${r_status}" == "CONNECTED" ]]; then
                r_colored="\e[1;32mCONNECTED\e[0m"
            else
                r_colored="\e[1;33mDISCONNECTED\e[0m"
            fi
            local r_ssid_disp="${REMOTE_WIFI_SSID:-none}"
            if [[ "${r_status}" == "CONNECTED" && -n "${REMOTE_WIFI_BAND:-}" ]]; then
                r_ssid_disp="${r_ssid_disp} (${REMOTE_WIFI_BAND})"
            fi
            printf '%-19s %-20s \e[1;36m%-10s\e[0m %-22s %-24s %-15s %-14s %b\n' \
                "[Remote] ${REMOTE_CLIENT_HOST}" "Distributed Wi-Fi" "PHYSICAL" "OTA Hardware (SSH)" "${r_ssid_disp}" "${REMOTE_WIFI_IP:--}" "${REMOTE_WIFI_GATEWAY:--}" "${r_colored}"
        fi
    fi

    # --- Namespace Rows ---
    for entry in "${all_endpoints[@]}"; do
        local ns role type veth_h target_ssid band is_wifi
        IFS=":" read -r ns role type veth_h target_ssid band is_wifi <<< "${entry}"

        if (( filter_wifi == 1 && is_wifi == 0 )); then
            continue
        fi

        if ! ns_exists "${ns}"; then
            continue
        fi

        local v_ip="-" v_gw="-" v_status="DISCONNECTED"
        if [[ "${ns}" == "${WAN_NS:-ns-wan}" ]]; then
            v_ip="${WAN_SERVER_IP:-10.10.0.1}"
            v_gw="-"
            v_status="UP"
        elif [[ "${ns}" == "${DUT_NS:-ns-dut}" ]]; then
            if is_root; then
                local lan_ip wan_ip
                lan_ip="$(ip -n "${ns}" -4 -o addr show dev br-lan 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
                wan_ip="$(ip -n "${ns}" -4 -o addr show dev eth-wan 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
                v_gw="$(ip -n "${ns}" -4 route show default 2>/dev/null | awk '{print $3}' | head -n1 || echo "")"
                if [[ -n "${lan_ip}" ]]; then
                    v_ip="${lan_ip}"
                    v_status="UP"
                elif [[ -n "${wan_ip}" ]]; then
                    v_ip="${wan_ip}"
                    v_status="UP"
                fi
            else
                v_ip="${DUT_LAN_IP:-192.168.1.1}"
                v_gw="${WAN_SERVER_IP:-10.10.0.1}"
                v_status="UP"
            fi
        elif is_root; then
            v_ip="$(ip -n "${ns}" -4 -o addr show dev eth0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
            v_gw="$(ip -n "${ns}" -4 route show default 2>/dev/null | awk '{print $3}' | head -n1 || echo "")"
            if [[ -n "${v_ip}" ]]; then v_status="CONNECTED"; fi
        else
            v_ip="$(awk '/lease of/{ip=$4} END{print ip}' "${LOG_DIR}/udhcpc-${ns}.log" 2>/dev/null || echo "")"
            v_gw="$(awk '/lease of/{gw=$7} END{print gw}' "${LOG_DIR}/udhcpc-${ns}.log" 2>/dev/null | tr -d ',' || echo "")"
            local pidfile="${STATE_DIR}/udhcpc-${ns}.pid"
            if is_pidfile_running "${pidfile}" && [[ -n "${v_ip}" ]]; then
                v_status="CONNECTED"
            elif is_pidfile_running "${pidfile}"; then
                v_status="CONNECTING"
            fi
        fi
        [[ -z "${v_ip}" ]] && v_ip="-"
        [[ -z "${v_gw}" ]] && v_gw="-"

        local medium="veth: ${veth_h}"
        if [[ "${ns}" == "${DUT_NS:-ns-dut}" ]]; then
            medium="br-lan + eth-wan"
        elif [[ -z "${veth_h}" || "${veth_h}" == "-" ]]; then
            medium="netns link"
        fi

        local ssid_disp="-"
        if [[ -n "${target_ssid}" && "${target_ssid}" != "-" ]]; then
            ssid_disp="${target_ssid}"
            if [[ -n "${band}" && "${band}" != "-" ]]; then
                ssid_disp="${ssid_disp} (${band})"
            fi
        fi

        local v_colored
        if [[ "${v_status}" == "CONNECTED" || "${v_status}" == "UP" ]]; then
            v_colored="\e[1;32m${v_status}\e[0m"
        elif [[ "${v_status}" == "CONNECTING" ]]; then
            v_colored="\e[1;33mCONNECTING\e[0m"
        else
            v_colored="\e[1;31mDISCONNECTED\e[0m"
        fi

        printf '%-19s %-20s \e[1;35m%-10s\e[0m %-22s %-24s %-15s %-14s %b\n' \
            "${ns}" "${role}" "VIRTUAL" "${medium}" "${ssid_disp}" "${v_ip}" "${v_gw}" "${v_colored}"
    done

    # 4. Detailed Inspection Cards & In-Depth Status
    printf '\n\e[1;37mDetailed Interface & Namespace Inspection:\e[0m\n'

    # 4.1 Physical Wi-Fi Details
    if (( ${#phy_devs[@]} > 0 )); then
        for wif in "${phy_devs[@]}"; do
            local w_link w_ssid="" w_bssid="" w_freq="" w_signal="" w_txrate="" w_status="DISCONNECTED" w_chan=""
            w_link="$(iw dev "${wif}" link 2>/dev/null || true)"
            if [[ -n "${w_link}" && "${w_link}" != *"Not connected"* ]]; then
                w_status="CONNECTED"
                w_ssid="$(printf '%s\n' "${w_link}" | awk -F'SSID: ' '/SSID:/{print $2}' | xargs || true)"
                w_bssid="$(printf '%s\n' "${w_link}" | awk '/Connected to/{print $3}' | tr -d '()' || true)"
                w_freq="$(printf '%s\n' "${w_link}" | awk '/freq:/{print $2}' || true)"
                w_signal="$(printf '%s\n' "${w_link}" | awk -F'signal: ' '/signal:/{print $2}' | xargs || true)"
                w_txrate="$(printf '%s\n' "${w_link}" | awk -F'tx bitrate: ' '/tx bitrate:/{print $2}' | xargs || true)"
            fi

            # Band & Channel detection
            local w_band="Unknown"
            local w_freq_int="${w_freq//[!0-9.]/}"
            w_freq_int="${w_freq_int%%.*}"
            if [[ -n "${w_freq_int}" && "${w_freq_int}" =~ ^[0-9]+$ ]]; then
                if (( w_freq_int >= 2400 && w_freq_int <= 2500 )); then w_band="2.4GHz"
                elif (( w_freq_int >= 5150 && w_freq_int <= 5895 )); then w_band="5GHz"
                elif (( w_freq_int >= 5925 && w_freq_int <= 7125 )); then w_band="6GHz"
                fi
            fi

            w_chan="$(iw dev "${wif}" info 2>/dev/null | awk '/channel/{print $2}' || true)"
            [[ -z "${w_chan}" ]] && w_chan="-"

            # IP & Gateway
            local w_ip w_gw
            w_ip="$(ip -4 -o addr show dev "${wif}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1 || echo "")"
            w_gw="$(ip -4 route show dev "${wif}" 2>/dev/null | awk '/default via/{print $3}' | head -n1 || echo "")"
            [[ -z "${w_ip}" ]] && w_ip="-"
            [[ -z "${w_gw}" ]] && w_gw="-"

            # Supported Bands
            local supp_bands=""
            if command -v iw >/dev/null 2>&1; then
                local phy_info
                phy_info="$(iw phy 2>/dev/null || true)"
                local b2=0 b5=0 b6=0
                if printf '%s\n' "${phy_info}" | grep -Eq "24[0-9]{2}\.[0-9]\s+MHz"; then b2=1; fi
                if printf '%s\n' "${phy_info}" | grep -Eq "5[1-8][0-9]{2}\.[0-9]\s+MHz"; then b5=1; fi
                if printf '%s\n' "${phy_info}" | grep -Eq "59[2-9][0-9]\.[0-9]|6[0-9]{3}\.[0-9]"; then b6=1; fi
                local s_arr=()
                (( b2 == 1 )) && s_arr+=("2.4GHz")
                (( b5 == 1 )) && s_arr+=("5GHz")
                (( b6 == 1 )) && s_arr+=("6GHz")
                supp_bands="$(IFS=', '; echo "${s_arr[*]}")"
            fi
            [[ -z "${supp_bands}" ]] && supp_bands="${PHYSICAL_WIFI_SUPPORTED_BANDS:-Unknown}"

            local status_colored
            if [[ "${w_status}" == "CONNECTED" ]]; then
                status_colored="\e[1;32mCONNECTED\e[0m"
            else
                status_colored="\e[1;33mDISCONNECTED\e[0m"
            fi

            printf '  • \e[1;36m%s\e[0m [Host Physical Wi-Fi Adapter]\n' "${wif}"
            printf '    - Connection Type : \e[1;36mPHYSICAL\e[0m (Real Over-The-Air RF Hardware Adapter)\n'
            printf '    - Connection State: %b\n' "${status_colored}"
            if [[ "${w_status}" == "CONNECTED" ]]; then
                printf '    - Connected SSID  : \e[1;35m%s\e[0m (BSSID: %s)\n' "${w_ssid}" "${w_bssid:-N/A}"
                printf '    - RF Parameters   : Frequency: %s MHz (%s) | Channel: %s\n' "${w_freq:-N/A}" "${w_band}" "${w_chan}"
                printf '    - Signal & Bitrate: Signal: %s | TX Bitrate: %s\n' "${w_signal:-N/A}" "${w_txrate:-N/A}"
            else
                printf '    - Connected SSID  : \e[1;33m(None / Unassociated)\e[0m\n'
                printf '    - Target DUT SSID : %s (Configured in config.env)\n' "${DUT_SSID_5G:-DUT_5G}"
                printf '    - Action to Link  : Run \e[1;36msudo ./scripts/wifi_connect.sh connect 5g\e[0m\n'
            fi
            printf '    - IP / Gateway    : IPv4: %s | Gateway: %s\n' "${w_ip}" "${w_gw}"
            printf '    - Hardware Bands  : [%s]\n' "${supp_bands}"
            printf '    - Test Allocation : Active OTA adapter for TC-SIM-01 (real_single_band benchmark)\n'
        done
    fi

    # 4.2 Remote Client Station Details (if configured)
    if [[ -n "${REMOTE_CLIENT_HOST:-}" ]] && [[ -x "${SCRIPT_DIR}/remote_client.sh" ]]; then
        local r_env
        r_env="$("${SCRIPT_DIR}/remote_client.sh" wifi-env --check-ping "${DUT_LAN_IP:-192.168.1.1}" 2>/dev/null || true)"
        if [[ -n "${r_env}" ]]; then
            eval "${r_env}"
            local r_status="${REMOTE_WIFI_STATUS:-DISCONNECTED}"
            local r_status_colored
            if [[ "${r_status}" == "CONNECTED" ]]; then
                r_status_colored="\e[1;32mCONNECTED\e[0m"
            else
                r_status_colored="\e[1;33mDISCONNECTED\e[0m"
            fi

            printf '  • \e[1;36m[Remote Station] %s\e[0m (%s)\n' "${REMOTE_CLIENT_HOST}" "${REMOTE_WIFI_IF:-wlan0}"
            printf '    - Connection Type : \e[1;36mDISTRIBUTED PHYSICAL\e[0m (Secondary Wi-Fi Client via SSH)\n'
            printf '    - Connection State: %b\n' "${r_status_colored}"
            if [[ "${r_status}" == "CONNECTED" ]]; then
                printf '    - Connected SSID  : \e[1;35m%s\e[0m (BSSID: %s)\n' "${REMOTE_WIFI_SSID:-none}" "${REMOTE_WIFI_BSSID:-N/A}"
                printf '    - RF Parameters   : Frequency: %s | Band: %s | Channel: %s | Width: %s\n' "${REMOTE_WIFI_BAND:-N/A}" "${REMOTE_WIFI_BAND:-N/A}" "${REMOTE_WIFI_CHANNEL:-N/A}" "${REMOTE_WIFI_WIDTH:-N/A}"
                printf '    - Signal & Bitrate: Signal: %s | TX Bitrate: %s\n' "${REMOTE_WIFI_SIGNAL:-N/A}" "${REMOTE_WIFI_BITRATE:-N/A}"
                printf '    - IP / Gateway    : IPv4: %s | Gateway: %s\n' "${REMOTE_WIFI_IP:-none}" "${REMOTE_WIFI_GATEWAY:-none}"
                if [[ "${REMOTE_WIFI_PING_OK:-0}" == "1" ]]; then
                    printf '    - DUT Reachability: \e[1;32mREACHABLE\e[0m (Ping RTT: %s)\n' "${REMOTE_WIFI_PING_RTT:-<1ms}"
                else
                    printf '    - DUT Reachability: \e[1;31mFAILED\e[0m (Cannot ping gateway %s)\n' "${DUT_LAN_IP:-192.168.1.1}"
                fi
            else
                printf '    - Connected SSID  : \e[1;33m(None / Unassociated)\e[0m\n'
                printf '    - Target DUT SSID : %s\n' "${DUT_SSID_2G:-DUT_2.4G}"
                printf '    - Action to Link  : Run \e[1;36m./scripts/remote_client.sh wifi-connect 2g\e[0m\n'
            fi
            printf '    - Test Allocation : Remote Phone 2 for VoIP QoS (TC-QOS-01) / 3-way concurrent station\n'
        fi
    fi

    # 4.3 Namespaces Details
    if is_root; then
        for entry in "${all_endpoints[@]}"; do
            local ns role type veth_h target_ssid band is_wifi
            IFS=":" read -r ns role type veth_h target_ssid band is_wifi <<< "${entry}"
            if (( filter_wifi == 1 && is_wifi == 0 )); then continue; fi
            if ! ns_exists "${ns}"; then continue; fi

            printf '  • \e[1;36m%s\e[0m [%s | Type: \e[1;35m%s\e[0m (veth: %s)]\n' "${ns}" "${role}" "${type}" "${veth_h:-internal}"
            if [[ -n "${target_ssid}" && "${target_ssid}" != "-" ]]; then
                printf '    - Target SSID     : \e[1;35m%s\e[0m (Band: %s)\n' "${target_ssid}" "${band}"
            fi
            ip netns exec "${ns}" ip -br -4 addr show 2>/dev/null | awk '{printf "    [IPv4] %-10s %s\n", $1, $3}' || true
            ip netns exec "${ns}" ip -br -6 addr show 2>/dev/null | awk '{printf "    [IPv6] %-10s %s\n", $1, $3}' || true
            ip netns exec "${ns}" ip -4 route show 2>/dev/null | awk '{printf "    v4 route: %s\n", $0}' || true
            ip netns exec "${ns}" ip -6 route show default 2>/dev/null | awk '{printf "    v6 route: %s\n", $0}' || true
            if [[ "${ns}" == "${DUT_NS:-ns-dut}" ]]; then
                local tc_wan tc_stb
                tc_wan="$(ip netns exec "${ns}" tc qdisc show dev eth-wan 2>/dev/null || true)"
                [[ -n "${tc_wan}" ]] && printf '    tc qdisc (eth-wan): %s\n' "${tc_wan}"
                tc_stb="$(ip netns exec "${ns}" tc qdisc show dev veth-dut-stb 2>/dev/null || true)"
                [[ -n "${tc_stb}" ]] && printf '    tc qdisc (veth-dut-stb): %s\n' "${tc_stb}"
            elif [[ "${ns}" == "${STB_NS:-ns-stb}" ]]; then
                local tc_info
                tc_info="$(ip netns exec "${ns}" tc qdisc show dev eth0 2>/dev/null || true)"
                [[ -n "${tc_info}" ]] && printf '    tc qdisc: %s\n' "${tc_info}"
            fi
        done
    else
        printf '  Note: Run with sudo to inspect internal routing tables, IPv6 SLAAC, and traffic control rules.\n'
        for entry in "${all_endpoints[@]}"; do
            local ns role type veth_h target_ssid band is_wifi
            IFS=":" read -r ns role type veth_h target_ssid band is_wifi <<< "${entry}"
            if (( filter_wifi == 1 && is_wifi == 0 )); then continue; fi
            if ! ns_exists "${ns}"; then continue; fi

            local cur_ip="-" cur_gw="-" mac="-"
            if [[ "${ns}" == "${WAN_NS:-ns-wan}" ]]; then
                cur_ip="${WAN_SERVER_IP:-10.10.0.1}"
                cur_gw="-"
            elif [[ "${ns}" == "${DUT_NS:-ns-dut}" ]]; then
                cur_ip="${DUT_LAN_IP:-192.168.1.1}"
                cur_gw="${WAN_SERVER_IP:-10.10.0.1}"
            else
                cur_ip="$(awk '/lease of/{ip=$4} END{print ip}' "${LOG_DIR}/udhcpc-${ns}.log" 2>/dev/null || echo "")"
                cur_gw="$(awk '/lease of/{gw=$7} END{print gw}' "${LOG_DIR}/udhcpc-${ns}.log" 2>/dev/null | tr -d ',' || echo "")"
                [[ -z "${cur_ip}" ]] && cur_ip="-"
                [[ -z "${cur_gw}" ]] && cur_gw="-"
            fi
            mac="$(cat "/sys/class/net/${veth_h}/address" 2>/dev/null || echo "N/A")"

            local ssid_note=""
            if [[ -n "${target_ssid}" && "${target_ssid}" != "-" ]]; then
                ssid_note=" | Target SSID: ${target_ssid}"
            fi

            printf '  • \e[1;36m%-14s\e[0m [%-22s | veth: %-8s%s] IPv4: %-15s Gateway: %s (MAC: %s)\n' \
                "${ns}" "${role}" "${veth_h:-internal}" "${ssid_note}" "${cur_ip}" "${cur_gw}" "${mac}"
        done
    fi
}

main() {
    local wifi_only=0
    for arg in "$@"; do
        case "${arg}" in
            -h|--help)
                usage
                exit 0
                ;;
            -w|--wifi)
                wifi_only=1
                ;;
        esac
    done

    load_config
    if [[ -f "${STATE_DIR}/topology_state.env" ]]; then
        # shellcheck disable=SC1090
        source "${STATE_DIR}/topology_state.env"
    fi

    print_header "NETWORK TEST LAB RUNTIME STATE"

    # 1. Topology State
    print_section "TOPOLOGY METADATA"
    if [[ -f "${STATE_DIR}/topology_state.env" ]]; then
        cat "${STATE_DIR}/topology_state.env"
    else
        printf 'No active topology state found (run sudo ./scripts/setup.sh).\n'
    fi

    # 2. Linux Bridges
    print_section "BRIDGES & PORTS"
    local br
    for br in "${WAN_BRIDGE:-br-test-wan}" "${LAN_BRIDGE:-br-test-lan}"; do
        if bridge_exists "${br}"; then
            printf 'Bridge: %s (State: UP)\n' "${br}"
            ip link show master "${br}" 2>/dev/null | grep -E '^[0-9]+:' | awk '{print "  - Member: "$2}' | tr -d ':' || true
        else
            printf 'Bridge: %s (NOT FOUND)\n' "${br}"
        fi
    done

    # 3. All Network Namespaces & Interfaces (Unified with Physical & Virtual Wi-Fi)
    print_namespaces_section "${wifi_only}"

    # 4. Supervised Daemons & Stale PID Detection
    print_section "SUPERVISED DAEMONS & SERVICES"
    local pid_found=0
    local pid_file
    for pid_file in "${STATE_DIR}"/*.pid; do
        if [[ -f "${pid_file}" ]]; then
            pid_found=1
            local name pid
            name="$(basename "${pid_file}" .pid)"
            pid="$(cat "${pid_file}" 2>/dev/null || true)"
            if is_pidfile_running "${pid_file}"; then
                printf '  %-24s -> \e[1;32mRUNNING\e[0m (PID: %s)\n' "${name}" "${pid}"
            else
                printf '  %-24s -> \e[1;31mSTALE PID FILE\e[0m (Process dead)\n' "${name}"
            fi
        fi
    done
    if (( pid_found == 0 )); then
        printf 'No active daemon PID files registered.\n'
    fi

    # 5. Packet Captures
    print_section "PACKET CAPTURES"
    if [[ -d "${CAPTURE_DIR}" ]]; then
        local pcap_count=0
        while IFS= read -r pcap_path; do
            if [[ -f "${pcap_path}" ]]; then
                pcap_count=$((pcap_count + 1))
                local size
                size="$(du -h "${pcap_path}" | cut -f1)"
                printf '  [%s] %s\n' "${size}" "$(basename "${pcap_path}")"
            fi
        done < <(find "${CAPTURE_DIR}" -maxdepth 1 -name '*.pcap*' -type f -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk '{print $2}' | head -n 5)
        if (( pcap_count == 0 )); then
            printf 'No PCAP capture files found in %s.\n' "${CAPTURE_DIR}"
        fi
    fi
    printf '==================================================================\n'
}

main "$@"

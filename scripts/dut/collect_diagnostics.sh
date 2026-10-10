#!/bin/sh
# ==============================================================================
# DUT Full Diagnostic Telemetry Collection Suite
# Gathers system, link, hardware pause/drop, QoS, conntrack, wireless, and log snapshots.
# Archives them into a compressed tarball and streams hex via xxd.
# ==============================================================================

rm -rf /tmp/dut_artifacts && mkdir -p /tmp/dut_artifacts

run_save() {
    fname="/tmp/dut_artifacts/$1"
    shift
    echo "=== [COMMAND: $*] ===" > "$fname"
    "$@" >> "$fname" 2>&1 || true
}

# 1. System Overview
run_save dut_01_system.txt uname -a
run_save dut_02_uptime.txt uptime
run_save dut_03_memory.txt free -m
run_save dut_04_cpuinfo.txt cat /proc/cpuinfo
run_save dut_05_version.txt cat /proc/version

# 2. Network & Interfaces
run_save dut_06_ip_links.txt ip -d link show
run_save dut_07_ip_addrs.txt ip addr show
run_save dut_08_ip_routes.txt ip route show
run_save dut_09_ip_routes6.txt ip -6 route show
run_save dut_10_ip_neigh.txt ip neigh show
run_save dut_11_arp_table.txt cat /proc/net/arp
run_save dut_12_bridge_fdb.txt bridge fdb show
run_save dut_13_bridge_link.txt bridge link show

# 3. Drops & Statistics
run_save dut_14_link_stats.txt ip -s link show
run_save dut_15_proc_net_dev.txt cat /proc/net/dev

# Ethtool hardware drop/pause inspection
if has_cmd ethtool; then
    for iface in eth0 eth1 eth2 eth3 eth4 br0 wl0 wl1 wl2; do
        run_save "dut_16_ethtool_${iface}.txt" ethtool -S "$iface"
        run_save "dut_17_ethtool_drv_${iface}.txt" ethtool -i "$iface"
    done
fi

# 4. QoS & Traffic Control
if has_cmd tc; then
    run_save dut_18_tc_qdisc.txt tc -s qdisc show
    run_save dut_19_tc_class.txt tc -s class show
    run_save dut_20_tc_filter.txt tc -s filter show
fi
if has_cmd iptables-save; then
    run_save dut_21_iptables_save.txt iptables-save
fi
if has_cmd iptables; then
    run_save dut_22_iptables_mangle.txt iptables -t mangle -nvL
    run_save dut_23_iptables_nat.txt iptables -t nat -nvL
fi
if has_cmd nft; then
    run_save dut_23_nft_ruleset.txt nft list ruleset
fi

# 5. Conntrack & Buffers
if [ -f /proc/sys/net/netfilter/nf_conntrack_count ]; then
    run_save dut_24_conntrack_count.txt cat /proc/sys/net/netfilter/nf_conntrack_count
    run_save dut_25_conntrack_max.txt cat /proc/sys/net/netfilter/nf_conntrack_max
fi
run_save dut_26_sysctl_net.txt sysctl net

# 6. Wireless Subsystem
if has_cmd wl; then
    for wlif in wl0 wl1 wl2; do
        if wl -i "$wlif" status >/dev/null 2>&1; then
            run_save "dut_27_${wlif}_status.txt" wl -i "$wlif" status
            run_save "dut_28_${wlif}_assoclist.txt" wl -i "$wlif" assoclist
            run_save "dut_29_${wlif}_counters.txt" wl -i "$wlif" counters
            run_save "dut_30_${wlif}_wme_ap.txt" wl -i "$wlif" wme_ac ap
            run_save "dut_31_${wlif}_wme_sta.txt" wl -i "$wlif" wme_ac sta
        fi
    done
elif has_cmd iw; then
    run_save dut_27_iw_dev.txt iw dev
    run_save dut_28_iw_phy.txt iw phy
fi

# 7. Logs
run_save dut_32_dmesg.log dmesg
if has_cmd logread; then
    run_save dut_33_logread.log logread
elif [ -f /var/log/messages ]; then
    run_save dut_33_messages.log cat /var/log/messages
elif [ -f /tmp/log/messages ]; then
    run_save dut_33_messages.log cat /tmp/log/messages
fi

# Package artifacts into compressed tarball and stream via xxd
tar -czf /tmp/dut_artifacts.tar.gz -C /tmp/dut_artifacts .
xxd -p /tmp/dut_artifacts.tar.gz
rm -rf /tmp/dut_artifacts /tmp/dut_artifacts.tar.gz

#!/bin/sh
# ==============================================================================
# DUT Environment & Tool Capability Probe
# Runs on remote target (DUT) over POSIX sh to inspect OS release and tools.
# ==============================================================================

echo "AUTH:OK"
echo "UNAME:$(uname -srm 2>/dev/null || echo "unknown")"
echo "HOSTNAME:$(hostname 2>/dev/null || echo "unknown")"
echo "UPTIME:$(uptime 2>/dev/null || echo "unknown")"

# Check OS release
os_name="Generic Linux"
if [ -f /etc/openwrt_release ]; then
    os_name="OpenWrt"
elif [ -f /etc/os-release ]; then
    os_name="$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
fi
echo "OS_NAME:${os_name}"

# Probe networking & QoS tools
for tool in ip tc ethtool brctl bridge iptables nft uci wl iw hostapd_cli; do
    if has_cmd "$tool"; then
        tool_path="$(which "$tool" 2>/dev/null || echo "$tool")"
        echo "TOOL:${tool}:AVAILABLE:${tool_path}"
    else
        echo "TOOL:${tool}:MISSING"
    fi
done

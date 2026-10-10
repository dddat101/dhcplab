#!/bin/sh
# ==============================================================================
# DUT Runtime Status Overview
# Runs on remote target (DUT) over POSIX sh to dump system, link, and qdisc status.
# ==============================================================================

echo "=== [SYSTEM & UPTIME] ==="
uptime 2>/dev/null || true
free -m 2>/dev/null || free 2>/dev/null || true
echo ""

echo "=== [NETWORK INTERFACES] ==="
ip -d link show 2>/dev/null | grep -E "^[0-9]+: " | awk '{print $2}' | tr -d ":" || true
echo ""

echo "=== [WIRELESS SUBSYSTEM] ==="
if has_cmd wl; then
    echo "Wireless Driver: wl CLI detected"
    for wlif in wl1 wl0 wl2; do
        if wl -i "$wlif" status >/dev/null 2>&1; then
            echo "--- Interface: $wlif ---"
            wl -i "$wlif" status 2>/dev/null | grep -E "SSID:|Channel:|Mode:|BSSID:|QBSS" || true
        fi
    done
elif has_cmd iw; then
    echo "Wireless Driver: nl80211 (iw) detected"
    iw dev 2>/dev/null || true
else
    echo "No standard wireless CLI (wl / iw) detected."
fi
echo ""

echo "=== [QOS & TC QDISC] ==="
if has_cmd tc; then
    tc -s qdisc show 2>/dev/null || true
else
    echo "tc tool not found on DUT."
fi

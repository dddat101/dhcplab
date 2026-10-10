#!/bin/sh
# ==============================================================================
# DUT AP-Side WMM EDCA Parameter Extractor
# Usage: wmm_edca.sh [INTERFACE] [BSSID] [BAND]
# Runs on remote target (DUT) over POSIX sh to extract AP-side WMM parameters.
# ==============================================================================

sel_if="${1:-}"
want_bssid="${2:-}"
want_band="${3:-}"

if has_cmd wl; then
    cands=""
    for c in wl0 wl1 wl2 wl3; do
        if wl -i "$c" status >/dev/null 2>&1; then
            cands="$cands $c"
        fi
    done

    radio_bssid() {
        wl -i "$1" status 2>/dev/null | sed -n "s/.*BSSID: \([0-9A-Fa-f:]*\).*/\1/p" | sed -n 1p | tr "A-F" "a-f"
    }

    # Selection priority: explicit iface > BSSID match > band match > first active radio
    if [ -z "$sel_if" ] && [ -n "$want_bssid" ]; then
        for c in $cands; do
            if [ "$(radio_bssid "$c")" = "$want_bssid" ]; then
                sel_if="$c"
                echo "MATCH:bssid"
                break
            fi
        done
    fi

    if [ -z "$sel_if" ] && [ -n "$want_band" ]; then
        for c in $cands; do
            if wl -i "$c" status 2>/dev/null | grep -q "Chanspec: ${want_band}"; then
                sel_if="$c"
                echo "MATCH:band"
                break
            fi
        done
    fi

    if [ -z "$sel_if" ]; then
        for c in $cands; do
            sel_if="$c"
            echo "MATCH:first_active"
            break
        done
    fi

    [ -z "$sel_if" ] && { echo "DRIVER:NO_ACTIVE_RADIO"; exit 0; }

    echo "DRIVER:WL_CLI"
    echo "INTERFACE:${sel_if}"
    echo "BSSID:$(radio_bssid "$sel_if")"
    echo "CHANSPEC:$(wl -i "$sel_if" status 2>/dev/null | sed -n "s/^[[:space:]]*Chanspec: //p" | sed -n 1p)"
    echo "--- AP_EDCA ---"
    wl -i "${sel_if}" wme_ac ap 2>/dev/null || true
    echo "--- STA_EDCA ---"
    wl -i "${sel_if}" wme_ac sta 2>/dev/null || true
    exit 0
fi

if has_cmd hostapd_cli; then
    echo "DRIVER:HOSTAPD_UNSUPPORTED"
    exit 0
fi

echo "DRIVER:UNKNOWN"

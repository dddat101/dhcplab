#!/bin/sh
# ==============================================================================
# DUT /proc/net/dev Interface Counter Snapshot
# Runs on remote target (DUT) over POSIX sh to dump interface traffic & drop stats.
# ==============================================================================

awk 'NR > 2 {
    iface=$1; sub(":", "", iface);
    rx_b=$2; rx_p=$3; rx_err=$4; rx_drp=$5;
    tx_b=$10; tx_p=$11; tx_err=$12; tx_drp=$13;
    print iface, rx_p, rx_b, rx_drp, rx_err, tx_p, tx_b, tx_drp, tx_err;
}' /proc/net/dev 2>/dev/null || true

#!/usr/bin/env python3
"""
Broadband Gateway Test Lab - IEEE 802.11e Wireless QoS Multi-Service Audit Tool

Audits standard Wireless QoS mapping (IEEE 802.11e WMM & RFC 2474 DSCP):
- Voice Service: DSCP 46 (0xb8 / EF) -> 802.11e WMM AC_VO (TID 6/7)
- Video Service: DSCP 34 (0x88 / AF41) -> 802.11e WMM AC_VI (TID 4/5)
- Best Effort  : DSCP 0 (0x00 / CS0) -> 802.11e WMM AC_BE (TID 0/3)

Audits packet preservation, cross-DUT packet loss, jitter, and QoS priority separation
across WAN Ingress and Wi-Fi/LAN Egress captures.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from evidence_auditor import (
    EvidenceError,
    audit_captures,
    load_json,
    parse_rtp_streams,
    run_tshark_count,
    run_tshark_sum_bytes,
)



# ------------------------------------------------------------------------------
# IEEE 802.11e WMM EDCA Parameter Audit
# ------------------------------------------------------------------------------
# Scope notes:
#   * The WMM Parameter Element carried in Beacon / Probe Response frames defines
#     the EDCA parameters that associated STATIONS must use (uplink contention).
#   * The AP's own transmit EDCA parameters (downlink) are configured separately
#     on the AP (e.g. hostapd tx_queue_data*, or vendor "AP-side" WME tables) and
#     are NOT carried over the air. They can only be verified from the DUT
#     configuration (supplied via --ap-edca-json).
#   * No value is ever synthesized: if parameters cannot be read, the verdict is
#     NOT_VERIFIED.

AC_ORDER = ("AC_VO", "AC_VI", "AC_BE", "AC_BK")

AC_META: Dict[str, Dict[str, Any]] = {
    "AC_VO": {"label": "Voice (AC_VO)", "service": "Voice (VoIP / VoWiFi)", "dscp_target": "46 (0xb8 / EF)", "tid": 6},
    "AC_VI": {"label": "Video (AC_VI)", "service": "Video (IPTV / VOD)", "dscp_target": "34 (0x88 / AF41)", "tid": 4},
    "AC_BE": {"label": "BestEff (AC_BE)", "service": "Best Effort (Bulk Data)", "dscp_target": "0 (0x00 / CS0)", "tid": 0},
    "AC_BK": {"label": "Backgrd (AC_BK)", "service": "Background Load", "dscp_target": "8 (0x20 / CS1)", "tid": 1},
}

# IEEE 802.11 default EDCA Parameter Set for STAs on OFDM PHYs
# (aCWmin = 15, aCWmax = 1023). CW values are window sizes in slots (2^ECW - 1).
IEEE_DEFAULT_STA_EDCA: Dict[str, Dict[str, int]] = {
    "AC_VO": {"aifsn": 2, "cwmin": 3, "cwmax": 7, "txop_limit_us": 1504},
    "AC_VI": {"aifsn": 2, "cwmin": 7, "cwmax": 15, "txop_limit_us": 3008},
    "AC_BE": {"aifsn": 3, "cwmin": 15, "cwmax": 1023, "txop_limit_us": 0},
    "AC_BK": {"aifsn": 7, "cwmin": 15, "cwmax": 1023, "txop_limit_us": 0},
}

EDCA_LINE_RE = re.compile(
    r"\*\s+(VO|VI|BE|BK):\s+(?:acm\s+)?CW\s+(\d+)-(\d+),\s+AIFSN\s+(\d+)(?:,\s+TXOP\s+(\d+)\s+usec)?"
)
BSS_HEADER_RE = re.compile(r"^BSS\s+([0-9a-fA-F:]{17})")


def extract_connected_bssid(wifi_if: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (bssid, ssid, phy_rate) from `iw dev <wifi_if> link`."""
    try:
        proc = subprocess.run(["iw", "dev", wifi_if, "link"], capture_output=True, text=True, check=False)
        out = proc.stdout
        bssid_m = re.search(r"Connected to ([0-9a-fA-F:]{17})", out)
        ssid_m = re.search(r"SSID:\s*(.+)", out)
        rate_m = re.search(r"tx bitrate:\s*(.+)", out)
        return (
            bssid_m.group(1).lower() if bssid_m else None,
            ssid_m.group(1).strip() if ssid_m else None,
            rate_m.group(1).strip() if rate_m else None,
        )
    except Exception:
        return None, None, None


def check_station_wmm_support(wifi_if: str) -> bool:
    """Return True if `iw dev <wifi_if> station dump` reports WMM/WME: yes."""
    try:
        proc = subprocess.run(["iw", "dev", wifi_if, "station", "dump"], capture_output=True, text=True, check=False)
        return re.search(r"WMM/WME:\s*yes", proc.stdout) is not None
    except Exception:
        return False


def detect_first_wifi_iface() -> Optional[str]:
    """Auto-detect the first wireless interface known to nl80211."""
    try:
        proc = subprocess.run(["iw", "dev"], capture_output=True, text=True, check=False)
        found = re.findall(r"Interface\s+([a-zA-Z0-9_\-]+)", proc.stdout)
        if found:
            return found[0]
    except Exception:
        pass
    return None


def is_wireless_iface(wifi_if: str) -> bool:
    """True if the interface is a real nl80211 wireless device (not a veth / bridge)."""
    return Path(f"/sys/class/net/{wifi_if}/wireless").exists() or Path(f"/sys/class/net/{wifi_if}/phy80211").exists()


def select_bss_block(scan_out: str, bssid: Optional[str]) -> str:
    """Select the scan-dump block whose header line is exactly `BSS <bssid>`."""
    blocks = re.split(r"\n(?=BSS [0-9a-fA-F:]{17})", scan_out)
    for block in blocks:
        header = BSS_HEADER_RE.match(block.strip())
        if not header:
            continue
        if bssid and header.group(1).lower() == bssid.lower():
            return block
        if not bssid and "-- associated" in block.splitlines()[0]:
            return block
    return ""


def parse_wmm_parameter_element(bss_block: str) -> Tuple[Dict[str, Dict[str, int]], bool, Dict[str, Any]]:
    """Parse the WMM Parameter Element section of one BSS block."""
    params: Dict[str, Dict[str, int]] = {}
    meta: Dict[str, Any] = {"ie_source": "unknown", "last_seen_ms": None, "wmm_ie_present": False}

    src_m = re.search(r"Information elements from (Probe Response|Beacon) frame", bss_block)
    if src_m:
        meta["ie_source"] = src_m.group(1)
    seen_m = re.search(r"last seen:\s*(\d+)\s*ms", bss_block)
    if seen_m:
        meta["last_seen_ms"] = int(seen_m.group(1))

    wmm_m = re.search(r"\n\tWMM:(.*?)(?=\n\t[A-Za-z]|\Z)", bss_block, re.DOTALL)
    if not wmm_m:
        return params, False, meta
    meta["wmm_ie_present"] = True
    wmm_section = wmm_m.group(1)

    for m in EDCA_LINE_RE.finditer(wmm_section):
        ac_tag, cwmin, cwmax, aifsn, txop = m.groups()
        txop_us = int(txop) if txop else 0
        params[f"AC_{ac_tag}"] = {
            "aifsn": int(aifsn),
            "cwmin": int(cwmin),
            "cwmax": int(cwmax),
            "txop_limit_us": txop_us,
            "txop_limit_units": txop_us // 32,
        }
    uapsd = re.search(r"\*\s+u-APSD", wmm_section) is not None
    return params, uapsd, meta


def parse_wmm_parameter_from_pcap(
    pcap_path: str, target_bssid: Optional[str] = None
) -> Tuple[Dict[str, Dict[str, int]], Optional[bool], Dict[str, Any]]:
    """Parse WMM Parameter Element from Beacon or Probe Response in an 802.11 PCAP."""
    params: Dict[str, Dict[str, int]] = {}
    meta: Dict[str, Any] = {
        "ie_source": "PCAP Over-The-Air Frame",
        "last_seen_ms": None,
        "wmm_ie_present": False,
        "bssid": target_bssid,
        "ssid": None,
    }
    if not pcap_path or not Path(pcap_path).is_file():
        return params, None, meta

    flt = "(wlan.fc.type_subtype == 8 or wlan.fc.type_subtype == 5) and (wlan.tag.number == 221)"
    if target_bssid:
        flt = f"wlan.bssid == {target_bssid} and {flt}"

    cmd_find = ["tshark", "-r", "-", "-Y", flt, "-T", "fields", "-e", "frame.number"]
    try:
        with open(pcap_path, "rb") as f:
            proc_find = subprocess.run(cmd_find, stdin=f, capture_output=True, text=True, check=False)
        frame_numbers = [line.strip() for line in proc_find.stdout.splitlines() if line.strip()]
        if not frame_numbers:
            return params, None, meta
        target_frame = frame_numbers[0]
        cmd_detail = ["tshark", "-r", "-", "-Y", f"frame.number == {target_frame}", "-V"]
        with open(pcap_path, "rb") as f:
            proc_detail = subprocess.run(cmd_detail, stdin=f, capture_output=True, text=True, check=False)
        out = proc_detail.stdout
    except Exception:
        return params, None, meta

    bssid_m = (
        re.search(r"BSS Id:.*?\(([0-9a-fA-F:]{17})\)", out)
        or re.search(r"BSS Id:\s*([0-9a-fA-F:]{17})", out)
        or re.search(r"Transmitter address:.*?\(([0-9a-fA-F:]{17})\)", out)
        or re.search(r"Transmitter address:\s*([0-9a-fA-F:]{17})", out)
    )
    if bssid_m:
        meta["bssid"] = bssid_m.group(1).lower()

    ssid_m = re.search(r"SSID:\s*\"?([^\r\n\"]+)\"?", out)
    if ssid_m:
        meta["ssid"] = ssid_m.group(1).strip()

    wmm_block = re.search(r"WMM/WME: Parameter Element(.*?)(?=\n\s*Tag:|\n\s*Expert Info|\Z)", out, re.DOTALL)
    if not wmm_block:
        return params, None, meta

    sec = wmm_block.group(1)
    meta["wmm_ie_present"] = True
    uapsd = re.search(r"U-APSD:\s*Enabled", sec, re.IGNORECASE) is not None

    ac_name_map = {"voice": "AC_VO", "video": "AC_VI", "best effort": "AC_BE", "background": "AC_BK"}
    edca_pat = re.compile(
        r"Ac Parameters ACI \d+ \(([^)]+)\), ACM ([^,]+), AIFSN (\d+), "
        r"ECWmin/max (\d+)/(\d+) \(CWmin/max (\d+)/(\d+)\), TXOP (\d+)",
        re.IGNORECASE
    )

    for m in edca_pat.finditer(sec):
        name_raw, acm, aifsn, ecwmin, ecwmax, cwmin, cwmax, txop = m.groups()
        ac_key = ac_name_map.get(name_raw.lower().strip())
        if ac_key:
            txop_units = int(txop)
            txop_us = txop_units * 32
            params[ac_key] = {
                "aifsn": int(aifsn),
                "cwmin": int(cwmin),
                "cwmax": int(cwmax),
                "txop_limit_us": txop_us,
                "txop_limit_units": txop_units,
            }

    return params, uapsd, meta


def audit_ota_qos_frames(ota_pcap: str, bssid: Optional[str] = None) -> Dict[str, Any]:
    """Audit Over-The-Air 802.11 QoS Control frame counts by TID."""
    if not ota_pcap or not Path(ota_pcap).is_file():
        return {}

    bssid_flt = f" and (wlan.bssid == {bssid} or wlan.addr == {bssid})" if bssid else ""
    counts = {
        "AC_VO": run_tshark_count(ota_pcap, f"wlan.fc.type == 2 and (wlan.qos.tid == 6 or wlan.qos.tid == 7){bssid_flt}"),
        "AC_VI": run_tshark_count(ota_pcap, f"wlan.fc.type == 2 and (wlan.qos.tid == 4 or wlan.qos.tid == 5){bssid_flt}"),
        "AC_BE": run_tshark_count(ota_pcap, f"wlan.fc.type == 2 and (wlan.qos.tid == 0 or wlan.qos.tid == 3){bssid_flt}"),
        "AC_BK": run_tshark_count(ota_pcap, f"wlan.fc.type == 2 and (wlan.qos.tid == 1 or wlan.qos.tid == 2){bssid_flt}"),
    }
    return {
        "ota_pcap": ota_pcap,
        "total_qos_frames": sum(counts.values()),
        "counts": counts,
        "voice_frames": counts["AC_VO"],
        "video_frames": counts["AC_VI"],
        "be_frames": counts["AC_BE"],
        "bk_frames": counts["AC_BK"],
    }


def classify_ac(ac: str, values: Dict[str, int]) -> str:
    """
    Compare one AC against the IEEE 802.11 default STA EDCA set.
      TUNED            : at least one parameter more aggressive than default, none less
      DEFAULT-COMPLIANT: identical to the IEEE default
      DEGRADED         : at least one parameter less aggressive than default
    """
    ref = IEEE_DEFAULT_STA_EDCA[ac]
    better = worse = False
    for key in ("aifsn", "cwmin", "cwmax"):
        if values[key] < ref[key]:
            better = True
        elif values[key] > ref[key]:
            worse = True
    if values["txop_limit_us"] > ref["txop_limit_us"]:
        better = True
    elif values["txop_limit_us"] < ref["txop_limit_us"]:
        worse = True
    if worse:
        return "DEGRADED"
    return "TUNED" if better else "DEFAULT-COMPLIANT"


def evaluate_edca_set(params: Dict[str, Dict[str, int]]) -> Dict[str, Any]:
    """Evaluate a complete 4-AC EDCA set: per-AC classification + inter-AC priority order."""
    missing = [ac for ac in AC_ORDER if ac not in params]
    if missing:
        return {"complete": False, "missing_acs": missing}
    vo, vi, be, bk = (params[ac] for ac in AC_ORDER)
    priority_order_valid = (
        vo["cwmin"] <= vi["cwmin"] < be["cwmin"]
        and vo["aifsn"] <= vi["aifsn"] < be["aifsn"] <= bk["aifsn"]
    )
    return {
        "complete": True,
        "missing_acs": [],
        "classification": {ac: classify_ac(ac, params[ac]) for ac in AC_ORDER},
        "priority_order_valid": priority_order_valid,
    }


def load_ap_edca_json(path: Optional[str]) -> Tuple[Optional[Dict[str, Dict[str, int]]], Optional[str]]:
    """
    Load AP-side (downlink) EDCA parameters taken from the DUT configuration.
    Expected schema: {"source": "...", "AC_VO": {"aifsn":..,"cwmin":..,"cwmax":..,"txop_limit_us":..}, ...}
    """
    if not path:
        return None, None
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        params = {}
        for ac in AC_ORDER:
            if ac in raw:
                params[ac] = {k: int(raw[ac][k]) for k in ("aifsn", "cwmin", "cwmax", "txop_limit_us")}
                params[ac]["txop_limit_units"] = params[ac]["txop_limit_us"] // 32
        return params, str(raw.get("source", path))
    except Exception as exc:
        print(f"Warning: cannot load AP-side EDCA file '{path}': {exc}", file=sys.stderr)
        return None, None


def audit_wmm_edca_parameters(
    wifi_if: Optional[str] = None,
    target_bssid: Optional[str] = None,
    ap_edca_json: Optional[str] = None,
    ota_pcap: Optional[str] = None,
    max_ie_age_ms: int = 30000,
) -> Dict[str, Any]:
    """
    Audit IEEE 802.11e WMM EDCA parameters.

    Scope A - Advertised STA EDCA (uplink): read from the WMM Parameter Element in the
              over-the-air capture (via --ota-pcap) or cached Beacon / Probe Response (`iw scan dump`).
    Scope B - AP TX EDCA (downlink): only verifiable from DUT configuration; evaluated
              when --ap-edca-json is supplied, otherwise NOT_VERIFIED.
    """
    wifi_if = wifi_if or detect_first_wifi_iface() or "wlp3s0"
    notes: List[str] = []
    result: Dict[str, Any] = {
        "standard": "IEEE 802.11e WMM EDCA Parameter Set",
        "reference_baseline": "IEEE 802.11 default STA EDCA (OFDM PHY, aCWmin=15, aCWmax=1023)",
        "interface": wifi_if,
        "is_wireless_iface": is_wireless_iface(wifi_if) or bool(ota_pcap),
        "bssid": None,
        "ssid": None,
        "phy_rate": None,
        "station_wmm_active": False,
        "uapsd_advertised": None,
        "ie_source": None,
        "ie_last_seen_ms": None,
    }

    # ---------------- Scope A: advertised STA EDCA (over the air) ----------------
    sta_scope: Dict[str, Any] = {
        "scope": "Advertised STA EDCA (uplink, WMM Parameter Element)",
        "status": "NOT_VERIFIED",
        "parameters": {},
    }

    if ota_pcap and Path(ota_pcap).is_file():
        result["is_wireless_iface"] = True
        params, uapsd, meta = parse_wmm_parameter_from_pcap(ota_pcap, target_bssid)
        result["bssid"] = target_bssid or meta.get("bssid")
        result["ssid"] = meta.get("ssid")
        result["station_wmm_active"] = meta.get("wmm_ie_present", False)
        result["uapsd_advertised"] = uapsd if meta.get("wmm_ie_present") else None
        result["ie_source"] = f"PCAP ({Path(ota_pcap).name})"
        if not meta.get("wmm_ie_present"):
            notes.append(f"WMM Parameter Element not found in over-the-air capture '{ota_pcap}'.")
        else:
            sta_scope["parameters"] = params
            evaluation = evaluate_edca_set(params)
            sta_scope["evaluation"] = evaluation
            if not evaluation["complete"]:
                notes.append(f"Incomplete EDCA set in PCAP, missing: {', '.join(evaluation['missing_acs'])}.")
            else:
                cls = evaluation["classification"]
                fail = (
                    cls["AC_VO"] == "DEGRADED"
                    or cls["AC_VI"] == "DEGRADED"
                    or not evaluation["priority_order_valid"]
                )
                sta_scope["status"] = "FAIL" if fail else "PASS"
        ota_stats = audit_ota_qos_frames(ota_pcap, result["bssid"])
        if ota_stats:
            result["ota_qos_audit"] = ota_stats
    elif not result["is_wireless_iface"]:
        notes.append(f"Interface '{wifi_if}' is not an nl80211 wireless device; over-the-air WMM IE cannot be read.")
    else:
        bssid, ssid, rate = extract_connected_bssid(wifi_if)
        result.update({"bssid": target_bssid or bssid, "ssid": ssid, "phy_rate": rate})
        result["station_wmm_active"] = check_station_wmm_support(wifi_if)

        scan_out = ""
        try:
            scan_out = subprocess.run(["iw", "dev", wifi_if, "scan", "dump"],
                                      capture_output=True, text=True, check=False).stdout
        except Exception as exc:
            notes.append(f"iw scan dump failed: {exc}")

        block = select_bss_block(scan_out, result["bssid"])
        if not block:
            notes.append("Associated BSS not found in scan cache (run a scan or re-associate).")
        else:
            params, uapsd, meta = parse_wmm_parameter_element(block)
            result["uapsd_advertised"] = uapsd if meta["wmm_ie_present"] else None
            result["ie_source"] = meta["ie_source"]
            result["ie_last_seen_ms"] = meta["last_seen_ms"]
            if meta["last_seen_ms"] is not None and meta["last_seen_ms"] > max_ie_age_ms:
                notes.append(f"Cached IE is {meta['last_seen_ms']} ms old (> {max_ie_age_ms} ms); values may be stale.")
            if not meta["wmm_ie_present"]:
                notes.append("WMM Parameter Element not present in BSS IEs.")
            sta_scope["parameters"] = params

            evaluation = evaluate_edca_set(params)
            sta_scope["evaluation"] = evaluation
            if not evaluation["complete"]:
                notes.append(f"Incomplete EDCA set, missing: {', '.join(evaluation['missing_acs'])}.")
            else:
                cls = evaluation["classification"]
                fail = (
                    not result["station_wmm_active"]
                    or cls["AC_VO"] == "DEGRADED"
                    or cls["AC_VI"] == "DEGRADED"
                    or not evaluation["priority_order_valid"]
                )
                sta_scope["status"] = "FAIL" if fail else "PASS"

    # ---------------- Scope B: AP TX EDCA (DUT configuration) ----------------
    ap_scope: Dict[str, Any] = {
        "scope": "AP TX EDCA (downlink, DUT configuration)",
        "status": "NOT_VERIFIED",
        "source": None,
        "parameters": {},
    }
    ap_params, ap_source = load_ap_edca_json(ap_edca_json)
    if ap_params is None:
        notes.append("AP-side (downlink) EDCA is not carried over the air; supply DUT values via --ap-edca-json.")
    else:
        ap_scope.update({"source": ap_source, "parameters": ap_params})
        ap_eval = evaluate_edca_set(ap_params)
        ap_scope["evaluation"] = ap_eval
        if ap_eval["complete"]:
            ap_scope["status"] = "PASS" if ap_eval["priority_order_valid"] else "FAIL"
        else:
            notes.append(f"AP-side EDCA set incomplete, missing: {', '.join(ap_eval['missing_acs'])}.")

    # ---------------- U-APSD default-state observation ----------------
    if result["uapsd_advertised"] is True:
        notes.append("U-APSD is advertised (enabled). If the DUT is at factory defaults, this conflicts "
                     "with a 'disabled by default' expectation; confirm the factory-default state.")

    statuses = (sta_scope["status"], ap_scope["status"])
    if "FAIL" in statuses:
        overall = "FAIL"
    elif statuses == ("PASS", "PASS"):
        overall = "PASS"
    elif "PASS" in statuses:
        overall = "PARTIAL"
    else:
        overall = "NOT_VERIFIED"

    result.update({
        "sta_edca": sta_scope,
        "ap_edca": ap_scope,
        "overall_status": overall,
        "notes": notes,
    })

    # Backward compatibility aliases
    sta_params = sta_scope.get("parameters", {})
    sta_eval = sta_scope.get("evaluation", {})
    cls_map = sta_eval.get("classification", {})
    result["parameters"] = sta_params
    result["voice_optimized"] = cls_map.get("AC_VO") in ("DEFAULT-COMPLIANT", "TUNED")
    result["video_optimized"] = cls_map.get("AC_VI") in ("DEFAULT-COMPLIANT", "TUNED")
    result["priority_order_valid"] = sta_eval.get("priority_order_valid", False)

    return result


def _color_status(status: str) -> str:
    colors = {
        "PASS": "1;32", "TUNED": "1;32", "DEFAULT-COMPLIANT": "1;36",
        "PARTIAL": "1;33", "NOT_VERIFIED": "1;33", "DEGRADED": "1;31", "FAIL": "1;31",
    }
    code = colors.get(status)
    return f"\033[{code}m{status}\033[0m" if code else status


def _print_edca_rows(scope: Dict[str, Any]) -> None:
    params = scope.get("parameters", {})
    cls_map = scope.get("evaluation", {}).get("classification", {})
    if not params:
        print("  (no parameters available)")
        return
    for ac in AC_ORDER:
        p = params.get(ac)
        meta = AC_META[ac]
        if not p:
            print(f"{meta['label']:<18} {'-':<8} {'-':<8} {'-':<8} {'-':<26} {meta['dscp_target']:<20} {_color_status('NOT_VERIFIED')}")
            continue
        txop_str = f"{p['txop_limit_us']} usec ({p['txop_limit_units']})"
        print(f"{meta['label']:<18} {p['aifsn']:<8} {p['cwmin']:<8} {p['cwmax']:<8} {txop_str:<26} "
              f"{meta['dscp_target']:<20} {_color_status(cls_map.get(ac, '-'))}")


def print_wmm_table(data: Dict[str, Any]) -> None:
    """Print the WMM EDCA field values table for both audit scopes."""
    width = 100
    header = (f"{'ACCESS CATEGORY':<18} {'AIFSN':<8} {'CWmin':<8} {'CWmax':<8} "
              f"{'TXOP LIMIT (usec / 32us)':<26} {'DSCP (default map)':<20} {'VS IEEE DEFAULT'}")

    print("\n" + "=" * width)
    print("  IEEE 802.11e WMM EDCA PARAMETERS AUDIT & FIELD VALUES")
    print("=" * width)
    print(f"  Target BSSID     : {data.get('bssid') or 'unknown'} (SSID: {data.get('ssid') or 'unknown'})")
    print(f"  Wi-Fi Interface  : {data.get('interface')} (PHY Tx: {data.get('phy_rate') or 'N/A'})")
    wmm = data.get("station_wmm_active")
    print(f"  802.11e Assoc    : {_color_status('PASS') if wmm else _color_status('FAIL')} (station dump WMM/WME: {'yes' if wmm else 'no'})")
    uapsd = data.get("uapsd_advertised")
    uapsd_str = "ADVERTISED (enabled)" if uapsd is True else ("NOT ADVERTISED (disabled)" if uapsd is False else "UNKNOWN")
    print(f"  U-APSD Flag      : {uapsd_str}")
    if data.get("ie_source"):
        print(f"  IE Source        : {data['ie_source']} frame (cached, last seen {data.get('ie_last_seen_ms')} ms ago)")
    print(f"  Baseline         : {data.get('reference_baseline')}")

    for key in ("sta_edca", "ap_edca"):
        scope = data.get(key, {})
        print("-" * width)
        src = f" | source: {scope['source']}" if scope.get("source") else ""
        print(f"  [{scope.get('scope')}] -> {_color_status(scope.get('status', 'NOT_VERIFIED'))}{src}")
        print("-" * width)
        print(header)
        _print_edca_rows(scope)
        prio = scope.get("evaluation", {}).get("priority_order_valid")
        if prio is not None:
            print(f"  Inter-AC priority order (VO <= VI < BE <= BK): {'VALID' if prio else 'INVALID'}")

    notes = data.get("notes") or []
    if notes:
        print("-" * width)
        for note in notes:
            print(f"  \033[1;33m[NOTE]\033[0m {note}")
    print("-" * width)
    print(f"  OVERALL VERDICT: {_color_status(data.get('overall_status', 'NOT_VERIFIED'))}")
    print("=" * width + "\n")


def main():
    # Handle shorthand positional invocation: audit-wmm
    if len(sys.argv) > 1 and sys.argv[1] == "audit-wmm":
        sys.argv.pop(1)
        sys.argv.insert(1, "--audit-wmm")

    parser = argparse.ArgumentParser(
        description="IEEE 802.11e Wireless QoS (WMM & DSCP Mapping) Audit Tool"
    )
    parser.add_argument("--audit-wmm", action="store_true", help="Audit AP WMM EDCA Parameter Set IE and station negotiation.")
    parser.add_argument("--wifi-if", default=None, help="Target Wi-Fi interface name (default: auto-detected).")
    parser.add_argument("--bssid", default=None, help="Target AP BSSID to audit.")
    parser.add_argument("--ap-edca-json", default=None, help="Path to JSON file containing AP-side (downlink) EDCA configuration.")
    parser.add_argument("--wmm-json", default=None, help="Path to write WMM field values JSON.")
    parser.add_argument("--ota-pcap", default=None, help="Over-The-Air 802.11 monitor PCAP capture file.")
    parser.add_argument("--wan-pcap", default=None, help="WAN endpoint PCAP capture file.")
    parser.add_argument("--lan-pcap", default=None, help="LAN (or merged LAN+Wi-Fi) PCAP capture file.")
    parser.add_argument("--wifi-pcap", default=None, help="Dedicated Wi-Fi PCAP capture file (if not merged into LAN).")
    parser.add_argument("--voice-ports", default="5060,5062,5064,10000,10002,10004", help="Voice UDP ports.")
    parser.add_argument("--video-ports", default="5005,10006", help="Video UDP ports.")
    parser.add_argument("--be-ports", default="5201", help="Best-effort TCP/UDP ports.")
    parser.add_argument("--voice-dscp", type=int, default=46, help="Target DSCP for Voice (default: 46 = 0xb8).")
    parser.add_argument("--video-dscp", type=int, default=34, help="Target DSCP for Video (default: 34 = 0x88).")
    parser.add_argument("--context-json", help="Run-scoped metadata and client evidence.")
    parser.add_argument("--audit-profile", choices=("practical", "strict"),
                        help="practical (default): MAC/TID fallback; strict: decoded flows and radio telemetry.")
    parser.add_argument("--max-jitter-ms", type=float, default=20.0)
    parser.add_argument("--max-loss-pct", type=float, default=1.0, help="Max acceptable loss %% for Voice/Video (default: 1.0%%).")
    parser.add_argument("--output-json", "-o", help="Path to write JSON audit summary.")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal table output.")

    args = parser.parse_args()

    try:
        context = load_json(args.context_json) if args.context_json else {}
    except EvidenceError as exc:
        results = {"overall_status": "INVALID", "verdict": "INVALID", "reasons": [str(exc)]}
        if args.output_json:
            Path(args.output_json).write_text(json.dumps(results, indent=2))
        print(str(exc), file=sys.stderr)
        return 2
    args.bssid = args.bssid or context.get("bssid")
    context["audit_profile"] = args.audit_profile or context.get("audit_profile", "practical")

    wmm_audit_result = None
    if args.audit_wmm or args.ota_pcap or args.ap_edca_json:
        wmm_audit_result = audit_wmm_edca_parameters(
            wifi_if="eth0" if context.get("mode") == "remote_only" and not args.ota_pcap else args.wifi_if,
            target_bssid=args.bssid,
            ap_edca_json=args.ap_edca_json,
            ota_pcap=args.ota_pcap,
        )
        if not args.quiet:
            print_wmm_table(wmm_audit_result)
        if args.wmm_json:
            with open(args.wmm_json, "w", encoding="utf-8") as f:
                json.dump(wmm_audit_result, f, indent=2)

        # If no PCAP files supplied, terminate with WMM audit verdict
        if not args.wan_pcap and not args.lan_pcap:
            if args.output_json and not args.wmm_json:
                with open(args.output_json, "w", encoding="utf-8") as f:
                    json.dump(wmm_audit_result, f, indent=2)
            status = wmm_audit_result.get("overall_status")
            if status in ("PASS", "PARTIAL"):
                return 0
            elif status == "FAIL":
                return 1
            else:
                return 0

    ports = lambda value: tuple(int(p.strip()) for p in value.split(",") if p.strip())
    # One receiver capture only. Merged captures are deduplicated by transport
    # identities in audit_captures; separate LAN and Wi-Fi counts are never added.
    receiver_pcap = args.wifi_pcap or args.lan_pcap
    results = audit_captures(
        args.wan_pcap, receiver_pcap, args.ota_pcap, context,
        ports(args.voice_ports), ports(args.video_ports), ports(args.be_ports),
        args.voice_dscp, args.video_dscp, args.max_loss_pct, args.max_jitter_ms,
    )
    if wmm_audit_result:
        results["wmm_parameters"] = wmm_audit_result
    edca_status = (wmm_audit_result or {}).get("ap_edca", {}).get("status", "NOT_VERIFIED")
    if results["overall_status"] != "INVALID":
        if edca_status == "FAIL":
            results["overall_status"] = results["verdict"] = "FAIL"
            results["reasons"].append("AP downlink EDCA check failed")
        elif edca_status != "PASS" and results["overall_status"] != "FAIL":
            results["overall_status"] = results["verdict"] = "INCONCLUSIVE"
            results["reasons"].append("AP downlink EDCA not verified")
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(results, indent=2))
    if not args.quiet:
        print("\nWIRELESS QoS EVIDENCE AUDIT")
        print(f"  WAN Ingress Capture : {args.wan_pcap}")
        print(f"  LAN Egress Capture  : {args.lan_pcap}")
        if args.wifi_pcap:
            print(f"  Wi-Fi Capture       : {args.wifi_pcap}")
        if args.ota_pcap:
            print(f"  OTA Monitor Capture : {args.ota_pcap}")
        print(f"  Receiver Used       : {receiver_pcap}")
        print(f"  Audit Profile       : {results.get('audit_profile', context['audit_profile'])}")
        print("-" * 126)
        print(f"{'SERVICE':<13} {'DSCP':<6} {'AC/TID TARGET':<15} {'WAN PKTS':>10} {'RX PKTS':>10} {'LOSS %':>8} "
              f"{'DSCP KEEP %':>12} {'JITTER ms':>10} {'OTA FRAMES':>11} {'STATUS':>14}")
        print("-" * 126)
        value = lambda number: "N/A" if number is None else f"{number:.2f}"
        categories = results.get("mac_tid_evidence", {}).get("categories", {})
        targets = {"voice": "AC_VO (6/7)", "video": "AC_VI (4/5)", "best_effort": "AC_BE (0/3)"}
        for name, metrics in results["services"].items():
            frames = categories.get(name, {}).get("frame_count")
            frames_text = "N/A" if frames is None else f"{frames:,}"
            print(f"{name:<13} {metrics.get('dscp_value', 'N/A')!s:<6} {targets.get(name, 'N/A'):<15} "
                  f"{metrics.get('wan_packets', 0):>10,} {metrics.get('lan_packets', 0):>10,} "
                  f"{value(metrics.get('loss_pct')):>8} "
                  f"{value(metrics.get('dscp_preservation_pct')):>12} "
                  f"{value(metrics.get('max_jitter_ms')):>10} {frames_text:>11} {metrics.get('status', 'N/A'):>14}")
        print("-" * 126)
        mac = results.get("mac_tid_evidence", {})
        if mac.get("categories"):
            print(f"  OTA MAC/TID Evidence: AP {mac.get('bssid')} -> STA {mac.get('station_mac')}")
            print(f"  QoS Data Frames     : {mac.get('total_frames')} (protected: {mac.get('protected_frames')}, decoded IP: {mac.get('decoded_ip_frames')})")
            print(f"  Mapping Basis       : {results.get('mapping_basis', 'NOT_VERIFIED')}")
            for name, observation in mac["categories"].items():
                print(f"  {name:<12} {observation['ac']:<6} | TIDs={observation['observed_tids']} "
                      f"| OTA frames={observation['frame_count']} | {observation['status']}")
        print(f"  OVERALL VERDICT: {results['overall_status']}")
        for reason in results["reasons"]:
            print(f"  - {reason}")
        for warning in results.get("warnings", []):
            print(f"  [NOTE] {warning}")
    return {"PASS": 0, "FAIL": 1, "INVALID": 2, "INCONCLUSIVE": 2}[results["overall_status"]]


if __name__ == "__main__":
    sys.exit(main())

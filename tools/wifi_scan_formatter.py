#!/usr/bin/env python3
"""
wifi_scan_formatter.py - Format and colorize nmcli Wi-Fi scan results.

Parses colon-separated scan records from `nmcli -t -f IN-USE,BSSID,SSID,CHAN,SIGNAL,SECURITY dev wifi list`
and outputs clean, standardized terminal status indicators.
"""

import argparse
import re
import sys
from typing import Optional


def format_scan_entry(line: str, band: str, ssid: str) -> str:
    """Format an individual nmcli scan entry with color status."""
    # nmcli escapes colons in fields like BSSID as \:
    parts = re.split(r"(?<!\\):", line)
    in_use = parts[0].strip() if len(parts) > 0 else ""
    chan = parts[3].strip() if len(parts) > 3 else "N/A"
    sig = parts[4].strip() if len(parts) > 4 else "N/A"
    sec = parts[5].strip().replace(r"\:", ":") if len(parts) > 5 else "N/A"

    status = "[CONNECTED]" if in_use == "*" else "[VISIBLE]"
    color = "\033[1;32m" if in_use == "*" else "\033[1;36m"
    return f"  {color}{status:<12}\033[0m {band:<6} SSID: {ssid:<20} | Chan: {chan:<4} | Signal: {sig:<3}% | Security: {sec}"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Format and colorize nmcli Wi-Fi scan output."
    )
    # Support both named arguments and positional arguments for maximum shell compatibility
    parser.add_argument("pos_args", nargs="*", help="Optional positional arguments: <line> <band> <ssid>")
    parser.add_argument("--line", "-l", dest="line", help="Raw nmcli colon-delimited output line")
    parser.add_argument("--band", "-b", dest="band", help="Frequency band (e.g., 2.4GHz, 5.0GHz, 6.0GHz)")
    parser.add_argument("--ssid", "-s", dest="ssid", help="Target SSID")

    args = parser.parse_args()

    line: Optional[str] = args.line
    band: Optional[str] = args.band
    ssid: Optional[str] = args.ssid

    if args.pos_args:
        if len(args.pos_args) >= 1 and not line:
            line = args.pos_args[0]
        if len(args.pos_args) >= 2 and not band:
            band = args.pos_args[1]
        if len(args.pos_args) >= 3 and not ssid:
            ssid = args.pos_args[2]

    if not line or not band or not ssid:
        parser.print_usage(sys.stderr)
        sys.stderr.write("Error: 'line', 'band', and 'ssid' are all required.\n")
        return 1

    formatted = format_scan_entry(line, band, ssid)
    print(formatted)
    return 0


if __name__ == "__main__":
    sys.exit(main())

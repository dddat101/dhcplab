#!/usr/bin/env python3
"""
Gateway Network Test Lab - Wi-Fi Phone (VoIP/SIP/RTP) Simulator
Thin adapter delegating to deep engine tools/traffic_generator.py.
"""

import argparse
import sys
from pathlib import Path

# Ensure tools directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from traffic_generator import (
    RTP_STRUCT,
    handle_rtp_echo,
    run_voip_client,
    run_voip_server,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Wi-Fi Phone (VoIP RTP) Simulator (Optimized)")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Server mode (in ns-wan)
    srv = subparsers.add_parser("server", help="Run VoIP RTP Echo/Media Server")
    srv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    srv.add_argument("--ports", default="10000,10002", help="Comma-separated UDP ports to listen on")
    srv.add_argument("--duration", type=float, default=60.0, help="Server run duration in seconds")
    srv.add_argument("--dscp", type=int, default=46, help="IP DSCP value (default: 46 for Voice EF = 0xb8)")

    # Client mode (in ns-phone1, ns-phone2, or physical Wi-Fi interface)
    cli = subparsers.add_parser("client", help="Run Wi-Fi Phone Call Endpoint")
    cli.add_argument("--server-ip", required=True, help="VoIP Server IP address")
    cli.add_argument("--server-port", type=int, default=10000, help="VoIP Server UDP port")
    cli.add_argument("--bind-ip", default="0.0.0.0", help="Local IP address to bind (e.g. Wi-Fi interface IP)")
    cli.add_argument("--bind-port", type=int, default=0, help="Local UDP port to bind")
    cli.add_argument("--duration", type=float, default=30.0, help="Call duration in seconds")
    cli.add_argument("--phone-id", default="phone-1", help="Identifier for logging")
    cli.add_argument("--dscp", type=int, default=46, help="IP DSCP value (default: 46 for Voice EF = 0xb8)")
    cli.add_argument("--output-json", default="", help="Path to write JSON results")

    return parser.parse_args()


def run_server(args):
    return run_voip_server(args)


def run_client(args):
    return run_voip_client(args)


def main():
    args = parse_args()
    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        sys.exit(run_client(args))


if __name__ == "__main__":
    main()

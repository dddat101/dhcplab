#!/usr/bin/env python3
"""
Gateway Network Test Lab - UHD+Dolby 1.2x VOD Playback Tester
Thin adapter delegating to deep engine tools/traffic_generator.py.
"""

import argparse
import sys
from pathlib import Path

# Ensure tools directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from traffic_generator import (
    VOD_HANDSHAKE_ACK,
    VOD_HANDSHAKE_ID,
    VOD_HANDSHAKE_PROBE,
    VOD_MAGIC,
    VOD_STRUCT,
    run_vod_client,
    run_vod_server,
)


def parse_args():
    parser = argparse.ArgumentParser(description="UHD+Dolby VOD 1.2x Stream Tester (Optimized)")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Server mode
    srv = subparsers.add_parser("server", help="Run VOD Video Streaming Server")
    srv.add_argument("--dest-ip", required=True, help="STB Client IP address")
    srv.add_argument("--dest-port", type=int, default=5005, help="STB Client UDP port")
    srv.add_argument("--duration", type=float, default=5.0, help="Test duration in seconds")
    srv.add_argument("--base-bitrate-mbps", type=float, default=35.0, help="Base UHD 4K bitrate (Mbps)")
    srv.add_argument("--playback-speed", type=float, default=1.2, help="Playback speed multiplier (e.g. 1.2)")
    srv.add_argument("--wait-handshake", action="store_true", help="Wait for client NAT hole punching probe before streaming")
    srv.add_argument("--handshake-timeout", type=float, default=5.0, help="Seconds to wait for client probe (default: 5.0)")
    srv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP for handshake listening")
    srv.add_argument("--bind-port", type=int, default=0, help="Binding port for handshake listening (default: same as dest-port)")
    srv.add_argument("--report-interval", type=float, default=1.0, help="Periodic progress reporting interval in seconds (default: 1.0, 0 to disable)")
    srv.add_argument("--dscp", type=int, default=34, help="IP DSCP value (default: 34 for Video AF41 = 0x88)")

    # Client mode
    cli = subparsers.add_parser("client", help="Run VOD Playback Client (STB)")
    cli.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    cli.add_argument("--bind-port", type=int, default=5005, help="Binding UDP port")
    cli.add_argument("--server-ip", default="", help="Streaming server IP to initiate NAT hole punching")
    cli.add_argument("--server-port", type=int, default=0, help="Streaming server port (default: same as bind-port)")
    cli.add_argument("--duration", type=float, default=6.0, help="Listen duration in seconds")
    cli.add_argument("--report-interval", type=float, default=1.0, help="Periodic progress reporting interval in seconds (default: 1.0, 0 to disable)")
    cli.add_argument("--dscp", type=int, default=34, help="IP DSCP value (default: 34 for Video AF41 = 0x88)")
    cli.add_argument("--output-json", default="", help="Path to write JSON results")
    cli.add_argument("--min-throughput-mbps", type=float, default=35.0,
                     help="Minimum playback throughput (default: 35 Mbps)")
    cli.add_argument("--max-loss-pct", type=float, default=0.0,
                     help="Maximum acceptable packet loss (default: 0%%)")

    return parser.parse_args()


def run_server(args):
    return run_vod_server(args)


def run_client(args):
    return run_vod_client(args)


def main():
    args = parse_args()
    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        sys.exit(run_client(args))


if __name__ == "__main__":
    main()

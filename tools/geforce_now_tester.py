#!/usr/bin/env python3
"""
Gateway Network Test Lab - Cloud Gaming (GeForce NOW) Network Tester
Thin adapter delegating to deep engine tools/traffic_generator.py.
"""

import argparse
import sys
from pathlib import Path

# Ensure tools directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from traffic_generator import (
    GFN_HANDSHAKE_ACK,
    GFN_HANDSHAKE_ID,
    GFN_HANDSHAKE_PROBE,
    GFN_MAGIC,
    GFN_STRUCT,
    run_gaming_client,
    run_gaming_server,
)


def parse_args():
    parser = argparse.ArgumentParser(description="Cloud Gaming (GeForce NOW) Protocol Tester (Optimized)")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # Server mode
    srv = subparsers.add_parser("server", help="Run Cloud Gaming streaming server")
    srv.add_argument("--dest-ip", required=True, help="STB Client IP address")
    srv.add_argument("--dest-port", type=int, default=5004, help="STB Client UDP port")
    srv.add_argument("--duration", type=float, default=5.0, help="Test duration in seconds")
    srv.add_argument("--frame-rate", type=int, default=60, help="Game frames per second (60 or 120)")
    srv.add_argument("--bitrate-mbps", type=float, default=25.0, help="Target game video bitrate (Mbps)")
    srv.add_argument("--wait-handshake", action="store_true", help="Wait for client NAT hole punching probe before streaming")
    srv.add_argument("--handshake-timeout", type=float, default=5.0, help="Seconds to wait for client probe (default: 5.0)")
    srv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP for handshake listening")
    srv.add_argument("--bind-port", type=int, default=0, help="Binding port for handshake listening (default: same as dest-port)")
    srv.add_argument("--report-interval", type=float, default=1.0, help="Interval in seconds for periodic progress log (default: 1.0, 0 to disable)")

    # Client mode
    cli = subparsers.add_parser("client", help="Run Cloud Gaming diagnostic client (STB)")
    cli.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    cli.add_argument("--bind-port", type=int, default=5004, help="Binding UDP port")
    cli.add_argument("--server-ip", default="", help="Streaming server IP to initiate NAT hole punching")
    cli.add_argument("--server-port", type=int, default=0, help="Streaming server port (default: same as bind-port)")
    cli.add_argument("--duration", type=float, default=6.0, help="Listen duration in seconds")
    cli.add_argument("--report-interval", type=float, default=1.0, help="Interval in seconds for periodic progress log (default: 1.0, 0 to disable)")
    cli.add_argument("--max-loss-pct", type=float, default=0.0, help="Maximum allowed packet loss (percent)")
    cli.add_argument("--max-jitter-ms", type=float, default=2.0, help="Maximum allowed jitter (ms)")
    cli.add_argument("--fps", type=int, default=60, help="Expected game frame rate (e.g. 60 or 120)")
    cli.add_argument("--target-mbps", type=float, default=25.0, help="Target game video bitrate (Mbps)")
    cli.add_argument("--output-json", default="", help="Path to write JSON results")

    return parser.parse_args()


def run_server(args):
    return run_gaming_server(args)


def run_client(args):
    return run_gaming_client(args)


def main():
    args = parse_args()
    if args.mode == "server":
        run_server(args)
    elif args.mode == "client":
        sys.exit(run_client(args))


if __name__ == "__main__":
    main()

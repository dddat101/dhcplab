#!/usr/bin/env python3
"""
Gateway Network Test Lab - Traffic Generator Utility
High-Performance Wire-rate Unicast, Multicast, and WAN-to-LAN Burst Engine.
Optimized with zero-allocation buffers, connected UDP sockets, and O(1) sequence tracking.
"""

import sys
import os
import time
import socket
import struct
import json
import argparse
import threading
from typing import Dict, Any, Optional

MAGIC_HEADER = 0x50455246  # "PERF" in hex
HEADER_STRUCT = struct.Struct("!IIId")  # 20 bytes: magic(4), burst_or_stream(4), seq(4), ts(8)

# NAT Hole Punching Handshake constants (reserved burst/stream ID 0xFFFFFFFF)
HANDSHAKE_BURST_IDX = 0xFFFFFFFF
HANDSHAKE_SEQ_PROBE = 0x01
HANDSHAKE_SEQ_ACK   = 0x02

# Cloud Gaming (GeForce NOW) protocol constants
GFN_MAGIC = 0x47464E54  # "GFNT"
GFN_STRUCT = struct.Struct("!IIId")  # 20 bytes: magic(4), frame_id(4), seq(4), send_ts(8)
GFN_HANDSHAKE_ID = 0xFFFFFFFF
GFN_HANDSHAKE_PROBE = 0x01
GFN_HANDSHAKE_ACK   = 0x02

# UHD+Dolby VOD protocol constants
VOD_MAGIC = 0x55484456  # "UHDV"
VOD_STRUCT = struct.Struct("!IIId")  # 20 bytes: magic(4), stream_id(4), seq(4), send_ts(8)
VOD_HANDSHAKE_ID = 0xFFFFFFFF
VOD_HANDSHAKE_PROBE = 0x01
VOD_HANDSHAKE_ACK   = 0x02

# VoIP RTP protocol constants
RTP_STRUCT = struct.Struct("!BBHII")  # 12 bytes: V/P/X/CC(1), M/PT(1), seq(2), ts(4), ssrc(4)

def parse_args():
    parser = argparse.ArgumentParser(description="Precision Network Traffic Generator & Receiver (Optimized)")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    # 1. Burst Mode Sender
    burst_send = subparsers.add_parser("burst-send", help="Send precision burst traffic")
    burst_send.add_argument("--dest-ip", required=True, help="Destination IP address")
    burst_send.add_argument("--dest-port", type=int, default=5001, help="Destination UDP port")
    burst_send.add_argument("--packet-size", type=int, default=1500, help="Total Ethernet frame size (bytes)")
    burst_send.add_argument("--burst-length", type=int, default=53, help="Frames per burst")
    burst_send.add_argument("--burst-load", type=float, default=50.0, help="Burst load percentage (e.g. 50 or 16)")
    burst_send.add_argument("--burst-count", type=int, default=20, help="Number of bursts to emit")
    burst_send.add_argument("--rate-mbps", type=float, default=1000.0, help="Ingress line rate (Mbps)")
    burst_send.add_argument("--wait-handshake", action="store_true", help="Wait for client NAT hole punching probe before sending")
    burst_send.add_argument("--handshake-timeout", type=float, default=5.0, help="Seconds to wait for client probe (default: 5.0)")
    burst_send.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP for handshake listening")
    burst_send.add_argument("--bind-port", type=int, default=0, help="Binding port for handshake listening (default: same as dest-port)")

    # 2. Burst Mode Receiver
    burst_recv = subparsers.add_parser("burst-recv", help="Receive and verify burst traffic")
    burst_recv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    burst_recv.add_argument("--bind-port", type=int, default=5001, help="Binding UDP port")
    burst_recv.add_argument("--server-ip", default="", help="Traffic generator IP to initiate NAT hole punching")
    burst_recv.add_argument("--server-port", type=int, default=0, help="Traffic generator port (default: same as bind-port)")
    burst_recv.add_argument("--expected-packets", type=int, default=1060, help="Expected packet count")
    burst_recv.add_argument("--timeout", type=float, default=5.0, help="Timeout waiting for packets (sec)")
    burst_recv.add_argument("--output-json", default="", help="Path to write JSON results")

    # 3. Unicast Sender
    uni_send = subparsers.add_parser("unicast-send", help="Send wire-rate unicast packets")
    uni_send.add_argument("--dest-ip", required=True, help="Destination IP address")
    uni_send.add_argument("--dest-port", type=int, default=5002, help="Destination UDP port")
    uni_send.add_argument("--packet-size", type=int, default=1024, help="Total frame size (bytes)")
    uni_send.add_argument("--duration", type=float, default=5.0, help="Duration in seconds")
    uni_send.add_argument("--rate-mbps", type=float, default=950.0, help="Target transmission rate (Mbps)")
    uni_send.add_argument("--wait-handshake", action="store_true", help="Wait for client NAT hole punching probe before sending")
    uni_send.add_argument("--handshake-timeout", type=float, default=5.0, help="Seconds to wait for client probe (default: 5.0)")
    uni_send.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP for handshake listening")
    uni_send.add_argument("--bind-port", type=int, default=0, help="Binding port for handshake listening (default: same as dest-port)")

    # 4. Unicast Receiver
    uni_recv = subparsers.add_parser("unicast-recv", help="Receive wire-rate unicast packets")
    uni_recv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    uni_recv.add_argument("--bind-port", type=int, default=5002, help="Binding UDP port")
    uni_recv.add_argument("--server-ip", default="", help="Traffic generator IP to initiate NAT hole punching")
    uni_recv.add_argument("--server-port", type=int, default=0, help="Traffic generator port (default: same as bind-port)")
    uni_recv.add_argument("--duration", type=float, default=6.0, help="Listen duration (sec)")
    uni_recv.add_argument("--output-json", default="", help="Path to write JSON results")

    # 5. Multicast Sender
    mcast_send = subparsers.add_parser("mcast-send", help="Send wire-rate multicast packets")
    mcast_send.add_argument("--group-ip", default="239.255.0.1", help="Multicast group IP")
    mcast_send.add_argument("--port", type=int, default=5003, help="Multicast UDP port")
    mcast_send.add_argument("--packet-size", type=int, default=1024, help="Total frame size (bytes)")
    mcast_send.add_argument("--packets", type=int, default=5000, help="Number of packets to send")
    mcast_send.add_argument("--rate-mbps", type=float, default=100.0, help="Target rate (Mbps)")
    mcast_send.add_argument("--interface-ip", default="", help="Source interface IP")
    mcast_send.add_argument("--warmup-packets", type=int, default=20, help="Number of warmup packets to trigger hardware flow table")

    # 6. Multicast Receiver
    mcast_recv = subparsers.add_parser("mcast-recv", help="Receive wire-rate multicast packets")
    mcast_recv.add_argument("--group-ip", default="239.255.0.1", help="Multicast group IP")
    mcast_recv.add_argument("--port", type=int, default=5003, help="Multicast UDP port")
    mcast_recv.add_argument("--expected-packets", type=int, default=5000, help="Expected packets")
    mcast_recv.add_argument("--interface-ip", default="0.0.0.0", help="Interface IP to join group on")
    mcast_recv.add_argument("--timeout", type=float, default=6.0, help="Timeout in seconds")
    mcast_recv.add_argument("--output-json", default="", help="Path to write JSON results")

    # 7. Gaming Stream (GeForce NOW) Server
    gfn_srv = subparsers.add_parser("gaming-server", aliases=["gaming-send"], help="Run Cloud Gaming streaming server")
    gfn_srv.add_argument("--dest-ip", required=True, help="STB Client IP address")
    gfn_srv.add_argument("--dest-port", type=int, default=5004, help="STB Client UDP port")
    gfn_srv.add_argument("--duration", type=float, default=5.0, help="Test duration in seconds")
    gfn_srv.add_argument("--frame-rate", type=int, default=60, help="Game frames per second (60 or 120)")
    gfn_srv.add_argument("--bitrate-mbps", type=float, default=25.0, help="Target game video bitrate (Mbps)")
    gfn_srv.add_argument("--wait-handshake", action="store_true", help="Wait for client NAT hole punching probe")
    gfn_srv.add_argument("--handshake-timeout", type=float, default=5.0, help="Seconds to wait for client probe")
    gfn_srv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP for handshake listening")
    gfn_srv.add_argument("--bind-port", type=int, default=0, help="Binding port for handshake listening")
    gfn_srv.add_argument("--report-interval", type=float, default=1.0, help="Periodic progress log interval (sec)")

    # 8. Gaming Stream (GeForce NOW) Client
    gfn_cli = subparsers.add_parser("gaming-client", aliases=["gaming-recv"], help="Run Cloud Gaming diagnostic client (STB)")
    gfn_cli.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    gfn_cli.add_argument("--bind-port", type=int, default=5004, help="Binding UDP port")
    gfn_cli.add_argument("--server-ip", default="", help="Streaming server IP to initiate NAT hole punching")
    gfn_cli.add_argument("--server-port", type=int, default=0, help="Streaming server port")
    gfn_cli.add_argument("--duration", type=float, default=6.0, help="Listen duration in seconds")
    gfn_cli.add_argument("--report-interval", type=float, default=1.0, help="Periodic progress log interval (sec)")
    gfn_cli.add_argument("--max-loss-pct", type=float, default=0.0, help="Maximum allowed packet loss (percent)")
    gfn_cli.add_argument("--max-jitter-ms", type=float, default=2.0, help="Maximum allowed jitter (ms)")
    gfn_cli.add_argument("--fps", type=int, default=60, help="Expected game frame rate")
    gfn_cli.add_argument("--target-mbps", type=float, default=25.0, help="Target game video bitrate (Mbps)")
    gfn_cli.add_argument("--output-json", default="", help="Path to write JSON results")

    # 9. VOD 1.2x Streaming Server
    vod_srv = subparsers.add_parser("vod-server", aliases=["vod-send"], help="Run VOD Video Streaming Server")
    vod_srv.add_argument("--dest-ip", required=True, help="STB Client IP address")
    vod_srv.add_argument("--dest-port", type=int, default=5005, help="STB Client UDP port")
    vod_srv.add_argument("--duration", type=float, default=5.0, help="Test duration in seconds")
    vod_srv.add_argument("--base-bitrate-mbps", type=float, default=35.0, help="Base UHD 4K bitrate (Mbps)")
    vod_srv.add_argument("--playback-speed", type=float, default=1.2, help="Playback speed multiplier")
    vod_srv.add_argument("--wait-handshake", action="store_true", help="Wait for client NAT hole punching probe")
    vod_srv.add_argument("--handshake-timeout", type=float, default=5.0, help="Seconds to wait for client probe")
    vod_srv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP for handshake listening")
    vod_srv.add_argument("--bind-port", type=int, default=0, help="Binding port for handshake listening")
    vod_srv.add_argument("--report-interval", type=float, default=1.0, help="Periodic progress log interval (sec)")
    vod_srv.add_argument("--dscp", type=int, default=34, help="IP DSCP value (default: 34 for Video AF41 = 0x88)")

    # 10. VOD 1.2x Streaming Client
    vod_cli = subparsers.add_parser("vod-client", aliases=["vod-recv"], help="Run VOD Playback Client (STB)")
    vod_cli.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    vod_cli.add_argument("--bind-port", type=int, default=5005, help="Binding UDP port")
    vod_cli.add_argument("--server-ip", default="", help="Streaming server IP to initiate NAT hole punching")
    vod_cli.add_argument("--server-port", type=int, default=0, help="Streaming server port")
    vod_cli.add_argument("--duration", type=float, default=6.0, help="Listen duration in seconds")
    vod_cli.add_argument("--report-interval", type=float, default=1.0, help="Periodic progress reporting interval")
    vod_cli.add_argument("--dscp", type=int, default=34, help="IP DSCP value")
    vod_cli.add_argument("--output-json", default="", help="Path to write JSON results")
    vod_cli.add_argument("--min-throughput-mbps", type=float, default=35.0, help="Minimum playback throughput (Mbps)")
    vod_cli.add_argument("--max-loss-pct", type=float, default=0.0, help="Maximum acceptable packet loss (%%)")

    # 11. VoIP RTP Echo Server
    voip_srv = subparsers.add_parser("voip-server", help="Run VoIP RTP Echo/Media Server")
    voip_srv.add_argument("--bind-ip", default="0.0.0.0", help="Binding IP address")
    voip_srv.add_argument("--ports", default="10000,10002", help="Comma-separated UDP ports to listen on")
    voip_srv.add_argument("--duration", type=float, default=60.0, help="Server run duration in seconds")
    voip_srv.add_argument("--dscp", type=int, default=46, help="IP DSCP value (default: 46 for Voice EF = 0xb8)")

    # 12. VoIP Endpoint Client
    voip_cli = subparsers.add_parser("voip-client", help="Run Wi-Fi Phone Call Endpoint")
    voip_cli.add_argument("--server-ip", required=True, help="VoIP Server IP address")
    voip_cli.add_argument("--server-port", type=int, default=10000, help="VoIP Server UDP port")
    voip_cli.add_argument("--bind-ip", default="0.0.0.0", help="Local IP address to bind")
    voip_cli.add_argument("--bind-port", type=int, default=0, help="Local UDP port to bind")
    voip_cli.add_argument("--duration", type=float, default=30.0, help="Call duration in seconds")
    voip_cli.add_argument("--phone-id", default="phone-1", help="Identifier for logging")
    voip_cli.add_argument("--dscp", type=int, default=46, help="IP DSCP value (default: 46 for Voice EF = 0xb8)")
    voip_cli.add_argument("--output-json", default="", help="Path to write JSON results")

    # 13. Declarative Stream Sender
    str_send = subparsers.add_parser("stream-send", help="Send declarative stream by profile")
    str_send.add_argument("--profile", required=True, choices=["gaming", "vod", "voip", "unicast", "burst", "multicast"], help="Traffic profile")
    str_send.add_argument("--dest-ip", default="", help="Destination IP address")
    str_send.add_argument("--dest-port", type=int, default=0, help="Destination UDP port")
    str_send.add_argument("--duration", type=float, default=5.0, help="Duration in seconds")
    str_send.add_argument("--rate-mbps", type=float, default=25.0, help="Bitrate in Mbps")
    str_send.add_argument("--dscp", type=int, default=0, help="IP DSCP mark")
    str_send.add_argument("--bind-ip", default="0.0.0.0", help="Local bind IP")
    str_send.add_argument("--bind-port", type=int, default=0, help="Local bind port")
    str_send.add_argument("--wait-handshake", action="store_true", help="Wait for NAT probe")
    str_send.add_argument("--handshake-timeout", type=float, default=5.0, help="Handshake timeout")
    str_send.add_argument("--report-interval", type=float, default=1.0, help="Report interval")

    # 14. Declarative Stream Receiver
    str_recv = subparsers.add_parser("stream-recv", help="Receive declarative stream by profile")
    str_recv.add_argument("--profile", required=True, choices=["gaming", "vod", "voip", "unicast", "burst", "multicast"], help="Traffic profile")
    str_recv.add_argument("--bind-ip", default="0.0.0.0", help="Bind IP address")
    str_recv.add_argument("--bind-port", type=int, default=0, help="Bind UDP port")
    str_recv.add_argument("--server-ip", default="", help="Server IP for NAT probing")
    str_recv.add_argument("--server-port", type=int, default=0, help="Server port")
    str_recv.add_argument("--duration", type=float, default=6.0, help="Duration in seconds")
    str_recv.add_argument("--dscp", type=int, default=0, help="Expected DSCP")
    str_recv.add_argument("--output-json", default="", help="Path to write JSON results")
    str_recv.add_argument("--max-loss-pct", type=float, default=0.0, help="Max loss %%")
    str_recv.add_argument("--max-jitter-ms", type=float, default=2.0, help="Max jitter ms")
    str_recv.add_argument("--min-throughput-mbps", type=float, default=0.0, help="Min throughput Mbps")
    str_recv.add_argument("--report-interval", type=float, default=1.0, help="Report interval")

    return parser.parse_args()

def run_burst_sender(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    target_addr = (args.dest_ip, args.dest_port)

    # Stateful NAT Hole Punching: Wait for client probe before sending
    if getattr(args, "wait_handshake", False):
        listen_port = args.bind_port if getattr(args, "bind_port", 0) > 0 else args.dest_port
        try:
            sock.bind((getattr(args, "bind_ip", "0.0.0.0"), listen_port))
        except Exception as e:
            print(f"Error binding UDP socket on {args.bind_ip}:{listen_port}: {e}")
            sock.close()
            return

        sock.settimeout(0.5)
        print(f"=== BURST SENDER: WAITING FOR CLIENT NAT HANDSHAKE ===")
        print(f"  Listening on: {getattr(args, 'bind_ip', '0.0.0.0')}:{listen_port} (Timeout: {getattr(args, 'handshake_timeout', 5.0)}s)...")

        start_wait = time.time()
        handshake_done = False
        rx_buf = bytearray(2048)

        while (time.time() - start_wait) < getattr(args, "handshake_timeout", 5.0):
            try:
                nbytes, client_addr = sock.recvfrom_into(rx_buf)
                if nbytes >= 20:
                    magic, burst_idx, seq, _ = HEADER_STRUCT.unpack_from(rx_buf, 0)
                    if magic == MAGIC_HEADER and burst_idx == HANDSHAKE_BURST_IDX:
                        print(f"  [PASS] Received NAT handshake probe from {client_addr[0]}:{client_addr[1]}. Session established.")
                        target_addr = client_addr
                        # Send ACK back so receiver knows probe succeeded and NAT pinhole is open
                        ack_buf = bytearray(max(32, args.packet_size - 42))
                        HEADER_STRUCT.pack_into(ack_buf, 0, MAGIC_HEADER, HANDSHAKE_BURST_IDX, HANDSHAKE_SEQ_ACK, time.time())
                        for _ in range(3):
                            sock.sendto(ack_buf, client_addr)
                            time.sleep(0.005)
                        handshake_done = True
                        break
            except socket.timeout:
                continue

        if not handshake_done:
            print(f"  [WARN] No handshake probe received within {getattr(args, 'handshake_timeout', 5.0)}s. Falling back to {target_addr[0]}:{target_addr[1]}")
        else:
            time.sleep(0.05)  # Allow NAT pinhole to settle

    # Optimization: Connect UDP socket once to avoid repeated routing lookups in kernel
    try:
        sock.connect(target_addr)
    except Exception as e:
        print(f"Error connecting UDP socket: {e}")
        sock.close()
        return

    payload_len = max(32, args.packet_size - 42)
    # Optimization: Pre-allocate single bytearray and pack into it in-place
    buf = bytearray(payload_len)
    buf[20:] = b"\xaa" * (payload_len - 20)
    pack_into = HEADER_STRUCT.pack_into
    send_call = sock.send

    frame_bits = (args.packet_size + 20) * 8
    frame_time_sec = frame_bits / (args.rate_mbps * 1e6)
    burst_duration_sec = frame_time_sec * args.burst_length

    # RFC 2544 / RFC 2889: Time required for 100M egress to drain one burst of frames
    drain_time_100m = (frame_bits * args.burst_length) / (100.0 * 1e6)
    duty_cycle_idle = burst_duration_sec * ((100.0 - args.burst_load) / args.burst_load) if args.burst_load < 100.0 else 0.0
    inter_burst_pause = max(duty_cycle_idle, drain_time_100m + 0.003)

    print(f"=== BURST GENERATOR START (OPTIMIZED) ===")
    print(f"  Target: {target_addr[0]}:{target_addr[1]}")
    print(f"  Frame Size: {args.packet_size}B (Payload: {payload_len}B)")
    print(f"  Burst Length: {args.burst_length} frames | Load: {args.burst_load}% | Bursts: {args.burst_count}")
    print(f"  Burst Active: {burst_duration_sec * 1e6:.2f} us | Inter-Burst Pause: {inter_burst_pause * 1e3:.2f} ms")

    total_sent = 0
    time.sleep(0.05)

    perf_counter = time.perf_counter
    time_func = time.time

    for burst_idx in range(args.burst_count):
        burst_start = perf_counter()
        now_ts = time_func()
        for seq_in_burst in range(args.burst_length):
            pack_into(buf, 0, MAGIC_HEADER, burst_idx, seq_in_burst, now_ts)
            send_call(buf)
            total_sent += 1

        burst_elapsed = perf_counter() - burst_start
        sleep_needed = inter_burst_pause - burst_elapsed
        if sleep_needed > 0:
            target_time = perf_counter() + sleep_needed
            if sleep_needed > 0.002:
                time.sleep(sleep_needed - 0.001)
            while perf_counter() < target_time:
                pass

    sock.close()
    print(f"=== BURST GENERATOR COMPLETE: Sent {total_sent} frames ===")

def run_burst_receiver(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    try:
        sock.bind((args.bind_ip, args.bind_port))
    except Exception as e:
        print(f"Error binding burst receiver on {args.bind_ip}:{args.bind_port}: {e}", file=sys.stderr, flush=True)
        sock.close()
        return 1

    sock.settimeout(0.1)  # 100ms timeout for responsive probing and timeout loop

    target_server_port = args.server_port if getattr(args, "server_port", 0) > 0 else args.bind_port
    has_server = bool(getattr(args, "server_ip", ""))

    print(f"=== BURST RECEIVER LISTENING on {args.bind_ip}:{args.bind_port} ===", flush=True)
    print(f"  Expected packets: {args.expected_packets} | Timeout: {args.timeout}s", flush=True)
    if has_server:
        print(f"  NAT Traversal: Active (Probing {args.server_ip}:{target_server_port})", flush=True)

    # Optimization: Pre-allocated buffer and O(1) burst tracking
    rx_buf = bytearray(2048)
    recv_into = sock.recv_into
    unpack_from = HEADER_STRUCT.unpack_from

    probe_buf = bytearray(32)
    pack_into = HEADER_STRUCT.pack_into

    received_packets = 0
    burst_counts = {}
    start_time = None
    last_rx_time = time.time()
    time_func = time.time

    handshake_acked = False
    last_probe_time = 0.0

    while True:
        now = time_func()

        # Proactive NAT Hole Punching: send probes until data or ACK received
        if has_server and not handshake_acked and received_packets == 0:
            if (now - last_probe_time) >= 0.15:
                try:
                    pack_into(probe_buf, 0, MAGIC_HEADER, HANDSHAKE_BURST_IDX, HANDSHAKE_SEQ_PROBE, now)
                    sock.sendto(probe_buf, (args.server_ip, target_server_port))
                    if last_probe_time == 0.0:
                        print(f"  [INFO] Sent initial NAT probe to {args.server_ip}:{target_server_port}...", flush=True)
                    last_probe_time = now
                except Exception as e:
                    if last_probe_time == 0.0 or (now - last_probe_time) >= 1.0:
                        print(f"  [WARN] NAT probe sendto({args.server_ip}:{target_server_port}) failed: {e}", file=sys.stderr, flush=True)
                    last_probe_time = now

        try:
            nbytes = recv_into(rx_buf)
            if nbytes >= 20:
                magic, burst_idx, seq_in_burst, _ = unpack_from(rx_buf, 0)
                if magic == MAGIC_HEADER:
                    if burst_idx == HANDSHAKE_BURST_IDX:
                        # Handshake probe or ACK received; pinhole confirmed open
                        handshake_acked = True
                        continue

                    # Valid burst traffic frame received
                    handshake_acked = True
                    if start_time is None:
                        start_time = now
                    received_packets += 1
                    burst_counts[burst_idx] = burst_counts.get(burst_idx, 0) + 1
                    last_rx_time = now
        except socket.timeout:
            now = time_func()
            if start_time is not None and (now - last_rx_time) > args.timeout:
                break
            if start_time is None and (now - last_rx_time) > (args.timeout + 4.0):
                break

    sock.close()

    lost_packets = max(0, args.expected_packets - received_packets)
    loss_pct = (lost_packets / args.expected_packets * 100.0) if args.expected_packets > 0 else 0.0
    status = "PASS" if lost_packets == 0 else "FAIL"

    result = {
        "test": "burst_traffic",
        "expected_packets": args.expected_packets,
        "received_packets": received_packets,
        "lost_packets": lost_packets,
        "loss_pct": round(loss_pct, 4),
        "total_bursts_seen": len(burst_counts),
        "status": status
    }

    print("\n--- BURST TEST RESULT ---")
    print(f"  Expected: {args.expected_packets} | Received: {received_packets} | Lost: {lost_packets} ({loss_pct:.2f}%)")
    print(f"  Verdict: [{status}]")

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)

    return 0 if status == "PASS" else 1

def run_unicast_sender(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)

    target_addr = (args.dest_ip, args.dest_port)

    # Stateful NAT Hole Punching: Wait for client probe before sending
    if getattr(args, "wait_handshake", False):
        listen_port = args.bind_port if getattr(args, "bind_port", 0) > 0 else args.dest_port
        try:
            sock.bind((getattr(args, "bind_ip", "0.0.0.0"), listen_port))
        except Exception as e:
            print(f"Error binding UDP socket on {args.bind_ip}:{listen_port}: {e}")
            sock.close()
            return

        sock.settimeout(0.5)
        print(f"=== UNICAST SENDER: WAITING FOR CLIENT NAT HANDSHAKE ===")
        print(f"  Listening on: {getattr(args, 'bind_ip', '0.0.0.0')}:{listen_port} (Timeout: {getattr(args, 'handshake_timeout', 5.0)}s)...")

        start_wait = time.time()
        handshake_done = False
        rx_buf = bytearray(2048)

        while (time.time() - start_wait) < getattr(args, "handshake_timeout", 5.0):
            try:
                nbytes, client_addr = sock.recvfrom_into(rx_buf)
                if nbytes >= 20:
                    magic, burst_idx, seq, _ = HEADER_STRUCT.unpack_from(rx_buf, 0)
                    if magic == MAGIC_HEADER and burst_idx == HANDSHAKE_BURST_IDX:
                        print(f"  [PASS] Received NAT handshake probe from {client_addr[0]}:{client_addr[1]}. Session established.")
                        target_addr = client_addr
                        ack_buf = bytearray(max(32, args.packet_size - 42))
                        HEADER_STRUCT.pack_into(ack_buf, 0, MAGIC_HEADER, HANDSHAKE_BURST_IDX, HANDSHAKE_SEQ_ACK, time.time())
                        for _ in range(3):
                            sock.sendto(ack_buf, client_addr)
                            time.sleep(0.005)
                        handshake_done = True
                        break
            except socket.timeout:
                continue

        if not handshake_done:
            print(f"  [WARN] No handshake probe received within {getattr(args, 'handshake_timeout', 5.0)}s. Falling back to {target_addr[0]}:{target_addr[1]}")
        else:
            time.sleep(0.05)

    try:
        sock.connect(target_addr)
    except Exception as e:
        print(f"Error connecting UDP socket: {e}")
        return

    payload_len = max(32, args.packet_size - 42)
    buf = bytearray(payload_len)
    buf[20:] = b"\xbb" * (payload_len - 20)

    pack_into = HEADER_STRUCT.pack_into
    send_call = sock.send
    perf_counter = time.perf_counter
    time_func = time.time

    frame_bits = (args.packet_size + 20) * 8
    target_pps = (args.rate_mbps * 1e6) / frame_bits
    inter_packet_delay = 1.0 / target_pps

    # Optimization: Batch clock pacing to avoid timer syscall overhead on every packet
    batch_size = 16 if target_pps > 20000 else 4
    batch_delay = inter_packet_delay * batch_size

    print(f"=== UNICAST SENDER START (OPTIMIZED) ===")
    print(f"  Target: {target_addr[0]}:{target_addr[1]}")
    print(f"  Frame Size: {args.packet_size}B | Target Rate: {args.rate_mbps} Mbps (~{target_pps:.0f} PPS)")
    print(f"  Duration: {args.duration}s | Batch Size: {batch_size}")

    end_time = time_func() + args.duration
    sent_count = 0
    seq = 0
    next_send = perf_counter()

    while time_func() < end_time:
        now_ts = time_func()
        for _ in range(batch_size):
            pack_into(buf, 0, MAGIC_HEADER, 0, seq, now_ts)
            send_call(buf)
            seq += 1
            sent_count += 1

        next_send += batch_delay
        wait = next_send - perf_counter()
        if wait > 0:
            if wait > 0.001:
                time.sleep(wait)
            else:
                while perf_counter() < next_send:
                    pass

    sock.close()
    print(f"=== UNICAST SENDER COMPLETE: Sent {sent_count} packets ===")

def run_unicast_receiver(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024 * 1024)
    sock.bind((args.bind_ip, args.bind_port))
    sock.settimeout(0.1)

    target_server_port = args.server_port if getattr(args, "server_port", 0) > 0 else args.bind_port
    has_server = bool(getattr(args, "server_ip", ""))

    print(f"=== UNICAST RECEIVER LISTENING on {args.bind_ip}:{args.bind_port} (OPTIMIZED) ===")
    if has_server:
        print(f"  NAT Traversal: Active (Probing {args.server_ip}:{target_server_port})")

    # Optimization: O(1) streaming stats without accumulating giant packet lists in memory
    rx_buf = bytearray(2048)
    recv_into = sock.recv_into
    unpack_from = HEADER_STRUCT.unpack_from
    probe_buf = bytearray(32)
    pack_into = HEADER_STRUCT.pack_into
    time_func = time.time

    received_packets = 0
    bytes_received = 0
    first_ts = None
    last_ts = None
    min_seq = None
    max_seq = None
    dropped_packets = 0
    expected_next_seq = 0
    handshake_acked = False
    last_probe_time = 0.0

    start_listen = time_func()
    while (time_func() - start_listen) < args.duration:
        now = time_func()

        if has_server and not handshake_acked and received_packets == 0:
            if (now - last_probe_time) >= 0.15:
                try:
                    pack_into(probe_buf, 0, MAGIC_HEADER, HANDSHAKE_BURST_IDX, HANDSHAKE_SEQ_PROBE, now)
                    sock.sendto(probe_buf, (args.server_ip, target_server_port))
                    last_probe_time = now
                except Exception:
                    pass

        try:
            nbytes = recv_into(rx_buf)
            now = time_func()

            if nbytes >= 20:
                magic, stream_idx, seq, _ = unpack_from(rx_buf, 0)
                if magic == MAGIC_HEADER:
                    if stream_idx == HANDSHAKE_BURST_IDX:
                        handshake_acked = True
                        continue

                    handshake_acked = True
                    if first_ts is None:
                        first_ts = now
                    last_ts = now
                    received_packets += 1
                    bytes_received += nbytes + 42

                    if min_seq is None:
                        min_seq = seq
                        max_seq = seq
                        expected_next_seq = seq + 1
                    else:
                        if seq > max_seq:
                            max_seq = seq
                        if seq > expected_next_seq:
                            dropped_packets += (seq - expected_next_seq)
                            expected_next_seq = seq + 1
                        elif seq == expected_next_seq:
                            expected_next_seq += 1
        except socket.timeout:
            continue

    sock.close()
    elapsed = (last_ts - first_ts) if (first_ts and last_ts and last_ts > first_ts) else 1.0
    throughput_mbps = (bytes_received * 8) / (elapsed * 1e6)

    if min_seq is not None and max_seq is not None:
        total_expected = max_seq - min_seq + 1
        loss_pct = (dropped_packets / total_expected * 100.0) if total_expected > 0 else 0.0
    else:
        loss_pct = 0.0

    status = "PASS" if loss_pct == 0.0 and received_packets > 0 else "FAIL"

    result = {
        "test": "unicast_throughput",
        "received_packets": received_packets,
        "throughput_mbps": round(throughput_mbps, 2),
        "loss_pct": round(loss_pct, 4),
        "status": status
    }

    print("\n--- UNICAST TEST RESULT ---")
    print(f"  Received: {received_packets} packets | Throughput: {throughput_mbps:.2f} Mbps | Loss: {loss_pct:.2f}%")
    print(f"  Verdict: [{status}]")

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)

    return 0 if status == "PASS" else 1

def run_mcast_sender(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    if args.interface_ip:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.interface_ip))

    try:
        sock.connect((args.group_ip, args.port))
    except Exception:
        pass

    payload_len = max(32, args.packet_size - 42)
    buf = bytearray(payload_len)
    buf[20:] = b"\xcc" * (payload_len - 20)

    pack_into = HEADER_STRUCT.pack_into
    send_call = sock.send
    perf_counter = time.perf_counter
    time_func = time.time

    frame_bits = (args.packet_size + 20) * 8
    target_pps = (args.rate_mbps * 1e6) / frame_bits
    inter_delay = 1.0 / target_pps

    print(f"=== MULTICAST SENDER START (OPTIMIZED) ===")
    print(f"  Group: {args.group_ip}:{args.port}")
    print(f"  Frame Size: {args.packet_size}B | Packets: {args.packets} | Rate: {args.rate_mbps} Mbps")

    warmup_count = getattr(args, "warmup_packets", 0)
    if warmup_count > 0:
        print(f"  Emitting {warmup_count} warmup packets to prime DUT hardware flow table...")
        for wseq in range(warmup_count):
            pack_into(buf, 0, MAGIC_HEADER, 0, wseq, time_func())
            send_call(buf)
            time.sleep(0.003)
        time.sleep(0.05)

    sent = 0
    next_t = perf_counter()
    for seq in range(args.packets):
        pack_into(buf, 0, MAGIC_HEADER, 1, seq, time_func())
        send_call(buf)
        sent += 1
        next_t += inter_delay
        wait = next_t - perf_counter()
        if wait > 0:
            if wait > 0.001:
                time.sleep(wait)
            else:
                while perf_counter() < next_t:
                    pass

    sock.close()
    print(f"=== MULTICAST SENDER COMPLETE: Sent {sent} packets ===")

def run_mcast_receiver(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", args.port))

    mreq = struct.pack("4s4s", socket.inet_aton(args.group_ip), socket.inet_aton(args.interface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    sock.settimeout(0.5)

    print(f"=== MULTICAST RECEIVER JOINED {args.group_ip}:{args.port} (OPTIMIZED) ===")
    print(f"  Expecting {args.expected_packets} packets | Timeout: {args.timeout}s")

    rx_buf = bytearray(2048)
    recv_into = sock.recv_into
    unpack_from = HEADER_STRUCT.unpack_from
    time_func = time.time

    received = 0
    first_seq = None
    last_seq = None
    start = None
    last_rx = time_func()

    while True:
        try:
            nbytes = recv_into(rx_buf)
            now = time_func()
            if start is None:
                start = now
            last_rx = now
            if nbytes >= 20:
                magic, stream_type, seq, _ = unpack_from(rx_buf, 0)
                if magic == MAGIC_HEADER:
                    if stream_type == 0:
                        continue  # Skip warmup packet
                    received += 1
                    if first_seq is None:
                        first_seq = seq
                    last_seq = seq
        except socket.timeout:
            now = time_func()
            if start and (now - last_rx) > args.timeout:
                break
            if not start and (now - last_rx) > (args.timeout + 4.0):
                break

    sock.close()
    lost = max(0, args.expected_packets - received)
    loss_pct = (lost / args.expected_packets * 100.0) if args.expected_packets > 0 else 0.0
    status = "PASS" if lost == 0 else "FAIL"

    result = {
        "test": "multicast_forwarding",
        "expected_packets": args.expected_packets,
        "received_packets": received,
        "lost_packets": lost,
        "loss_pct": round(loss_pct, 4),
        "first_seq_received": first_seq,
        "last_seq_received": last_seq,
        "status": status
    }

    print("\n--- MULTICAST TEST RESULT ---")
    print(f"  Expected: {args.expected_packets} | Received: {received} (seq {first_seq}..{last_seq}) | Lost: {lost} ({loss_pct:.2f}%)")
    print(f"  Verdict: [{status}]")

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)

    return 0 if status == "PASS" else 1

# ==============================================================================
# Cloud Gaming (GeForce NOW) Engine
# ==============================================================================

def run_gaming_server(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    target_addr = (args.dest_ip, args.dest_port)

    if getattr(args, "wait_handshake", False):
        listen_port = args.bind_port if getattr(args, "bind_port", 0) > 0 else args.dest_port
        try:
            sock.bind((getattr(args, "bind_ip", "0.0.0.0"), listen_port))
        except Exception as e:
            print(f"Error binding UDP socket on {args.bind_ip}:{listen_port}: {e}")
            sock.close()
            return

        sock.settimeout(0.5)
        print(f"=== GEFORCE NOW SERVER: WAITING FOR CLIENT NAT HANDSHAKE ===")
        print(f"  Listening on: {getattr(args, 'bind_ip', '0.0.0.0')}:{listen_port} (Timeout: {getattr(args, 'handshake_timeout', 5.0)}s)...")

        start_wait = time.time()
        handshake_done = False
        rx_buf = bytearray(2048)

        while (time.time() - start_wait) < getattr(args, "handshake_timeout", 5.0):
            try:
                nbytes, client_addr = sock.recvfrom_into(rx_buf)
                if nbytes >= 20:
                    magic, f_id, seq, _ = GFN_STRUCT.unpack_from(rx_buf, 0)
                    if magic == GFN_MAGIC and f_id == GFN_HANDSHAKE_ID:
                        print(f"  [PASS] Received NAT handshake probe from {client_addr[0]}:{client_addr[1]}. Session established.")
                        target_addr = client_addr
                        ack_buf = bytearray(max(32, 1200 - 42))
                        GFN_STRUCT.pack_into(ack_buf, 0, GFN_MAGIC, GFN_HANDSHAKE_ID, GFN_HANDSHAKE_ACK, time.time())
                        for _ in range(3):
                            sock.sendto(ack_buf, client_addr)
                            time.sleep(0.005)
                        handshake_done = True
                        break
            except socket.timeout:
                continue

        if not handshake_done:
            print(f"  [WARN] No handshake probe received within {getattr(args, 'handshake_timeout', 5.0)}s. Falling back to {target_addr[0]}:{target_addr[1]}")
        else:
            time.sleep(0.05)

    try:
        sock.connect(target_addr)
    except Exception as e:
        print(f"Error connecting UDP socket: {e}")
        sock.close()
        return

    frame_rate = getattr(args, "frame_rate", 60)
    bitrate_mbps = getattr(args, "bitrate_mbps", 25.0)
    packets_per_frame = max(1, int((bitrate_mbps * 1e6) / (frame_rate * 8 * 1200)))
    packet_size = 1200
    payload_len = max(32, packet_size - 42)

    buf = bytearray(payload_len)
    buf[20:] = b"\xdd" * (payload_len - 20)

    frame_interval = 1.0 / frame_rate
    slice_interval = frame_interval / packets_per_frame

    pack_into = GFN_STRUCT.pack_into
    send_call = sock.send
    perf_counter = time.perf_counter
    sleep_func = time.sleep

    print(f"=== GEFORCE NOW SERVER STREAMING (OPTIMIZED) ===")
    print(f"  Target STB: {args.dest_ip}:{args.dest_port}")
    print(f"  Bitrate: {bitrate_mbps} Mbps | FPS: {frame_rate} | Slices/Frame: {packets_per_frame}")
    print(f"  Duration: {args.duration}s")

    start_stream = perf_counter()
    end_time = start_stream + args.duration
    seq = 0
    frame_idx = 0
    total_sent = 0
    next_packet_time = start_stream
    last_report_time = start_stream
    report_interval = getattr(args, "report_interval", 1.0)

    while perf_counter() < end_time:
        for _ in range(packets_per_frame):
            send_ts = perf_counter()
            pack_into(buf, 0, GFN_MAGIC, frame_idx, seq, send_ts)
            send_call(buf)
            seq += 1
            total_sent += 1

            next_packet_time += slice_interval
            wait_time = next_packet_time - perf_counter()
            if wait_time > 0:
                if wait_time > 0.001:
                    sleep_func(wait_time - 0.0005)
                while perf_counter() < next_packet_time:
                    pass
        frame_idx += 1

        now_pc = perf_counter()
        if report_interval > 0 and (now_pc - last_report_time) >= report_interval:
            elapsed = now_pc - start_stream
            current_pps = total_sent / elapsed if elapsed > 0 else 0
            current_mbps = (total_sent * 1200 * 8) / (elapsed * 1e6) if elapsed > 0 else 0
            print(f"  [Tx {elapsed:5.1f}s / {args.duration:.1f}s] Sent: {total_sent:7d} pkts ({frame_idx:4d} frames) | Rate: {current_mbps:5.2f} Mbps | PPS: {current_pps:5.0f}", flush=True)
            last_report_time = now_pc

    sock.close()
    print(f"=== GEFORCE NOW SERVER COMPLETE: Sent {total_sent} packets ({frame_idx} frames) ===", flush=True)


def run_gaming_client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    try:
        sock.bind((args.bind_ip, args.bind_port))
    except Exception as e:
        print(f"Error binding UDP socket on {args.bind_ip}:{args.bind_port}: {e}", file=sys.stderr, flush=True)
        sock.close()
        return 1
    sock.settimeout(0.1)

    target_server_port = args.server_port if getattr(args, "server_port", 0) > 0 else args.bind_port
    has_server = bool(getattr(args, "server_ip", ""))

    print(f"=== GEFORCE NOW CLIENT LISTENING on {args.bind_ip}:{args.bind_port} (OPTIMIZED) ===", flush=True)
    print(f"  Criteria: Max Loss <= {getattr(args, 'max_loss_pct', 0.0)}%, Max Jitter <= {getattr(args, 'max_jitter_ms', 2.0)} ms", flush=True)
    if has_server:
        print(f"  NAT Traversal: Active (Probing {args.server_ip}:{target_server_port})", flush=True)

    rx_buf = bytearray(2048)
    recv_into = sock.recv_into
    unpack_from = GFN_STRUCT.unpack_from
    probe_buf = bytearray(32)
    pack_into = GFN_STRUCT.pack_into
    perf_counter = time.perf_counter
    time_func = time.time

    received = 0
    min_seq = None
    max_seq = 0
    expected_next_seq = 0
    dropped_packets = 0

    jitter = 0.0
    prev_send_ts = None
    prev_recv_ts = None
    first_ts = None
    last_ts = None
    handshake_acked = False
    last_probe_time = 0.0
    last_report_time = 0.0
    last_report_rx = 0

    start_listen = perf_counter()
    while (perf_counter() - start_listen) < args.duration:
        now_t = time_func()

        if has_server and not handshake_acked and received == 0:
            if (now_t - last_probe_time) >= 0.15:
                try:
                    pack_into(probe_buf, 0, GFN_MAGIC, GFN_HANDSHAKE_ID, GFN_HANDSHAKE_PROBE, perf_counter())
                    sock.sendto(probe_buf, (args.server_ip, target_server_port))
                    if last_probe_time == 0.0:
                        print(f"  [INFO] Sent initial NAT probe to {args.server_ip}:{target_server_port}...", flush=True)
                    last_probe_time = now_t
                except Exception as e:
                    if last_probe_time == 0.0 or (now_t - last_probe_time) >= 1.0:
                        print(f"  [WARN] NAT probe sendto({args.server_ip}:{target_server_port}) failed: {e}", file=sys.stderr, flush=True)
                    last_probe_time = now_t

        try:
            nbytes = recv_into(rx_buf)
            now = perf_counter()

            if nbytes >= 20:
                magic, f_id, seq, send_ts = unpack_from(rx_buf, 0)
                if magic == GFN_MAGIC:
                    if f_id == GFN_HANDSHAKE_ID:
                        handshake_acked = True
                        continue

                    handshake_acked = True
                    if first_ts is None:
                        first_ts = now
                    last_ts = now
                    received += 1

                    if min_seq is None:
                        min_seq = seq
                        max_seq = seq
                        expected_next_seq = seq + 1
                    else:
                        if seq > max_seq:
                            max_seq = seq
                        if seq == expected_next_seq:
                            expected_next_seq = seq + 1
                        elif seq > expected_next_seq:
                            dropped_packets += (seq - expected_next_seq)
                            expected_next_seq = seq + 1

                    if prev_send_ts is not None and prev_recv_ts is not None:
                        d = (now - send_ts) - (prev_recv_ts - prev_send_ts)
                        jitter += (abs(d) - jitter) / 16.0
                    prev_send_ts = send_ts
                    prev_recv_ts = now

                    report_interval = getattr(args, "report_interval", 1.0)
                    if report_interval > 0 and (now - last_report_time) >= report_interval:
                        if last_report_time == 0.0:
                            last_report_time = first_ts
                        int_sec = now - last_report_time
                        int_rx = received - last_report_rx
                        int_mbps = (int_rx * 1200 * 8) / (int_sec * 1e6) if int_sec > 0 else 0
                        int_pps = int_rx / int_sec if int_sec > 0 else 0
                        total_elapsed = now - first_ts
                        print(f"  [Rx {total_elapsed:5.1f}s] Rx: {received:7d} pkts | Rate: {int_mbps:5.2f} Mbps | Jitter: {jitter*1000:6.3f} ms | Drops: {dropped_packets:2d}", flush=True)
                        last_report_time = now
                        last_report_rx = received
        except socket.timeout:
            if received > 0 and last_ts and (perf_counter() - last_ts) > 2.0:
                break

    sock.close()

    if min_seq is not None:
        expected = max_seq - min_seq + 1
        lost = max(0, expected - received)
        loss_pct = (lost / expected * 100.0) if expected > 0 else 0.0
    else:
        expected = 0
        lost = 0
        loss_pct = 100.0

    jitter_ms = jitter * 1000.0
    max_loss_pct = getattr(args, "max_loss_pct", 0.0)
    max_jitter_ms = getattr(args, "max_jitter_ms", 2.0)
    is_normal = (loss_pct <= max_loss_pct) and (jitter_ms <= max_jitter_ms) and (received > 0)
    status = "PASS" if is_normal else "FAIL"

    measured_duration = (last_ts - first_ts) if (last_ts and first_ts and last_ts > first_ts) else 0.0
    measured_mbps = round((received * 1200 * 8) / (measured_duration * 1e6), 2) if measured_duration > 0 else 0.0

    result = {
        "test": "geforce_now_network_test",
        "target_fps": getattr(args, "fps", 60),
        "target_mbps": getattr(args, "target_mbps", 25.0),
        "measured_mbps": measured_mbps,
        "expected_packets": expected,
        "received_packets": received,
        "lost_packets": lost,
        "loss_pct": round(loss_pct, 4),
        "jitter_ms": round(jitter_ms, 3),
        "max_jitter_ms": max_jitter_ms,
        "network_test_status": "NORMAL" if is_normal else "ABNORMAL",
        "verdict": status
    }

    print("\n--- GEFORCE NOW NETWORK TEST RESULT ---")
    print(f"  Received: {received} / {expected} | Loss: {loss_pct:.2f}% | Jitter: {jitter_ms:.3f} ms")
    print(f"  App Status: {result['network_test_status']}")
    print(f"  Verdict: [{status}]")

    if getattr(args, "output_json", ""):
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)

    return 0 if status == "PASS" else 1

# ==============================================================================
# UHD+Dolby VOD 1.2x Streaming Engine
# ==============================================================================

def run_vod_server(args):
    base_rate = getattr(args, "base_bitrate_mbps", 35.0)
    speed = getattr(args, "playback_speed", 1.2)
    target_bitrate = base_rate * speed
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    if getattr(args, "dscp", 0) > 0:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.dscp << 2)
        except Exception as e:
            print(f"Warning: Could not set IP_TOS: {e}")

    target_addr = (args.dest_ip, args.dest_port)

    if getattr(args, "wait_handshake", False):
        listen_port = args.bind_port if getattr(args, "bind_port", 0) > 0 else args.dest_port
        try:
            sock.bind((getattr(args, "bind_ip", "0.0.0.0"), listen_port))
        except Exception as e:
            print(f"Error binding UDP socket on {args.bind_ip}:{listen_port}: {e}")
            sock.close()
            return

        sock.settimeout(0.5)
        print(f"=== UHD+DOLBY VOD SERVER: WAITING FOR CLIENT NAT HANDSHAKE ===")
        print(f"  Listening on: {getattr(args, 'bind_ip', '0.0.0.0')}:{listen_port} (Timeout: {getattr(args, 'handshake_timeout', 5.0)}s)...")

        start_wait = time.time()
        handshake_done = False
        rx_buf = bytearray(2048)

        while (time.time() - start_wait) < getattr(args, "handshake_timeout", 5.0):
            try:
                nbytes, client_addr = sock.recvfrom_into(rx_buf)
                if nbytes >= 20:
                    magic, stream_id, seq, _ = VOD_STRUCT.unpack_from(rx_buf, 0)
                    if magic == VOD_MAGIC and stream_id == VOD_HANDSHAKE_ID:
                        print(f"  [PASS] Received NAT handshake probe from {client_addr[0]}:{client_addr[1]}. Session established.")
                        target_addr = client_addr
                        ack_buf = bytearray(max(32, 1316 - 42))
                        VOD_STRUCT.pack_into(ack_buf, 0, VOD_MAGIC, VOD_HANDSHAKE_ID, VOD_HANDSHAKE_ACK, time.time())
                        for _ in range(3):
                            sock.sendto(ack_buf, client_addr)
                            time.sleep(0.005)
                        handshake_done = True
                        break
            except socket.timeout:
                continue

        if not handshake_done:
            print(f"  [WARN] No handshake probe received within {getattr(args, 'handshake_timeout', 5.0)}s. Falling back to {target_addr[0]}:{target_addr[1]}")
        else:
            time.sleep(0.05)

    try:
        sock.connect(target_addr)
    except Exception as e:
        print(f"Error connecting UDP socket: {e}")
        sock.close()
        return

    packet_size = 1316
    payload_len = max(32, packet_size - 42)

    buf = bytearray(payload_len)
    buf[20:] = b"\xee" * (payload_len - 20)

    frame_bits = (packet_size + 20) * 8
    target_pps = (target_bitrate * 1e6) / frame_bits
    inter_packet_delay = 1.0 / target_pps

    pack_into = VOD_STRUCT.pack_into
    send_call = sock.send
    perf_counter = time.perf_counter
    sleep_func = time.sleep

    batch_size = 4
    batch_delay = inter_packet_delay * batch_size

    print(f"=== UHD+DOLBY VOD SERVER START (OPTIMIZED) ===")
    print(f"  Target STB: {args.dest_ip}:{args.dest_port}")
    print(f"  Base Bitrate: {base_rate} Mbps | Speed: {speed}x -> Target: {target_bitrate:.2f} Mbps")
    print(f"  Duration: {args.duration}s (~{target_pps:.0f} PPS)")

    start_stream = perf_counter()
    end_time = start_stream + args.duration
    seq = 0
    total_sent = 0
    next_send = perf_counter()
    last_report_time = start_stream
    report_interval = getattr(args, "report_interval", 1.0)

    while perf_counter() < end_time:
        now_ts = perf_counter()
        for _ in range(batch_size):
            pack_into(buf, 0, VOD_MAGIC, 0, seq, now_ts)
            send_call(buf)
            seq += 1
            total_sent += 1

        if report_interval > 0 and (now_ts - last_report_time) >= report_interval:
            elapsed = now_ts - start_stream
            current_pps = total_sent / elapsed if elapsed > 0 else 0
            current_mbps = (total_sent * (packet_size + 20) * 8) / (elapsed * 1e6) if elapsed > 0 else 0
            print(f"  [Tx {elapsed:5.1f}s / {args.duration:.1f}s] Sent: {total_sent:7d} pkts | Rate: {current_mbps:5.2f} Mbps | PPS: {current_pps:5.0f}", flush=True)
            last_report_time = now_ts

        next_send += batch_delay
        wait = next_send - perf_counter()
        if wait > 0:
            if wait > 0.001:
                sleep_func(wait - 0.0005)
            while perf_counter() < next_send:
                pass

    sock.close()
    print(f"=== UHD+DOLBY VOD SERVER COMPLETE: Sent {total_sent} packets ===", flush=True)


def run_vod_client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    if getattr(args, "dscp", 0) > 0:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.dscp << 2)
        except Exception as e:
            print(f"Warning: Could not set IP_TOS: {e}")
    try:
        sock.bind((args.bind_ip, args.bind_port))
    except Exception as e:
        print(f"Error binding UDP socket on {args.bind_ip}:{args.bind_port}: {e}", file=sys.stderr, flush=True)
        sock.close()
        return 1
    sock.settimeout(0.1)

    target_server_port = args.server_port if getattr(args, "server_port", 0) > 0 else args.bind_port
    has_server = bool(getattr(args, "server_ip", ""))

    print(f"=== UHD+DOLBY VOD CLIENT LISTENING on {args.bind_ip}:{args.bind_port} (OPTIMIZED) ===", flush=True)
    if has_server:
        print(f"  NAT Traversal: Active (Probing {args.server_ip}:{target_server_port})", flush=True)

    rx_buf = bytearray(2048)
    recv_into = sock.recv_into
    unpack_from = VOD_STRUCT.unpack_from
    probe_buf = bytearray(32)
    pack_into = VOD_STRUCT.pack_into
    perf_counter = time.perf_counter
    time_func = time.time

    received = 0
    bytes_rx = 0
    min_seq = None
    max_seq = 0
    expected_next_seq = 0
    dropped_packets = 0

    first_ts = None
    last_ts = None
    stall_events = 0
    prev_rx = None
    handshake_acked = False
    last_probe_time = 0.0
    last_report_time = 0.0
    last_report_rx = 0
    last_report_bytes = 0

    start_listen = perf_counter()
    while (perf_counter() - start_listen) < args.duration:
        now_t = time_func()

        if has_server and not handshake_acked and received == 0:
            if (now_t - last_probe_time) >= 0.15:
                try:
                    pack_into(probe_buf, 0, VOD_MAGIC, VOD_HANDSHAKE_ID, VOD_HANDSHAKE_PROBE, perf_counter())
                    sock.sendto(probe_buf, (args.server_ip, target_server_port))
                    if last_probe_time == 0.0:
                        print(f"  [INFO] Sent initial NAT probe to {args.server_ip}:{target_server_port}...", flush=True)
                    last_probe_time = now_t
                except Exception as e:
                    if last_probe_time == 0.0 or (now_t - last_probe_time) >= 1.0:
                        print(f"  [WARN] NAT probe sendto({args.server_ip}:{target_server_port}) failed: {e}", file=sys.stderr, flush=True)
                    last_probe_time = now_t

        try:
            nbytes = recv_into(rx_buf)
            now = perf_counter()

            if nbytes >= 20:
                magic, stream_id, seq, _ = unpack_from(rx_buf, 0)
                if magic == VOD_MAGIC:
                    if stream_id == VOD_HANDSHAKE_ID:
                        handshake_acked = True
                        continue

                    handshake_acked = True
                    if first_ts is None:
                        first_ts = now

                    if prev_rx is not None and (now - prev_rx) > 0.05:
                        stall_events += 1

                    prev_rx = now
                    last_ts = now
                    received += 1
                    bytes_rx += nbytes + 42

                    if min_seq is None:
                        min_seq = seq
                        max_seq = seq
                        expected_next_seq = seq + 1
                    else:
                        if seq > max_seq:
                            max_seq = seq
                        if seq == expected_next_seq:
                            expected_next_seq = seq + 1
                        elif seq > expected_next_seq:
                            dropped_packets += (seq - expected_next_seq)
                            expected_next_seq = seq + 1

                    report_interval = getattr(args, "report_interval", 1.0)
                    if report_interval > 0 and (now - last_report_time) >= report_interval:
                        if last_report_time == 0.0:
                            last_report_time = first_ts
                        int_sec = now - last_report_time
                        int_rx = received - last_report_rx
                        int_bytes = bytes_rx - last_report_bytes
                        int_mbps = (int_bytes * 8) / (int_sec * 1e6) if int_sec > 0 else 0
                        int_pps = int_rx / int_sec if int_sec > 0 else 0
                        total_elapsed = now - first_ts
                        print(f"  [Rx {total_elapsed:5.1f}s] Rx: {received:7d} pkts | Rate: {int_mbps:5.2f} Mbps | PPS: {int_pps:5.0f} | Stalls: {stall_events:2d} | Drops: {dropped_packets:2d}", flush=True)
                        last_report_time = now
                        last_report_rx = received
                        last_report_bytes = bytes_rx
        except socket.timeout:
            if received > 0 and last_ts and (perf_counter() - last_ts) > 2.0:
                break

    sock.close()

    elapsed = (last_ts - first_ts) if (first_ts and last_ts and last_ts > first_ts) else 1.0
    throughput_mbps = (bytes_rx * 8) / (elapsed * 1e6)

    if min_seq is not None:
        expected = max_seq - min_seq + 1
        lost = max(0, expected - received)
        loss_pct = (lost / expected * 100.0) if expected > 0 else 0.0
    else:
        expected = 0
        lost = 0
        loss_pct = 100.0

    min_tp = getattr(args, "min_throughput_mbps", 35.0)
    max_loss = getattr(args, "max_loss_pct", 0.0)
    is_normal = (loss_pct <= max_loss) and (throughput_mbps >= min_tp) and (stall_events <= 1)
    status = "PASS" if is_normal else "FAIL"

    result = {
        "test": "uhd_dolby_vod_1_2x",
        "received_packets": received,
        "loss_pct": round(loss_pct, 4),
        "throughput_mbps": round(throughput_mbps, 2),
        "stall_events": stall_events,
        "playback_status": "NORMAL" if is_normal else "STALLING_OR_DROPPED",
        "verdict": status
    }

    print("\n--- UHD+DOLBY 1.2x VOD TEST RESULT ---")
    print(f"  Throughput: {throughput_mbps:.2f} Mbps | Loss: {loss_pct:.2f}% | Stalls: {stall_events}")
    print(f"  Playback Status: {result['playback_status']}")
    print(f"  Verdict: [{status}]")

    if getattr(args, "output_json", ""):
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)

    return 0 if status == "PASS" else 1

# ==============================================================================
# VoIP RTP Echo & Call Simulation Engine
# ==============================================================================

def handle_rtp_echo(sock, port):
    buf = bytearray(1024)
    view = memoryview(buf)
    recvfrom_into = sock.recvfrom_into
    sendto = sock.sendto

    while True:
        try:
            nbytes, addr = recvfrom_into(buf)
            sendto(view[:nbytes], addr)
        except Exception:
            break


def run_voip_server(args):
    ports_raw = getattr(args, "ports", "10000,10002")
    ports = [int(p.strip()) for p in ports_raw.split(",")]
    sockets = []
    threads = []

    print(f"=== VOIP MEDIA SERVER LISTENING on ports {ports} (OPTIMIZED) ===")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        if getattr(args, "dscp", 0) > 0:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.dscp << 2)
            except Exception as e:
                print(f"Warning: Could not set IP_TOS on server socket: {e}")
        sock.bind((args.bind_ip, port))
        sockets.append(sock)

        t = threading.Thread(target=handle_rtp_echo, args=(sock, port), daemon=True)
        t.start()
        threads.append(t)

    time.sleep(args.duration)
    for s in sockets:
        s.close()
    print("=== VOIP MEDIA SERVER TERMINATED ===")


def run_voip_client(args):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)

    dscp_val = getattr(args, "dscp", 46)
    if dscp_val > 0:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp_val << 2)
        except Exception as e:
            print(f"Warning: Could not set IP_TOS: {e}")

    bind_ip = getattr(args, "bind_ip", "0.0.0.0")
    bind_port = getattr(args, "bind_port", 0)
    if bind_ip != "0.0.0.0" or bind_port != 0:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_ip, bind_port))
        except Exception as e:
            print(f"Warning: Could not bind to {bind_ip}:{bind_port}: {e}")

    try:
        sock.connect((args.server_ip, args.server_port))
    except Exception as e:
        print(f"Error connecting UDP socket: {e}")
        return 1

    sock.setblocking(False)

    tx_buf = bytearray(172)
    rx_buf = bytearray(512)

    ssrc = 0x12345678
    seq = 0
    rtp_ts = 0

    pack_into = RTP_STRUCT.pack_into
    send_call = sock.send
    recv_into = sock.recv_into
    perf_counter = time.perf_counter
    sleep_func = time.sleep

    phone_id = getattr(args, "phone_id", "phone-1")
    print(f"=== WI-FI PHONE ({phone_id}) CALL IN PROGRESS (OPTIMIZED) ===")
    print(f"  Target Server: {args.server_ip}:{args.server_port} | Codec: G.711 (20ms, 64kbps + overhead)")
    print(f"  Call Duration: {args.duration}s")

    end_time = perf_counter() + args.duration
    sent = 0
    received = 0
    next_send = perf_counter()

    while perf_counter() < end_time:
        pack_into(tx_buf, 0, 0x80, 0x00, seq & 0xffff, rtp_ts & 0xffffffff, ssrc)
        try:
            send_call(tx_buf)
            sent += 1
        except Exception:
            pass

        seq += 1
        rtp_ts += 160

        while True:
            try:
                nbytes = recv_into(rx_buf)
                if nbytes >= 12:
                    received += 1
            except (BlockingIOError, socket.error):
                break

        next_send += 0.020
        wait = next_send - perf_counter()
        if wait > 0:
            if wait > 0.001:
                sleep_func(wait - 0.0005)
            while perf_counter() < next_send:
                pass

    sock.close()

    loss_pkts = max(0, sent - received)
    loss_pct = (loss_pkts / sent * 100.0) if sent > 0 else 0.0
    status = "PASS" if loss_pct <= 1.0 else "FAIL"

    result = {
        "test": "voip_rtp_simulation",
        "phone_id": phone_id,
        "sent_packets": sent,
        "received_packets": received,
        "lost_packets": loss_pkts,
        "loss_pct": round(loss_pct, 2),
        "dscp": dscp_val,
        "verdict": status
    }

    print(f"\n--- WI-FI PHONE ({phone_id}) RESULT ---")
    print(f"  Sent: {sent} | Received: {received} | Lost: {loss_pkts} ({loss_pct:.2f}%)")
    print(f"  Verdict: [{status}]")

    if getattr(args, "output_json", ""):
        with open(args.output_json, "w") as f:
            json.dump(result, f, indent=2)

    return 0 if status == "PASS" else 1

# ==============================================================================
# Declarative Stream Dispatcher
# ==============================================================================

def run_stream_sender(args):
    prof = args.profile
    if prof == "gaming":
        if not getattr(args, "dest_port", 0):
            args.dest_port = 5004
        return run_gaming_server(args)
    elif prof == "vod":
        if not getattr(args, "dest_port", 0):
            args.dest_port = 5005
        return run_vod_server(args)
    elif prof == "voip":
        return run_voip_server(args)
    elif prof in ("unicast", "wire_rate"):
        if not getattr(args, "dest_port", 0):
            args.dest_port = 5002
        return run_unicast_sender(args)
    elif prof == "burst":
        if not getattr(args, "dest_port", 0):
            args.dest_port = 5001
        return run_burst_sender(args)
    elif prof == "multicast":
        return run_mcast_sender(args)
    else:
        print(f"Unknown stream profile: {prof}", file=sys.stderr)
        return 1


def run_stream_receiver(args):
    prof = args.profile
    if prof == "gaming":
        if not getattr(args, "bind_port", 0):
            args.bind_port = 5004
        return run_gaming_client(args)
    elif prof == "vod":
        if not getattr(args, "bind_port", 0):
            args.bind_port = 5005
        return run_vod_client(args)
    elif prof == "voip":
        return run_voip_client(args)
    elif prof in ("unicast", "wire_rate"):
        if not getattr(args, "bind_port", 0):
            args.bind_port = 5002
        return run_unicast_receiver(args)
    elif prof == "burst":
        if not getattr(args, "bind_port", 0):
            args.bind_port = 5001
        return run_burst_receiver(args)
    elif prof == "multicast":
        return run_mcast_receiver(args)
    else:
        print(f"Unknown stream profile: {prof}", file=sys.stderr)
        return 1

# ==============================================================================
# CLI Main
# ==============================================================================

def main():
    args = parse_args()
    if args.mode == "burst-send":
        run_burst_sender(args)
    elif args.mode == "burst-recv":
        sys.exit(run_burst_receiver(args))
    elif args.mode == "unicast-send":
        run_unicast_sender(args)
    elif args.mode == "unicast-recv":
        sys.exit(run_unicast_receiver(args))
    elif args.mode == "mcast-send":
        run_mcast_sender(args)
    elif args.mode == "mcast-recv":
        sys.exit(run_mcast_receiver(args))
    elif args.mode in ("gaming-server", "gaming-send"):
        run_gaming_server(args)
    elif args.mode in ("gaming-client", "gaming-recv"):
        sys.exit(run_gaming_client(args))
    elif args.mode in ("vod-server", "vod-send"):
        run_vod_server(args)
    elif args.mode in ("vod-client", "vod-recv"):
        sys.exit(run_vod_client(args))
    elif args.mode == "voip-server":
        run_voip_server(args)
    elif args.mode == "voip-client":
        sys.exit(run_voip_client(args))
    elif args.mode == "stream-send":
        sys.exit(run_stream_sender(args) or 0)
    elif args.mode == "stream-recv":
        sys.exit(run_stream_receiver(args) or 0)

if __name__ == "__main__":
    main()

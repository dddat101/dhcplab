#!/usr/bin/env python3
"""
Gateway Network Test Lab - Gateway IGMP Multicast Forwarder Daemon (Optimized)
Emulates CPE/AP Hardware Multicast Snooping & IGMP Proxy forwarding between WAN and LAN.
Optimized with pre-allocated zero-copy bytearray buffers, connected multicast sockets,
and signal-safe termination.
"""

import sys
import os
import signal
import socket
import struct
import time
import argparse

running = True

def handle_signal(sig, frame):
    global running
    running = False

def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    parser = argparse.ArgumentParser(description="IGMP Multicast Forwarder Proxy (Optimized)")
    parser.add_argument("--group-ip", default="239.255.0.1", help="Multicast group IP")
    parser.add_argument("--port", type=int, default=5003, help="Multicast UDP port")
    parser.add_argument("--wan-if-ip", default="10.10.0.2", help="DUT WAN interface IP to join on")
    parser.add_argument("--lan-if-ip", default="192.168.1.1", help="DUT LAN interface IP to emit on")
    parser.add_argument("--duration", type=float, default=15.0, help="Run duration in seconds")
    args = parser.parse_args()

    # 1. Receiver socket on WAN interface
    rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    rx_sock.bind(("", args.port))

    # Join multicast group on WAN interface
    mreq = struct.pack("4s4s", socket.inet_aton(args.group_ip), socket.inet_aton(args.wan_if_ip))
    rx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    rx_sock.settimeout(0.1)

    # 2. Sender socket on LAN interface
    tx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    tx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    tx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 4)
    tx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(args.lan_if_ip))

    use_connected_send = True
    try:
        tx_sock.connect((args.group_ip, args.port))
    except Exception:
        use_connected_send = False

    print(f"=== MULTICAST FORWARDER ACTIVE (OPTIMIZED): {args.group_ip}:{args.port} (WAN {args.wan_if_ip} -> LAN {args.lan_if_ip}) ===")

    # Zero-allocation buffer and memoryview
    rx_buf = bytearray(2048)
    view = memoryview(rx_buf)
    recv_into = rx_sock.recv_into
    send_call = tx_sock.send if use_connected_send else None
    sendto_call = tx_sock.sendto
    dest_tuple = (args.group_ip, args.port)

    perf_counter = time.perf_counter
    end_time = perf_counter() + args.duration
    forwarded = 0

    while running and perf_counter() < end_time:
        try:
            nbytes = recv_into(rx_buf)
            if nbytes > 0:
                if use_connected_send:
                    send_call(view[:nbytes])
                else:
                    sendto_call(view[:nbytes], dest_tuple)
                forwarded += 1
        except socket.timeout:
            continue
        except Exception:
            break

    try:
        rx_sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, mreq)
    except Exception:
        pass

    rx_sock.close()
    tx_sock.close()
    print(f"=== MULTICAST FORWARDER STOPPED: Forwarded {forwarded} packets ===")

if __name__ == "__main__":
    main()

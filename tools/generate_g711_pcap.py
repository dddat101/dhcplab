#!/usr/bin/env python3
"""
Generate a continuous 20-second G.711 PCAP stream (50 PPS, 20ms pacing, DSCP 46 EF).
Compatible with SIPp play_pcap_audio and Wireshark RTP stream analysis.
"""
import struct
import math
import argparse
import sys

def ip_checksum(data):
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def generate_pcap(output_file="templates/g711a_20s.pcap", duration=20.0, pps=50):
    packet_count = int(duration * pps)
    interval_sec = 1.0 / pps
    samples_per_pkt = 160  # 8000 Hz * 0.02s

    global_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Generate 440 Hz audio tone in G.711 A-law (PCMA)
    audio_sample = bytearray(samples_per_pkt)
    for i in range(samples_per_pkt):
        audio_sample[i] = int(128 + 64 * math.sin(2 * math.pi * 440 * i / 8000)) & 0xff

    src_mac = b"\x00\x11\x22\x33\x44\x55"
    dst_mac = b"\x66\x77\x88\x99\xaa\xbb"
    eth_hdr = dst_mac + src_mac + struct.pack("!H", 0x0800)

    src_ip = bytes([192, 168, 1, 100])
    dst_ip = bytes([10, 10, 0, 1])

    ssrc = 0x11223344
    base_ts = 1000000

    with open(output_file, "wb") as f:
        f.write(global_hdr)

        for seq in range(packet_count):
            t = seq * interval_sec
            ts_sec = int(t)
            ts_usec = int((t - ts_sec) * 1_000_000)

            # RTP Header (12 bytes)
            # PT=8 (PCMA)
            rtp_hdr = struct.pack("!BBHII", 0x80, 8, seq & 0xffff, (base_ts + seq * samples_per_pkt) & 0xffffffff, ssrc)
            rtp_pkt = rtp_hdr + bytes(audio_sample)

            # UDP Header (8 bytes)
            udp_len = 8 + len(rtp_pkt)
            udp_hdr = struct.pack("!HHHH", 10000, 10000, udp_len, 0)

            # IP Header (20 bytes)
            ip_len = 20 + udp_len
            ip_hdr_no_cksum = struct.pack("!BBHHHBBH4s4s", 0x45, 0xb8, ip_len, seq & 0xffff, 0, 64, 17, 0, src_ip, dst_ip)
            cksum = ip_checksum(ip_hdr_no_cksum)
            ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0xb8, ip_len, seq & 0xffff, 0, 64, 17, cksum, src_ip, dst_ip)

            frame = eth_hdr + ip_hdr + udp_hdr + rtp_pkt
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
            f.write(pkt_hdr + frame)

    print(f"[OK] Generated {output_file}: {packet_count} packets, duration: {duration}s, {pps} PPS.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate G.711 RTP PCAP file for SIPp play_pcap_audio")
    parser.add_argument("--output", "-o", default="templates/g711a_20s.pcap", help="Output PCAP file path")
    parser.add_argument("--duration", "-d", type=float, default=20.0, help="Duration in seconds (default: 20)")
    parser.add_argument("--pps", type=int, default=50, help="Packets per second (default: 50)")
    args = parser.parse_args()

    generate_pcap(output_file=args.output, duration=args.duration, pps=args.pps)

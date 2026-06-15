#!/usr/bin/env python3
import argparse
import os
import select
import socket
import struct
import time

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xffff) + (total >> 16)

    return (~total) & 0xffff


def make_echo_request(ident: int, seq: int) -> bytes:
    payload = struct.pack("!d", time.time()) + b"python-ping"
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    csum = checksum(header + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident, seq) + payload


def ping_once(interface: str, target: str, timeout: float = 1.0):
    target_ip = socket.gethostbyname(target)
    ident = os.getpid() & 0xffff
    seq = 1

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Linux: bind outgoing/incoming packets to this interface.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")

    packet = make_echo_request(ident, seq)
    start = time.time()
    sock.sendto(packet, (target_ip, 0))

    ready, _, _ = select.select([sock], [], [], timeout)
    if not ready:
        print(f"timeout from {target_ip} via {interface}")
        return False

    while ready:
        data, addr = sock.recvfrom(4096)
        ip_header_len = (data[0] & 0x0f) * 4
        icmp_header = data[ip_header_len:ip_header_len + 8]

        icmp_type, code, _, reply_id, reply_seq = struct.unpack("!BBHHH", icmp_header)

        if icmp_type == ICMP_ECHO_REPLY and reply_id == ident and reply_seq == seq:
            rtt_ms = (time.time() - start) * 1000
            print(f"reply from {addr[0]} via {interface}: time={rtt_ms:.2f} ms")
            return True

        ready, _, _ = select.select([sock], [], [], max(0, timeout - (time.time() - start)))

    print(f"timeout from {target_ip} via {interface}")
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="Interface name, e.g. eth0")
    parser.add_argument("target", help="Target hostname or IPv4 address")
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args()

    ping_once(args.interface, args.target, args.timeout)
# Run it with root or CAP_NET_RAW:

# bash

# sudo python3 iface_ping_once.py eth0 8.8.8.8
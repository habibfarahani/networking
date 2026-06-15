#!/usr/bin/env python3
import argparse
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


def build_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, ident: int) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_len = 20 + payload_len
    flags_frag = 0
    ttl = 64
    proto = socket.IPPROTO_ICMP
    csum = 0

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        csum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    csum = checksum(header)

    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        csum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )


def build_echo_reply(request_icmp: bytes) -> bytes:
    if len(request_icmp) < 8:
        raise ValueError("truncated ICMP packet")

    _rtype, code, _csum, ident, seq = struct.unpack("!BBHHH", request_icmp[:8])
    payload = request_icmp[8:]

    header = struct.pack("!BBHHH", ICMP_ECHO_REPLY, code, 0, ident, seq)
    csum = checksum(header + payload)

    return struct.pack("!BBHHH", ICMP_ECHO_REPLY, code, csum, ident, seq) + payload


def run_responder(interface: str):
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")

    print(f"listening for ICMP echo requests on {interface}")

    while True:
        packet, _addr = recv_sock.recvfrom(65535)

        if len(packet) < 28:
            continue

        ip_header_len = (packet[0] & 0x0f) * 4
        ip_header = packet[:ip_header_len]
        icmp_packet = packet[ip_header_len:]

        proto = packet[9]
        if proto != socket.IPPROTO_ICMP:
            continue

        src_ip = socket.inet_ntoa(packet[12:16])
        dst_ip = socket.inet_ntoa(packet[16:20])

        icmp_type = icmp_packet[0]
        if icmp_type != ICMP_ECHO_REQUEST:
            continue

        ip_ident = struct.unpack("!H", ip_header[4:6])[0]
        reply_icmp = build_echo_reply(icmp_packet)
        reply_ip = build_ipv4_header(
            src_ip=dst_ip,
            dst_ip=src_ip,
            payload_len=len(reply_icmp),
            ident=ip_ident,
        )

        send_sock.sendto(reply_ip + reply_icmp, (src_ip, 0))
        print(f"replied to ping from {src_ip} to {dst_ip} via {interface}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("interface", help="Interface name, e.g. eth0")
    args = parser.parse_args()

    run_responder(args.interface)
# Run as root:

# bash

# sudo python3 iface_ping_responder.py eth0
# Note: if the Linux kernel is already replying to pings for that address, this script can create duplicate replies. For isolated testing, temporarily disable kernel echo replies:

# bash

# sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
# Re-enable afterward:

# bash

# sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0




# 9:47 PM





# Default permissions

# 5.5
# Extra High


# Work locally
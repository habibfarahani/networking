#!/usr/bin/env python3
import argparse
import socket
import struct
import time
import fcntl

ETH_P_IPV6 = 0x86DD
IPPROTO_HOPOPTS = 0
IPPROTO_ICMPV6 = 58
ICMPV6_MLD_QUERY = 130

SIOCGIFHWADDR = 0x8927


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def get_iface_mac(iface: str) -> bytes:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack("256s", iface[:15].encode())
    res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    return res[18:24]


def ipv6_multicast_mac(ipv6_addr: str) -> bytes:
    addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
    return b"\x33\x33" + addr[-4:]


def build_hop_by_hop_header() -> bytes:
    # Next Header = ICMPv6, Hdr Ext Len = 0 means 8 bytes total.
    # Router Alert option: type 5, len 2, value 0.
    # PadN option fills remaining 2 bytes.
    return struct.pack("!BB", IPPROTO_ICMPV6, 0) + b"\x05\x02\x00\x00\x01\x00"


def build_mld_query(src_ip: str, group: str | None, max_resp_ms: int) -> bytes:
    dst_ip = group if group else "ff02::1"
    query_group = group if group else "::"

    src = socket.inet_pton(socket.AF_INET6, src_ip)
    dst = socket.inet_pton(socket.AF_INET6, dst_ip)
    query_addr = socket.inet_pton(socket.AF_INET6, query_group)

    # MLDv1 Query:
    # type, code, checksum, max response delay, reserved, multicast address
    icmp = struct.pack(
        "!BBHHH16s",
        ICMPV6_MLD_QUERY,
        0,
        0,
        max_resp_ms,
        0,
        query_addr,
    )

    pseudo = src + dst + struct.pack("!I3xB", len(icmp), IPPROTO_ICMPV6)
    csum = checksum(pseudo + icmp)

    icmp = struct.pack(
        "!BBHHH16s",
        ICMPV6_MLD_QUERY,
        0,
        csum,
        max_resp_ms,
        0,
        query_addr,
    )

    hbh = build_hop_by_hop_header()
    payload = hbh + icmp

    version_tc_fl = 6 << 28
    ipv6_header = struct.pack(
        "!IHBB16s16s",
        version_tc_fl,
        len(payload),
        IPPROTO_HOPOPTS,
        1,  # Hop Limit must be 1 for MLD
        src,
        dst,
    )

    return ipv6_header + payload


def main():
    parser = argparse.ArgumentParser(description="Standalone MLDv1 Querier")
    parser.add_argument("--iface", required=True, help="Interface, e.g. eth0")
    parser.add_argument(
        "--src",
        required=True,
        help="IPv6 source address, usually link-local, e.g. fe80::1",
    )
    parser.add_argument(
        "--group",
        help="Optional group-specific query target, e.g. ff02::1234",
    )
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--count", type=int, default=0, help="0 means forever")
    parser.add_argument("--max-response-ms", type=int, default=10000)
    args = parser.parse_args()

    src_mac = get_iface_mac(args.iface)
    dst_ip = args.group if args.group else "ff02::1"
    dst_mac = ipv6_multicast_mac(dst_ip)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))

    sent = 0
    while args.count == 0 or sent < args.count:
        ipv6_packet = build_mld_query(
            src_ip=args.src,
            group=args.group,
            max_resp_ms=args.max_response_ms,
        )

        eth = dst_mac + src_mac + struct.pack("!H", ETH_P_IPV6)
        sock.send(eth + ipv6_packet)

        kind = "group-specific" if args.group else "general"
        print(f"sent MLDv1 {kind} query on {args.iface} to {dst_ip}")

        sent += 1
        if args.count == 0 or sent < args.count:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
# Example:

# bash

# sudo python3 standalone_mld_querier.py --iface eth0 --src fe80::1234 --count 5
# Group-specific query:

# bash

# sudo python3 standalone_mld_querier.py \
#   --iface eth0 \
#   --src fe80::1234 \
#   --group ff02::1234




# 11:05 PM


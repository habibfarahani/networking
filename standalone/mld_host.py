#!/usr/bin/env python3
import argparse
import socket
import struct
import time


def join_ipv6_multicast(sock: socket.socket, group: str, ifname: str) -> int:
    ifindex = socket.if_nametoindex(ifname)
    group_bin = socket.inet_pton(socket.AF_INET6, group)

    # struct ipv6_mreq: 16-byte multicast addr + 4-byte interface index
    mreq = group_bin + struct.pack("@I", ifindex)

    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, ifindex)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)

    return ifindex


def leave_ipv6_multicast(sock: socket.socket, group: str, ifindex: int) -> None:
    group_bin = socket.inet_pton(socket.AF_INET6, group)
    mreq = group_bin + struct.pack("@I", ifindex)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq)


def main():
    parser = argparse.ArgumentParser(description="Simple IPv6 MLD host")
    parser.add_argument("--iface", required=True, help="Interface name, e.g. eth0")
    parser.add_argument("--group", required=True, help="IPv6 multicast group, e.g. ff02::1234")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--send", help="Optional message to send to the group")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind to all IPv6 addresses on the selected UDP port.
    sock.bind(("::", args.port))

    ifindex = join_ipv6_multicast(sock, args.group, args.iface)

    print(f"Joined {args.group}%{args.iface} on UDP port {args.port}")

    try:
        if args.send:
            dst = (args.group, args.port, 0, ifindex)
            sock.sendto(args.send.encode(), dst)
            print(f"Sent: {args.send}")

        while True:
            data, addr = sock.recvfrom(2048)
            print(f"Received from {addr}: {data!r}")

    except KeyboardInterrupt:
        print("\nLeaving group")

    finally:
        leave_ipv6_multicast(sock, args.group, ifindex)
        sock.close()


if __name__ == "__main__":
    main()
# Example:

# bash

# python3 mld_host.py --iface eth0 --group ff02::1234 --port 5000
# Send a test packet:

# bash

# python3 mld_host.py --iface eth0 --group ff02::1234 --port 5000 --send "hello"
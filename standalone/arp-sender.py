#!/usr/bin/env python3
"""
Send ARP packets using Python raw Ethernet sockets.

Run with administrative privileges on Linux:

    python standalone/arp_sender.py request --interface eth0 --sender-ip 192.0.2.10 --target-ip 192.0.2.1
    python standalone/arp_sender.py gratuitous --interface eth0 --sender-ip 192.0.2.10
    python standalone/arp_sender.py reply --interface eth0 --sender-ip 192.0.2.10 --target-ip 192.0.2.20 --target-mac aa:bb:cc:dd:ee:ff


while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth1 --sender-mac 9c:69:d3:39:f5:c4 --target-ip 192.168.168.101 --sender-ip 192.168.168.21; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth2 --sender-mac 9c:69:d3:39:f3:10 --target-ip 192.168.168.101 --sender-ip 192.168.168.22; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth3 --sender-mac 9c:69:d3:39:e4:4d  --target-ip 192.168.168.101 --sender-ip 192.168.168.23; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth4 --sender-mac 9c:69:d3:39:f3:0c --target-ip 192.168.168.101 --sender-ip 192.168.168.24; done
Use this on networks you own or have permission to test.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from dataclasses import dataclass


ETHERTYPE_ARP = 0x0806
ETH_P_ALL = 0x0003
ARP_HTYPE_ETHERNET = 1
ARP_PTYPE_IPV4 = 0x0800
ARP_HLEN_ETHERNET = 6
ARP_PLEN_IPV4 = 4
ARP_REQUEST = 1
ARP_REPLY = 2
BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
ZERO_MAC = b"\x00\x00\x00\x00\x00\x00"


@dataclass(frozen=True)
class ArpFrame:
    dst_mac: bytes
    src_mac: bytes
    opcode: int
    sender_mac: bytes
    sender_ip: str
    target_mac: bytes
    target_ip: str


def parse_mac(value: str) -> bytes:
    parts = value.replace("-", ":").split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError("MAC address must have 6 octets")

    try:
        mac = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("MAC address contains non-hex octets") from exc

    if len(mac) != 6:
        raise argparse.ArgumentTypeError("MAC address must have 6 octets")
    return mac


def format_mac(mac: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in mac)


def parse_ip(value: str) -> str:
    try:
        socket.inet_aton(value)
    except OSError as exc:
        raise argparse.ArgumentTypeError(f"invalid IPv4 address: {value}") from exc
    return value


def get_interface_mac(interface: str) -> bytes:
    path = f"/sys/class/net/{interface}/address"
    try:
        with open(path, "r", encoding="ascii") as handle:
            return parse_mac(handle.read().strip())
    except OSError as exc:
        raise RuntimeError(f"could not read {path}; pass --sender-mac explicitly") from exc


def build_arp_frame(frame: ArpFrame) -> bytes:
    ethernet = struct.pack("!6s6sH", frame.dst_mac, frame.src_mac, ETHERTYPE_ARP)
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HTYPE_ETHERNET,
        ARP_PTYPE_IPV4,
        ARP_HLEN_ETHERNET,
        ARP_PLEN_IPV4,
        frame.opcode,
        frame.sender_mac,
        socket.inet_aton(frame.sender_ip),
        frame.target_mac,
        socket.inet_aton(frame.target_ip),
    )
    return ethernet + arp


def make_socket(interface: str):
    if not sys.platform.startswith("linux"):
        raise OSError("standalone raw Ethernet sending is supported on Linux")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((interface, 0))
    return sock


def send_repeated(interface: str, packet: bytes, count: int, interval: float) -> None:
    with make_socket(interface) as sock:
        for index in range(count):
            sock.send(packet)
            if index + 1 < count:
                time.sleep(interval)


def build_request(args: argparse.Namespace) -> ArpFrame:
    sender_mac = args.sender_mac or get_interface_mac(args.interface)
    return ArpFrame(
        dst_mac=BROADCAST_MAC,
        src_mac=sender_mac,
        opcode=ARP_REQUEST,
        sender_mac=sender_mac,
        sender_ip=args.sender_ip,
        target_mac=ZERO_MAC,
        target_ip=args.target_ip,
    )


def build_reply(args: argparse.Namespace) -> ArpFrame:
    sender_mac = args.sender_mac or get_interface_mac(args.interface)
    dst_mac = args.ethernet_dst or args.target_mac
    return ArpFrame(
        dst_mac=dst_mac,
        src_mac=sender_mac,
        opcode=ARP_REPLY,
        sender_mac=sender_mac,
        sender_ip=args.sender_ip,
        target_mac=args.target_mac,
        target_ip=args.target_ip,
    )


def build_gratuitous(args: argparse.Namespace) -> ArpFrame:
    sender_mac = args.sender_mac or get_interface_mac(args.interface)
    opcode = ARP_REPLY if args.reply else ARP_REQUEST
    target_mac = sender_mac if args.reply else ZERO_MAC
    return ArpFrame(
        dst_mac=BROADCAST_MAC,
        src_mac=sender_mac,
        opcode=opcode,
        sender_mac=sender_mac,
        sender_ip=args.sender_ip,
        target_mac=target_mac,
        target_ip=args.sender_ip,
    )


def describe(frame: ArpFrame, count: int) -> str:
    kind = "request" if frame.opcode == ARP_REQUEST else "reply"
    return (
        f"sent {count} ARP {kind} frame(s): eth {format_mac(frame.src_mac)}"
        f"->{format_mac(frame.dst_mac)} arp {format_mac(frame.sender_mac)}"
        f"/{frame.sender_ip} -> {format_mac(frame.target_mac)}/{frame.target_ip}"
    )


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-i", "--interface", required=True, help="interface to send from, e.g. eth0")
    parser.add_argument("--sender-mac", type=parse_mac, help="source MAC; defaults to interface MAC on Linux")
    parser.add_argument("--sender-ip", type=parse_ip, required=True, help="sender IPv4 address in the ARP payload")
    parser.add_argument("-c", "--count", type=int, default=1, help="number of packets to send")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between packets when count is greater than 1")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send ARP request, reply, or gratuitous ARP packets")
    subparsers = parser.add_subparsers(dest="command", required=True)

    request = subparsers.add_parser("request", help="broadcast an ARP who-has request")
    add_common_args(request)
    request.add_argument("--target-ip", type=parse_ip, required=True, help="IPv4 address to resolve")
    request.set_defaults(builder=build_request)

    reply = subparsers.add_parser("reply", help="send an ARP is-at reply")
    add_common_args(reply)
    reply.add_argument("--target-ip", type=parse_ip, required=True, help="target IPv4 address in the ARP payload")
    reply.add_argument("--target-mac", type=parse_mac, required=True, help="target MAC address in the ARP payload")
    reply.add_argument("--ethernet-dst", type=parse_mac, help="Ethernet destination; defaults to --target-mac")
    reply.set_defaults(builder=build_reply)

    gratuitous = subparsers.add_parser("gratuitous", help="broadcast gratuitous ARP for sender-ip")
    add_common_args(gratuitous)
    gratuitous.add_argument("--reply", action="store_true", help="send gratuitous ARP as a reply instead of a request")
    gratuitous.set_defaults(builder=build_gratuitous)

    args = parser.parse_args(argv)
    if args.count < 1:
        parser.error("--count must be at least 1")
    if args.interval < 0:
        parser.error("--interval cannot be negative")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        frame = args.builder(args)
        packet = build_arp_frame(frame)
        send_repeated(args.interface, packet, args.count, args.interval)
    except (OSError, RuntimeError) as exc:
        print(f"arp_sender: {exc}", file=sys.stderr)
        return 1

    print(describe(frame, args.count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

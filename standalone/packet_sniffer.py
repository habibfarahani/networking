"""
Capture and print packets using Python raw sockets.

Run with administrative privileges:

    python independent/packet_sniffer.py --interface eth0 --count 20

Raw capture support differs by OS. On Windows, use the Scapy version in this
workspace with Npcap installed.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


ETH_P_ALL = 0x0003
ETH_HEADER_LEN = 14
IPV4_HEADER_MIN_LEN = 20
TCP_HEADER_MIN_LEN = 20
UDP_HEADER_LEN = 8
ICMP_HEADER_MIN_LEN = 4


@dataclass(frozen=True)
class EthernetFrame:
    dst_mac: str
    src_mac: str
    ethertype: int
    payload: bytes


@dataclass(frozen=True)
class IPv4Packet:
    src_ip: str
    dst_ip: str
    protocol: int
    header_len: int
    ttl: int
    payload: bytes


def mac_addr(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def ipv4_addr(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def parse_ethernet(data: bytes) -> EthernetFrame:
    if len(data) < ETH_HEADER_LEN:
        raise ValueError("packet too short for Ethernet")

    dst, src, ethertype = struct.unpack("!6s6sH", data[:ETH_HEADER_LEN])
    return EthernetFrame(
        dst_mac=mac_addr(dst),
        src_mac=mac_addr(src),
        ethertype=ethertype,
        payload=data[ETH_HEADER_LEN:],
    )


def parse_ipv4(data: bytes) -> IPv4Packet:
    if len(data) < IPV4_HEADER_MIN_LEN:
        raise ValueError("packet too short for IPv4")

    version_ihl = data[0]
    version = version_ihl >> 4
    header_len = (version_ihl & 0x0F) * 4
    if version != 4 or len(data) < header_len:
        raise ValueError("invalid IPv4 header")

    ttl = data[8]
    protocol = data[9]
    src = data[12:16]
    dst = data[16:20]
    return IPv4Packet(
        src_ip=ipv4_addr(src),
        dst_ip=ipv4_addr(dst),
        protocol=protocol,
        header_len=header_len,
        ttl=ttl,
        payload=data[header_len:],
    )


def parse_transport(ip_packet: IPv4Packet) -> str:
    data = ip_packet.payload

    if ip_packet.protocol == 1:
        if len(data) < ICMP_HEADER_MIN_LEN:
            return "ICMP truncated"
        icmp_type, code = struct.unpack("!BB", data[:2])
        return f"ICMP type={icmp_type} code={code}"

    if ip_packet.protocol == 6:
        if len(data) < TCP_HEADER_MIN_LEN:
            return "TCP truncated"
        src_port, dst_port, sequence, ack, offset_flags = struct.unpack("!HHIIH", data[:14])
        flags = offset_flags & 0x01FF
        return (
            f"TCP {src_port}->{dst_port} seq={sequence} ack={ack} "
            f"flags=0x{flags:03x}"
        )

    if ip_packet.protocol == 17:
        if len(data) < UDP_HEADER_LEN:
            return "UDP truncated"
        src_port, dst_port, length = struct.unpack("!HHH", data[:6])
        return f"UDP {src_port}->{dst_port} length={length}"

    return f"IP protocol={ip_packet.protocol}"


def hexdump(data: bytes, width: int = 16) -> str:
    rows = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_bytes = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        rows.append(f"    {offset:04x}  {hex_bytes:<{width * 3}} {ascii_bytes}")
    return "\n".join(rows)


def make_socket(interface: Optional[str]) -> socket.socket:
    if sys.platform.startswith("linux"):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        if interface:
            sock.bind((interface, 0))
        return sock

    if hasattr(socket, "AF_LINK"):
        return socket.socket(socket.AF_LINK, socket.SOCK_RAW)

    raise OSError("raw Ethernet capture is not supported here; try scapy/packet_sniffer_scapy.py")


def print_packet(data: bytes, show_hex: bool) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    try:
        frame = parse_ethernet(data)
    except ValueError as exc:
        print(f"{timestamp} malformed frame: {exc} length={len(data)}")
        return

    prefix = (
        f"{timestamp} ETH {frame.src_mac}->{frame.dst_mac} "
        f"type=0x{frame.ethertype:04x} length={len(data)}"
    )

    if frame.ethertype == 0x0800:
        try:
            ip_packet = parse_ipv4(frame.payload)
            detail = parse_transport(ip_packet)
            print(
                f"{prefix} IPv4 {ip_packet.src_ip}->{ip_packet.dst_ip} "
                f"ttl={ip_packet.ttl} {detail}"
            )
        except ValueError as exc:
            print(f"{prefix} malformed IPv4: {exc}")
    elif frame.ethertype == 0x0806:
        print(f"{prefix} ARP")
    elif frame.ethertype == 0x86DD:
        print(f"{prefix} IPv6")
    else:
        print(prefix)

    if show_hex:
        print(hexdump(data))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture and print packets")
    parser.add_argument("-i", "--interface", help="interface to capture from, e.g. eth0")
    parser.add_argument("-c", "--count", type=int, default=0, help="number of packets to capture; 0 means forever")
    parser.add_argument("--hex", action="store_true", help="print packet bytes as a hex dump")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        with make_socket(args.interface) as sock:
            seen = 0
            while args.count == 0 or seen < args.count:
                data, _addr = sock.recvfrom(65535)
                seen += 1
                print_packet(data, args.hex)
    except KeyboardInterrupt:
        print("\nstopped")
    except OSError as exc:
        print(f"packet_sniffer: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

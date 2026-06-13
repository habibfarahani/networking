#!/usr/bin/env python3
"""
Generate unknown multicast traffic into a pcap file.

The packet is "unknown" only when the test setup has no membership or
forwarding entry for the destination group/MAC. This script generates the
traffic; the surrounding test controls whether that traffic is unknown.
"""

import argparse
import ipaddress
import sys

try:
    from scapy.all import Dot1Q, Ether, IP, PcapWriter, Raw, UDP
except ImportError as exc:
    sys.stderr.write("Error: scapy is required to generate packets\n")
    raise SystemExit(2) from exc


DEFAULT_SRC_MAC = "00:11:22:33:44:55"
DEFAULT_SRC_IP = "10.0.0.1"
DEFAULT_DST_IP = "239.255.200.1"
DEFAULT_SRC_PORT = 30000
DEFAULT_DST_PORT = 2000
DEFAULT_PAYLOAD_SIZE = 64


def int_in_range(name, minimum, maximum):
    def parse(value):
        try:
            result = int(value, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "%s must be an integer" % name
            ) from exc

        if result < minimum or result > maximum:
            raise argparse.ArgumentTypeError(
                "%s must be in range %d..%d" % (name, minimum, maximum)
            )
        return result

    return parse


def parse_ipv4(value):
    try:
        return ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "%s is not a valid IPv4 address" % value
        ) from exc


def parse_multicast_ipv4(value):
    address = parse_ipv4(value)
    if not address.is_multicast:
        raise argparse.ArgumentTypeError(
            "%s is not an IPv4 multicast address" % value
        )
    return address


def parse_mac(value):
    parts = value.split(":")
    if len(parts) != 6:
        raise argparse.ArgumentTypeError(
            "%s is not a valid Ethernet MAC address" % value
        )

    octets = []
    for part in parts:
        if len(part) != 2:
            raise argparse.ArgumentTypeError(
                "%s is not a valid Ethernet MAC address" % value
            )
        try:
            octets.append(int(part, 16))
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "%s is not a valid Ethernet MAC address" % value
            ) from exc

    return ":".join("%02x" % octet for octet in octets)


def parse_multicast_mac(value):
    mac = parse_mac(value)
    first_octet = int(mac.split(":")[0], 16)
    if (first_octet & 0x01) == 0:
        raise argparse.ArgumentTypeError(
            "%s is not an Ethernet multicast MAC address" % value
        )
    if mac == "ff:ff:ff:ff:ff:ff":
        raise argparse.ArgumentTypeError(
            "broadcast MAC is not valid for unknown multicast generation"
        )
    return mac


def ipv4_multicast_mac(address):
    low_23_bits = int(address) & 0x7FFFFF
    return "01:00:5e:%02x:%02x:%02x" % (
        (low_23_bits >> 16) & 0x7F,
        (low_23_bits >> 8) & 0xFF,
        low_23_bits & 0xFF,
    )


def multicast_group(base_address, offset):
    candidate = ipaddress.IPv4Address(int(base_address) + offset)
    if not candidate.is_multicast:
        raise ValueError(
            "multicast group offset %d produces non-multicast address %s"
            % (offset, candidate)
        )
    return candidate


def payload(index, size):
    prefix = ("unknown-mcast-%04d" % index).encode("ascii")
    if size <= len(prefix):
        return prefix[:size]

    fill = bytes((index + offset) & 0xFF for offset in range(size - len(prefix)))
    return prefix + fill


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate IPv4 UDP or L2-only unknown multicast pcaps."
    )
    parser.add_argument(
        "-o",
        "--out-file",
        default="unknown_multicast.pcap",
        help="pcap path to write (default: %(default)s)",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int_in_range("count", 1, 1000000),
        default=1,
        help="number of packets to generate (default: %(default)s)",
    )
    parser.add_argument(
        "--group-count",
        type=int_in_range("group-count", 1, 1000000),
        default=1,
        help="number of sequential multicast groups to cycle through",
    )
    parser.add_argument(
        "--src-mac",
        type=parse_mac,
        default=DEFAULT_SRC_MAC,
        help="source Ethernet MAC (default: %(default)s)",
    )
    parser.add_argument(
        "--dst-mac",
        type=parse_multicast_mac,
        default=None,
        help="destination multicast MAC; derived from --dst-ip if omitted",
    )
    parser.add_argument(
        "--src-ip",
        type=parse_ipv4,
        default=DEFAULT_SRC_IP,
        help="source IPv4 address for IPv4 UDP mode (default: %(default)s)",
    )
    parser.add_argument(
        "--dst-ip",
        type=parse_multicast_ipv4,
        default=DEFAULT_DST_IP,
        help="base destination multicast IPv4 address (default: %(default)s)",
    )
    parser.add_argument(
        "--src-port",
        type=int_in_range("src-port", 0, 65535),
        default=DEFAULT_SRC_PORT,
        help="UDP source port for IPv4 UDP mode (default: %(default)s)",
    )
    parser.add_argument(
        "--dst-port",
        type=int_in_range("dst-port", 0, 65535),
        default=DEFAULT_DST_PORT,
        help="UDP destination port for IPv4 UDP mode (default: %(default)s)",
    )
    parser.add_argument(
        "--ttl",
        type=int_in_range("ttl", 1, 255),
        default=1,
        help="IPv4 TTL for IPv4 UDP mode (default: %(default)s)",
    )
    parser.add_argument(
        "--ip-id-start",
        type=int_in_range("ip-id-start", 0, 65535),
        default=0,
        help="initial IPv4 ID, wrapping at 65535 (default: %(default)s)",
    )
    parser.add_argument(
        "--payload-size",
        type=int_in_range("payload-size", 0, 65507),
        default=DEFAULT_PAYLOAD_SIZE,
        help="payload bytes per packet (default: %(default)s)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="timestamp interval between packets in seconds",
    )
    parser.add_argument(
        "--start-time",
        type=float,
        default=0.0,
        help="timestamp for the first packet in seconds",
    )
    parser.add_argument(
        "--vlan",
        type=int_in_range("vlan", 0, 4094),
        default=None,
        help="optional 802.1Q VLAN ID",
    )
    parser.add_argument(
        "--l2-only",
        action="store_true",
        help="generate Ethernet multicast frames without IPv4/UDP headers",
    )
    parser.add_argument(
        "--ether-type",
        type=int_in_range("ether-type", 0, 65535),
        default=0x88B5,
        help="EtherType for --l2-only frames (default: 0x88b5)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print a short summary after writing the pcap",
    )

    args = parser.parse_args()

    if args.interval < 0.0:
        parser.error("--interval must be non-negative")
    if args.start_time < 0.0:
        parser.error("--start-time must be non-negative")

    try:
        multicast_group(args.dst_ip, args.group_count - 1)
    except ValueError as exc:
        parser.error(str(exc))

    return args


def ethernet_header(args, dst_mac):
    if args.vlan is None:
        if args.l2_only:
            return Ether(src=args.src_mac, dst=dst_mac, type=args.ether_type)
        return Ether(src=args.src_mac, dst=dst_mac)

    if args.l2_only:
        return (
            Ether(src=args.src_mac, dst=dst_mac)
            / Dot1Q(vlan=args.vlan, type=args.ether_type)
        )
    return Ether(src=args.src_mac, dst=dst_mac) / Dot1Q(vlan=args.vlan)


def build_packet(args, index):
    dst_ip = multicast_group(args.dst_ip, index % args.group_count)
    dst_mac = args.dst_mac or ipv4_multicast_mac(dst_ip)
    packet = ethernet_header(args, dst_mac)

    if args.l2_only:
        packet /= Raw(load=payload(index, args.payload_size))
    else:
        packet /= (
            IP(
                src=str(args.src_ip),
                dst=str(dst_ip),
                ttl=args.ttl,
                id=(args.ip_id_start + index) & 0xFFFF,
            )
            / UDP(sport=args.src_port, dport=args.dst_port)
            / Raw(load=payload(index, args.payload_size))
        )

    packet.time = args.start_time + (index * args.interval)
    return packet


def main():
    args = parse_args()
    writer = PcapWriter(args.out_file, append=False, sync=True)
    try:
        for index in range(args.count):
            writer.write(build_packet(args, index))
    finally:
        writer.close()

    if args.verbose:
        print("Wrote %d packets to %s" % (args.count, args.out_file))


if __name__ == "__main__":
    main()
click-elts/elts-meraki/test/unknown_multicast_packet_generator.py
Full file content failed to load
Retry
import ipaddress
import sys

try:
    from scapy.all import Dot1Q, Ether, IP, PcapWriter, Raw, UDP
except ImportError as exc:
    sys.stderr.write("Error: scapy is required to generate packets\n")
    raise SystemExit(2) from exc
import struct

DEFAULT_PAYLOAD_SIZE = 64
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_DOT1Q = 0x8100
IP_PROTO_UDP = 17
PCAP_LINKTYPE_ETHERNET = 1


def mac_to_bytes(mac):
    return bytes(int(part, 16) for part in mac.split(":"))


def multicast_group(base_address, offset):

def internet_checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def parse_args():
        type=parse_ipv4,
        default=DEFAULT_SRC_IP,
        default=parse_ipv4(DEFAULT_SRC_IP),
        help="source IPv4 address for IPv4 UDP mode (default: %(default)s)",
        type=parse_multicast_ipv4,
        default=DEFAULT_DST_IP,
        default=parse_multicast_ipv4(DEFAULT_DST_IP),
        help="base destination multicast IPv4 address (default: %(default)s)",

def ethernet_header(args, dst_mac):
def ethernet_header(args, dst_mac, ethertype):
    header = mac_to_bytes(dst_mac) + mac_to_bytes(args.src_mac)
    if args.vlan is None:
        if args.l2_only:
            return Ether(src=args.src_mac, dst=dst_mac, type=args.ether_type)
        return Ether(src=args.src_mac, dst=dst_mac)
        return header + struct.pack("!H", ethertype)

    return header + struct.pack("!HHH", ETHERTYPE_DOT1Q, args.vlan, ethertype)


    if args.l2_only:
        return (
            Ether(src=args.src_mac, dst=dst_mac)
            / Dot1Q(vlan=args.vlan, type=args.ether_type)
        )
    return Ether(src=args.src_mac, dst=dst_mac) / Dot1Q(vlan=args.vlan)
def ipv4_udp_packet(args, index, dst_ip):
    data = payload(index, args.payload_size)
    src_ip = args.src_ip.packed
    dst_ip_bytes = dst_ip.packed
    udp_length = 8 + len(data)

    udp_header = struct.pack(
        "!HHHH", args.src_port, args.dst_port, udp_length, 0
    )
    pseudo_header = (
        src_ip
        + dst_ip_bytes
        + struct.pack("!BBH", 0, IP_PROTO_UDP, udp_length)
    )
    udp_checksum = internet_checksum(pseudo_header + udp_header + data)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    udp_header = struct.pack(
        "!HHHH", args.src_port, args.dst_port, udp_length, udp_checksum
    )

def build_packet(args, index):
    total_length = 20 + udp_length
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        (args.ip_id_start + index) & 0xFFFF,
        0,
        args.ttl,
        IP_PROTO_UDP,
        0,
        src_ip,
        dst_ip_bytes,
    )
    ip_checksum = internet_checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        (args.ip_id_start + index) & 0xFFFF,
        0,
        args.ttl,
        IP_PROTO_UDP,
        ip_checksum,
        src_ip,
        dst_ip_bytes,
    )

    return ip_header + udp_header + data


def build_frame(args, index):
    dst_ip = multicast_group(args.dst_ip, index % args.group_count)
    dst_mac = args.dst_mac or ipv4_multicast_mac(dst_ip)
    packet = ethernet_header(args, dst_mac)

    if args.l2_only:
        packet /= Raw(load=payload(index, args.payload_size))
    else:
        packet /= (
            IP(
                src=str(args.src_ip),
                dst=str(dst_ip),
                ttl=args.ttl,
                id=(args.ip_id_start + index) & 0xFFFF,
            )
            / UDP(sport=args.src_port, dport=args.dst_port)
            / Raw(load=payload(index, args.payload_size))
        return ethernet_header(args, dst_mac, args.ether_type) + payload(
            index, args.payload_size
        )

    packet.time = args.start_time + (index * args.interval)
    return packet
    return ethernet_header(args, dst_mac, ETHERTYPE_IPV4) + ipv4_udp_packet(
        args, index, dst_ip
    )


def main():
    args = parse_args()
    writer = PcapWriter(args.out_file, append=False, sync=True)
    try:
def pcap_timestamp(timestamp):
    seconds = int(timestamp)
    microseconds = int(round((timestamp - seconds) * 1000000))
    if microseconds == 1000000:
        seconds += 1
        microseconds = 0
    return seconds, microseconds


def write_pcap(args):
    with open(args.out_file, "wb") as pcap:
        pcap.write(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,
                2,
                4,
                0,
                0,
                65535,
                PCAP_LINKTYPE_ETHERNET,
            )
        )
        for index in range(args.count):
            writer.write(build_packet(args, index))
    finally:
        writer.close()
            frame = build_frame(args, index)
            timestamp = args.start_time + (index * args.interval)
            seconds, microseconds = pcap_timestamp(timestamp)
            pcap.write(
                struct.pack(
                    "<IIII", seconds, microseconds, len(frame), len(frame)
                )
            )
            pcap.write(frame)


def main():
    args = parse_args()
    write_pcap(args)
    if args.verbose:
import ipaddress
import math
import struct

def parse_non_negative_float(name):
    def parse(value):
        try:
            result = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                "%s must be a number" % name
            ) from exc

        if not math.isfinite(result) or result < 0.0:
            raise argparse.ArgumentTypeError(
                "%s must be a finite non-negative number" % name
            )
        return result

    return parse


def parse_multicast_ipv4(value):
        "--interval",
        type=float,
        type=parse_non_negative_float("interval"),
        default=0.1,
        "--start-time",
        type=float,
        type=parse_non_negative_float("start-time"),
        default=0.0,
    args = parser.parse_args()

    if args.interval < 0.0:
        parser.error("--interval must be non-negative")
    if args.start_time < 0.0:
        parser.error("--start-time must be non-negative")

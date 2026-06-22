#!/usr/bin/env python3

"""Generate Device Level Ring multicast beacon packets."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import socket
import struct
import sys
import time
from typing import Iterable, Optional


DLR_ETHERTYPE = 0x80E1
DLR_BEACON_MULTICAST = "01:21:6c:00:00:01"
DLR_RING_SUBTYPE = 0x01
DLR_PROTOCOL_VERSION = 0x01
DLR_FRAME_TYPE_BEACON = 0x01
DLR_RING_NORMAL_STATE = 0x01
DLR_RING_FAULT_STATE = 0x02
DLR_BEACON_RESERVED_LEN = 20
ETHERNET_MIN_FRAME_NO_FCS = 60
PCAP_LINKTYPE_ETHERNET = 1
PCAP_SNAPLEN = 65535

MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
RING_STATE_BY_NAME = {
    "normal": DLR_RING_NORMAL_STATE,
    "fault": DLR_RING_FAULT_STATE,
}


def parse_bounded_int(name: str, minimum: int, maximum: int):
    def parser(value: str) -> int:
        try:
            parsed = int(value, 0)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"{name} must be an integer"
            ) from exc
        if parsed < minimum or parsed > maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parser


def parse_bounded_float(name: str, minimum: float, maximum: float):
    def parser(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"{name} must be a number"
            ) from exc
        if parsed < minimum or parsed > maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parser


def normalize_mac(value: str) -> str:
    if not MAC_RE.match(value):
        raise argparse.ArgumentTypeError(
            "MAC addresses must use colon-separated hex bytes"
        )
    return value.lower()


def mac_bytes(value: str) -> bytes:
    return bytes(int(part, 16) for part in value.split(":"))


def parse_source_mac(value: str) -> str:
    mac = normalize_mac(value)
    if mac_bytes(mac)[0] & 0x01:
        raise argparse.ArgumentTypeError("source MAC must be unicast")
    return mac


def parse_multicast_mac(value: str) -> str:
    mac = normalize_mac(value)
    if not (mac_bytes(mac)[0] & 0x01):
        raise argparse.ArgumentTypeError("destination MAC must be multicast")
    return mac


def parse_ipv4(value: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("source IP must be IPv4") from exc


def parse_ring_state(value: str) -> int:
    if value.lower() in RING_STATE_BY_NAME:
        return RING_STATE_BY_NAME[value.lower()]
    return parse_bounded_int("ring state", 0, 0xFF)(value)


def parse_iface_name(value: str) -> str:
    if not IFACE_RE.match(value):
        raise argparse.ArgumentTypeError(
            "interface names may only contain letters, digits, '_', '.', ':', and '-'"
        )
    return value


def build_dlr_beacon_payload(
    *,
    source_port: int,
    source_ip: ipaddress.IPv4Address,
    sequence_id: int,
    ring_state: int,
    supervisor_precedence: int,
    beacon_interval_us: int,
    beacon_timeout_us: int,
) -> bytes:
    payload = struct.pack(
        "!BBBB4sIBBII20s",
        DLR_RING_SUBTYPE,
        DLR_PROTOCOL_VERSION,
        DLR_FRAME_TYPE_BEACON,
        source_port,
        source_ip.packed,
        sequence_id,
        ring_state,
        supervisor_precedence,
        beacon_interval_us,
        beacon_timeout_us,
        b"\x00" * DLR_BEACON_RESERVED_LEN,
    )
    if len(payload) != 42:
        raise AssertionError(f"unexpected DLR beacon payload length: {len(payload)}")
    return payload


def build_dlr_beacon(
    *,
    src_mac: str,
    dst_mac: str,
    vlan: Optional[int],
    pcp: int,
    pad: bool,
    **payload_kwargs,
) -> bytes:
    payload = build_dlr_beacon_payload(**payload_kwargs)
    src = mac_bytes(src_mac)
    dst = mac_bytes(dst_mac)

    if vlan is None:
        packet = dst + src + struct.pack("!H", DLR_ETHERTYPE) + payload
    else:
        vlan_tci = (pcp << 13) | vlan
        packet = (
            dst
            + src
            + struct.pack("!HHH", 0x8100, vlan_tci, DLR_ETHERTYPE)
            + payload
        )

    packet_len = len(packet)
    if pad and packet_len < ETHERNET_MIN_FRAME_NO_FCS:
        packet += b"\x00" * (ETHERNET_MIN_FRAME_NO_FCS - packet_len)
    return packet


def sequence_ids(start: int, count: int) -> Iterable[int]:
    for offset in range(count):
        yield (start + offset) & 0xFFFFFFFF


def packet_for_sequence(args, sequence_id: int):
    return build_dlr_beacon(
        src_mac=args.src,
        dst_mac=args.dst,
        vlan=args.vlan,
        pcp=args.pcp,
        pad=not args.no_pad,
        source_port=args.source_port,
        source_ip=args.source_ip,
        sequence_id=sequence_id,
        ring_state=args.ring_state,
        supervisor_precedence=args.supervisor_precedence,
        beacon_interval_us=args.beacon_interval_us,
        beacon_timeout_us=args.beacon_timeout_us,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate multicast EtherNet/IP DLR beacon packets."
    )
    parser.add_argument(
        "--iface",
        type=parse_iface_name,
        help="interface to transmit on; also used to infer --src when --src is omitted",
    )
    parser.add_argument("--send", action="store_true", help="transmit packets")
    parser.add_argument(
        "--output-pcap",
        help="write generated packet(s) to this pcap file",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="print generated packet bytes as a hexadecimal string",
    )
    parser.add_argument(
        "--count",
        type=parse_bounded_int("count", 0, 1_000_000),
        default=1,
        help="number of packets; 0 means send forever with --send",
    )
    parser.add_argument(
        "--interval-sec",
        type=parse_bounded_float("interval-sec", 0.0, 3600.0),
        help="seconds between transmitted packets; default is beacon interval",
    )
    parser.add_argument(
        "--src",
        type=parse_source_mac,
        help="source MAC; defaults to the interface MAC when --iface is set",
    )
    parser.add_argument(
        "--dst",
        type=parse_multicast_mac,
        default=DLR_BEACON_MULTICAST,
        help=f"destination multicast MAC; default {DLR_BEACON_MULTICAST}",
    )
    parser.add_argument(
        "--vlan",
        type=parse_bounded_int("vlan", 0, 4094),
        help="optional 802.1Q VLAN ID for DLR frames",
    )
    parser.add_argument(
        "--pcp",
        type=parse_bounded_int("pcp", 0, 7),
        default=7,
        help="802.1Q priority code point when --vlan is set",
    )
    parser.add_argument(
        "--source-port",
        type=parse_bounded_int("source-port", 0, 2),
        default=0,
        help="DLR source port: 0=port1-or-port2, 1=port1, 2=port2",
    )
    parser.add_argument(
        "--source-ip",
        type=parse_ipv4,
        default=ipaddress.IPv4Address("0.0.0.0"),
        help="DLR source IP field",
    )
    parser.add_argument(
        "--sequence-id",
        type=parse_bounded_int("sequence-id", 0, 0xFFFFFFFF),
        default=0,
        help="initial DLR sequence ID",
    )
    parser.add_argument(
        "--ring-state",
        type=parse_ring_state,
        default=DLR_RING_NORMAL_STATE,
        help="DLR ring state: normal, fault, or an 8-bit integer",
    )
    parser.add_argument(
        "--supervisor-precedence",
        type=parse_bounded_int("supervisor-precedence", 0, 0xFF),
        default=0,
        help="active supervisor precedence",
    )
    parser.add_argument(
        "--beacon-interval-us",
        type=parse_bounded_int("beacon-interval-us", 0, 0xFFFFFFFF),
        default=400,
        help="DLR beacon interval field, in microseconds",
    )
    parser.add_argument(
        "--beacon-timeout-us",
        type=parse_bounded_int("beacon-timeout-us", 0, 0xFFFFFFFF),
        default=1960,
        help="DLR beacon timeout field, in microseconds",
    )
    parser.add_argument(
        "--no-pad",
        action="store_true",
        help="do not pad the Ethernet frame to 60 bytes excluding FCS",
    )
    return parser


def get_interface_mac(iface: str) -> str:
    with open(os.path.join("/sys/class/net", iface, "address"), encoding="ascii") as f:
        return parse_source_mac(f.read().strip())


def resolve_source_mac(args, parser: argparse.ArgumentParser) -> None:
    if args.src:
        return
    if not args.iface:
        parser.error("--src is required unless --iface is supplied")
    try:
        args.src = get_interface_mac(args.iface)
    except Exception as exc:
        parser.error(f"failed to read source MAC from {args.iface}: {exc}")


def generated_count(args, parser: argparse.ArgumentParser) -> int:
    if args.count == 0 and (args.output_pcap or args.hex):
        parser.error("--count 0 is only valid with --send")
    return args.count if args.count else 1


def write_pcap(path: str, packets: Iterable[bytes]) -> None:
    with open(path, "wb") as f:
        f.write(
            struct.pack(
                "<IHHIIII",
                0xA1B2C3D4,
                2,
                4,
                0,
                0,
                PCAP_SNAPLEN,
                PCAP_LINKTYPE_ETHERNET,
            )
        )
        for packet in packets:
            now = time.time()
            seconds = int(now)
            microseconds = int((now - seconds) * 1_000_000)
            f.write(
                struct.pack(
                    "<IIII",
                    seconds,
                    microseconds,
                    len(packet),
                    len(packet),
                )
            )
            f.write(packet)


def transmit(args) -> None:
    interval = (
        args.interval_sec
        if args.interval_sec is not None
        else args.beacon_interval_us / 1_000_000.0
    )
    sent = 0
    next_send = time.monotonic()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((args.iface, 0))
        while args.count == 0 or sent < args.count:
            packet = packet_for_sequence(args, (args.sequence_id + sent) & 0xFFFFFFFF)
            sock.send(packet)
            sent += 1
            if args.count != 0 and sent >= args.count:
                break
            next_send += interval
            time.sleep(max(0.0, next_send - time.monotonic()))


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if not args.send and not args.output_pcap and not args.hex:
        args.hex = True
    if args.send and not args.iface:
        parser.error("--send requires --iface")

    resolve_source_mac(args, parser)

    count = generated_count(args, parser)
    packets = [
        packet_for_sequence(args, sequence_id)
        for sequence_id in sequence_ids(args.sequence_id, count)
    ]

    if args.output_pcap:
        write_pcap(args.output_pcap, packets)
    if args.hex:
        for packet in packets:
            print(packet.hex())
    if args.send:
        transmit(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())

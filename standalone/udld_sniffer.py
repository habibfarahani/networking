#!/usr/bin/env python3
"""
Capture and decode Cisco UDLD packets.

Run with administrative privileges:

    python standalone/udld_sniffer.py --interface eth0

UDLD uses 802.3 LLC/SNAP frames with destination MAC 01:00:0c:cc:cc:cc,
Cisco OUI 00:00:0c, and protocol type 0x0111.
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
UDLD_MULTICAST = b"\x01\x00\x0c\xcc\xcc\xcc"
UDLD_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x01\x11"
UDLD_HEADER_LEN = 4

OPCODES = {
    0: "reserved",
    1: "probe",
    2: "echo",
    3: "flush",
}

TLV_NAMES = {
    1: "device_id",
    2: "port_id",
    3: "echo",
    4: "message_interval",
    5: "timeout_interval",
    6: "device_name",
    7: "sequence_number",
}


@dataclass(frozen=True)
class EthernetFrame:
    dst_mac: bytes
    src_mac: bytes
    length_or_type: int
    payload: bytes


@dataclass(frozen=True)
class UdldPacket:
    version: int
    opcode: int
    flags: int
    checksum: int
    tlvs: dict[int, list[bytes]]


def format_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def parse_ethernet(data: bytes) -> EthernetFrame:
    if len(data) < ETH_HEADER_LEN:
        raise ValueError("frame is too short for Ethernet")

    dst, src, length_or_type = struct.unpack("!6s6sH", data[:ETH_HEADER_LEN])
    return EthernetFrame(
        dst_mac=dst,
        src_mac=src,
        length_or_type=length_or_type,
        payload=data[ETH_HEADER_LEN:],
    )


def ones_complement_checksum(data: bytes) -> int:
    total = 0
    index = 0
    while index + 1 < len(data):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
        index += 2

    if index < len(data):
        total += data[index]
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def parse_tlvs(data: bytes) -> dict[int, list[bytes]]:
    tlvs: dict[int, list[bytes]] = {}
    offset = 0

    while offset < len(data):
        remaining = len(data) - offset
        if remaining < 4:
            raise ValueError(f"trailing {remaining} byte(s) after TLVs")

        tlv_type, tlv_len = struct.unpack("!HH", data[offset : offset + 4])
        if tlv_len < 4:
            raise ValueError(f"invalid TLV length {tlv_len} for type {tlv_type}")
        if offset + tlv_len > len(data):
            raise ValueError(f"TLV type {tlv_type} extends past packet end")

        value = data[offset + 4 : offset + tlv_len]
        tlvs.setdefault(tlv_type, []).append(value)
        offset += tlv_len

    return tlvs


def parse_udld_pdu(data: bytes) -> UdldPacket:
    if len(data) < UDLD_HEADER_LEN:
        raise ValueError("UDLD PDU is too short")

    version_opcode, flags, checksum = struct.unpack("!BBH", data[:UDLD_HEADER_LEN])
    return UdldPacket(
        version=version_opcode >> 5,
        opcode=version_opcode & 0x1F,
        flags=flags,
        checksum=checksum,
        tlvs=parse_tlvs(data[UDLD_HEADER_LEN:]),
    )


def find_udld_payload(frame: EthernetFrame) -> Optional[bytes]:
    # UDLD is sent as 802.3 length + LLC/SNAP, not Ethernet II ethertype.
    if frame.dst_mac != UDLD_MULTICAST:
        return None
    if frame.length_or_type > 1500:
        return None
    if not frame.payload.startswith(UDLD_SNAP):
        return None
    return frame.payload[len(UDLD_SNAP) :]


def text_value(packet: UdldPacket, tlv_type: int) -> Optional[str]:
    values = packet.tlvs.get(tlv_type)
    if not values:
        return None
    return values[0].decode("ascii", errors="replace").rstrip("\x00")


def int8_value(packet: UdldPacket, tlv_type: int) -> Optional[int]:
    values = packet.tlvs.get(tlv_type)
    return values[0][0] if values and len(values[0]) >= 1 else None


def int32_value(packet: UdldPacket, tlv_type: int) -> Optional[int]:
    values = packet.tlvs.get(tlv_type)
    return struct.unpack("!I", values[0][:4])[0] if values and len(values[0]) >= 4 else None


def echo_summary(packet: UdldPacket) -> str:
    values = packet.tlvs.get(3, [])
    if not values:
        return "echo=absent"
    total_bytes = sum(len(value) for value in values)
    return f"echo_tlvs={len(values)} echo_bytes={total_bytes}"


def tlv_summary(packet: UdldPacket) -> str:
    parts = []
    for tlv_type in sorted(packet.tlvs):
        name = TLV_NAMES.get(tlv_type, f"type_{tlv_type}")
        count = len(packet.tlvs[tlv_type])
        parts.append(name if count == 1 else f"{name}x{count}")
    return ",".join(parts) if parts else "none"


def flag_summary(flags: int) -> str:
    names = []
    if flags & 0x01:
        names.append("RT")
    if flags & 0x02:
        names.append("RSY")
    unknown = flags & ~0x03
    if unknown:
        names.append(f"0x{unknown:02x}")
    return ",".join(names) if names else "none"


def print_udld(data: bytes, show_hex: bool) -> bool:
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    try:
        frame = parse_ethernet(data)
        payload = find_udld_payload(frame)
        if payload is None:
            return False
        packet = parse_udld_pdu(payload)
    except ValueError as exc:
        print(f"{timestamp} malformed UDLD: {exc}")
        return True

    checksum_ok = ones_complement_checksum(payload) == 0
    opcode = OPCODES.get(packet.opcode, f"unknown({packet.opcode})")
    device_id = text_value(packet, 1) or "unknown"
    port_id = text_value(packet, 2) or "unknown"
    device_name = text_value(packet, 6) or "unknown"
    message_interval = int8_value(packet, 4)
    timeout_interval = int8_value(packet, 5)
    sequence = int32_value(packet, 7)

    print(
        f"{timestamp} UDLD {format_mac(frame.src_mac)}->{format_mac(frame.dst_mac)} "
        f"version={packet.version} opcode={opcode} flags={flag_summary(packet.flags)} "
        f"checksum={'ok' if checksum_ok else f'bad(0x{packet.checksum:04x})'} "
        f"device_id={device_id!r} port_id={port_id!r} device_name={device_name!r} "
        f"msg_interval={message_interval if message_interval is not None else 'unknown'}s "
        f"timeout={timeout_interval if timeout_interval is not None else 'unknown'}s "
        f"seq={sequence if sequence is not None else 'unknown'} {echo_summary(packet)} "
        f"tlvs={tlv_summary(packet)} length={len(data)}"
    )

    if show_hex:
        print(hexdump(data))

    return True


def hexdump(data: bytes, width: int = 16) -> str:
    rows = []
    for offset in range(0, len(data), width):
        chunk = data[offset : offset + width]
        hex_bytes = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_bytes = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        rows.append(f"    {offset:04x}  {hex_bytes:<{width * 3}} {ascii_bytes}")
    return "\n".join(rows)


def make_socket(interface: Optional[str]) -> socket.socket:
    if not sys.platform.startswith("linux"):
        raise OSError("raw 802.3 capture is best supported on Linux; try scapy/udld_sniffer_scapy.py")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if interface:
        sock.bind((interface, 0))
    return sock


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture and decode Cisco UDLD packets")
    parser.add_argument("-i", "--interface", help="interface to capture from, e.g. eth0")
    parser.add_argument("-c", "--count", type=int, default=0, help="number of UDLD packets to print; 0 means forever")
    parser.add_argument("--hex", action="store_true", help="print matching packet bytes as a hex dump")
    parser.add_argument("--show-non-udld", action="store_true", help="print a dot for each non-UDLD frame")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        with make_socket(args.interface) as sock:
            seen = 0
            while args.count == 0 or seen < args.count:
                data, _addr = sock.recvfrom(65535)
                matched = print_udld(data, args.hex)
                if matched:
                    seen += 1
                elif args.show_non_udld:
                    print(".", end="", flush=True)
    except KeyboardInterrupt:
        print("\nstopped")
    except OSError as exc:
        print(f"udld_sniffer: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

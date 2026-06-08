#!/usr/bin/env python3
"""
Capture and decode STP/RSTP/MSTP/PVST BPDU packets.

Run with administrative privileges on Linux:

    python standalone/bpdu_sniffer.py --interface eth0 --count 5

Standard BPDUs use destination MAC 01:80:c2:00:00:00 with LLC 42:42:03.
Cisco PVST+/RPVST+ BPDUs commonly use destination MAC 01:00:0c:cc:cc:cd
with SNAP OUI 00:00:0c and PID 0x010b.

while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth1 --sender-mac dc:a6:32:d4:ee:da --target-ip 192.168.168.101 --sender-ip 192.168.168.158; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth1 --sender-mac 9c:69:d3:39:f5:c4 --target-ip 192.168.168.135 --sender-ip 192.168.168.21; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth2 --sender-mac 9c:69:d3:39:f3:10 --target-ip 192.168.168.106 --sender-ip 192.168.168.22; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth3 --sender-mac 9c:69:d3:39:e4:4d --target-ip 192.168.168.32 --sender-ip 192.168.168.23; done
while [ 1 ]; do sudo python3 standalone/arp-sender.py request -i eth4 --sender-mac 9c:69:d3:39:f3:0c--target-ip 192.168.168.104 --sender-ip 192.168.168.33; done

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
VLAN_TPIDS = {0x8100, 0x88A8, 0x9100}

STP_MULTICAST = b"\x01\x80\xc2\x00\x00\x00"
PVST_MULTICAST = b"\x01\x00\x0c\xcc\xcc\xcd"
STP_LLC = b"\x42\x42\x03"
PVST_SNAP = b"\xaa\xaa\x03\x00\x00\x0c\x01\x0b"

BPDU_TYPE_NAMES = {
    0x00: "config",
    0x02: "rstp/mstp",
    0x80: "topology-change",
}

PROTOCOL_VERSION_NAMES = {
    0: "stp",
    2: "rstp",
    3: "mstp",
    4: "spb",
}

PORT_ROLE_NAMES = {
    0: "unknown",
    1: "alternate-or-backup",
    2: "root",
    3: "designated",
}


@dataclass(frozen=True)
class EthernetFrame:
    dst_mac: bytes
    src_mac: bytes
    length_or_type: int
    payload: bytes
    vlan_ids: list[int]


@dataclass(frozen=True)
class BridgeId:
    priority: int
    mac: bytes


@dataclass(frozen=True)
class BpduPacket:
    protocol_id: int
    version: int
    bpdu_type: int
    flags: Optional[int] = None
    root_id: Optional[BridgeId] = None
    root_path_cost: Optional[int] = None
    bridge_id: Optional[BridgeId] = None
    port_id: Optional[int] = None
    message_age: Optional[float] = None
    max_age: Optional[float] = None
    hello_time: Optional[float] = None
    forward_delay: Optional[float] = None
    version_1_length: Optional[int] = None
    version_3_length: Optional[int] = None


def format_mac(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def format_bridge_id(bridge_id: Optional[BridgeId]) -> str:
    if bridge_id is None:
        return "unknown"
    return f"{bridge_id.priority}.{format_mac(bridge_id.mac)}"


def parse_bridge_id(data: bytes) -> BridgeId:
    if len(data) != 8:
        raise ValueError("bridge ID must be 8 bytes")
    priority = struct.unpack("!H", data[:2])[0]
    return BridgeId(priority=priority, mac=data[2:])


def fixed_256(value: int) -> float:
    return value / 256.0


def parse_ethernet(data: bytes) -> EthernetFrame:
    if len(data) < ETH_HEADER_LEN:
        raise ValueError("frame is too short for Ethernet")

    dst, src, length_or_type = struct.unpack("!6s6sH", data[:ETH_HEADER_LEN])
    offset = ETH_HEADER_LEN
    vlan_ids: list[int] = []

    while length_or_type in VLAN_TPIDS:
        if len(data) < offset + 4:
            raise ValueError("frame ended inside VLAN tag")
        tci, length_or_type = struct.unpack("!HH", data[offset : offset + 4])
        vlan_ids.append(tci & 0x0FFF)
        offset += 4

    return EthernetFrame(
        dst_mac=dst,
        src_mac=src,
        length_or_type=length_or_type,
        payload=data[offset:],
        vlan_ids=vlan_ids,
    )


def find_bpdu_payload(frame: EthernetFrame) -> tuple[Optional[bytes], Optional[str]]:
    # Standard STP/RSTP/MSTP: 802.3 length + LLC.
    if frame.dst_mac == STP_MULTICAST and frame.length_or_type <= 1500:
        if frame.payload.startswith(STP_LLC):
            return frame.payload[len(STP_LLC) :], "stp-llc"
        return None, None

    # Cisco PVST+/RPVST+: 802.3 length + LLC/SNAP.
    if frame.dst_mac == PVST_MULTICAST and frame.length_or_type <= 1500:
        if frame.payload.startswith(PVST_SNAP):
            return frame.payload[len(PVST_SNAP) :], "pvst-snap"
        return None, None

    return None, None


def parse_bpdu(data: bytes) -> BpduPacket:
    if len(data) < 4:
        raise ValueError("BPDU is too short")

    protocol_id, version, bpdu_type = struct.unpack("!HBB", data[:4])
    if bpdu_type == 0x80:
        return BpduPacket(protocol_id=protocol_id, version=version, bpdu_type=bpdu_type)

    if len(data) < 35:
        raise ValueError("configuration BPDU is too short")

    flags = data[4]
    root_id = parse_bridge_id(data[5:13])
    root_path_cost = struct.unpack("!I", data[13:17])[0]
    bridge_id = parse_bridge_id(data[17:25])
    port_id = struct.unpack("!H", data[25:27])[0]
    message_age, max_age, hello_time, forward_delay = struct.unpack("!HHHH", data[27:35])
    version_1_length = data[35] if len(data) >= 36 else None
    version_3_length = struct.unpack("!H", data[36:38])[0] if len(data) >= 38 else None

    return BpduPacket(
        protocol_id=protocol_id,
        version=version,
        bpdu_type=bpdu_type,
        flags=flags,
        root_id=root_id,
        root_path_cost=root_path_cost,
        bridge_id=bridge_id,
        port_id=port_id,
        message_age=fixed_256(message_age),
        max_age=fixed_256(max_age),
        hello_time=fixed_256(hello_time),
        forward_delay=fixed_256(forward_delay),
        version_1_length=version_1_length,
        version_3_length=version_3_length,
    )


def flag_summary(flags: Optional[int]) -> str:
    if flags is None:
        return "none"

    names = []
    if flags & 0x01:
        names.append("tc")
    if flags & 0x02:
        names.append("proposal")

    role = (flags >> 2) & 0x03
    if role:
        names.append(f"role={PORT_ROLE_NAMES[role]}")

    if flags & 0x10:
        names.append("learning")
    if flags & 0x20:
        names.append("forwarding")
    if flags & 0x40:
        names.append("agreement")
    if flags & 0x80:
        names.append("tca")

    return ",".join(names) if names else "none"


def vlan_summary(vlan_ids: list[int]) -> str:
    return ",".join(str(vlan_id) for vlan_id in vlan_ids) if vlan_ids else "none"


def print_bpdu(data: bytes, show_hex: bool) -> bool:
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    try:
        frame = parse_ethernet(data)
        payload, encapsulation = find_bpdu_payload(frame)
        if payload is None or encapsulation is None:
            return False
        bpdu = parse_bpdu(payload)
    except ValueError as exc:
        print(f"{timestamp} malformed BPDU: {exc}")
        return True

    version_name = PROTOCOL_VERSION_NAMES.get(bpdu.version, f"version-{bpdu.version}")
    type_name = BPDU_TYPE_NAMES.get(bpdu.bpdu_type, f"unknown(0x{bpdu.bpdu_type:02x})")

    parts = [
        f"{timestamp} BPDU {format_mac(frame.src_mac)}->{format_mac(frame.dst_mac)}",
        f"encap={encapsulation}",
        f"vlan={vlan_summary(frame.vlan_ids)}",
        f"protocol_id=0x{bpdu.protocol_id:04x}",
        f"version={version_name}",
        f"type={type_name}",
    ]

    if bpdu.bpdu_type != 0x80:
        parts.extend(
            [
                f"flags={flag_summary(bpdu.flags)}",
                f"root={format_bridge_id(bpdu.root_id)}",
                f"cost={bpdu.root_path_cost}",
                f"bridge={format_bridge_id(bpdu.bridge_id)}",
                f"port=0x{bpdu.port_id:04x}",
                f"age={bpdu.message_age:.2f}s",
                f"max_age={bpdu.max_age:.2f}s",
                f"hello={bpdu.hello_time:.2f}s",
                f"fwd_delay={bpdu.forward_delay:.2f}s",
            ]
        )

        if bpdu.version_1_length is not None:
            parts.append(f"v1_len={bpdu.version_1_length}")
        if bpdu.version_3_length is not None:
            parts.append(f"v3_len={bpdu.version_3_length}")

    parts.append(f"length={len(data)}")
    print(" ".join(parts))

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


def make_socket(interface: Optional[str]):
    if not sys.platform.startswith("linux"):
        raise OSError("raw 802.3 capture is best supported on Linux")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    if interface:
        sock.bind((interface, 0))
    return sock


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture and decode STP/RSTP/MSTP/PVST BPDU packets")
    parser.add_argument("-i", "--interface", help="interface to capture from, e.g. eth0")
    parser.add_argument("-c", "--count", type=int, default=0, help="number of BPDU packets to print; 0 means forever")
    parser.add_argument("--hex", action="store_true", help="print matching packet bytes as a hex dump")
    parser.add_argument("--show-non-bpdu", action="store_true", help="print a dot for each non-BPDU frame")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    try:
        with make_socket(args.interface) as sock:
            seen = 0
            while args.count == 0 or seen < args.count:
                data, _addr = sock.recvfrom(65535)
                matched = print_bpdu(data, args.hex)
                if matched:
                    seen += 1
                elif args.show_non_bpdu:
                    print(".", end="", flush=True)
    except KeyboardInterrupt:
        print("\nstopped")
    except OSError as exc:
        print(f"bpdu_sniffer: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

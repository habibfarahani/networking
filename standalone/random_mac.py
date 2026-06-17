#!/usr/bin/env python3

import argparse
import re
import secrets
import sys
from typing import Iterable, List, Optional, Sequence


MAC_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
PREFIX_RE = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){0,5}$")


def parse_mac(value: str) -> List[int]:
    if not MAC_RE.match(value):
        raise ValueError("invalid MAC address: %s" % value)
    return [int(part, 16) for part in re.split(r"[:-]", value)]


def parse_prefix(value: str) -> List[int]:
    if not PREFIX_RE.match(value):
        raise ValueError("invalid MAC prefix: %s" % value)
    return [int(part, 16) for part in re.split(r"[:-]", value)]


def format_mac(octets: Iterable[int], separator: str = ":") -> str:
    return separator.join("%02x" % octet for octet in octets)


def generate_random_mac(prefix: Optional[Sequence[int]] = None) -> List[int]:
    prefix_octets = list(prefix or [])
    if len(prefix_octets) > 6:
        raise ValueError("prefix must contain at most 6 octets")

    octets = prefix_octets + [secrets.randbelow(256) for _ in range(6 - len(prefix_octets))]
    if not prefix_octets:
        # Locally administered, unicast address:
        # bit 1 set, multicast bit 0 cleared in the first octet.
        octets[0] = (octets[0] | 0x02) & 0xFE
    return octets


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate random MAC addresses.")
    parser.add_argument("-n", "--count", type=int, default=1, help="number of MACs to generate")
    parser.add_argument(
        "--prefix",
        help="fixed prefix, from 1 to 6 octets, e.g. 02:42 or 02:42:ac",
    )
    parser.add_argument(
        "--separator",
        choices=(":", "-"),
        default=":",
        help="octet separator for output",
    )
    parser.add_argument(
        "--uppercase",
        action="store_true",
        help="print uppercase hex digits",
    )
    args = parser.parse_args(argv)

    if args.count < 1:
        parser.error("--count must be positive")
    if args.prefix:
        parse_prefix(args.prefix)
    return args


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    prefix = parse_prefix(args.prefix) if args.prefix else None
    for _ in range(args.count):
        mac = format_mac(generate_random_mac(prefix), args.separator)
        print(mac.upper() if args.uppercase else mac)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

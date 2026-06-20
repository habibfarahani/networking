#!/usr/bin/env python3
"""
Send an mDNS query and print decoded responses.

Run from a host attached to the local link:

    python standalone/mdns_query.py _services._dns-sd._udp.local PTR
    python standalone/mdns_query.py my-printer.local A --timeout 3

mDNS uses UDP multicast 224.0.0.251:5353. No third-party packages are needed,
but firewalls and OS multicast policy can affect whether responses arrive.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


MDNS_IPV4 = "224.0.0.251"
MDNS_PORT = 5353
CLASS_IN = 1
QU_MASK = 0x8000

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_ANY = 255

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_PTR: "PTR",
    TYPE_TXT: "TXT",
    TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV",
    TYPE_ANY: "ANY",
}

NAME_TYPES = {TYPE_PTR, TYPE_SRV}


@dataclass(frozen=True)
class Question:
    name: str
    qtype: int
    qclass: int


@dataclass(frozen=True)
class ResourceRecord:
    name: str
    rrtype: int
    rrclass: int
    ttl: int
    data: object


@dataclass(frozen=True)
class DnsMessage:
    transaction_id: int
    flags: int
    questions: list[Question]
    answers: list[ResourceRecord]
    authorities: list[ResourceRecord]
    additionals: list[ResourceRecord]


def type_name(value: int) -> str:
    return TYPE_NAMES.get(value, f"TYPE{value}")


def parse_type(value: str) -> int:
    upper = value.upper()
    for number, name in TYPE_NAMES.items():
        if upper == name:
            return number
    try:
        number = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"unknown DNS type: {value}") from exc
    if not 0 <= number <= 65535:
        raise argparse.ArgumentTypeError("DNS type must fit in 16 bits")
    return number


def encode_name(name: str) -> bytes:
    name = name.rstrip(".")
    if not name:
        return b"\x00"

    encoded = bytearray()
    for label in name.split("."):
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raise ValueError(f"DNS label is too long: {label}")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def decode_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    next_offset = offset
    seen_offsets: set[int] = set()

    while True:
        if offset >= len(packet):
            raise ValueError("DNS name extends beyond packet")
        length = packet[offset]

        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen_offsets:
                raise ValueError("DNS compression pointer loop")
            seen_offsets.add(pointer)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        if length & 0xC0:
            raise ValueError("unsupported DNS label type")

        offset += 1
        if length == 0:
            if not jumped:
                next_offset = offset
            break
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset : offset + length].decode("utf-8", "replace"))
        offset += length

    return (".".join(labels) or "."), next_offset


def build_query(name: str, qtype: int, unicast_response: bool) -> bytes:
    qclass = CLASS_IN | (QU_MASK if unicast_response else 0)
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack("!HH", qtype, qclass)
    return header + question


def parse_question(packet: bytes, offset: int) -> tuple[Question, int]:
    name, offset = decode_name(packet, offset)
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return Question(name=name, qtype=qtype, qclass=qclass), offset + 4


def parse_txt(data: bytes) -> list[str]:
    values = []
    offset = 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            values.append(data[offset:].decode("utf-8", "replace"))
            break
        values.append(data[offset : offset + length].decode("utf-8", "replace"))
        offset += length
    return values


def parse_rr_data(packet: bytes, rrtype: int, rdata: bytes, rdata_offset: int) -> object:
    if rrtype == TYPE_A and len(rdata) == 4:
        return socket.inet_ntoa(rdata)
    if rrtype == TYPE_AAAA and len(rdata) == 16:
        return str(ipaddress.IPv6Address(rdata))
    if rrtype in NAME_TYPES:
        if rrtype == TYPE_PTR:
            name, _offset = decode_name(packet, rdata_offset)
            return name

        if len(rdata) < 6:
            return rdata
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _offset = decode_name(packet, rdata_offset + 6)
        return {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target,
        }
    if rrtype == TYPE_TXT:
        return parse_txt(rdata)
    return rdata


def parse_rr(packet: bytes, offset: int) -> tuple[ResourceRecord, int]:
    name, offset = decode_name(packet, offset)
    if offset + 10 > len(packet):
        raise ValueError("truncated DNS resource record")

    rrtype, rrclass, ttl, rdlength = struct.unpack("!HHIH", packet[offset : offset + 10])
    offset += 10
    rdata_offset = offset
    end = offset + rdlength
    if end > len(packet):
        raise ValueError("truncated DNS resource data")

    rdata = packet[offset:end]
    return (
        ResourceRecord(
            name=name,
            rrtype=rrtype,
            rrclass=rrclass,
            ttl=ttl,
            data=parse_rr_data(packet, rrtype, rdata, rdata_offset),
        ),
        end,
    )


def parse_message(packet: bytes) -> DnsMessage:
    if len(packet) < 12:
        raise ValueError("DNS packet is too short")

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", packet[:12])
    offset = 12
    questions = []
    answers = []
    authorities = []
    additionals = []

    for _index in range(qdcount):
        question, offset = parse_question(packet, offset)
        questions.append(question)
    for target, count in ((answers, ancount), (authorities, nscount), (additionals, arcount)):
        for _index in range(count):
            rr, offset = parse_rr(packet, offset)
            target.append(rr)

    return DnsMessage(
        transaction_id=transaction_id,
        flags=flags,
        questions=questions,
        answers=answers,
        authorities=authorities,
        additionals=additionals,
    )


def format_data(rr: ResourceRecord) -> str:
    if rr.rrtype == TYPE_SRV and isinstance(rr.data, dict):
        return (
            f"priority={rr.data['priority']} weight={rr.data['weight']} "
            f"port={rr.data['port']} target={rr.data['target']}"
        )
    if rr.rrtype == TYPE_TXT and isinstance(rr.data, list):
        return " ".join(repr(value) for value in rr.data) if rr.data else "empty"
    if isinstance(rr.data, bytes):
        return rr.data.hex()
    return str(rr.data)


def format_rr(rr: ResourceRecord, section: str) -> str:
    cache_flush = bool(rr.rrclass & QU_MASK)
    rrclass = rr.rrclass & ~QU_MASK
    extras = [f"ttl={rr.ttl}", f"class={rrclass}"]
    if cache_flush:
        extras.append("cache-flush")
    return f"{section} {rr.name} {type_name(rr.rrtype)} {' '.join(extras)} {format_data(rr)}"


def make_socket(source_ip: Optional[str], timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    if source_ip:
        packed = socket.inet_aton(source_ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, packed)
        sock.bind((source_ip, 0))
    else:
        sock.bind(("", 0))
    return sock


def print_message(data: bytes, addr: tuple[str, int], only_answers: bool) -> bool:
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    try:
        message = parse_message(data)
    except ValueError as exc:
        print(f"{timestamp} malformed response from {addr[0]}:{addr[1]}: {exc}")
        return True

    records = [
        ("answer", message.answers),
        ("authority", message.authorities),
        ("additional", message.additionals),
    ]
    if not any(section_records for _name, section_records in records):
        return False

    print(f"{timestamp} response from {addr[0]}:{addr[1]}")
    for section, section_records in records:
        if only_answers and section != "answer":
            continue
        for rr in section_records:
            print(f"  {format_rr(rr, section)}")
    return True


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send an mDNS query and print decoded responses")
    parser.add_argument("name", nargs="?", default="_services._dns-sd._udp.local", help="DNS name to query")
    parser.add_argument("type", nargs="?", type=parse_type, default=TYPE_PTR, help="record type, e.g. PTR, SRV, TXT, A, AAAA")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="seconds to wait for responses")
    parser.add_argument("-c", "--count", type=int, default=0, help="maximum responses to print; 0 means until timeout")
    parser.add_argument("--source-ip", help="IPv4 address of the interface to send multicast from")
    parser.add_argument("--unicast-response", action="store_true", help="request unicast responses by setting the QU bit")
    parser.add_argument("--answers-only", action="store_true", help="hide authority and additional records")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    query = build_query(args.name, args.type, args.unicast_response)
    deadline = time.monotonic() + args.timeout
    seen = 0

    try:
        with make_socket(args.source_ip, args.timeout) as sock:
            sock.sendto(query, (MDNS_IPV4, MDNS_PORT))
            # while time.monotonic() < deadline and (args.count == 0 or seen < args.count):
            #     remaining = max(0.0, deadline - time.monotonic())
            #     sock.settimeout(remaining)
            #     try:
            #         data, addr = sock.recvfrom(9000)
            #     except socket.timeout:
            #         break
            #     if print_message(data, addr, args.answers_only):
            #         seen += 1
    except OSError as exc:
        print(f"mdns_query: {exc}", file=sys.stderr)
        return 1

    if seen == 0:
        print("no mDNS responses")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

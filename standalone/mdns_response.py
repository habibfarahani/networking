#!/usr/bin/env python3
import ipaddress
import struct
from dataclasses import dataclass
from typing import Any


RR_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    12: "PTR",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    47: "NSEC",
}


@dataclass
class Question:
    name: str
    qtype: str
    qclass: int
    unicast_response: bool


@dataclass
class Record:
    name: str
    rtype: str
    rclass: int
    cache_flush: bool
    ttl: int
    value: Any
    raw: bytes


@dataclass
class DNSMessage:
    transaction_id: int
    flags: int
    questions: list[Question]
    answers: list[Record]
    authorities: list[Record]
    additionals: list[Record]

    @property
    def is_response(self) -> bool:
        return bool(self.flags & 0x8000)


def read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end_offset = offset
    seen_offsets = set()

    while True:
        if offset >= len(packet):
            raise ValueError("DNS name exceeds packet length")

        length = packet[offset]

        # Compression pointer: top two bits set.
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")

            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer in seen_offsets:
                raise ValueError("DNS compression pointer loop")

            seen_offsets.add(pointer)

            if not jumped:
                end_offset = offset + 2
                jumped = True

            offset = pointer
            continue

        if length & 0xC0:
            raise ValueError("Unsupported DNS label format")

        offset += 1

        if length == 0:
            if not jumped:
                end_offset = offset
            return ".".join(labels) + ".", end_offset

        if offset + length > len(packet):
            raise ValueError("DNS label exceeds packet length")

        labels.append(packet[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length


def parse_txt(raw: bytes) -> list[str]:
    values = []
    offset = 0

    while offset < len(raw):
        length = raw[offset]
        offset += 1
        values.append(raw[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length

    return values


def parse_nsec_bitmap(raw: bytes) -> list[str]:
    types = []
    offset = 0

    while offset + 2 <= len(raw):
        window = raw[offset]
        bitmap_len = raw[offset + 1]
        offset += 2

        bitmap = raw[offset:offset + bitmap_len]
        offset += bitmap_len

        for byte_index, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    rr_type = window * 256 + byte_index * 8 + bit
                    types.append(RR_TYPES.get(rr_type, str(rr_type)))

    return types


def parse_rdata(packet: bytes, rtype: int, rdata_offset: int, rdlength: int) -> Any:
    raw = packet[rdata_offset:rdata_offset + rdlength]

    if rtype == 1 and rdlength == 4:  # A
        return str(ipaddress.IPv4Address(raw))

    if rtype == 28 and rdlength == 16:  # AAAA
        return str(ipaddress.IPv6Address(raw))

    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = read_name(packet, rdata_offset)
        return name

    if rtype == 16:  # TXT
        return parse_txt(raw)

    if rtype == 33:  # SRV
        if rdlength < 6:
            return raw.hex()

        priority, weight, port = struct.unpack_from("!HHH", packet, rdata_offset)
        target, _ = read_name(packet, rdata_offset + 6)

        return {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target,
        }

    if rtype == 47:  # NSEC
        next_name, bitmap_offset = read_name(packet, rdata_offset)
        bitmap = packet[bitmap_offset:rdata_offset + rdlength]

        return {
            "next_domain": next_name,
            "types": parse_nsec_bitmap(bitmap),
        }

    return raw.hex()


def parse_question(packet: bytes, offset: int) -> tuple[Question, int]:
    name, offset = read_name(packet, offset)

    if offset + 4 > len(packet):
        raise ValueError("Truncated DNS question")

    qtype, qclass_raw = struct.unpack_from("!HH", packet, offset)
    offset += 4

    return Question(
        name=name,
        qtype=RR_TYPES.get(qtype, str(qtype)),
        qclass=qclass_raw & 0x7FFF,
        unicast_response=bool(qclass_raw & 0x8000),
    ), offset


def parse_record(packet: bytes, offset: int) -> tuple[Record, int]:
    name, offset = read_name(packet, offset)

    if offset + 10 > len(packet):
        raise ValueError("Truncated DNS resource record")

    rtype, rclass_raw, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
    offset += 10

    rdata_offset = offset
    offset += rdlength

    if offset > len(packet):
        raise ValueError("DNS RDATA exceeds packet length")

    raw = packet[rdata_offset:rdata_offset + rdlength]

    return Record(
        name=name,
        rtype=RR_TYPES.get(rtype, str(rtype)),
        rclass=rclass_raw & 0x7FFF,
        cache_flush=bool(rclass_raw & 0x8000),
        ttl=ttl,
        value=parse_rdata(packet, rtype, rdata_offset, rdlength),
        raw=raw,
    ), offset


def parse_mdns_response(packet: bytes) -> DNSMessage:
    if len(packet) < 12:
        raise ValueError("Packet too short for DNS header")

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH",
        packet,
        0,
    )

    offset = 12
    questions = []
    answers = []
    authorities = []
    additionals = []

    for _ in range(qdcount):
        question, offset = parse_question(packet, offset)
        questions.append(question)

    for _ in range(ancount):
        record, offset = parse_record(packet, offset)
        answers.append(record)

    for _ in range(nscount):
        record, offset = parse_record(packet, offset)
        authorities.append(record)

    for _ in range(arcount):
        record, offset = parse_record(packet, offset)
        additionals.append(record)

    return DNSMessage(
        transaction_id=transaction_id,
        flags=flags,
        questions=questions,
        answers=answers,
        authorities=authorities,
        additionals=additionals,
    )
Example usage with a UDP socket:

python

data, addr = sock.recvfrom(9000)
msg = parse_mdns_response(data)

for record in msg.answers + msg.additionals:
    print(record.name, record.rtype, record.ttl, record.value)
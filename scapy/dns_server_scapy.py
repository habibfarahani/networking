#!/usr/bin/env python3
"""Minimal DNS server implemented with Scapy."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from collections import defaultdict
from typing import Any

from scapy.all import DNS, DNSQR, DNSRR

QTYPE_MAP = {
    "A": 1,
    "AAAA": 28,
    "TXT": 16,
    "CNAME": 5,
}

QTYPE_NAME = {value: key for key, value in QTYPE_MAP.items()}


def normalize_name(name: str) -> str:
    return name.rstrip(".").lower() + "."


def parse_record(text: str) -> tuple[str, int, int, str]:
    parts = text.split(":", 3)
    if len(parts) != 4:
        raise ValueError(f"invalid record format: {text!r}")
    name, rtype_name, ttl_text, value = parts
    rtype = QTYPE_MAP.get(rtype_name.upper())
    if rtype is None:
        raise ValueError(f"unsupported record type: {rtype_name}")
    ttl = int(ttl_text)
    if rtype == 1:
        ipaddress.IPv4Address(value)
    elif rtype == 28:
        ipaddress.IPv6Address(value)
    return normalize_name(name), rtype, ttl, value


def decode_qname(qname: bytes | str) -> str:
    if isinstance(qname, bytes):
        return qname.decode(errors="replace")
    return str(qname)


def chain_records(records: list[DNSRR]) -> DNSRR | None:
    if not records:
        return None
    head = records[0]
    current = head
    for record in records[1:]:
        current /= record
        current = record
    return head


class DNSServer:
    def __init__(self, bind_ip: str, port: int, records: list[tuple[str, int, int, str]]) -> None:
        self.bind_ip = bind_ip
        self.port = port
        self.records: dict[tuple[str, int], list[tuple[int, str]]] = defaultdict(list)
        for name, rtype, ttl, value in records:
            self.records[(name, rtype)].append((ttl, value))

    def lookup(self, qname: str, qtype: int) -> list[DNSRR]:
        key = (normalize_name(qname), qtype)
        answers = []
        for ttl, value in self.records.get(key, []):
            answers.append(DNSRR(rrname=key[0], type=qtype, ttl=ttl, rdata=value))
        return answers

    def handle_query(self, data: bytes, client: tuple[str, int], sock: socket.socket) -> None:
        try:
            dns = DNS(data)
        except Exception as exc:
            print(f"invalid packet from={client[0]}:{client[1]} error={exc}", file=sys.stderr)
            return

        if dns.qr != 0 or dns.qdcount == 0 or not isinstance(dns.qd, DNSQR):
            return

        question = dns.qd
        qname = decode_qname(question.qname)
        qtype = int(question.qtype)
        qtype_text = QTYPE_NAME.get(qtype, str(qtype))
        print(f"query from={client[0]}:{client[1]} name={qname} qtype={qtype_text}")

        answers = self.lookup(qname, qtype)
        response = DNS(
            id=dns.id,
            qr=1,
            opcode=dns.opcode,
            aa=1,
            rd=dns.rd,
            ra=0,
            rcode=0 if answers else 3,
            qd=dns.qd,
            qdcount=1,
            an=chain_records(answers),
            ancount=len(answers),
        )
        sock.sendto(bytes(response), client)

        if answers:
            joined = ", ".join(str(answer.rdata) for answer in answers)
            print(f"reply to={client[0]}:{client[1]} answers={joined}")
        else:
            print(f"reply to={client[0]}:{client[1]} nxdomain")

    def serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.bind_ip, self.port))
        print(f"listening on udp://{self.bind_ip}:{self.port}")
        try:
            while True:
                data, client = sock.recvfrom(4096)
                self.handle_query(data, client, sock)
        except KeyboardInterrupt:
            pass
        finally:
            sock.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal DNS server using Scapy packet parsing")
    parser.add_argument("--bind-ip", default="0.0.0.0", help="IP address to bind")
    parser.add_argument("--port", type=int, default=5354, help="UDP port to bind")
    parser.add_argument(
        "--record",
        action="append",
        default=[],
        help="Static record in name:TYPE:TTL:value format, e.g. example.local:A:60:192.168.1.10",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = []
    try:
        for item in args.record:
            records.append(parse_record(item))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    server = DNSServer(bind_ip=args.bind_ip, port=args.port, records=records)
    try:
        server.serve()
    except PermissionError:
        print("permission denied while binding socket", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
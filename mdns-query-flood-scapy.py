#!/usr/bin/env python3
"""mDNS query tool implemented with Scapy."""

from __future__ import annotations

import argparse
import random
import sys
from typing import Any

from scapy.all import DNS, DNSQR, IP, UDP, conf, get_if_addr, send, sniff

MDNS_MCAST_IP = "224.0.0.251"
MDNS_PORT = 5353

QTYPE_MAP = {
    "A": 1,
    "PTR": 12,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "ANY": 255,
}


def decode_rdata(rr: Any) -> str:
    rdata = rr.rdata
    if isinstance(rdata, bytes):
        try:
            return rdata.decode(errors="replace")
        except Exception:
            return rdata.hex()
    if isinstance(rdata, list):
        return ",".join(str(item) for item in rdata)
    return str(rdata)


def print_rr(section: str, rr: Any, count: int) -> None:
    current = rr
    for index in range(count):
        print(
            f"  {section}[{index}] name={current.rrname.decode(errors='replace') if isinstance(current.rrname, bytes) else current.rrname} "
            f"type={current.type} ttl={current.ttl} data={decode_rdata(current)}"
        )
        current = current.payload


def handle_response(pkt: Any) -> None:
    if DNS not in pkt:
        return
    dns = pkt[DNS]
    if dns.qr != 1:
        return

    src_ip = pkt[IP].src if IP in pkt else "unknown"
    print(f"response from={src_ip} answers={dns.ancount} authority={dns.nscount} additional={dns.arcount}")
    if dns.ancount:
        print_rr("answer", dns.an, dns.ancount)
    if dns.nscount:
        print_rr("authority", dns.ns, dns.nscount)
    if dns.arcount:
        print_rr("additional", dns.ar, dns.arcount)


def build_query(name: str, qtype: int, unicast_response: bool) -> DNS:
    question = DNSQR(qname=name, qtype=qtype, qclass=0x8001 if unicast_response else 0x0001)
    return DNS(
        id=random.randint(0, 0xFFFF),
        qr=0,
        opcode=0,
        aa=0,
        rd=0,
        qdcount=1,
        qd=question,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="mDNS query tool using Scapy")
    parser.add_argument("--iface", required=True, help="Interface to send and sniff on")
    parser.add_argument("--name", default="_services._dns-sd._udp.local", help="mDNS name to query, e.g. _services._dns-sd._udp.local")
    parser.add_argument("--qtype", default="PTR", help="DNS query type: A, PTR, TXT, AAAA, SRV, ANY")
    parser.add_argument("--timeout", type=int, default=5, help="Sniff timeout in seconds")
    parser.add_argument("--count", type=int, default=100, help="Number of query packets to send")
    parser.add_argument("--interval", type=float, default=1.0, help="Delay between repeated queries")
    parser.add_argument("--unicast-response", action="store_true", help="Request unicast responses")
    args = parser.parse_args()

    qtype_name = args.qtype.upper()
    qtype = QTYPE_MAP.get(qtype_name)
    if qtype is None:
        print(f"unsupported qtype: {args.qtype}", file=sys.stderr)
        return 1

    conf.checkIPaddr = False
    src_ip = get_if_addr(args.iface)
    query_name = args.name if args.name.endswith(".") else f"{args.name}."

    packet = (
        IP(src=src_ip, dst=MDNS_MCAST_IP)
        / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
        / build_query(query_name, qtype, args.unicast_response)
    )

    print(
        f"sending mDNS query iface={args.iface} src={src_ip} "
        f"name={query_name} qtype={qtype_name} count={args.count}"
    )

    try:
        for _ in range(args.count):
            send(packet, iface=args.iface, verbose=False)
            if args.count > 1:
                conf.route.resync()
            if args.interval > 0 and _ + 1 < args.count:
                import time

                time.sleep(args.interval)

        # sniff(
        #     iface=args.iface,
        #     filter="udp port 5353",
        #     lfilter=lambda pkt: DNS in pkt and pkt[DNS].qr == 1,
        #     prn=handle_response,
        #     store=False,
        #     timeout=args.timeout,
        # )
    except PermissionError:
        print("Permission denied. Run as root to send/sniff mDNS packets.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

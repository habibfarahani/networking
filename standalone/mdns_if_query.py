#!/usr/bin/env python3
import argparse
import fcntl
import select
import socket
import struct
import time

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
QTYPE = {"A": 1, "PTR": 12, "TXT": 16, "AAAA": 28, "SRV": 33, "ANY": 255}


def iface_ipv4(iface: str) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        ifreq = struct.pack("256s", iface[:15].encode())
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, ifreq)[20:24])


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"


def build_query(name: str, qtype: str) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    question = dns_name(name) + struct.pack("!HH", QTYPE[qtype], 1)
    return header + question


def read_name(pkt: bytes, off: int):
    labels, end, seen = [], None, set()
    while True:
        length = pkt[off]
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | pkt[off + 1]
            if ptr in seen:
                raise ValueError("DNS compression loop")
            seen.add(ptr)
            end = end or off + 2
            off = ptr
            continue
        if length == 0:
            off += 1
            return ".".join(labels) + ".", end or off
        off += 1
        labels.append(pkt[off:off + length].decode(errors="replace"))
        off += length


def parse_answers(pkt: bytes):
    _, _, qd, an, ns, ar = struct.unpack_from("!HHHHHH", pkt, 0)
    off = 12

    for _ in range(qd):
        _, off = read_name(pkt, off)
        off += 4

    for _ in range(an + ns + ar):
        name, off = read_name(pkt, off)
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", pkt, off)
        off += 10
        rdata_off, rdata = off, pkt[off:off + rdlen]
        off += rdlen

        if rtype == 1 and rdlen == 4:
            value = socket.inet_ntoa(rdata)
            kind = "A"
        elif rtype == 28 and rdlen == 16:
            value = socket.inet_ntop(socket.AF_INET6, rdata)
            kind = "AAAA"
        elif rtype == 12:
            value, _ = read_name(pkt, rdata_off)
            kind = "PTR"
        elif rtype == 33:
            prio, weight, port = struct.unpack_from("!HHH", pkt, rdata_off)
            target, _ = read_name(pkt, rdata_off + 6)
            value = f"{prio} {weight} {port} {target}"
            kind = "SRV"
        elif rtype == 16:
            parts, i = [], 0
            while i < len(rdata):
                n = rdata[i]
                i += 1
                parts.append(rdata[i:i + n].decode(errors="replace"))
                i += n
            value = parts
            kind = "TXT"
        else:
            value = rdata.hex()
            kind = str(rtype)

        yield name, kind, ttl, value


def mdns_query(iface: str, name: str, qtype: str, timeout: float):
    iface_ip = iface_ipv4(iface)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_ADD_MEMBERSHIP,
        socket.inet_aton(MDNS_ADDR) + socket.inet_aton(iface_ip),
    )

    if hasattr(socket, "SO_BINDTODEVICE"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
        except PermissionError:
            pass

    sock.bind(("", MDNS_PORT))
    sock.sendto(build_query(name, qtype), (MDNS_ADDR, MDNS_PORT))

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sock], [], [], deadline - time.monotonic())
        if not ready:
            break

        pkt, src = sock.recvfrom(9000)
        for rec_name, rec_type, ttl, value in parse_answers(pkt):
            print(f"{src[0]} ttl={ttl} {rec_name} {rec_type} {value}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("iface", help="Interface name, e.g. eth0")
    p.add_argument("name", help="mDNS name, e.g. _http._tcp.local or printer.local")
    p.add_argument("--qtype", choices=QTYPE, default="PTR")
    p.add_argument("--timeout", type=float, default=3.0)
    args = p.parse_args()

    print(args)
    mdns_query(args.iface, args.name, args.qtype, args.timeout)


"""
Examples:

bash

python3 mdns_if_query.py eth0 _services._dns-sd._udp.local --qtype PTR
python3 mdns_if_query.py eth0 _http._tcp.local --qtype PTR
python3 mdns_if_query.py eth0 my-device.local --qtype A
If port 5353 is already exclusively held by an mDNS daemon, run with sufficient privileges or stop that daemon while testing.





7:23 PM





Default permissions

5.5
Extra High


Work locally

"""
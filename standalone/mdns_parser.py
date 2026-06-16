#!/usr/bin/env python3
#
# Listen for mDNS traffic on every local interface and decode the DNS payloads.

from __future__ import print_function

import argparse
import binascii
import datetime
import errno
import fcntl
import json
import os
import selectors
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


MDNS_PORT = 5353
MDNS_IPV4_GROUP = "224.0.0.251"
MDNS_IPV6_GROUP = "ff02::fb"
MAX_NAME_POINTERS = 32

# Linux constants. Python exposes these on many builds, but not all of them.
IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
IPV6_RECVPKTINFO = getattr(socket, "IPV6_RECVPKTINFO", 49)
IPV6_PKTINFO = getattr(socket, "IPV6_PKTINFO", 50)

TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    47: "NSEC",
    64: "SVCB",
    65: "HTTPS",
    255: "ANY",
}

CLASS_NAMES = {
    1: "IN",
    255: "ANY",
}

SECTION_NAMES = (
    ("answers", "AN"),
    ("authorities", "NS"),
    ("additionals", "AR"),
)


class DnsParseError(ValueError):
    pass


class InterfaceDiscoveryError(RuntimeError):
    pass


@dataclass
class Interface:
    name: str
    index: int
    ipv4_addresses: List[str]
    has_ipv6: bool


@dataclass
class SocketState:
    family: int
    family_name: str
    sock: socket.socket
    joined_interfaces: List[str]


def type_name(value: int) -> str:
    return TYPE_NAMES.get(value, "TYPE%d" % value)


def class_name(value: int) -> str:
    return CLASS_NAMES.get(value, "CLASS%d" % value)


def safe_bytes(data: bytes, escape_dot: bool = False) -> str:
    chars = []
    for byte in data:
        if byte == 0x5C:
            chars.append("\\\\")
        elif escape_dot and byte == 0x2E:
            chars.append("\\.")
        elif 0x20 <= byte <= 0x7E:
            chars.append(chr(byte))
        else:
            chars.append("\\x%02x" % byte)
    return "".join(chars)


def short_hex(data: bytes, limit: int = 64) -> str:
    value = binascii.hexlify(data[:limit]).decode("ascii")
    if len(data) > limit:
        value += "..."
    return value


def require_length(packet: bytes, offset: int, length: int, context: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(packet):
        raise DnsParseError("%s exceeds packet length" % context)


def decode_dns_name(packet: bytes, offset: int) -> Tuple[str, int]:
    labels = []
    next_offset = offset
    jumped = False
    visited_offsets = set()
    pointer_count = 0

    while True:
        require_length(packet, offset, 1, "DNS name")
        length = packet[offset]

        if length & 0xC0 == 0xC0:
            require_length(packet, offset, 2, "DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if pointer >= len(packet):
                raise DnsParseError("DNS compression pointer is out of bounds")
            if pointer in visited_offsets:
                raise DnsParseError("DNS compression pointer loop detected")
            visited_offsets.add(pointer)
            pointer_count += 1
            if pointer_count > MAX_NAME_POINTERS:
                raise DnsParseError("too many DNS compression pointers")
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue

        if length & 0xC0:
            raise DnsParseError("unsupported DNS label type")

        offset += 1
        if length == 0:
            if not jumped:
                next_offset = offset
            break

        if length > 63:
            raise DnsParseError("DNS label is longer than 63 bytes")
        require_length(packet, offset, length, "DNS label")
        labels.append(safe_bytes(packet[offset:offset + length], escape_dot=True))
        offset += length

    return (".".join(labels) if labels else "."), next_offset


def ensure_rdata_consumed(actual_offset: int, end_offset: int, rrtype: int) -> None:
    if actual_offset != end_offset:
        raise DnsParseError(
            "%s RDATA has %d trailing byte(s)" %
            (type_name(rrtype), end_offset - actual_offset)
        )


def parse_nsec_bitmap(data: bytes) -> List[str]:
    names = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise DnsParseError("truncated NSEC type bitmap")
        window = data[offset]
        length = data[offset + 1]
        offset += 2
        if length == 0 or length > 32:
            raise DnsParseError("invalid NSEC type bitmap length")
        if offset + length > len(data):
            raise DnsParseError("NSEC type bitmap exceeds RDATA length")

        bitmap = data[offset:offset + length]
        for byte_index, bitmap_byte in enumerate(bitmap):
            for bit_index in range(8):
                if bitmap_byte & (0x80 >> bit_index):
                    rrtype = window * 256 + byte_index * 8 + bit_index
                    names.append(type_name(rrtype))
        offset += length
    return names


def parse_txt_rdata(data: bytes) -> List[str]:
    strings = []
    offset = 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        if offset + length > len(data):
            raise DnsParseError("TXT string exceeds RDATA length")
        strings.append(safe_bytes(data[offset:offset + length]))
        offset += length
    return strings


def parse_rdata(packet: bytes, rrtype: int, start: int, end: int) -> Dict[str, Any]:
    data = packet[start:end]

    if rrtype == 1:
        if len(data) != 4:
            raise DnsParseError("A record RDATA must be 4 bytes")
        return {"address": socket.inet_ntop(socket.AF_INET, data)}

    if rrtype == 28:
        if len(data) != 16:
            raise DnsParseError("AAAA record RDATA must be 16 bytes")
        return {"address": socket.inet_ntop(socket.AF_INET6, data)}

    if rrtype in (2, 5, 12):
        name, next_offset = decode_dns_name(packet, start)
        ensure_rdata_consumed(next_offset, end, rrtype)
        return {"name": name}

    if rrtype == 15:
        if len(data) < 3:
            raise DnsParseError("MX record RDATA is too short")
        preference = struct.unpack_from("!H", packet, start)[0]
        exchange, next_offset = decode_dns_name(packet, start + 2)
        ensure_rdata_consumed(next_offset, end, rrtype)
        return {"preference": preference, "exchange": exchange}

    if rrtype == 16:
        return {"strings": parse_txt_rdata(data)}

    if rrtype == 33:
        if len(data) < 7:
            raise DnsParseError("SRV record RDATA is too short")
        priority, weight, port = struct.unpack_from("!HHH", packet, start)
        target, next_offset = decode_dns_name(packet, start + 6)
        ensure_rdata_consumed(next_offset, end, rrtype)
        return {
            "priority": priority,
            "weight": weight,
            "port": port,
            "target": target,
        }

    if rrtype == 47:
        next_domain, next_offset = decode_dns_name(packet, start)
        if next_offset > end:
            raise DnsParseError("NSEC next domain exceeds RDATA length")
        return {
            "next_domain": next_domain,
            "types": parse_nsec_bitmap(packet[next_offset:end]),
        }

    return {"length": len(data), "hex": short_hex(data)}


def parse_rdata_safe(packet: bytes, rrtype: int, start: int, end: int) -> Dict[str, Any]:
    try:
        return parse_rdata(packet, rrtype, start, end)
    except (DnsParseError, OSError, ValueError, struct.error) as error:
        return {
            "error": str(error),
            "length": end - start,
            "hex": short_hex(packet[start:end]),
        }


def parse_question(packet: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, offset = decode_dns_name(packet, offset)
    require_length(packet, offset, 4, "DNS question")
    qtype, raw_qclass = struct.unpack_from("!HH", packet, offset)
    offset += 4
    qclass = raw_qclass & 0x7FFF
    return {
        "name": name,
        "type": type_name(qtype),
        "type_code": qtype,
        "class": class_name(qclass),
        "class_code": qclass,
        "unicast_response": bool(raw_qclass & 0x8000),
    }, offset


def parse_record(packet: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    name, offset = decode_dns_name(packet, offset)
    require_length(packet, offset, 10, "DNS resource record")
    rrtype, raw_rrclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
    offset += 10
    end = offset + rdlength
    require_length(packet, offset, rdlength, "DNS RDATA")
    rrclass = raw_rrclass & 0x7FFF
    record = {
        "name": name,
        "type": type_name(rrtype),
        "type_code": rrtype,
        "class": class_name(rrclass),
        "class_code": rrclass,
        "cache_flush": bool(raw_rrclass & 0x8000),
        "ttl": ttl,
        "rdata": parse_rdata_safe(packet, rrtype, offset, end),
    }
    return record, end


def parse_flags(flags: int) -> Dict[str, Any]:
    return {
        "raw": flags,
        "response": bool(flags & 0x8000),
        "opcode": (flags >> 11) & 0xF,
        "authoritative": bool(flags & 0x0400),
        "truncated": bool(flags & 0x0200),
        "recursion_desired": bool(flags & 0x0100),
        "recursion_available": bool(flags & 0x0080),
        "rcode": flags & 0xF,
    }


def parse_dns_message(packet: bytes) -> Dict[str, Any]:
    require_length(packet, 0, 12, "DNS header")
    message_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", packet, 0
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

    return {
        "id": message_id,
        "flags": parse_flags(flags),
        "counts": {
            "questions": qdcount,
            "answers": ancount,
            "authorities": nscount,
            "additionals": arcount,
        },
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
        "trailing_bytes": len(packet) - offset,
    }


def interface_ipv4_address(name: str) -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", name.encode("utf-8")[:15])
        result = fcntl.ioctl(sock.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        return socket.inet_ntoa(result[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def ipv6_interface_indexes() -> set:
    indexes = set()
    path = "/proc/net/if_inet6"
    if not os.path.exists(path):
        return indexes

    try:
        with open(path, "r", encoding="ascii") as ipv6_file:
            for line in ipv6_file:
                fields = line.split()
                if len(fields) >= 6:
                    try:
                        indexes.add(int(fields[1], 16))
                    except ValueError:
                        continue
    except OSError:
        return set()
    return indexes


def discover_interfaces(selected_names: Optional[Iterable[str]] = None) -> Dict[int, Interface]:
    selected = set(selected_names or [])
    ipv6_indexes = ipv6_interface_indexes()
    interfaces = {}

    try:
        system_interfaces = socket.if_nameindex()
    except OSError as error:
        raise InterfaceDiscoveryError("could not enumerate interfaces: %s" % error)

    for index, name in system_interfaces:
        if selected and name not in selected:
            continue
        ipv4 = interface_ipv4_address(name)
        interfaces[index] = Interface(
            name=name,
            index=index,
            ipv4_addresses=[ipv4] if ipv4 else [],
            has_ipv6=(index in ipv6_indexes),
        )

    return interfaces


def set_reuse_options(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass


def create_ipv4_socket(
    interfaces: Dict[int, Interface],
    port: int,
    errors: List[str],
) -> Optional[SocketState]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    set_reuse_options(sock)
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    except OSError as error:
        errors.append("IPv4 packet interface metadata disabled: %s" % error)

    try:
        sock.bind(("", port))
    except OSError as error:
        sock.close()
        errors.append("IPv4 bind on UDP/%d failed: %s" % (port, error))
        return None

    joined = []
    for interface in interfaces.values():
        for address in interface.ipv4_addresses:
            membership = socket.inet_aton(MDNS_IPV4_GROUP) + socket.inet_aton(address)
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
                joined.append("%s(%s)" % (interface.name, address))
            except OSError as error:
                if error.errno not in (errno.EADDRINUSE, errno.EINVAL, errno.ENODEV):
                    errors.append(
                        "IPv4 join failed on %s(%s): %s" %
                        (interface.name, address, error)
                    )

    if not joined:
        sock.close()
        return None

    sock.setblocking(False)
    return SocketState(socket.AF_INET, "ipv4", sock, joined)


def create_ipv6_socket(
    interfaces: Dict[int, Interface],
    port: int,
    errors: List[str],
) -> Optional[SocketState]:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    set_reuse_options(sock)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    except OSError:
        pass
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)
    except OSError as error:
        errors.append("IPv6 packet interface metadata disabled: %s" % error)

    try:
        sock.bind(("::", port))
    except OSError as error:
        sock.close()
        errors.append("IPv6 bind on UDP/%d failed: %s" % (port, error))
        return None

    joined = []
    for interface in interfaces.values():
        if not interface.has_ipv6:
            continue
        membership = (
            socket.inet_pton(socket.AF_INET6, MDNS_IPV6_GROUP) +
            struct.pack("@I", interface.index)
        )
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, membership)
            joined.append(interface.name)
        except OSError as error:
            if error.errno not in (errno.EADDRINUSE, errno.EINVAL, errno.ENODEV):
                errors.append("IPv6 join failed on %s: %s" % (interface.name, error))

    if not joined:
        sock.close()
        return None

    sock.setblocking(False)
    return SocketState(socket.AF_INET6, "ipv6", sock, joined)


def packet_interface_index(family: int, ancdata: Sequence[Tuple[int, int, bytes]]) -> Optional[int]:
    for level, cmsg_type, data in ancdata:
        if family == socket.AF_INET and level == socket.IPPROTO_IP and cmsg_type == IP_PKTINFO:
            if len(data) >= 4:
                return struct.unpack_from("I", data, 0)[0]
        if (
            family == socket.AF_INET6 and
            level == socket.IPPROTO_IPV6 and
            cmsg_type == IPV6_PKTINFO
        ):
            if len(data) >= 20:
                return struct.unpack_from("@I", data, 16)[0]
    return None


def split_source_address(address: Any) -> Tuple[str, int]:
    if isinstance(address, tuple) and len(address) >= 2:
        return str(address[0]), int(address[1])
    return str(address), 0


def rdata_summary(rdata: Dict[str, Any]) -> str:
    if "error" in rdata:
        return "malformed-rdata=%s len=%d hex=%s" % (
            rdata["error"], rdata["length"], rdata["hex"]
        )
    if "address" in rdata:
        return rdata["address"]
    if "name" in rdata:
        return rdata["name"]
    if "exchange" in rdata:
        return "preference=%d exchange=%s" % (rdata["preference"], rdata["exchange"])
    if "strings" in rdata:
        return json.dumps(rdata["strings"], ensure_ascii=True)
    if "target" in rdata:
        return "priority=%d weight=%d port=%d target=%s" % (
            rdata["priority"], rdata["weight"], rdata["port"], rdata["target"]
        )
    if "next_domain" in rdata:
        return "next=%s types=%s" % (
            rdata["next_domain"], ",".join(rdata["types"]) if rdata["types"] else "-"
        )
    return "len=%d hex=%s" % (rdata["length"], rdata["hex"])


def print_human_packet(event: Dict[str, Any]) -> None:
    message = event["message"]
    flags = message["flags"]
    direction = "response" if flags["response"] else "query"
    src = event["source"]
    interface = event.get("interface") or "ifindex:%s" % event.get("interface_index", "?")
    counts = message["counts"]

    print(
        "%s %s %s %s:%d %s id=0x%04x q=%d an=%d ns=%d ar=%d" % (
            event["time"],
            interface,
            event["family"],
            src["address"],
            src["port"],
            direction,
            message["id"],
            counts["questions"],
            counts["answers"],
            counts["authorities"],
            counts["additionals"],
        )
    )

    for question in message["questions"]:
        flags_text = " QU" if question["unicast_response"] else ""
        print(
            "  Q  %s %s %s%s" %
            (question["name"], question["type"], question["class"], flags_text)
        )

    for section_name, section_label in SECTION_NAMES:
        for record in message[section_name]:
            flush_text = " flush" if record["cache_flush"] else ""
            print(
                "  %-2s %s %s %s ttl=%d%s -> %s" %
                (
                    section_label,
                    record["name"],
                    record["type"],
                    record["class"],
                    record["ttl"],
                    flush_text,
                    rdata_summary(record["rdata"]),
                )
            )

    if message["trailing_bytes"]:
        print("  trailing-bytes=%d" % message["trailing_bytes"])
    sys.stdout.flush()


def print_interfaces(interfaces: Dict[int, Interface]) -> None:
    for interface in sorted(interfaces.values(), key=lambda item: item.index):
        ipv4 = ",".join(interface.ipv4_addresses) if interface.ipv4_addresses else "-"
        ipv6 = "yes" if interface.has_ipv6 else "no"
        print("%d\t%s\tipv4=%s\tipv6=%s" % (interface.index, interface.name, ipv4, ipv6))


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Listen for mDNS packets on all interfaces and decode DNS records."
    )
    parser.add_argument(
        "-i",
        "--interface",
        action="append",
        dest="interfaces",
        help="interface to listen on; may be specified more than once",
    )
    parser.add_argument(
        "--family",
        choices=("all", "ipv4", "ipv6"),
        default="all",
        help="address family to listen on",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="stop after this many packets; default is unlimited",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        help="stop after this many seconds without requiring Ctrl-C",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit one JSON object per packet",
    )
    parser.add_argument(
        "--show-malformed",
        action="store_true",
        help="print malformed packets to stderr instead of silently skipping them",
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="list detected interfaces and exit",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=MDNS_PORT,
        help="UDP port to bind; default is 5353",
    )
    args = parser.parse_args(argv)

    if args.count < 0:
        parser.error("--count must be non-negative")
    if args.timeout is not None and args.timeout < 0:
        parser.error("--timeout must be non-negative")
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be in 1..65535")

    return args


def listen(args: argparse.Namespace) -> int:
    try:
        interfaces = discover_interfaces(args.interfaces)
    except InterfaceDiscoveryError as error:
        print(error, file=sys.stderr)
        return 1
    if args.interfaces:
        missing = sorted(set(args.interfaces) - set(item.name for item in interfaces.values()))
        if missing:
            print("unknown interface(s): %s" % ", ".join(missing), file=sys.stderr)
            return 2

    if args.list_interfaces:
        print_interfaces(interfaces)
        return 0

    errors = []
    sockets = []
    if args.family in ("all", "ipv4"):
        state = create_ipv4_socket(interfaces, args.port, errors)
        if state:
            sockets.append(state)
    if args.family in ("all", "ipv6"):
        state = create_ipv6_socket(interfaces, args.port, errors)
        if state:
            sockets.append(state)

    if not sockets:
        print("no mDNS sockets could be joined", file=sys.stderr)
        for error in errors:
            print(error, file=sys.stderr)
        return 1

    for error in errors:
        print(error, file=sys.stderr)
    if not args.json:
        joined = []
        for state in sockets:
            joined.extend("%s:%s" % (state.family_name, item) for item in state.joined_interfaces)
        print("listening on %s" % ", ".join(joined), file=sys.stderr)

    selector = selectors.DefaultSelector()
    for state in sockets:
        selector.register(state.sock, selectors.EVENT_READ, state)

    packets_seen = 0
    start = datetime.datetime.now()
    try:
        while True:
            if args.timeout is None:
                wait = None
            else:
                elapsed = (datetime.datetime.now() - start).total_seconds()
                wait = max(args.timeout - elapsed, 0.0)
                if wait == 0.0:
                    break

            events = selector.select(wait)
            if not events:
                break

            for key, _ in events:
                state = key.data
                try:
                    packet, ancdata, _, address = state.sock.recvmsg(65535, 256)
                except BlockingIOError:
                    continue

                ifindex = packet_interface_index(state.family, ancdata)
                interface = interfaces.get(ifindex).name if ifindex in interfaces else None
                host, port = split_source_address(address)
                event_time = datetime.datetime.now().isoformat(timespec="seconds")

                try:
                    message = parse_dns_message(packet)
                except DnsParseError as error:
                    if args.show_malformed:
                        where = interface or "ifindex:%s" % (ifindex if ifindex else "?")
                        print(
                            "%s %s %s malformed packet from %s:%d: %s" %
                            (event_time, where, state.family_name, host, port, error),
                            file=sys.stderr,
                        )
                    continue

                event = {
                    "time": event_time,
                    "family": state.family_name,
                    "interface": interface,
                    "interface_index": ifindex,
                    "source": {"address": host, "port": port},
                    "message": message,
                }

                if args.json:
                    print(json.dumps(event, sort_keys=True), flush=True)
                else:
                    print_human_packet(event)

                packets_seen += 1
                if args.count and packets_seen >= args.count:
                    return 0
    except KeyboardInterrupt:
        return 130
    finally:
        selector.close()
        for state in sockets:
            state.sock.close()

    return 0


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    return listen(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))


# python3 -m py_compile scripts/mdns_parser.py scripts/tests/test_mdns_parser.py
# python3 scripts/tests/test_mdns_parser.py
# python3 scripts/mdns_parser.py --help
# python3 scripts/mdns_parser.py --list-interfaces
# python3 scripts/mdns_parser.py --timeout 1 --count 1 --json
#!/usr/bin/env python3
#
# Minimal DHCPv4 client for a single interface. This is a diagnostic tool: it
# sends DHCP packets and prints replies, but does not configure host addresses.

import argparse
import binascii
import fcntl
import ipaddress
import json
import re
import secrets
import selectors
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ETH_P_IP = 0x0800
ETH_P_ALL = 0x0003
IPPROTO_UDP = 17

DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
BOOTP_FIXED_LEN = 236
DHCP_MIN_LEN = 300

BOOTREQUEST = 1
BOOTREPLY = 2
HTYPE_ETHERNET = 1
DHCP_BROADCAST_FLAG = 0x8000

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPACK = 5
DHCPNAK = 6

OPTION_PAD = 0
OPTION_SUBNET_MASK = 1
OPTION_ROUTER = 3
OPTION_DNS = 6
OPTION_HOSTNAME = 12
OPTION_DOMAIN_NAME = 15
OPTION_BROADCAST = 28
OPTION_REQUESTED_IP = 50
OPTION_LEASE_TIME = 51
OPTION_MESSAGE_TYPE = 53
OPTION_SERVER_ID = 54
OPTION_PARAMETER_REQUEST_LIST = 55
OPTION_MESSAGE_SIZE = 57
OPTION_RENEWAL_TIME = 58
OPTION_REBINDING_TIME = 59
OPTION_VENDOR_CLASS = 60
OPTION_CLIENT_ID = 61
OPTION_CLASSLESS_STATIC_ROUTE = 121
OPTION_END = 255

MESSAGE_TYPE_NAMES = {
    DHCPDISCOVER: "DHCPDISCOVER",
    DHCPOFFER: "DHCPOFFER",
    DHCPREQUEST: "DHCPREQUEST",
    DHCPACK: "DHCPACK",
    DHCPNAK: "DHCPNAK",
}

OPTION_NAMES = {
    OPTION_SUBNET_MASK: "subnet_mask",
    OPTION_ROUTER: "router",
    OPTION_DNS: "domain_name_server",
    OPTION_HOSTNAME: "host_name",
    OPTION_DOMAIN_NAME: "domain_name",
    OPTION_BROADCAST: "broadcast_address",
    OPTION_REQUESTED_IP: "requested_ip_address",
    OPTION_LEASE_TIME: "ip_address_lease_time",
    OPTION_MESSAGE_TYPE: "dhcp_message_type",
    OPTION_SERVER_ID: "server_identifier",
    OPTION_PARAMETER_REQUEST_LIST: "parameter_request_list",
    OPTION_MESSAGE_SIZE: "maximum_dhcp_message_size",
    OPTION_RENEWAL_TIME: "renewal_time_value",
    OPTION_REBINDING_TIME: "rebinding_time_value",
    OPTION_VENDOR_CLASS: "vendor_class_identifier",
    OPTION_CLIENT_ID: "client_identifier",
    OPTION_CLASSLESS_STATIC_ROUTE: "classless_static_route",
}

IP_OPTIONS = {
    OPTION_SUBNET_MASK,
    OPTION_BROADCAST,
    OPTION_REQUESTED_IP,
    OPTION_SERVER_ID,
}
IP_LIST_OPTIONS = {OPTION_ROUTER, OPTION_DNS}
UINT32_OPTIONS = {OPTION_LEASE_TIME, OPTION_RENEWAL_TIME, OPTION_REBINDING_TIME}
UINT16_OPTIONS = {OPTION_MESSAGE_SIZE}
TEXT_OPTIONS = {OPTION_HOSTNAME, OPTION_DOMAIN_NAME, OPTION_VENDOR_CLASS}

DEFAULT_PARAMETER_REQUEST_LIST = [
    OPTION_SUBNET_MASK,
    OPTION_ROUTER,
    OPTION_DNS,
    OPTION_DOMAIN_NAME,
    OPTION_BROADCAST,
    OPTION_LEASE_TIME,
    OPTION_SERVER_ID,
    OPTION_RENEWAL_TIME,
    OPTION_REBINDING_TIME,
    OPTION_CLASSLESS_STATIC_ROUTE,
]

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253}[A-Za-z0-9])?$")


class DhcpError(RuntimeError):
    pass


class DhcpParseError(ValueError):
    pass


@dataclass
class DhcpPacket:
    eth_src: bytes
    eth_dst: bytes
    ip_src: str
    ip_dst: str
    udp_src_port: int
    udp_dst_port: int
    op: int
    htype: int
    hlen: int
    hops: int
    xid: int
    secs: int
    flags: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    chaddr: bytes
    options: Dict[int, List[bytes]]

    def option(self, code: int) -> Optional[bytes]:
        values = self.options.get(code)
        return values[-1] if values else None

    @property
    def message_type_code(self) -> Optional[int]:
        raw_value = self.option(OPTION_MESSAGE_TYPE)
        if raw_value is None or len(raw_value) != 1:
            return None
        return raw_value[0]

    @property
    def message_type(self) -> str:
        code = self.message_type_code
        if code is None:
            return "UNKNOWN"
        return MESSAGE_TYPE_NAMES.get(code, "TYPE%d" % code)

    def option_ip(self, code: int) -> Optional[str]:
        raw_value = self.option(code)
        if raw_value is None or len(raw_value) != 4:
            return None
        return str(ipaddress.IPv4Address(raw_value))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ethernet": {"src": format_mac(self.eth_src), "dst": format_mac(self.eth_dst)},
            "ip": {"src": self.ip_src, "dst": self.ip_dst},
            "udp": {"src_port": self.udp_src_port, "dst_port": self.udp_dst_port},
            "bootp": {
                "op": self.op,
                "htype": self.htype,
                "hlen": self.hlen,
                "hops": self.hops,
                "xid": self.xid,
                "secs": self.secs,
                "flags": self.flags,
                "ciaddr": self.ciaddr,
                "yiaddr": self.yiaddr,
                "siaddr": self.siaddr,
                "giaddr": self.giaddr,
                "chaddr": format_mac(self.chaddr) if len(self.chaddr) == 6 else hex_bytes(self.chaddr),
            },
            "dhcp": {
                "message_type": self.message_type,
                "message_type_code": self.message_type_code,
                "options": options_to_dict(self.options),
            },
        }


def require_length(data: bytes, offset: int, length: int, context: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise DhcpParseError("%s exceeds packet length" % context)


def hex_bytes(data: bytes) -> str:
    return binascii.hexlify(data).decode("ascii")


def safe_text(data: bytes) -> str:
    chars = []
    for byte in data:
        if byte == 0x5C:
            chars.append("\\\\")
        elif 0x20 <= byte <= 0x7E:
            chars.append(chr(byte))
        else:
            chars.append("\\x%02x" % byte)
    return "".join(chars)


def parse_mac(value: str) -> bytes:
    if not MAC_RE.match(value):
        raise ValueError("invalid MAC address: %s" % value)
    return bytes(int(part, 16) for part in value.split(":"))


def format_mac(value: bytes) -> str:
    return ":".join("%02x" % byte for byte in value)


def ipv4_packed(value: str) -> bytes:
    return ipaddress.IPv4Address(value).packed


def validate_hostname(value: str) -> str:
    if len(value) > 255 or not HOSTNAME_RE.match(value):
        raise ValueError("hostname must contain only letters, digits, hyphen, and dot")
    return value


def validate_ascii_option_text(value: str, name: str) -> str:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("%s must be ASCII" % name)
    if len(encoded) > 255:
        raise ValueError("%s is longer than 255 bytes" % name)
    return value


def parse_xid(value: str) -> int:
    xid = int(value, 0)
    if xid < 0 or xid > 0xFFFFFFFF:
        raise ValueError("transaction ID must fit in 32 bits")
    return xid


def parse_option_codes(value: str) -> List[int]:
    codes = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        code = int(item, 0)
        if code < 1 or code > 254:
            raise ValueError("DHCP option codes must be in 1..254")
        codes.append(code)
    if not codes:
        raise ValueError("at least one option code is required")
    return codes


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) + data[offset + 1]
        total = (total & 0xFFFF) + (total >> 16)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def udp_checksum(src_ip: bytes, dst_ip: bytes, udp_header: bytes, payload: bytes) -> int:
    pseudo_header = struct.pack(
        "!4s4sBBH", src_ip, dst_ip, 0, IPPROTO_UDP, len(udp_header) + len(payload)
    )
    checksum = internet_checksum(pseudo_header + udp_header + payload)
    return checksum if checksum else 0xFFFF


def build_ipv4_header(src_ip: str, dst_ip: str, payload_len: int, packet_id: int) -> bytes:
    src = ipv4_packed(src_ip)
    dst = ipv4_packed(dst_ip)
    total_len = 20 + payload_len
    if total_len > 0xFFFF:
        raise DhcpError("IPv4 packet is too large")

    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, packet_id & 0xFFFF, 0,
                         64, IPPROTO_UDP, 0, src, dst)
    checksum = internet_checksum(header)
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, packet_id & 0xFFFF, 0,
                       64, IPPROTO_UDP, checksum, src, dst)


def build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     payload: bytes) -> bytes:
    udp_len = 8 + len(payload)
    if udp_len > 0xFFFF:
        raise DhcpError("UDP packet is too large")
    header = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)
    checksum = udp_checksum(ipv4_packed(src_ip), ipv4_packed(dst_ip), header, payload)
    return struct.pack("!HHHH", src_port, dst_port, udp_len, checksum) + payload


def encode_option(code: int, value: bytes) -> bytes:
    if code <= OPTION_PAD or code >= OPTION_END:
        raise ValueError("option code must be in 1..254")
    if len(value) > 255:
        raise ValueError("option %d is longer than 255 bytes" % code)
    return bytes([code, len(value)]) + value


def encode_options(options: Iterable[Tuple[int, bytes]]) -> bytes:
    encoded = bytearray()
    for code, value in options:
        encoded.extend(encode_option(code, value))
    encoded.append(OPTION_END)
    return bytes(encoded)


def build_bootp_payload(mac: bytes, xid: int, message_type: int,
                        options: Sequence[Tuple[int, bytes]]) -> bytes:
    if len(mac) != 6:
        raise ValueError("only Ethernet MAC addresses are supported")
    chaddr = mac + (b"\x00" * 10)
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        BOOTREQUEST,
        HTYPE_ETHERNET,
        len(mac),
        0,
        xid,
        0,
        DHCP_BROADCAST_FLAG,
        ipv4_packed("0.0.0.0"),
        ipv4_packed("0.0.0.0"),
        ipv4_packed("0.0.0.0"),
        ipv4_packed("0.0.0.0"),
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    all_options = [(OPTION_MESSAGE_TYPE, bytes([message_type]))] + list(options)
    payload = fixed + DHCP_MAGIC_COOKIE + encode_options(all_options)
    if len(payload) < DHCP_MIN_LEN:
        payload += b"\x00" * (DHCP_MIN_LEN - len(payload))
    return payload


def build_dhcp_frame(mac: bytes, xid: int, message_type: int,
                     hostname: Optional[str] = None,
                     requested_ip: Optional[str] = None,
                     server_id: Optional[str] = None,
                     parameter_request_list: Optional[Sequence[int]] = None,
                     vendor_class: Optional[str] = None) -> bytes:
    options: List[Tuple[int, bytes]] = [
        (OPTION_CLIENT_ID, bytes([HTYPE_ETHERNET]) + mac),
        (OPTION_MESSAGE_SIZE, struct.pack("!H", 1500)),
    ]
    if requested_ip:
        options.append((OPTION_REQUESTED_IP, ipv4_packed(requested_ip)))
    if server_id:
        options.append((OPTION_SERVER_ID, ipv4_packed(server_id)))
    if hostname:
        options.append((OPTION_HOSTNAME, validate_hostname(hostname).encode("ascii")))
    if vendor_class:
        options.append((OPTION_VENDOR_CLASS,
                        validate_ascii_option_text(vendor_class, "vendor class").encode("ascii")))

    requested_options = parameter_request_list or DEFAULT_PARAMETER_REQUEST_LIST
    options.append((OPTION_PARAMETER_REQUEST_LIST, bytes(requested_options)))

    payload = build_bootp_payload(mac, xid, message_type, options)
    src_ip = "0.0.0.0"
    dst_ip = "255.255.255.255"
    udp_packet = build_udp_packet(src_ip, dst_ip, DHCP_CLIENT_PORT, DHCP_SERVER_PORT, payload)
    ip_header = build_ipv4_header(src_ip, dst_ip, len(udp_packet), xid & 0xFFFF)
    eth_header = (b"\xff" * 6) + mac + struct.pack("!H", ETH_P_IP)
    return eth_header + ip_header + udp_packet


def build_discover_frame(mac: bytes, xid: int, hostname: Optional[str],
                         requested_ip: Optional[str],
                         parameter_request_list: Sequence[int],
                         vendor_class: Optional[str]) -> bytes:
    return build_dhcp_frame(
        mac=mac,
        xid=xid,
        message_type=DHCPDISCOVER,
        hostname=hostname,
        requested_ip=requested_ip,
        parameter_request_list=parameter_request_list,
        vendor_class=vendor_class,
    )


def build_request_frame(mac: bytes, xid: int, requested_ip: str,
                        server_id: Optional[str], hostname: Optional[str],
                        parameter_request_list: Sequence[int],
                        vendor_class: Optional[str]) -> bytes:
    return build_dhcp_frame(
        mac=mac,
        xid=xid,
        message_type=DHCPREQUEST,
        hostname=hostname,
        requested_ip=requested_ip,
        server_id=server_id,
        parameter_request_list=parameter_request_list,
        vendor_class=vendor_class,
    )


def parse_options(data: bytes) -> Dict[int, List[bytes]]:
    options: Dict[int, List[bytes]] = {}
    offset = 0
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == OPTION_PAD:
            continue
        if code == OPTION_END:
            break
        require_length(data, offset, 1, "DHCP option length")
        length = data[offset]
        offset += 1
        require_length(data, offset, length, "DHCP option %d" % code)
        options.setdefault(code, []).append(data[offset:offset + length])
        offset += length
    return options


def parse_option_value(code: int, value: bytes) -> Any:
    if code == OPTION_MESSAGE_TYPE:
        if len(value) != 1:
            return {"error": "invalid message type length", "hex": hex_bytes(value)}
        return MESSAGE_TYPE_NAMES.get(value[0], "TYPE%d" % value[0])
    if code in IP_OPTIONS:
        if len(value) != 4:
            return {"error": "invalid IPv4 option length", "hex": hex_bytes(value)}
        return str(ipaddress.IPv4Address(value))
    if code in IP_LIST_OPTIONS:
        if len(value) % 4:
            return {"error": "invalid IPv4 list option length", "hex": hex_bytes(value)}
        return [
            str(ipaddress.IPv4Address(value[offset:offset + 4]))
            for offset in range(0, len(value), 4)
        ]
    if code in UINT32_OPTIONS:
        if len(value) != 4:
            return {"error": "invalid uint32 option length", "hex": hex_bytes(value)}
        return struct.unpack("!I", value)[0]
    if code in UINT16_OPTIONS:
        if len(value) != 2:
            return {"error": "invalid uint16 option length", "hex": hex_bytes(value)}
        return struct.unpack("!H", value)[0]
    if code == OPTION_PARAMETER_REQUEST_LIST:
        return list(value)
    if code == OPTION_CLIENT_ID:
        return hex_bytes(value)
    if code in TEXT_OPTIONS:
        return safe_text(value)
    return {"length": len(value), "hex": hex_bytes(value)}


def options_to_dict(options: Dict[int, List[bytes]]) -> Dict[str, Any]:
    result = {}
    for code in sorted(options):
        name = OPTION_NAMES.get(code, "option_%d" % code)
        values = [parse_option_value(code, value) for value in options[code]]
        result[name] = values[0] if len(values) == 1 else values
    return result


def parse_dhcp_payload(payload: bytes, eth_src: bytes, eth_dst: bytes, ip_src: str,
                       ip_dst: str, udp_src_port: int,
                       udp_dst_port: int) -> DhcpPacket:
    require_length(payload, 0, BOOTP_FIXED_LEN + 4, "BOOTP/DHCP payload")
    (
        op,
        htype,
        hlen,
        hops,
        xid,
        secs,
        flags,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        chaddr,
        _sname,
        _file,
    ) = struct.unpack_from("!BBBBIHH4s4s4s4s16s64s128s", payload, 0)

    if payload[BOOTP_FIXED_LEN:BOOTP_FIXED_LEN + 4] != DHCP_MAGIC_COOKIE:
        raise DhcpParseError("missing DHCP magic cookie")
    if hlen > len(chaddr):
        raise DhcpParseError("hardware address length exceeds chaddr field")

    return DhcpPacket(
        eth_src=eth_src,
        eth_dst=eth_dst,
        ip_src=str(ipaddress.IPv4Address(ip_src)),
        ip_dst=str(ipaddress.IPv4Address(ip_dst)),
        udp_src_port=udp_src_port,
        udp_dst_port=udp_dst_port,
        op=op,
        htype=htype,
        hlen=hlen,
        hops=hops,
        xid=xid,
        secs=secs,
        flags=flags,
        ciaddr=str(ipaddress.IPv4Address(ciaddr)),
        yiaddr=str(ipaddress.IPv4Address(yiaddr)),
        siaddr=str(ipaddress.IPv4Address(siaddr)),
        giaddr=str(ipaddress.IPv4Address(giaddr)),
        chaddr=chaddr[:hlen],
        options=parse_options(payload[BOOTP_FIXED_LEN + 4:]),
    )


def parse_dhcp_frame(frame: bytes) -> DhcpPacket:
    require_length(frame, 0, 14, "Ethernet header")
    eth_dst = frame[0:6]
    eth_src = frame[6:12]
    eth_type = struct.unpack_from("!H", frame, 12)[0]
    if eth_type != ETH_P_IP:
        raise DhcpParseError("not an IPv4 Ethernet frame")

    ip_offset = 14
    require_length(frame, ip_offset, 20, "IPv4 header")
    version_ihl = frame[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4:
        raise DhcpParseError("not an IPv4 packet")
    if ihl < 20:
        raise DhcpParseError("invalid IPv4 header length")
    require_length(frame, ip_offset, ihl, "IPv4 header")

    total_length = struct.unpack_from("!H", frame, ip_offset + 2)[0]
    flags_fragment = struct.unpack_from("!H", frame, ip_offset + 6)[0]
    protocol = frame[ip_offset + 9]
    if protocol != IPPROTO_UDP:
        raise DhcpParseError("not a UDP packet")
    if total_length < ihl:
        raise DhcpParseError("IPv4 total length is shorter than header length")
    require_length(frame, ip_offset, total_length, "IPv4 packet")
    if flags_fragment & 0x3FFF:
        raise DhcpParseError("fragmented DHCP packets are not supported")

    ip_src = str(ipaddress.IPv4Address(frame[ip_offset + 12:ip_offset + 16]))
    ip_dst = str(ipaddress.IPv4Address(frame[ip_offset + 16:ip_offset + 20]))
    udp_offset = ip_offset + ihl
    require_length(frame, udp_offset, 8, "UDP header")
    udp_src_port, udp_dst_port, udp_len, _checksum = struct.unpack_from("!HHHH", frame, udp_offset)
    if udp_len < 8:
        raise DhcpParseError("invalid UDP length")
    require_length(frame, udp_offset, udp_len, "UDP packet")
    if udp_src_port not in (DHCP_SERVER_PORT, DHCP_CLIENT_PORT):
        raise DhcpParseError("not a DHCP UDP source port")
    if udp_dst_port not in (DHCP_SERVER_PORT, DHCP_CLIENT_PORT):
        raise DhcpParseError("not a DHCP UDP destination port")

    return parse_dhcp_payload(
        frame[udp_offset + 8:udp_offset + udp_len],
        eth_src=eth_src,
        eth_dst=eth_dst,
        ip_src=ip_src,
        ip_dst=ip_dst,
        udp_src_port=udp_src_port,
        udp_dst_port=udp_dst_port,
    )


def build_server_frame(server_mac: bytes, client_mac: bytes, xid: int,
                       message_type: int, yiaddr: str, server_ip: str,
                       options: Sequence[Tuple[int, bytes]]) -> bytes:
    chaddr = client_mac + (b"\x00" * 10)
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        BOOTREPLY,
        HTYPE_ETHERNET,
        len(client_mac),
        0,
        xid,
        0,
        DHCP_BROADCAST_FLAG,
        ipv4_packed("0.0.0.0"),
        ipv4_packed(yiaddr),
        ipv4_packed(server_ip),
        ipv4_packed("0.0.0.0"),
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    payload = fixed + DHCP_MAGIC_COOKIE + encode_options(
        [(OPTION_MESSAGE_TYPE, bytes([message_type]))] + list(options)
    )
    if len(payload) < DHCP_MIN_LEN:
        payload += b"\x00" * (DHCP_MIN_LEN - len(payload))

    udp_packet = build_udp_packet(server_ip, "255.255.255.255",
                                  DHCP_SERVER_PORT, DHCP_CLIENT_PORT, payload)
    ip_header = build_ipv4_header(server_ip, "255.255.255.255", len(udp_packet), xid & 0xFFFF)
    return (b"\xff" * 6) + server_mac + struct.pack("!H", ETH_P_IP) + ip_header + udp_packet


def interface_mac(interface: str) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("256s", interface.encode("utf-8")[:15])
        result = fcntl.ioctl(sock.fileno(), 0x8927, ifreq)  # SIOCGIFHWADDR
        return result[18:24]
    except OSError as error:
        raise DhcpError("could not read MAC for %s: %s" % (interface, error))
    finally:
        sock.close()


def raw_socket(interface: str) -> socket.socket:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError as error:
        raise DhcpError("raw socket requires root or CAP_NET_RAW: %s" % error)
    try:
        sock.bind((interface, 0))
    except OSError as error:
        sock.close()
        raise DhcpError("could not bind raw socket to %s: %s" % (interface, error))
    sock.setblocking(False)
    return sock


def packet_matches(packet: DhcpPacket, xid: int, mac: bytes, wanted_types: Iterable[int]) -> bool:
    wanted = wanted_types if isinstance(wanted_types, set) else set(wanted_types)
    return (
        packet.op == BOOTREPLY and
        packet.xid == xid and
        packet.chaddr == mac and
        packet.message_type_code in wanted
    )


def receive_matching(sock: socket.socket, xid: int, mac: bytes,
                     wanted_types: Iterable[int], timeout: float) -> Optional[DhcpPacket]:
    wanted = set(wanted_types)
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            events = selector.select(remaining)
            if not events:
                return None
            for _key, _mask in events:
                frame = sock.recv(65535)
                try:
                    packet = parse_dhcp_frame(frame)
                except DhcpParseError:
                    continue
                if packet_matches(packet, xid, mac, wanted):
                    return packet
    finally:
        selector.close()


def print_event(event: str, packet: Optional[DhcpPacket], json_output: bool,
                extra: Optional[Dict[str, Any]] = None) -> None:
    data: Dict[str, Any] = {"event": event}
    if packet is not None:
        data["packet"] = packet.to_dict()
    if extra:
        data.update(extra)

    if json_output:
        print(json.dumps(data, sort_keys=True), flush=True)
        return

    if packet is None:
        detail = ""
        if extra:
            detail = " " + " ".join("%s=%s" % (key, value) for key, value in extra.items())
        print("%s%s" % (event, detail), flush=True)
        return

    options = packet.to_dict()["dhcp"]["options"]
    server = options.get("server_identifier", packet.siaddr)
    lease = options.get("ip_address_lease_time")
    routers = options.get("router")
    dns_servers = options.get("domain_name_server")
    parts = [
        event,
        packet.message_type,
        "server=%s" % server,
        "yiaddr=%s" % packet.yiaddr,
        "xid=0x%08x" % packet.xid,
    ]
    if lease is not None:
        parts.append("lease=%ss" % lease)
    if routers:
        parts.append("router=%s" % ",".join(routers if isinstance(routers, list) else [routers]))
    if dns_servers:
        parts.append("dns=%s" % ",".join(
            dns_servers if isinstance(dns_servers, list) else [dns_servers]
        ))
    print(" ".join(parts), flush=True)


def run_client(args: argparse.Namespace) -> int:
    try:
        socket.if_nametoindex(args.interface)
    except OSError as error:
        print("unknown interface %s: %s" % (args.interface, error), file=sys.stderr)
        return 2

    try:
        mac = parse_mac(args.mac) if args.mac else interface_mac(args.interface)
        xid = parse_xid(args.xid) if args.xid else secrets.randbits(32)
        requested_ip = str(ipaddress.IPv4Address(args.requested_ip)) if args.requested_ip else None
        parameter_request_list = parse_option_codes(args.parameter_request_list)
        hostname = validate_hostname(args.hostname) if args.hostname else None
        vendor_class = validate_ascii_option_text(args.vendor_class, "vendor class") \
            if args.vendor_class else None
        sock = raw_socket(args.interface)
    except (DhcpError, ValueError, ipaddress.AddressValueError) as error:
        print(error, file=sys.stderr)
        return 2

    try:
        discover = build_discover_frame(
            mac=mac,
            xid=xid,
            hostname=hostname,
            requested_ip=requested_ip,
            parameter_request_list=parameter_request_list,
            vendor_class=vendor_class,
        )
        sock.send(discover)
        print_event(
            "sent_discover",
            None,
            args.json,
            {"interface": args.interface, "mac": format_mac(mac), "xid": "0x%08x" % xid},
        )

        offer = receive_matching(sock, xid, mac, [DHCPOFFER], args.timeout)
        if offer is None:
            print_event("timeout_waiting_for_offer", None, args.json, {"xid": "0x%08x" % xid})
            return 1
        print_event("received_offer", offer, args.json)

        if args.discover_only:
            return 0

        offered_ip = requested_ip or offer.yiaddr
        if offered_ip == "0.0.0.0":
            print("offer did not include a usable yiaddr", file=sys.stderr)
            return 1
        server_id = offer.option_ip(OPTION_SERVER_ID)
        if server_id is None and offer.siaddr != "0.0.0.0":
            server_id = offer.siaddr

        request = build_request_frame(
            mac=mac,
            xid=xid,
            requested_ip=offered_ip,
            server_id=server_id,
            hostname=hostname,
            parameter_request_list=parameter_request_list,
            vendor_class=vendor_class,
        )
        sock.send(request)
        print_event(
            "sent_request",
            None,
            args.json,
            {"requested_ip": offered_ip, "server_identifier": server_id or ""},
        )

        reply = receive_matching(sock, xid, mac, [DHCPACK, DHCPNAK], args.timeout)
        if reply is None:
            print_event("timeout_waiting_for_ack", None, args.json, {"xid": "0x%08x" % xid})
            return 1
        print_event("received_reply", reply, args.json)
        return 0 if reply.message_type_code == DHCPACK else 1
    finally:
        sock.close()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Minimal DHCPv4 client for one Linux interface. It sends DHCP packets "
            "and prints replies without configuring the interface."
        )
    )
    parser.add_argument("-i", "--interface", required=True, help="interface to send from")
    parser.add_argument("--discover-only", action="store_true",
                        help="stop after receiving the first DHCPOFFER")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="seconds to wait for each server response")
    parser.add_argument("--hostname", help="DHCP host-name option")
    parser.add_argument("--requested-ip", help="requested IPv4 address")
    parser.add_argument("--vendor-class", help="DHCP vendor-class-identifier option")
    parser.add_argument("--mac", help="override client MAC address; default is interface MAC")
    parser.add_argument("--xid", help="transaction ID, e.g. 0x12345678")
    parser.add_argument(
        "--parameter-request-list",
        default=",".join(str(code) for code in DEFAULT_PARAMETER_REQUEST_LIST),
        help="comma-separated DHCP option codes to request",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON events")
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        if args.hostname:
            validate_hostname(args.hostname)
        if args.requested_ip:
            ipaddress.IPv4Address(args.requested_ip)
        if args.vendor_class:
            validate_ascii_option_text(args.vendor_class, "vendor class")
        if args.mac:
            parse_mac(args.mac)
        if args.xid:
            parse_xid(args.xid)
        parse_option_codes(args.parameter_request_list)
    except (ValueError, UnicodeEncodeError, ipaddress.AddressValueError) as error:
        parser.error(str(error))

    return args


def main(argv: Sequence[str]) -> int:
    return run_client(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
# sudo ./scripts/dhcp4_client.py -i ens1f0
# sudo ./scripts/dhcp4_client.py -i ens1f0 --discover-only
# sudo ./scripts/dhcp4_client.py -i ens1f0 --json --timeout 3
# It binds a Linux raw socket to the exact -i/--interface, sends DHCPDISCOVER, optionally sends DHCPREQUEST after an offer, and prints the response. It does not configure the interface or install a lease.

# Verified:

# bash

# python3 -m py_compile scripts/dhcp4_client.py scripts/tests/test_dhcp4_client.py
# python3 scripts/tests/test_dhcp4_client.py
# python3 scripts/dhcp4_client.py --help
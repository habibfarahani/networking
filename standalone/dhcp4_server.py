#!/usr/bin/env python3
#
# Minimal DHCPv4 server for a single interface. This is a diagnostic tool: it
# sends DHCP replies from an explicit pool, but does not configure host state.

import argparse
import binascii
import fcntl
import ipaddress
import json
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

DHCP_SERVER_PORT = 67
DHCP_CLIENT_PORT = 68
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
DHCPDECLINE = 4
DHCPACK = 5
DHCPNAK = 6
DHCPRELEASE = 7

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
OPTION_MESSAGE = 56
OPTION_MESSAGE_SIZE = 57
OPTION_RENEWAL_TIME = 58
OPTION_REBINDING_TIME = 59
OPTION_CLIENT_ID = 61
OPTION_CLASSLESS_STATIC_ROUTE = 121
OPTION_END = 255

MESSAGE_TYPE_NAMES = {
    DHCPDISCOVER: "DHCPDISCOVER",
    DHCPOFFER: "DHCPOFFER",
    DHCPREQUEST: "DHCPREQUEST",
    DHCPDECLINE: "DHCPDECLINE",
    DHCPACK: "DHCPACK",
    DHCPNAK: "DHCPNAK",
    DHCPRELEASE: "DHCPRELEASE",
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
    OPTION_MESSAGE: "message",
    OPTION_MESSAGE_SIZE: "maximum_dhcp_message_size",
    OPTION_RENEWAL_TIME: "renewal_time_value",
    OPTION_REBINDING_TIME: "rebinding_time_value",
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
TEXT_OPTIONS = {OPTION_HOSTNAME, OPTION_DOMAIN_NAME, OPTION_MESSAGE}

BROADCAST_MAC = b"\xff" * 6
ZERO_IP = "0.0.0.0"
BROADCAST_IP = "255.255.255.255"


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

    @property
    def client_key(self) -> bytes:
        return self.option(OPTION_CLIENT_ID) or self.chaddr

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


@dataclass
class Lease:
    ip: int
    client_key: bytes
    mac: bytes
    expires_at: float
    hostname: Optional[str] = None


@dataclass
class ServerConfig:
    interface: str
    server_ip: str
    server_mac: bytes
    pool_start: int
    pool_end: int
    subnet_mask: str
    routers: List[str]
    dns_servers: List[str]
    domain_name: Optional[str]
    broadcast_address: Optional[str]
    lease_time: int


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


def format_mac(value: bytes) -> str:
    return ":".join("%02x" % byte for byte in value)


def ipv4_packed(value: str) -> bytes:
    return ipaddress.IPv4Address(value).packed


def ip_to_int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def int_to_ip(value: int) -> str:
    return str(ipaddress.IPv4Address(value))


def parse_ipv4_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    addresses = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        addresses.append(str(ipaddress.IPv4Address(item)))
    return addresses


def encode_ipv4_list(addresses: Sequence[str]) -> bytes:
    encoded = bytearray()
    for address in addresses:
        encoded.extend(ipv4_packed(address))
    if len(encoded) > 255:
        raise ValueError("IPv4 option list is longer than 255 bytes")
    return bytes(encoded)


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
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        packet_id & 0xFFFF,
        0,
        64,
        IPPROTO_UDP,
        0,
        src,
        dst,
    )
    checksum = internet_checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        packet_id & 0xFFFF,
        0,
        64,
        IPPROTO_UDP,
        checksum,
        src,
        dst,
    )


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
        raise ValueError("DHCP option code must be in 1..254")
    if len(value) > 255:
        raise ValueError("DHCP option %d is longer than 255 bytes" % code)
    return bytes([code, len(value)]) + value


def encode_options(options: Iterable[Tuple[int, bytes]]) -> bytes:
    encoded = bytearray()
    for code, value in options:
        encoded.extend(encode_option(code, value))
    encoded.append(OPTION_END)
    return bytes(encoded)


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


class LeasePool:
    def __init__(self, pool_start: int, pool_end: int, reserved_ips: Iterable[int]):
        if pool_start > pool_end:
            raise ValueError("pool start must be <= pool end")
        self.pool_start = pool_start
        self.pool_end = pool_end
        self.reserved_ips = set(reserved_ips)
        self.leases_by_key: Dict[bytes, Lease] = {}
        self.leases_by_ip: Dict[int, Lease] = {}

    def contains(self, ip_value: int) -> bool:
        return self.pool_start <= ip_value <= self.pool_end and ip_value not in self.reserved_ips

    def _expire_old(self, now: float) -> None:
        expired = [key for key, lease in self.leases_by_key.items() if lease.expires_at <= now]
        for key in expired:
            lease = self.leases_by_key.pop(key)
            self.leases_by_ip.pop(lease.ip, None)

    def _is_available(self, ip_value: int, client_key: bytes, now: float) -> bool:
        lease = self.leases_by_ip.get(ip_value)
        return lease is None or lease.expires_at <= now or lease.client_key == client_key

    def _set_lease(self, client_key: bytes, mac: bytes, ip_value: int,
                   lease_time: int, hostname: Optional[str], now: float) -> Lease:
        old_lease = self.leases_by_key.get(client_key)
        if old_lease:
            self.leases_by_ip.pop(old_lease.ip, None)
        lease = Lease(
            ip=ip_value,
            client_key=client_key,
            mac=mac,
            expires_at=now + lease_time,
            hostname=hostname,
        )
        self.leases_by_key[client_key] = lease
        self.leases_by_ip[ip_value] = lease
        return lease

    def offer(self, client_key: bytes, mac: bytes, requested_ip: Optional[str],
              lease_time: int, hostname: Optional[str], now: Optional[float] = None) -> Optional[Lease]:
        now = time.monotonic() if now is None else now
        self._expire_old(now)

        existing = self.leases_by_key.get(client_key)
        if existing and existing.expires_at > now:
            return existing

        if requested_ip:
            requested = ip_to_int(requested_ip)
            if self.contains(requested) and self._is_available(requested, client_key, now):
                return self._set_lease(client_key, mac, requested, lease_time, hostname, now)

        for ip_value in range(self.pool_start, self.pool_end + 1):
            if self.contains(ip_value) and self._is_available(ip_value, client_key, now):
                return self._set_lease(client_key, mac, ip_value, lease_time, hostname, now)
        return None

    def acknowledge(self, client_key: bytes, mac: bytes, requested_ip: Optional[str],
                    lease_time: int, hostname: Optional[str],
                    now: Optional[float] = None) -> Optional[Lease]:
        now = time.monotonic() if now is None else now
        self._expire_old(now)
        existing = self.leases_by_key.get(client_key)

        if requested_ip:
            requested = ip_to_int(requested_ip)
            if not self.contains(requested) or not self._is_available(requested, client_key, now):
                return None
            return self._set_lease(client_key, mac, requested, lease_time, hostname, now)

        if existing and existing.expires_at > now:
            return self._set_lease(client_key, mac, existing.ip, lease_time, hostname, now)
        return None

    def release(self, client_key: bytes) -> None:
        lease = self.leases_by_key.pop(client_key, None)
        if lease:
            self.leases_by_ip.pop(lease.ip, None)


def packet_hostname(packet: DhcpPacket) -> Optional[str]:
    raw_value = packet.option(OPTION_HOSTNAME)
    if raw_value is None:
        return None
    return safe_text(raw_value)[:255]


def reply_destination(packet: DhcpPacket) -> Tuple[bytes, str]:
    if packet.flags & DHCP_BROADCAST_FLAG or packet.ciaddr == ZERO_IP:
        return BROADCAST_MAC, BROADCAST_IP
    return packet.eth_src, packet.ciaddr


def base_reply_options(config: ServerConfig, message_type: int) -> List[Tuple[int, bytes]]:
    options = [
        (OPTION_MESSAGE_TYPE, bytes([message_type])),
        (OPTION_SERVER_ID, ipv4_packed(config.server_ip)),
    ]
    if message_type in (DHCPOFFER, DHCPACK):
        renewal = max(config.lease_time // 2, 1)
        rebinding = max((config.lease_time * 7) // 8, renewal)
        options.extend([
            (OPTION_LEASE_TIME, struct.pack("!I", config.lease_time)),
            (OPTION_RENEWAL_TIME, struct.pack("!I", renewal)),
            (OPTION_REBINDING_TIME, struct.pack("!I", rebinding)),
            (OPTION_SUBNET_MASK, ipv4_packed(config.subnet_mask)),
        ])
        if config.routers:
            options.append((OPTION_ROUTER, encode_ipv4_list(config.routers)))
        if config.dns_servers:
            options.append((OPTION_DNS, encode_ipv4_list(config.dns_servers)))
        if config.domain_name:
            domain = config.domain_name.encode("ascii")
            options.append((OPTION_DOMAIN_NAME, domain))
        if config.broadcast_address:
            options.append((OPTION_BROADCAST, ipv4_packed(config.broadcast_address)))
    return options


def build_reply_frame(config: ServerConfig, request: DhcpPacket, message_type: int,
                      yiaddr: str, extra_options: Sequence[Tuple[int, bytes]] = ()) -> bytes:
    dst_mac, dst_ip = reply_destination(request)
    chaddr = request.chaddr[:16] + (b"\x00" * max(0, 16 - len(request.chaddr[:16])))
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        BOOTREPLY,
        request.htype,
        request.hlen,
        0,
        request.xid,
        0,
        request.flags,
        ipv4_packed(ZERO_IP),
        ipv4_packed(yiaddr),
        ipv4_packed(config.server_ip),
        ipv4_packed(request.giaddr),
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    payload = fixed + DHCP_MAGIC_COOKIE + encode_options(
        base_reply_options(config, message_type) + list(extra_options)
    )
    if len(payload) < DHCP_MIN_LEN:
        payload += b"\x00" * (DHCP_MIN_LEN - len(payload))

    udp_packet = build_udp_packet(config.server_ip, dst_ip, DHCP_SERVER_PORT,
                                  DHCP_CLIENT_PORT, payload)
    ip_header = build_ipv4_header(config.server_ip, dst_ip, len(udp_packet), request.xid & 0xFFFF)
    eth_header = dst_mac + config.server_mac + struct.pack("!H", ETH_P_IP)
    return eth_header + ip_header + udp_packet


def build_nak_frame(config: ServerConfig, request: DhcpPacket, message: str) -> bytes:
    return build_reply_frame(
        config,
        request,
        DHCPNAK,
        ZERO_IP,
        [(OPTION_MESSAGE, message.encode("ascii", errors="replace")[:255])],
    )


def handle_dhcp_packet(config: ServerConfig, leases: LeasePool,
                       packet: DhcpPacket) -> Tuple[Optional[bytes], str, Optional[str]]:
    if packet.op != BOOTREQUEST or packet.htype != HTYPE_ETHERNET or packet.hlen != 6:
        return None, "ignored_unsupported_bootp", None
    if packet.udp_src_port != DHCP_CLIENT_PORT or packet.udp_dst_port != DHCP_SERVER_PORT:
        return None, "ignored_wrong_ports", None

    message_type = packet.message_type_code
    requested_ip = packet.option_ip(OPTION_REQUESTED_IP)
    server_id = packet.option_ip(OPTION_SERVER_ID)
    hostname = packet_hostname(packet)

    if message_type == DHCPDISCOVER:
        lease = leases.offer(packet.client_key, packet.chaddr, requested_ip,
                             config.lease_time, hostname)
        if not lease:
            return None, "no_free_lease", None
        offer_ip = int_to_ip(lease.ip)
        return build_reply_frame(config, packet, DHCPOFFER, offer_ip), "sent_offer", offer_ip

    if message_type == DHCPREQUEST:
        if server_id is not None and server_id != config.server_ip:
            return None, "ignored_request_for_other_server", None
        lease_ip = requested_ip if requested_ip else (packet.ciaddr if packet.ciaddr != ZERO_IP else None)
        lease = leases.acknowledge(packet.client_key, packet.chaddr, lease_ip,
                                   config.lease_time, hostname)
        if not lease:
            return build_nak_frame(config, packet, "requested address unavailable"), "sent_nak", lease_ip
        ack_ip = int_to_ip(lease.ip)
        return build_reply_frame(config, packet, DHCPACK, ack_ip), "sent_ack", ack_ip

    if message_type in (DHCPDECLINE, DHCPRELEASE):
        leases.release(packet.client_key)
        return None, "released_lease", None

    return None, "ignored_%s" % packet.message_type.lower(), None


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

    parts = [event]
    if packet is not None:
        parts.extend([
            packet.message_type,
            "client=%s" % format_mac(packet.chaddr),
            "xid=0x%08x" % packet.xid,
        ])
    if extra:
        parts.extend("%s=%s" % (key, value) for key, value in extra.items())
    print(" ".join(parts), flush=True)


def run_server(args: argparse.Namespace) -> int:
    try:
        socket.if_nametoindex(args.interface)
        server_mac = interface_mac(args.interface)
        config = ServerConfig(
            interface=args.interface,
            server_ip=str(ipaddress.IPv4Address(args.server_ip)),
            server_mac=server_mac,
            pool_start=ip_to_int(args.pool_start),
            pool_end=ip_to_int(args.pool_end),
            subnet_mask=str(ipaddress.IPv4Address(args.subnet_mask)),
            routers=parse_ipv4_list(args.router),
            dns_servers=parse_ipv4_list(args.dns),
            domain_name=args.domain_name,
            broadcast_address=str(ipaddress.IPv4Address(args.broadcast_address))
            if args.broadcast_address else None,
            lease_time=args.lease_time,
        )
        if not config.domain_name:
            config.domain_name = None
        leases = LeasePool(config.pool_start, config.pool_end, [ip_to_int(config.server_ip)])
        sock = raw_socket(args.interface)
    except (DhcpError, OSError, ValueError, ipaddress.AddressValueError) as error:
        print(error, file=sys.stderr)
        return 2

    replies_sent = 0
    deadline = time.monotonic() + args.timeout if args.timeout else None
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    print_event(
        "server_started",
        None,
        args.json,
        {
            "interface": config.interface,
            "server_ip": config.server_ip,
            "server_mac": format_mac(config.server_mac),
            "pool": "%s-%s" % (int_to_ip(config.pool_start), int_to_ip(config.pool_end)),
        },
    )

    try:
        while True:
            if args.count and replies_sent >= args.count:
                return 0
            if deadline is None:
                wait = None
            else:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    return 0
            events = selector.select(wait)
            if not events:
                return 0
            for _key, _mask in events:
                frame = sock.recv(65535)
                try:
                    packet = parse_dhcp_frame(frame)
                except DhcpParseError:
                    continue
                response, event, lease_ip = handle_dhcp_packet(config, leases, packet)
                extra = {"lease_ip": lease_ip} if lease_ip else None
                if response is not None:
                    sock.send(response)
                    replies_sent += 1
                print_event(event, packet, args.json, extra)
    except KeyboardInterrupt:
        return 130
    finally:
        selector.close()
        sock.close()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Minimal DHCPv4 server for one Linux interface. It answers "
            "DHCPDISCOVER and DHCPREQUEST from an explicit in-memory pool."
        )
    )
    parser.add_argument("-i", "--interface", required=True, help="interface to serve on")
    parser.add_argument("--server-ip", required=True, help="server IPv4 address / DHCP server id")
    parser.add_argument("--pool-start", required=True, help="first IPv4 address to lease")
    parser.add_argument("--pool-end", required=True, help="last IPv4 address to lease")
    parser.add_argument("--subnet-mask", required=True, help="subnet mask option")
    parser.add_argument("--router", help="comma-separated router option addresses")
    parser.add_argument("--dns", help="comma-separated DNS server option addresses")
    parser.add_argument("--domain-name", help="domain-name option")
    parser.add_argument("--broadcast-address", help="broadcast-address option")
    parser.add_argument("--lease-time", type=int, default=3600, help="lease time in seconds")
    parser.add_argument("--count", type=int, default=0, help="stop after this many replies")
    parser.add_argument("--timeout", type=float, default=0,
                        help="stop after this many seconds; default runs until Ctrl-C")
    parser.add_argument("--json", action="store_true", help="emit JSON events")
    args = parser.parse_args(argv)

    try:
        server_ip = ip_to_int(args.server_ip)
        pool_start = ip_to_int(args.pool_start)
        pool_end = ip_to_int(args.pool_end)
        ipaddress.IPv4Address(args.subnet_mask)
        parse_ipv4_list(args.router)
        parse_ipv4_list(args.dns)
        if args.broadcast_address:
            ipaddress.IPv4Address(args.broadcast_address)
        if args.domain_name:
            args.domain_name.encode("ascii")
            if len(args.domain_name) > 255:
                raise ValueError("domain name must be at most 255 bytes")
        if pool_start > pool_end:
            raise ValueError("--pool-start must be <= --pool-end")
        if pool_start <= server_ip <= pool_end and pool_start == pool_end:
            raise ValueError("pool only contains --server-ip")
        if args.lease_time <= 0:
            raise ValueError("--lease-time must be positive")
        if args.count < 0:
            raise ValueError("--count must be non-negative")
        if args.timeout < 0:
            raise ValueError("--timeout must be non-negative")
    except (ValueError, UnicodeEncodeError, ipaddress.AddressValueError) as error:
        parser.error(str(error))

    return args


def main(argv: Sequence[str]) -> int:
    return run_server(parse_args(argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))



# sudo ./scripts/dhcp4_server.py \
#   -i ens1f0 \
#   --server-ip 192.0.2.1 \
#   --pool-start 192.0.2.10 \
#   --pool-end 192.0.2.50 \
#   --subnet-mask 255.255.255.0 \
#   --router 192.0.2.1 \
#   --dns 192.0.2.53

#sudo python3 standalone/dhcp4_server.py -i enp1s0 --server-ip 192.0.2.1 --pool-start 192.0.2.10 --pool-end 192.0.2.50 --subnet-mask 255.255.255.0 --router 192.0.2.1 --dns 192.0.2.53

# It binds a Linux raw socket to the specified -i/--interface, handles DHCPDISCOVER -> DHCPOFFER and DHCPREQUEST -> DHCPACK/DHCPNAK, keeps leases in memory, and does not configure the host interface.

# Verified:

# bash

# python3 -m py_compile scripts/dhcp4_server.py scripts/tests/test_dhcp4_server.py
# python3 scripts/tests/test_dhcp4_server.py
# python3 scripts/dhcp4_server.py --help
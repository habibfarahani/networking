#!/usr/bin/env python3
"""Minimal DHCP client implemented with Scapy."""

from __future__ import annotations

import argparse
import random
import sys
from typing import Any

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, conf, get_if_hwaddr, sendp, sniff


def dhcp_options(pkt: Any) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and len(opt) == 2:
            key, value = opt
            options[key] = value
    return options


def normalize_message_type(value: Any) -> str | None:
    if isinstance(value, int):
        return {
            1: "discover",
            2: "offer",
            3: "request",
            5: "ack",
            6: "nak",
        }.get(value)
    if isinstance(value, bytes):
        return value.decode(errors="ignore").lower()
    if isinstance(value, str):
        return value.lower()
    return None


def build_discover(client_mac: str, xid: int, hostname: str | None) -> Any:
    options: list[Any] = [
        ("message-type", "discover"),
        ("param_req_list", [1, 3, 6, 15, 28, 51, 54]),
    ]
    if hostname:
        options.append(("hostname", hostname))
    options.append("end")

    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=xid, flags=0x8000)
        / DHCP(options=options)
    )


def build_request(
    client_mac: str,
    xid: int,
    requested_ip: str,
    server_id: str,
    hostname: str | None,
) -> Any:
    options: list[Any] = [
        ("message-type", "request"),
        ("requested_addr", requested_ip),
        ("server_id", server_id),
        ("param_req_list", [1, 3, 6, 15, 28, 51, 54]),
    ]
    if hostname:
        options.append(("hostname", hostname))
    options.append("end")

    return (
        Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes.fromhex(client_mac.replace(":", "")), xid=xid, flags=0x8000)
        / DHCP(options=options)
    )


def wait_for_reply(interface: str, xid: int, timeout: int, expected: set[str]) -> Any | None:
    def matcher(pkt: Any) -> bool:
        if DHCP not in pkt or BOOTP not in pkt:
            return False
        if pkt[BOOTP].xid != xid:
            return False
        message_type = normalize_message_type(dhcp_options(pkt).get("message-type"))
        return message_type in expected

    packets = sniff(
        iface=interface,
        filter="udp and (port 67 or port 68)",
        lfilter=matcher,
        count=1,
        timeout=timeout,
        store=True,
    )
    return packets[0] if packets else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal DHCP client using Scapy")
    parser.add_argument("--iface", required=True, help="Interface to use")
    parser.add_argument("--hostname", help="Optional DHCP hostname")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout in seconds per step")
    args = parser.parse_args()

    conf.checkIPaddr = False
    client_mac = get_if_hwaddr(args.iface)
    xid = random.randint(1, 0xFFFFFFFF)

    discover = build_discover(client_mac, xid, args.hostname)
    print(f"Sending DISCOVER on {args.iface} from {client_mac} xid=0x{xid:08x}")
    sendp(discover, iface=args.iface, verbose=False)

    offer = wait_for_reply(args.iface, xid, args.timeout, {"offer"})
    if offer is None:
        print("Timed out waiting for DHCPOFFER", file=sys.stderr)
        return 1

    offer_options = dhcp_options(offer)
    offered_ip = offer[BOOTP].yiaddr
    server_id = offer_options.get("server_id")
    print(f"Received OFFER ip={offered_ip} server={server_id}")

    if not offered_ip or not server_id:
        print("Offer missing yiaddr or server_id", file=sys.stderr)
        return 1

    request = build_request(client_mac, xid, offered_ip, server_id, args.hostname)
    print(f"Sending REQUEST for {offered_ip}")
    sendp(request, iface=args.iface, verbose=False)

    reply = wait_for_reply(args.iface, xid, args.timeout, {"ack", "nak"})
    if reply is None:
        print("Timed out waiting for DHCPACK/DHCPNAK", file=sys.stderr)
        return 1

    reply_options = dhcp_options(reply)
    message_type = normalize_message_type(reply_options.get("message-type"))
    if message_type == "nak":
        print("Received NAK from server", file=sys.stderr)
        return 2

    dns = reply_options.get("name_server")
    router = reply_options.get("router")
    subnet_mask = reply_options.get("subnet_mask")
    lease_time = reply_options.get("lease_time")

    print("Lease acquired")
    print(f"  ip={reply[BOOTP].yiaddr}")
    print(f"  subnet_mask={subnet_mask}")
    print(f"  router={router}")
    print(f"  dns={dns}")
    print(f"  lease_time={lease_time}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
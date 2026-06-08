#!/usr/bin/env python3
"""DHCP load generator for many simulated Scapy clients."""

from __future__ import annotations

import argparse
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, conf, sendp, sniff


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


def random_mac(rng: random.Random) -> str:
    first = (rng.randint(0, 255) | 0x02) & 0xFE
    rest = [rng.randint(0, 255) for _ in range(5)]
    return ":".join(f"{byte:02x}" for byte in [first, *rest])


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


def build_request(client_mac: str, xid: int, requested_ip: str, server_id: str, hostname: str | None) -> Any:
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


class ReplyCollector:
    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.cv = threading.Condition()
        self.replies: dict[tuple[int, str], Any] = {}
        self.running = True
        self.thread = threading.Thread(target=self._sniff, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        self.thread.join(timeout=1)

    def _sniff(self) -> None:
        def handle(pkt: Any) -> None:
            if DHCP not in pkt or BOOTP not in pkt:
                return
            options = dhcp_options(pkt)
            message_type = normalize_message_type(options.get("message-type"))
            if message_type not in {"offer", "ack", "nak"}:
                return
            key = (pkt[BOOTP].xid, message_type)
            with self.cv:
                self.replies[key] = pkt
                self.cv.notify_all()

        sniff(
            iface=self.interface,
            filter="udp and (port 67 or port 68)",
            prn=handle,
            stop_filter=lambda _pkt: not self.running,
            store=False,
        )

    def wait_for(self, xid: int, expected: str, timeout: float) -> Any | None:
        deadline = time.time() + timeout
        key = (xid, expected)
        with self.cv:
            while True:
                pkt = self.replies.pop(key, None)
                if pkt is not None:
                    return pkt
                remaining = deadline - time.time()
                if remaining <= 0:
                    return None
                self.cv.wait(timeout=remaining)


def run_client(
    interface: str,
    collector: ReplyCollector,
    client_index: int,
    client_mac: str,
    timeout: float,
    hostname_prefix: str | None,
) -> dict[str, Any]:
    xid = random.randint(1, 0xFFFFFFFF)
    hostname = f"{hostname_prefix}-{client_index:03d}" if hostname_prefix else None

    sendp(build_discover(client_mac, xid, hostname), iface=interface, verbose=False)
    offer = collector.wait_for(xid, "offer", timeout)
    if offer is None:
        return {"client": client_index, "mac": client_mac, "status": "offer-timeout"}

    offer_options = dhcp_options(offer)
    offered_ip = offer[BOOTP].yiaddr
    server_id = offer_options.get("server_id")
    if not offered_ip or not server_id:
        return {"client": client_index, "mac": client_mac, "status": "bad-offer"}

    sendp(build_request(client_mac, xid, offered_ip, server_id, hostname), iface=interface, verbose=False)
    ack = collector.wait_for(xid, "ack", timeout)
    if ack is not None:
        return {
            "client": client_index,
            "mac": client_mac,
            "status": "ok",
            "ip": ack[BOOTP].yiaddr,
        }

    nak = collector.wait_for(xid, "nak", 0.1)
    if nak is not None:
        return {"client": client_index, "mac": client_mac, "status": "nak"}

    return {"client": client_index, "mac": client_mac, "status": "ack-timeout"}


def main() -> int:
    parser = argparse.ArgumentParser(description="DHCP load generator using Scapy")
    parser.add_argument("--iface", required=True, help="Interface to use")
    parser.add_argument("--clients", type=int, default=300, help="Number of simulated clients")
    parser.add_argument("--concurrency", type=int, default=50, help="Number of concurrent clients")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout per DHCP step")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")
    parser.add_argument("--hostname-prefix", default="scapy-client", help="Hostname prefix")
    args = parser.parse_args()

    conf.checkIPaddr = False
    rng = random.Random(args.seed)
    macs: set[str] = set()
    while len(macs) < args.clients:
        macs.add(random_mac(rng))
    client_macs = list(macs)

    collector = ReplyCollector(args.iface)
    collector.start()
    time.sleep(0.2)

    results: list[dict[str, Any]] = []
    try:
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = [
                pool.submit(
                    run_client,
                    args.iface,
                    collector,
                    index + 1,
                    client_macs[index],
                    args.timeout,
                    args.hostname_prefix,
                )
                for index in range(args.clients)
            ]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                status = result["status"]
                if status == "ok":
                    print(f"client={result['client']:03d} mac={result['mac']} ip={result['ip']} status=ok")
                else:
                    print(f"client={result['client']:03d} mac={result['mac']} status={status}")
    finally:
        collector.stop()

    ok = sum(1 for item in results if item["status"] == "ok")
    failed = len(results) - ok
    print(f"summary clients={len(results)} success={ok} failed={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
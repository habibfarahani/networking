#!/usr/bin/env python3

import pathlib
import socket
import struct
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import dhcp4_server  # noqa: E402


CLIENT_MAC = bytes.fromhex("001122334455")
SERVER_MAC = bytes.fromhex("aabbccddeeff")
XID = 0x12345678


def client_frame(message_type, xid=XID, mac=CLIENT_MAC, requested_ip=None,
                 server_id=None, client_id=None):
    options = [(dhcp4_server.OPTION_MESSAGE_TYPE, bytes([message_type]))]
    if client_id:
        options.append((dhcp4_server.OPTION_CLIENT_ID, client_id))
    if requested_ip:
        options.append((dhcp4_server.OPTION_REQUESTED_IP, socket.inet_aton(requested_ip)))
    if server_id:
        options.append((dhcp4_server.OPTION_SERVER_ID, socket.inet_aton(server_id)))
    options.append((dhcp4_server.OPTION_HOSTNAME, b"test-host"))

    chaddr = mac + (b"\x00" * 10)
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        dhcp4_server.BOOTREQUEST,
        dhcp4_server.HTYPE_ETHERNET,
        len(mac),
        0,
        xid,
        0,
        dhcp4_server.DHCP_BROADCAST_FLAG,
        dhcp4_server.ipv4_packed("0.0.0.0"),
        dhcp4_server.ipv4_packed("0.0.0.0"),
        dhcp4_server.ipv4_packed("0.0.0.0"),
        dhcp4_server.ipv4_packed("0.0.0.0"),
        chaddr,
        b"\x00" * 64,
        b"\x00" * 128,
    )
    payload = fixed + dhcp4_server.DHCP_MAGIC_COOKIE + dhcp4_server.encode_options(options)
    if len(payload) < dhcp4_server.DHCP_MIN_LEN:
        payload += b"\x00" * (dhcp4_server.DHCP_MIN_LEN - len(payload))

    udp = dhcp4_server.build_udp_packet(
        "0.0.0.0",
        "255.255.255.255",
        dhcp4_server.DHCP_CLIENT_PORT,
        dhcp4_server.DHCP_SERVER_PORT,
        payload,
    )
    ip_header = dhcp4_server.build_ipv4_header("0.0.0.0", "255.255.255.255", len(udp), xid)
    return (b"\xff" * 6) + mac + struct.pack("!H", dhcp4_server.ETH_P_IP) + ip_header + udp


def config():
    return dhcp4_server.ServerConfig(
        interface="test0",
        server_ip="192.0.2.1",
        server_mac=SERVER_MAC,
        pool_start=dhcp4_server.ip_to_int("192.0.2.10"),
        pool_end=dhcp4_server.ip_to_int("192.0.2.12"),
        subnet_mask="255.255.255.0",
        routers=["192.0.2.1"],
        dns_servers=["192.0.2.53", "192.0.2.54"],
        domain_name="example.test",
        broadcast_address="192.0.2.255",
        lease_time=3600,
    )


class Dhcp4ServerTest(unittest.TestCase):
    def test_discover_gets_offer_for_requested_pool_address(self):
        cfg = config()
        leases = dhcp4_server.LeasePool(cfg.pool_start, cfg.pool_end, [dhcp4_server.ip_to_int(cfg.server_ip)])
        packet = dhcp4_server.parse_dhcp_frame(
            client_frame(dhcp4_server.DHCPDISCOVER, requested_ip="192.0.2.11")
        )

        response, event, lease_ip = dhcp4_server.handle_dhcp_packet(cfg, leases, packet)
        self.assertEqual("sent_offer", event)
        self.assertEqual("192.0.2.11", lease_ip)

        offer = dhcp4_server.parse_dhcp_frame(response)
        offer_options = offer.to_dict()["dhcp"]["options"]
        self.assertEqual(dhcp4_server.DHCPOFFER, offer.message_type_code)
        self.assertEqual("192.0.2.11", offer.yiaddr)
        self.assertEqual("192.0.2.1", offer.option_ip(dhcp4_server.OPTION_SERVER_ID))
        self.assertEqual(["192.0.2.53", "192.0.2.54"], offer_options["domain_name_server"])
        self.assertEqual("example.test", offer_options["domain_name"])

    def test_request_gets_ack(self):
        cfg = config()
        leases = dhcp4_server.LeasePool(cfg.pool_start, cfg.pool_end, [dhcp4_server.ip_to_int(cfg.server_ip)])
        request = dhcp4_server.parse_dhcp_frame(
            client_frame(
                dhcp4_server.DHCPREQUEST,
                requested_ip="192.0.2.10",
                server_id="192.0.2.1",
            )
        )

        response, event, lease_ip = dhcp4_server.handle_dhcp_packet(cfg, leases, request)

        self.assertEqual("sent_ack", event)
        self.assertEqual("192.0.2.10", lease_ip)
        ack = dhcp4_server.parse_dhcp_frame(response)
        self.assertEqual(dhcp4_server.DHCPACK, ack.message_type_code)
        self.assertEqual("192.0.2.10", ack.yiaddr)

    def test_request_for_other_server_is_ignored(self):
        cfg = config()
        leases = dhcp4_server.LeasePool(cfg.pool_start, cfg.pool_end, [])
        request = dhcp4_server.parse_dhcp_frame(
            client_frame(
                dhcp4_server.DHCPREQUEST,
                requested_ip="192.0.2.10",
                server_id="192.0.2.99",
            )
        )

        response, event, lease_ip = dhcp4_server.handle_dhcp_packet(cfg, leases, request)

        self.assertIsNone(response)
        self.assertEqual("ignored_request_for_other_server", event)
        self.assertIsNone(lease_ip)

    def test_unavailable_requested_address_gets_nak(self):
        cfg = config()
        leases = dhcp4_server.LeasePool(cfg.pool_start, cfg.pool_end, [])
        request = dhcp4_server.parse_dhcp_frame(
            client_frame(
                dhcp4_server.DHCPREQUEST,
                requested_ip="192.0.2.200",
                server_id="192.0.2.1",
            )
        )

        response, event, lease_ip = dhcp4_server.handle_dhcp_packet(cfg, leases, request)

        self.assertEqual("sent_nak", event)
        self.assertEqual("192.0.2.200", lease_ip)
        nak = dhcp4_server.parse_dhcp_frame(response)
        self.assertEqual(dhcp4_server.DHCPNAK, nak.message_type_code)
        self.assertEqual("0.0.0.0", nak.yiaddr)

    def test_malformed_option_length_is_rejected(self):
        with self.assertRaises(dhcp4_server.DhcpParseError):
            dhcp4_server.parse_options(b"\x35\x02\x01")

    def test_pool_skips_reserved_server_ip(self):
        leases = dhcp4_server.LeasePool(
            dhcp4_server.ip_to_int("192.0.2.1"),
            dhcp4_server.ip_to_int("192.0.2.2"),
            [dhcp4_server.ip_to_int("192.0.2.1")],
        )

        lease = leases.offer(b"client", CLIENT_MAC, None, 60, None, now=100.0)

        self.assertEqual("192.0.2.2", dhcp4_server.int_to_ip(lease.ip))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

import pathlib
import socket
import struct
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import dhcp4_client  # noqa: E402


CLIENT_MAC = bytes.fromhex("001122334455")
SERVER_MAC = bytes.fromhex("aabbccddeeff")
XID = 0x12345678


class Dhcp4ClientTest(unittest.TestCase):
    def test_build_and_parse_discover(self):
        frame = dhcp4_client.build_discover_frame(
            mac=CLIENT_MAC,
            xid=XID,
            hostname="test-host",
            requested_ip="192.0.2.10",
            parameter_request_list=[1, 3, 6],
            vendor_class="router-test",
        )

        packet = dhcp4_client.parse_dhcp_frame(frame)

        self.assertEqual(dhcp4_client.DHCPDISCOVER, packet.message_type_code)
        self.assertEqual(XID, packet.xid)
        self.assertEqual(CLIENT_MAC, packet.chaddr)
        self.assertEqual("0.0.0.0", packet.ip_src)
        self.assertEqual("255.255.255.255", packet.ip_dst)
        self.assertEqual("192.0.2.10", packet.option_ip(dhcp4_client.OPTION_REQUESTED_IP))
        self.assertEqual(b"\x01\x03\x06", packet.option(dhcp4_client.OPTION_PARAMETER_REQUEST_LIST))
        self.assertEqual(b"test-host", packet.option(dhcp4_client.OPTION_HOSTNAME))

    def test_build_and_parse_offer(self):
        frame = dhcp4_client.build_server_frame(
            server_mac=SERVER_MAC,
            client_mac=CLIENT_MAC,
            xid=XID,
            message_type=dhcp4_client.DHCPOFFER,
            yiaddr="192.0.2.20",
            server_ip="192.0.2.1",
            options=[
                (dhcp4_client.OPTION_SERVER_ID, socket.inet_aton("192.0.2.1")),
                (dhcp4_client.OPTION_LEASE_TIME, struct.pack("!I", 3600)),
                (dhcp4_client.OPTION_ROUTER, socket.inet_aton("192.0.2.1")),
                (
                    dhcp4_client.OPTION_DNS,
                    socket.inet_aton("192.0.2.53") + socket.inet_aton("192.0.2.54"),
                ),
            ],
        )

        packet = dhcp4_client.parse_dhcp_frame(frame)
        packet_dict = packet.to_dict()

        self.assertEqual(dhcp4_client.DHCPOFFER, packet.message_type_code)
        self.assertEqual("192.0.2.20", packet.yiaddr)
        self.assertEqual("192.0.2.1", packet.option_ip(dhcp4_client.OPTION_SERVER_ID))
        self.assertEqual(3600, packet_dict["dhcp"]["options"]["ip_address_lease_time"])
        self.assertEqual(
            ["192.0.2.53", "192.0.2.54"],
            packet_dict["dhcp"]["options"]["domain_name_server"],
        )

    def test_build_request_includes_server_identifier(self):
        frame = dhcp4_client.build_request_frame(
            mac=CLIENT_MAC,
            xid=XID,
            requested_ip="192.0.2.20",
            server_id="192.0.2.1",
            hostname=None,
            parameter_request_list=[1],
            vendor_class=None,
        )

        packet = dhcp4_client.parse_dhcp_frame(frame)

        self.assertEqual(dhcp4_client.DHCPREQUEST, packet.message_type_code)
        self.assertEqual("192.0.2.20", packet.option_ip(dhcp4_client.OPTION_REQUESTED_IP))
        self.assertEqual("192.0.2.1", packet.option_ip(dhcp4_client.OPTION_SERVER_ID))

    def test_malformed_option_length_is_rejected(self):
        with self.assertRaises(dhcp4_client.DhcpParseError):
            dhcp4_client.parse_options(b"\x35\x02\x01")

    def test_bad_mac_is_rejected(self):
        with self.assertRaises(ValueError):
            dhcp4_client.parse_mac("not-a-mac")

    def test_one_character_hostname_is_allowed(self):
        self.assertEqual("a", dhcp4_client.validate_hostname("a"))

    def test_non_ascii_vendor_class_is_rejected(self):
        with self.assertRaises(ValueError):
            dhcp4_client.validate_ascii_option_text("bad-value-\u2603", "vendor class")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3

import pathlib
import socket
import struct
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import mdns_parser  # noqa: E402


def dns_name(name):
    if name == ".":
        return b"\x00"
    encoded = bytearray()
    for label in name.rstrip(".").split("."):
        label_bytes = label.encode("ascii")
        encoded.append(len(label_bytes))
        encoded.extend(label_bytes)
    encoded.append(0)
    return bytes(encoded)


def header(flags=0, qd=0, an=0, ns=0, ar=0):
    return struct.pack("!HHHHHH", 0, flags, qd, an, ns, ar)


def rr(name, rrtype, rrclass, ttl, rdata):
    return (
        dns_name(name) +
        struct.pack("!HHIH", rrtype, rrclass, ttl, len(rdata)) +
        rdata
    )


class MdnsParserTest(unittest.TestCase):
    def test_question_and_compressed_a_answer(self):
        question = dns_name("host.local") + struct.pack("!HH", 1, 0x8001)
        answer = (
            b"\xc0\x0c" +
            struct.pack("!HHIH", 1, 0x8001, 120, 4) +
            socket.inet_aton("192.168.1.10")
        )
        packet = header(qd=1, an=1) + question + answer

        message = mdns_parser.parse_dns_message(packet)

        self.assertEqual("host.local", message["questions"][0]["name"])
        self.assertTrue(message["questions"][0]["unicast_response"])
        self.assertEqual("host.local", message["answers"][0]["name"])
        self.assertTrue(message["answers"][0]["cache_flush"])
        self.assertEqual("192.168.1.10", message["answers"][0]["rdata"]["address"])

    def test_srv_and_txt_rdata(self):
        ptr_data = dns_name("Printer._ipp._tcp.local")
        srv_data = struct.pack("!HHH", 0, 0, 631) + dns_name("printer.local")
        txt_data = b"\x0btxtvers=1.0\x06note=1"
        packet = (
            header(flags=0x8400, an=4) +
            rr("_services._dns-sd._udp.local", 12, 1, 4500, dns_name("_ipp._tcp.local")) +
            rr("_ipp._tcp.local", 12, 1, 4500, ptr_data) +
            rr("Printer._ipp._tcp.local", 33, 0x8001, 120, srv_data) +
            rr("Printer._ipp._tcp.local", 16, 0x8001, 120, txt_data)
        )

        message = mdns_parser.parse_dns_message(packet)

        self.assertTrue(message["flags"]["response"])
        self.assertEqual("_ipp._tcp.local", message["answers"][0]["rdata"]["name"])
        self.assertEqual(631, message["answers"][2]["rdata"]["port"])
        self.assertEqual("printer.local", message["answers"][2]["rdata"]["target"])
        self.assertEqual(["txtvers=1.0", "note=1"], message["answers"][3]["rdata"]["strings"])

    def test_nsec_bitmap(self):
        # NSEC bitmap window 0, length 4, bits for A(1), PTR(12), TXT(16), AAAA(28).
        bitmap = bytes([0, 4, 0x40, 0x08, 0x80, 0x08])
        packet = header(flags=0x8400, an=1) + rr(
            "host.local", 47, 1, 120, dns_name("host.local") + bitmap
        )

        message = mdns_parser.parse_dns_message(packet)

        self.assertEqual(["A", "PTR", "TXT", "AAAA"], message["answers"][0]["rdata"]["types"])

    def test_compression_pointer_loop_is_rejected(self):
        packet = header(flags=0x8400, an=1) + b"\xc0\x0c"

        with self.assertRaises(mdns_parser.DnsParseError):
            mdns_parser.parse_dns_message(packet)


if __name__ == "__main__":
    unittest.main()

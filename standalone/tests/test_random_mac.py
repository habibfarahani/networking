#!/usr/bin/env python3

import pathlib
import sys
import unittest


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import random_mac  # noqa: E402


class RandomMacTest(unittest.TestCase):
    def test_default_mac_is_local_unicast(self):
        mac = random_mac.generate_random_mac()

        self.assertEqual(6, len(mac))
        self.assertEqual(0, mac[0] & 0x01)
        self.assertEqual(0x02, mac[0] & 0x02)

    def test_prefix_is_preserved(self):
        mac = random_mac.generate_random_mac([0x02, 0x42, 0xAC])

        self.assertEqual([0x02, 0x42, 0xAC], mac[:3])
        self.assertEqual(6, len(mac))

    def test_parse_prefix_accepts_colon_or_dash(self):
        self.assertEqual([0x02, 0x42], random_mac.parse_prefix("02:42"))
        self.assertEqual([0x02, 0x42], random_mac.parse_prefix("02-42"))

    def test_parse_prefix_rejects_too_many_octets(self):
        with self.assertRaises(ValueError):
            random_mac.parse_prefix("02:42:ac:11:22:33:44")

    def test_format_mac(self):
        self.assertEqual("02:42:ac:11:22:33",
                         random_mac.format_mac([0x02, 0x42, 0xAC, 0x11, 0x22, 0x33]))
        self.assertEqual("02-42-ac-11-22-33",
                         random_mac.format_mac([0x02, 0x42, 0xAC, 0x11, 0x22, 0x33], "-"))


if __name__ == "__main__":
    unittest.main()

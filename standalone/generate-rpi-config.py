#!/usr/bin/env python3

import json
import socket
import subprocess
from pathlib import Path


EXPECTED_INTERFACES = ["eth0", "wlan0", "wlan1", "usb0", "eth1"]

RESPONSIBILITIES = {
    "eth0": "primary_lan_management",
    "wlan0": "wireless_uplink",
    "wlan1": "iot_or_guest_wireless_network",
    "usb0": "direct_usb_device_or_tethering",
    "eth1": "secondary_lan_or_sensor_network",
}


def run_ip_addr_scan():
    """
    Uses Linux iproute2 JSON output to scan network interfaces.
    Works on Raspberry Pi OS and most Linux distributions.
    """
    result = subprocess.run(
        ["ip", "-j", "addr", "show"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def extract_interface_info(raw_interfaces):
    scanned = {}

    for iface in raw_interfaces:
        name = iface.get("ifname")

        if not name or name == "lo":
            continue

        ip_addresses = []

        for addr in iface.get("addr_info", []):
            ip_addresses.append(
                {
                    "family": addr.get("family"),
                    "address": addr.get("local"),
                    "prefix_length": addr.get("prefixlen"),
                    "scope": addr.get("scope"),
                }
            )

        scanned[name] = {
            "name": name,
            "present": True,
            "state": iface.get("operstate"),
            "mac_address": iface.get("address"),
            "ip_addresses": ip_addresses,
            "responsibility": RESPONSIBILITIES.get(name, "unassigned"),
        }

    return scanned


def build_rpi_config():
    raw_interfaces = run_ip_addr_scan()
    scanned_interfaces = extract_interface_info(raw_interfaces)

    config_interfaces = []

    for name in EXPECTED_INTERFACES:
        if name in scanned_interfaces:
            config_interfaces.append(scanned_interfaces[name])
        else:
            config_interfaces.append(
                {
                    "name": name,
                    "present": False,
                    "state": "missing",
                    "mac_address": None,
                    "ip_addresses": [],
                    "responsibility": RESPONSIBILITIES.get(name, "unassigned"),
                }
            )

    return {
        "device_type": "raspberry_pi",
        "hostname": socket.gethostname(),
        "interface_count": len(config_interfaces),
        "network_interfaces": config_interfaces,
    }


def main():
    config = build_rpi_config()

    output_path = Path("rpi_network_config.json")
    output_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    print(json.dumps(config, indent=2))
    print(f"\nConfig written to: {output_path}")


if __name__ == "__main__":
    main()
# Run it on the Raspberry Pi:

# bash

# python3 generate_rpi_network_config.py
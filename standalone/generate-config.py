import json
import hashlib
from pathlib import Path


def generate_mac(device_id: str, interface_name: str) -> str:
    """
    Generates a deterministic locally administered MAC address.
    Replace with real hardware MACs if these are physical interfaces.
    """
    seed = f"{device_id}-{interface_name}".encode("utf-8")
    digest = hashlib.sha256(seed).digest()

    mac = [
        0x02,  # locally administered unicast MAC
        digest[0],
        digest[1],
        digest[2],
        digest[3],
        digest[4],
    ]

    return ":".join(f"{byte:02x}" for byte in mac)


def generate_rpi_config(device_id: str, hostname: str) -> dict:
    interfaces = [
        {
            "name": "eth0",
            "type": "ethernet",
            "ip_address": "192.168.10.10",
            "netmask": "255.255.255.0",
            "gateway": "192.168.10.1",
            "responsibility": "primary_lan_management",
        },
        {
            "name": "wlan0",
            "type": "wifi",
            "ip_address": "192.168.20.10",
            "netmask": "255.255.255.0",
            "gateway": "192.168.20.1",
            "responsibility": "wireless_uplink",
        },
        {
            "name": "usb0",
            "type": "usb_ethernet",
            "ip_address": "192.168.30.10",
            "netmask": "255.255.255.0",
            "gateway": None,
            "responsibility": "direct_device_control",
        },
        {
            "name": "eth1",
            "type": "ethernet",
            "ip_address": "192.168.40.10",
            "netmask": "255.255.255.0",
            "gateway": None,
            "responsibility": "sensor_network",
        },
        {
            "name": "wlan1",
            "type": "wifi",
            "ip_address": "192.168.50.10",
            "netmask": "255.255.255.0",
            "gateway": None,
            "responsibility": "iot_isolated_network",
        },
    ]

    for interface in interfaces:
        interface["mac_address"] = generate_mac(device_id, interface["name"])

    return {
        "device_id": device_id,
        "hostname": hostname,
        "device_type": "raspberry_pi",
        "network_interfaces": interfaces,
    }


if __name__ == "__main__":
    config = generate_rpi_config(
        device_id="rpi-001",
        hostname="rpi-edge-node-01",
    )

    output_file = Path("rpi_network_config.json")

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(json.dumps(config, indent=2))
    print(f"\nConfig written to {output_file}")
# Run it with:

# bash

# python3 generate_rpi_config.py
# It will print the config and write it to rpi_network_config.json.
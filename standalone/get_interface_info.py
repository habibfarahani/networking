#!/usr/bin/env python3
"""Get IP and MAC address of a network interface (Linux).

Usage: python3 standalone/get_interface_info.py eth0
"""
import argparse
import socket
import struct
import fcntl
import sys

SIOCGIFADDR = 0x8915
SIOCGIFHWADDR = 0x8927

def get_ip_address(ifname: str) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack('256s', ifname[:15].encode('utf-8'))
        res = fcntl.ioctl(s.fileno(), SIOCGIFADDR, packed)
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None

def get_mac_address(ifname: str) -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack('256s', ifname[:15].encode('utf-8'))
        res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, packed)
        mac_bytes = res[18:24]
        return ':'.join('%02x' % b for b in mac_bytes)
    except OSError:
        return None

def get_network_interfaces():
    interfaces = []

    for iface_path in Path("/sys/class/net").iterdir():
        name = iface_path.name

        if name == "lo":
            continue

        if name.startswith("docker"):
            continue

        interfaces.append(name)

    return interfaces

def main() -> None:
    parser = argparse.ArgumentParser(description='Get IP and MAC of interface')
    parser.add_argument('interface', help='interface name, e.g. eth0')
    args = parser.parse_args()

    ip = get_ip_address(args.interface)
    mac = get_mac_address(args.interface)

    if ip is None and mac is None:
        print(f'Interface {args.interface} not found or has no addresses', file=sys.stderr)
        sys.exit(2)

    if ip:
        print('IP:', ip)
    else:
        print('IP: <none>')

    if mac:
        print('MAC:', mac)
    else:
        print('MAC: <none>')

if __name__ == '__main__':
    main()

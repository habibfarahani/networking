#!/usr/bin/env python3

import socket
import psutil


def get_interfaces():
    result = {}

    for interface_name, addresses in psutil.net_if_addrs().items():
        ips = []
        mac = None

        for addr in addresses:
            if addr.family == socket.AF_INET:
                ips.append(addr.address)

            elif addr.family == socket.AF_INET6:
                ips.append(addr.address.split("%")[0])

            elif addr.family == psutil.AF_LINK:
                mac = addr.address

        result[interface_name] = {
            "ip_addresses": ips,
            "mac_address": mac,
        }

    return result


if __name__ == "__main__":
    for name, info in get_interfaces().items():
        print(f"Interface: {name}")
        print(f"  MAC: {info['mac_address']}")
        print(f"  IPs: {', '.join(info['ip_addresses']) or 'None'}")


# git status
|
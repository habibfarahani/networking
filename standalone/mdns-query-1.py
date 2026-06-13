import socket
import struct
import fcntl
import time
from pathlib import Path

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
SIOCGIFADDR = 0x8915


def get_iface_ip(iface: str) -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = fcntl.ioctl(
            sock.fileno(),
            SIOCGIFADDR,
            struct.pack("256s", iface[:15].encode()),
        )
        return socket.inet_ntoa(data[20:24])
    except OSError:
        return None
    finally:
        sock.close()


def get_interfaces():
    return [
        p.name
        for p in Path("/sys/class/net").iterdir()
        if p.name != "lo" and not p.name.startswith("docker")
    ]


def encode_dns_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    return b"".join(bytes([len(part)]) + part.encode() for part in parts) + b"\x00"


def build_mdns_query(name: str, qtype: int = 12) -> bytes:
    # qtype 12 = PTR, useful for service discovery.
    # Example: _http._tcp.local
    transaction_id = 0
    flags = 0
    qdcount = 1
    ancount = nscount = arcount = 0

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )

    qname = encode_dns_name(name)
    qclass = 1  # IN

    return header + qname + struct.pack("!HH", qtype, qclass)


def mdns_query_on_interface(iface: str, query_name: str, timeout: float = 2.0):
    iface_ip = get_iface_ip(iface)
    if not iface_ip:
        return []

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)

    try:
        # Bind to this interface's IP so the source interface is explicit.
        sock.bind((iface_ip, 0))

        # Force multicast packets out this interface.
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(iface_ip),
        )

        # Keep mDNS on local link only.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        packet = build_mdns_query(query_name)
        sock.sendto(packet, (MDNS_ADDR, MDNS_PORT))

        responses = []
        # deadline = time.time() + timeout

        # while time.time() < deadline:
        #     try:
        #         data, addr = sock.recvfrom(4096)
        #         responses.append((addr, data))
        #     except socket.timeout:
        #         break

        return responses
    finally:
        sock.close()


if __name__ == "__main__":
    # Common query: discover HTTP services on the local network.
    query = "_http._tcp.local"

    for iface in get_interfaces():
        print(f"Querying {query} on {iface}")

        responses = mdns_query_on_interface(iface, query)

        for addr, data in responses:
            print(f"  response from {addr[0]}:{addr[1]}, {len(data)} bytes")
# For common mDNS service discovery, use PTR queries like:

# python

# "_services._dns-sd._udp.local"
# "_http._tcp.local"
# "_ssh._tcp.local"
# "_ipp._tcp.local"
# This code is Linux-specific because it uses /sys/class/net and fcntl.ioctl to get interface IPs.





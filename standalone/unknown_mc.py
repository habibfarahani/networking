# python
import socket, struct, fcntl, random, time, sys

SIOCGIFHWADDR = 0x8927
SIOCGIFADDR = 0x8915

def get_if_mac(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname.encode()))
    return info[18:24]

def get_if_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', ifname.encode()))
    return socket.inet_ntoa(info[20:24])

def ip_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def build_ip_header(src_ip, dst_ip, payload_len, proto=17):
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + payload_len
    ident = random.randint(0, 0xffff)
    flags_frag = 0
    ttl = 64
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    chksum = ip_checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         ver_ihl, tos, total_len, ident, flags_frag,
                         ttl, proto, chksum,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    return header

def build_udp(src_port, dst_port, payload, src_ip, dst_ip):
    udp_len = 8 + len(payload)
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack('!BBH', 0, 17, udp_len)
    udp_header = struct.pack('!HHH H', src_port, dst_port, udp_len, 0)  # checksum 0 for simplicity
    # UDP checksum optional here (set to 0)
    return udp_header + payload

def multicast_mac_from_ip(ip):
    a,b,c,d = map(int, ip.split('.'))
    ip_int = (a<<24)|(b<<16)|(c<<8)|d
    lower23 = ip_int & 0x7fffff
    third = (lower23 >> 16) & 0x7f
    fourth = (lower23 >> 8) & 0xff
    fifth = lower23 & 0xff
    return bytes([0x01, 0x00, 0x5e, third, fourth, fifth])

def random_multicast_ip():
    return '.'.join([str(random.randint(224,239)),
                     str(random.randint(0,255)),
                     str(random.randint(0,255)),
                     str(random.randint(1,254))])

def send_multicast_frames(ifname='eth0', count=10, interval=0.5):
    src_mac = get_if_mac(ifname)
    src_ip = get_if_ip(ifname)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((ifname, 0))
    for i in range(count):
        dst_ip = random_multicast_ip()
        dst_mac = multicast_mac_from_ip(dst_ip)
        payload = b'unknown-mcast-pkt-%d' % i
        udp = build_udp(random.randint(1024,65535), random.randint(1024,65535), payload, src_ip, dst_ip)
        ip = build_ip_header(src_ip, dst_ip, len(udp))
        ethertype = struct.pack('!H', 0x0800)
        frame = dst_mac + src_mac + ethertype + ip + udp
        s.send(frame)
        time.sleep(interval)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Run as root (sudo)."); sys.exit(1)
    send_multicast_frames('eth0', count=20, interval=0.2)
#!/usr/bin/env python3
from scapy.all import (
    Packet,
    ByteField,
    ShortField,
    XShortField,
    LongField,
    StrFixedLenField,
    Ether,
    LLC,
    bind_layers,
    hexdump,
)

STP_MULTICAST = "01:80:c2:00:00:00"


class BPDU(Packet):
    name = "BPDU"

    fields_desc = [
        XShortField("protocol_id", 0x0000),
        ByteField("version_id", 0x00),     # 0 = STP, 2 = RSTP
        ByteField("bpdu_type", 0x00),      # 0x00 = config, 0x80 = TCN, 0x02 = RSTP
        ByteField("flags", 0x00),

        ShortField("root_priority", 32768),
        StrFixedLenField("root_mac", b"\x38\x84\x79\x00\xea\xbc", length=6),

        LongField("root_path_cost", 0),

        ShortField("bridge_priority", 32768),
        StrFixedLenField("bridge_mac", b"\x66\x77\x88\x99\xaa\xbb", length=6),

        ShortField("port_id", 0x8001),

        ShortField("message_age", 0x0000),
        ShortField("max_age", 0x1400),         # 20 sec in 1/256 sec units
        ShortField("hello_time", 0x0200),      # 2 sec
        ShortField("forward_delay", 0x0f00),   # 15 sec
    ]

    def extract_padding(self, s):
        return b"", s


bind_layers(Ether, LLC, dst=STP_MULTICAST)
bind_layers(LLC, BPDU, dsap=0x42, ssap=0x42, ctrl=0x03)


def build_stp_bpdu():
    return (
        Ether(dst=STP_MULTICAST)
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / BPDU(
            protocol_id=0x0000,
            version_id=0x00,
            bpdu_type=0x00,
            flags=0x00,
            root_priority=32768,
            root_mac=b"\x38\x84\x79\x00\xea\xbc",
            root_path_cost=0,
            bridge_priority=32768,
            bridge_mac=b"\x66\x77\x88\x99\xaa\xbb",
            port_id=0x8001,
        )
    )

from scapy.all import sendp, send

if __name__ == "__main__":
    pkt = build_stp_bpdu()

    pkt.show()
    hexdump(pkt)

    for _ in range(0,100):
        sendp(pkt, iface="eth0", verbose=True)

    pkt.show()
    hexdump(pkt)


# 11:15:07.309375 STP 802.1w, Rapid STP, Flags [Learn, Forward], bridge-id 8000.38:84:79:00:ea:bc.801a, length 36
#         message-age 0.00s, max-age 20.00s, hello-time 2.00s, forwarding-delay 15.00s
#         root-id 8000.38:84:79:00:ea:bc, root-pathcost 0, port-role Designated
#         0x0000:  0180 c200 0000 3884 7900 ead6 0027 4242  ......8.y....'BB
#         0x0010:  0300 0002 023c 8000 3884 7900 eabc 0000  .....<..8.y.....
#         0x0020:  0000 8000 3884 7900 eabc 801a 0000 1400  ....8.y.........
#         0x0030:  0200 0f00 0000 0000 0000 0000            ............
# 11:15:09.309792 STP 802.1w, Rapid STP, Flags [Learn, Forward], bridge-id 8000.38:84:79:00:ea:bc.801a, length 36
#         message-age 0.00s, max-age 20.00s, hello-time 2.00s, forwarding-delay 15.00s
#         root-id 8000.38:84:79:00:ea:bc, root-pathcost 0, port-role Designated
#         0x0000:  0180 c200 0000 3884 7900 ead6 0027 4242  ......8.y....'BB
#         0x0010:  0300 0002 023c 8000 3884 7900 eabc 0000  .....<..8.y.....
#         0x0020:  0000 8000 3884 7900 eabc 801a 0000 1400  ....8.y.........
#         0x0030:  0200 0f00 0000 0000 0000 0000            ............
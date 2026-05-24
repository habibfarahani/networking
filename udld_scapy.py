#!/usr/bin/env python3
from scapy.all import (
    Packet,
    ByteField,
    ShortField,
    XByteField,
    XShortField,
    StrLenField,
    FieldLenField,
    PacketListField,
    bind_layers,
    Ether,
    LLC,
    SNAP,
    hexdump,
)

UDLD_MULTICAST = "01:00:0c:cc:cc:cc"


class UDLDTLV(Packet):
    name = "UDLD TLV"

    fields_desc = [
        ShortField("type", 0x0000),
        FieldLenField("length", None, length_of="value", fmt="!H", adjust=lambda pkt, x: x + 4),
        StrLenField("value", b"", length_from=lambda pkt: pkt.length - 4),
    ]

    def extract_padding(self, s):
        return b"", s


class UDLD(Packet):
    name = "UDLD"

    fields_desc = [
        XByteField("version_opcode", 0x11),  # Version 1, Opcode 1
        ByteField("flags", 0x00),
        XShortField("checksum", 0x0000),
        PacketListField("tlvs", [], UDLDTLV, length_from=lambda pkt: None),
    ]

    def extract_padding(self, s):
        return b"", s


# UDLD is usually Ethernet -> LLC -> SNAP -> UDLD
bind_layers(Ether, LLC, dst=UDLD_MULTICAST)
bind_layers(LLC, SNAP, dsap=0xAA, ssap=0xAA, ctrl=0x03)
bind_layers(SNAP, UDLD, OUI=0x00000C, code=0x0111)


def build_udld_packet():
    pkt = (
        Ether(dst=UDLD_MULTICAST)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=0x00000C, code=0x0111)
        / UDLD(
            version_opcode=0x11,
            flags=0x00,
            checksum=0x0000,
            tlvs=[
                UDLDTLV(type=0x0002, value=b"26"),
                UDLDTLV(type=0x0003, value=b"00"),
            ],
        )
    )

    return pkt

from scapy.all import sendp, send

if __name__ == "__main__":
    pkt = build_udld_packet()

    # pkt.show()
    # hexdump(pkt)

    # To send:
    for _ in range(0,100):
        sendp(pkt, iface="eth0", verbose=True)

    pkt.show()
    hexdump(pkt)




        # Checksum 0x1da4 (unverified)
        # Device-ID TLV (0x0001) TLV, length 16, 38847900EABC
        # Port-ID TLV (0x0002) TLV, length 6, 26
        # Echo TLV (0x0003) TLV, length 8, ^@^@^@^@
        # Message Interval TLV (0x0004) TLV, length 5, 7s
        # Device Name TLV (0x0006) TLV, length 16, 38847900EABC
        # 0x0000:  2101 1da4 0001 0010 3338 3834 3739 3030  !.......38847900
        # 0x0010:  4541 4243 0002 0006 3236 0003 0008 0000  EABC....26......
        # 0x0020:  0000 0004 0005 0700 0600 1033 3838 3437  ...........38847
        # 0x0030:  3930 3045 4142 43                        900EABC

        # Checksum 0x1da4 (unverified)
        # Device-ID TLV (0x0001) TLV, length 16, 38847900EABC
        # Port-ID TLV (0x0002) TLV, length 6, 26
        # Echo TLV (0x0003) TLV, length 8, ^@^@^@^@
        # Message Interval TLV (0x0004) TLV, length 5, 7s
        # Device Name TLV (0x0006) TLV, length 16, 38847900EABC
        # 0x0000:  0100 0ccc cccc 3884 7900 ead6 003f aaaa  ......8.y....?..
        # 0x0010:  0300 000c 0111 2101 1da4 0001 0010 3338  ......!.......38
        # 0x0020:  3834 3739 3030 4541 4243 0002 0006 3236  847900EABC....26
        # 0x0030:  0003 0008 0000 0000 0004 0005 0700 0600  ................
        # 0x0040:  1033 3838 3437 3930 3045 4142 43         .38847900EABC        
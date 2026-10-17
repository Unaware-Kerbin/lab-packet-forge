"""Additional routing / multicast / PCE / telemetry control-plane protocols."""
from __future__ import annotations

import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

try:
    from scapy.contrib.ldp import LDP
except Exception:
    LDP = None  # type: ignore

try:
    from scapy.contrib.pim import PIMv2Hello, PIMv2JoinPrune
except Exception:
    PIMv2Hello = PIMv2JoinPrune = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "ldp",
    "rsvp_te",
    "msdp",
    "bmp",
    "pcep",
    "babel",
    "eigrp_update",
    "isis_lsp",
    "isis_csnp",
    "ospf_lsa",
    "bgp_notification",
    "bgp_update",
    "pim_join",
    "pim_register",
    "igmpv3",
    "mldv2",
    "dvmrp",
)


def _e(c, dst_mac="01:00:5e:00:00:02"):
    return Ether(dst=cfg(c, "dst_mac", dst_mac), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


register(
    ProtocolEntry(
        id="ldp",
        name="LDP Hello",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("01:00:5e:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", False, "224.0.0.2", advanced=True),
            field("router_id", "LSR ID", "ip", True, "1.1.1.1"),
            field("label_space", "Label space", "int", False, 0, advanced=True),
        ],
        build=lambda c: (
            (_e(c) / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip", "224.0.0.2"), ttl=1) / UDP(sport=646, dport=646) / LDP())
            if LDP is not None
            else (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip", "224.0.0.2"), ttl=1)
                / UDP(sport=646, dport=646)
                / Raw(
                    struct.pack("!HHI", 1, 14, 0)  # version, pdu len, lsr id placeholder
                    + __import__("ipaddress").IPv4Address(cfg(c, "router_id", "1.1.1.1")).packed
                    + struct.pack("!H", int(cfg(c, "label_space", 0)))
                    + struct.pack("!HHI", 0x0100, 4, 15)  # Common Hello params
                )
            )
        ),
        template=TemplateMeta(
            "LDP Hello (UDP/646)",
            "MPLS label distribution labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="rsvp_te",
        name="RSVP-TE Path",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (tunnel sender)", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (egress)", "ip", True, "10.0.0.2"),
            field("tunnel_id", "Tunnel ID", "int", True, 1),
            field("lsp_id", "LSP ID", "int", True, 1),
            field("label", "Suggested label", "int", False, 100, advanced=True),
        ],
        build=lambda c: _e(c, "02:00:00:00:00:02")
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=46, tos=0xC0)
        / Raw(
            bytes([1, 1, 0x0F, 0x01, 0, 32, 0, 0])
            + __import__("ipaddress").IPv4Address(cfg(c, "dst_ip")).packed
            + struct.pack("!H", int(cfg(c, "tunnel_id", 1)))
            + __import__("ipaddress").IPv4Address(cfg(c, "src_ip")).packed
            + struct.pack("!HI", int(cfg(c, "lsp_id", 1)), int(cfg(c, "label", 100)))
        ),
        template=TemplateMeta(
            "RSVP-TE Path skeleton with tunnel IDs",
            "MPLS-TE labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="msdp",
        name="MSDP SA",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (peer)", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (peer)", "ip", True, "10.0.0.2"),
            field("rp", "RP address", "ip", True, "10.0.0.10"),
            field("group", "Group", "ip", True, "239.1.1.1"),
            field("source", "Source", "ip", True, "10.1.1.1"),
        ],
        build=lambda c: _e(c, "02:00:00:00:00:02")
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=639, dport=639, flags="PA", seq=1, ack=1)
        / Raw(
            bytes([1, 0, 0, 20])  # SA type, length
            + __import__("ipaddress").IPv4Address(cfg(c, "rp")).packed
            + b"\x01"
            + __import__("ipaddress").IPv4Address(cfg(c, "group")).packed
            + __import__("ipaddress").IPv4Address(cfg(c, "source")).packed
        ),
        template=TemplateMeta(
            "MSDP Source-Active over TCP/639",
            "Inter-domain multicast labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


def _bmp_build(c):
    name = str(cfg(c, "sys_name", "forge-rr")).encode()
    info = struct.pack("!HH", 2, len(name)) + name  # type 2 = sysName
    total = 6 + len(info)
    body = struct.pack("!BIB", 3, total, 4) + info
    return (
        _e(c, "02:00:00:00:00:02")
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 11019)), flags="PA", seq=1, ack=1)
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="bmp",
        name="BMP Initiation",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (router)", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (collector)", "ip", True, "10.0.0.2"),
            field("dport", "BMP port", "int", True, 11019),
            field("sys_name", "SysName TLV", "text", False, "forge-rr", advanced=True),
        ],
        build=_bmp_build,
        template=TemplateMeta(
            "BMP Initiation-shaped TCP",
            "BGP monitoring protocol labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="pcep",
        name="PCEP Open",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (PCC)", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (PCE)", "ip", True, "10.0.0.2"),
            field("keepalive", "Keepalive (s)", "int", False, 30, advanced=True),
            field("deadtimer", "Deadtimer (s)", "int", False, 120, advanced=True),
            field("sid", "Session ID", "int", False, 1, advanced=True),
        ],
        build=lambda c: _e(c, "02:00:00:00:00:02")
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=4189, dport=4189, flags="PA", seq=1, ack=1)
        / Raw(
            # Common hdr: ver/flags, type=1 Open, length
            bytes([0x20, 1])
            + struct.pack("!H", 12)
            + bytes(
                [
                    1,  # Open object class-ish simplified
                    int(cfg(c, "keepalive", 30)) & 0xFF,
                    int(cfg(c, "deadtimer", 120)) & 0xFF,
                    int(cfg(c, "sid", 1)) & 0xFF,
                ]
            )
            + b"\x00" * 4
        ),
        template=TemplateMeta(
            "PCEP Open-shaped TCP/4189",
            "Path computation element labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="babel",
        name="Babel",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("01:00:5e:00:00:6f", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("router_id_hex", "Router ID (8B hex)", "hex", False, "0102030405060708", advanced=True),
        ],
        build=lambda c: _e(c, "01:00:5e:00:00:6f")
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.111", ttl=1)
        / UDP(sport=6696, dport=6696)
        / Raw(bytes([42, 0, 0, 8]) + hex_bytes(cfg(c, "router_id_hex", "0102030405060708"))),
        template=TemplateMeta(
            "Babel Hello-shaped (UDP/6696)",
            "Mesh / wireless routing labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="eigrp_update",
        name="EIGRP Update",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("as_number", "AS", "int", True, 100),
            field("prefix", "Prefix", "ip", True, "192.168.10.0"),
            field("prefixlen", "Prefix length", "int", True, 24, min=0, max=32),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:0a", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.10", proto=88, ttl=2)
        / Raw(
            struct.pack("!BBHII", 2, 1, int(cfg(c, "as_number", 100)), 0, 0)  # ver, opcode=Update, AS
            + bytes([0x01, 0x01, 0x00, 0x18])  # TLVs-ish
            + __import__("ipaddress").IPv4Address(cfg(c, "prefix")).packed
            + bytes([int(cfg(c, "prefixlen", 24))])
        ),
        template=TemplateMeta(
            "EIGRP Update with IPv4 internal route TLV-shaped body",
            "EIGRP adjacency / redistribution labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="isis_lsp",
        name="IS-IS LSP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("level", "Level", "select", True, "l1", options=[{"value": "l1", "label": "L1"}, {"value": "l2", "label": "L2"}]),
            field("lsp_id_hex", "LSP ID (8B hex)", "hex", False, "0100" + "010203040506", advanced=True),
            field("seq", "Sequence", "int", False, 1, advanced=True),
        ],
        build=lambda c: Ether(
            dst="01:80:c2:00:00:14" if str(cfg(c, "level")) == "l1" else "01:80:c2:00:00:15",
            src=cfg(c, "src_mac"),
            type=0x22F4,
        )
        / Raw(
            bytes([0x83, 18 if str(cfg(c, "level")) == "l1" else 20, 1, 0])  # IDRP, PDU type LSP, version, reserved
            + struct.pack("!H", 27)
            + hex_bytes(cfg(c, "lsp_id_hex", "0100010203040506"))[:8].ljust(8, b"\x00")
            + struct.pack("!I", int(cfg(c, "seq", 1)))
            + b"\x00\x00"
        ),
        template=TemplateMeta(
            "IS-IS LSP skeleton",
            "Link-state flooding labs",
            default_pps=1.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="isis_csnp",
        name="IS-IS CSNP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("level", "Level", "select", True, "l1", options=[{"value": "l1", "label": "L1"}, {"value": "l2", "label": "L2"}]),
        ],
        build=lambda c: Ether(
            dst="01:80:c2:00:00:14" if str(cfg(c, "level")) == "l1" else "01:80:c2:00:00:15",
            src=cfg(c, "src_mac"),
            type=0x22F4,
        )
        / Raw(bytes([0x83, 24 if str(cfg(c, "level")) == "l1" else 25, 1, 0]) + struct.pack("!H", 33) + b"\x00" * 24),
        template=TemplateMeta(
            "IS-IS Complete Sequence Number PDU skeleton",
            "Database sync labs",
            default_pps=1.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="ospf_lsa",
        name="OSPFv2 LSU (Router-LSA)",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("router_id", "Advertising router", "ip", True, "1.1.1.1"),
            field("link_id", "Link ID", "ip", True, "10.0.0.0"),
            field("link_data", "Link data", "ip", True, "255.255.255.0"),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:05", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.5", proto=89, ttl=1)
        / Raw(
            # OSPF header type=4 LSU
            bytes([2, 4])
            + struct.pack("!H", 48)
            + __import__("ipaddress").IPv4Address(cfg(c, "router_id")).packed
            + b"\x00\x00\x00\x00"  # area 0
            + b"\x00\x00\x00\x00"  # checksum/au
            + struct.pack("!I", 1)  # #LSAs
            # Router-LSA header + 1 link
            + bytes([0, 0, 0, 1])  # ls age + options + type=1
            + __import__("ipaddress").IPv4Address(cfg(c, "router_id")).packed  # link state id
            + __import__("ipaddress").IPv4Address(cfg(c, "router_id")).packed
            + struct.pack("!IHBB", 1, 24, 0, 0)
            + struct.pack("!H", 1)  # #links
            + __import__("ipaddress").IPv4Address(cfg(c, "link_id")).packed
            + __import__("ipaddress").IPv4Address(cfg(c, "link_data")).packed
            + bytes([3, 0])  # type stub, tos
            + struct.pack("!H", 10)  # metric
        ),
        template=TemplateMeta(
            "OSPFv2 LS Update carrying Router-LSA-shaped body",
            "LSA flooding / SPF labs",
            default_pps=1.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="bgp_notification",
        name="BGP Notification",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("code", "Error code", "int", True, 6, hint="6=Cease"),
            field("subcode", "Subcode", "int", False, 0, advanced=True),
        ],
        build=lambda c: _e(c, "02:00:00:00:00:02")
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=179, dport=179, flags="PA", seq=1, ack=1)
        / Raw(b"\xff" * 16 + struct.pack("!HB", 21, 3) + bytes([int(cfg(c, "code", 6)), int(cfg(c, "subcode", 0))])),
        template=TemplateMeta(
            "BGP NOTIFICATION",
            "Session teardown / error labs",
            default_pps=1.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="bgp_update",
        name="BGP Update",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("prefix", "NLRI prefix", "ip", True, "192.168.0.0"),
            field("prefixlen", "Prefix length", "int", True, 24),
            field("nexthop", "NEXT_HOP", "ip", True, "10.0.0.1"),
            field("as_path", "AS_PATH (first AS)", "int", True, 65001),
        ],
        build=lambda c: _e(c, "02:00:00:00:00:02")
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=179, dport=179, flags="PA", seq=1, ack=1)
        / Raw(
            b"\xff" * 16
            + struct.pack("!HB", 44, 2)  # length, UPDATE
            + struct.pack("!H", 0)  # withdrawn len
            + struct.pack("!H", 20)  # path attr len
            # ORIGIN
            + bytes([0x40, 1, 1, 0])
            # AS_PATH sequence 1 AS
            + bytes([0x40, 2, 4, 2, 1])
            + struct.pack("!H", int(cfg(c, "as_path", 65001)))
            # NEXT_HOP
            + bytes([0x40, 3, 4])
            + __import__("ipaddress").IPv4Address(cfg(c, "nexthop")).packed
            # NLRI
            + bytes([int(cfg(c, "prefixlen", 24))])
            + __import__("ipaddress").IPv4Address(cfg(c, "prefix")).packed[: (int(cfg(c, "prefixlen", 24) + 7) // 8)]
        ),
        template=TemplateMeta(
            "BGP UPDATE with IPv4 NLRI",
            "Route injection / policy labs",
            default_pps=1.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="pim_join",
        name="PIM Join/Prune",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("group", "Group", "ip", True, "239.1.1.1"),
            field("source", "Source", "ip", True, "10.1.1.1"),
            field(
                "action",
                "Action",
                "select",
                True,
                "join",
                options=[{"value": "join", "label": "Join"}, {"value": "prune", "label": "Prune"}],
            ),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:0d", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.13", proto=103, ttl=1)
        / Raw(
            bytes([0x20 | 3, 0, 0, 0])  # ver=2, type=Join/Prune
            + __import__("ipaddress").IPv4Address(cfg(c, "src_ip")).packed  # upstream neighbor shaped
            + b"\x00\x00\x00\x01"  # groups
            + __import__("ipaddress").IPv4Address(cfg(c, "group")).packed
            + b"\x20\x00"  # mask / holdtime placeholder
            + (
                b"\x00\x01\x00\x00"
                if str(cfg(c, "action")) == "join"
                else b"\x00\x00\x00\x01"
            )
            + __import__("ipaddress").IPv4Address(cfg(c, "source")).packed
        ),
        template=TemplateMeta(
            "PIMv2 Join/Prune skeleton",
            "Multicast tree labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="pim_register",
        name="PIM Register",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP (DR)", "ip", True, "10.0.0.1"),
            field("rp_ip", "RP IP", "ip", True, "10.0.0.10"),
            field("inner_src", "Multicast source", "ip", True, "10.1.1.1"),
            field("inner_grp", "Multicast group", "ip", True, "239.1.1.1"),
        ],
        build=lambda c: Ether(dst="02:00:00:00:00:02", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "rp_ip"), proto=103, ttl=64)
        / Raw(bytes([0x20 | 1, 0, 0, 0]) + bytes(IP(src=cfg(c, "inner_src"), dst=cfg(c, "inner_grp"), proto=17) / UDP() / Raw(b"mcast"))),
        template=TemplateMeta(
            "PIM Register with encapsulated multicast sample",
            "PIM-SM source registration labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="igmpv3",
        name="IGMPv3 Membership Report",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.50"),
            field("group", "Group", "ip", True, "239.1.1.1"),
            field(
                "record",
                "Record type",
                "select",
                True,
                "is_ex",
                options=[
                    {"value": "is_in", "label": "MODE_IS_INCLUDE"},
                    {"value": "is_ex", "label": "MODE_IS_EXCLUDE"},
                    {"value": "to_in", "label": "CHANGE_TO_INCLUDE"},
                    {"value": "to_ex", "label": "CHANGE_TO_EXCLUDE"},
                ],
            ),
            field("source", "Source (optional)", "ip", False, "", advanced=True),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:16", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.22", proto=2, ttl=1)
        / Raw(
            bytes(
                [
                    0x22,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,  # #records
                    {"is_in": 1, "is_ex": 2, "to_in": 3, "to_ex": 4}.get(str(cfg(c, "record", "is_ex")), 2),
                    0,  # aux
                    0,
                    1 if cfg(c, "source") else 0,  # #sources
                ]
            )
            + __import__("ipaddress").IPv4Address(cfg(c, "group")).packed
            + (
                __import__("ipaddress").IPv4Address(cfg(c, "source")).packed
                if cfg(c, "source")
                else b""
            )
        ),
        template=TemplateMeta(
            "IGMPv3 membership report",
            "SSM / IGMPv3 snooping labs",
            default_pps=5.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="mldv2",
        name="MLDv2 Report",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="control",
        fields=mac_fields("33:33:00:00:00:16", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "fe80::1"),
            field("group", "Group", "ipv6", True, "ff05::1:2:3"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / __import__("scapy.layers.inet6", fromlist=["IPv6"]).IPv6(
            src=cfg(c, "src_ip"), dst="ff02::16", hlim=1, nh=0
        )
        / Raw(
            # Hop-by-hop router alert would be ideal; simplified ICMPv6 type 143
            bytes([143, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0])
            + __import__("ipaddress").IPv6Address(cfg(c, "group")).packed
        ),
        template=TemplateMeta(
            "MLDv2 multicast listener report skeleton",
            "IPv6 multicast snooping labs",
            default_pps=5.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="dvmrp",
        name="DVMRP Probe",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:04", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.4", proto=2, ttl=1)
        / Raw(bytes([0x13, 0xFF, 0x02, 0x01]) + b"\x00" * 8),  # IGMP-ish DVMRP probe
        template=TemplateMeta(
            "DVMRP Probe skeleton",
            "Dense-mode multicast legacy labs",
            default_pps=1.0,
            soft_pps_cap=5.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)

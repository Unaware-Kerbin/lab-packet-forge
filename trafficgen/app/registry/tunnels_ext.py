"""Additional tunnels / overlays / NVO3-ish encapsulations."""
from __future__ import annotations

import struct

from scapy.contrib.geneve import GENEVE
from scapy.contrib.gtp import GTPHeader
from scapy.layers.inet import GRE, IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw

try:
    from scapy.contrib.nsh import NSH
except Exception:
    NSH = None  # type: ignore

try:
    from scapy.contrib.gtp_v2 import GTPHeader as GTPv2Header
except Exception:
    try:
        from scapy.contrib.gtp import GTPHeader as GTPv2Header  # type: ignore
    except Exception:
        GTPv2Header = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "geneve_opts",
    "vxlan_gpe",
    "gue",
    "fou",
    "etherip",
    "nsh",
    "gtpc",
    "gtpv2c",
    "l2tpv3",
    "gre_key",
)


def _base(c):
    return Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01")) / IP(
        src=cfg(c, "src_ip", "10.0.0.1"),
        dst=cfg(c, "dst_ip", "10.0.0.2"),
        ttl=int(cfg(c, "ttl", 64)),
    )


def _geneve_opts(c):
    # Option: class 0x0100 critical, type 1, len=1 (4-byte units) → 4 bytes data
    opt_class = int(str(cfg(c, "opt_class", "0100")), 16)
    opt_type = int(cfg(c, "opt_type", 1))
    opt_data = hex_bytes(cfg(c, "opt_data_hex", "deadbeef")).ljust(4, b"\x00")[:4]
    opt = struct.pack("!HBB", opt_class, opt_type, 1) + opt_data
    try:
        g = GENEVE(vni=int(cfg(c, "vni", 100)), proto=int(cfg(c, "proto", "6558"), 16), optionlen=len(opt) // 4)
        return _base(c) / UDP(sport=6081, dport=6081) / g / Raw(opt + hex_bytes(cfg(c, "payload_hex", "aabbccddeeff0200000000110800")))
    except Exception:
        # Manual Geneve: ver/optlen/oam/critical/rsvd/proto | vni | reserved | options | payload
        hdr = struct.pack("!BBH", 0x01 | ((len(opt) // 4) << 2), 0, int(cfg(c, "proto", "6558"), 16))
        hdr += struct.pack("!I", (int(cfg(c, "vni", 100)) & 0xFFFFFF) << 8)
        return _base(c) / UDP(sport=6081, dport=6081) / Raw(
            hdr + opt + hex_bytes(cfg(c, "payload_hex", "aabbccddeeff0200000000110800"))
        )


register(
    ProtocolEntry(
        id="geneve_opts",
        name="GENEVE with options",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("vni", "VNI", "int", True, 100),
            field("opt_class", "Option class (hex)", "hex", False, "0100", advanced=True),
            field("opt_type", "Option type", "int", False, 1, advanced=True),
            field("opt_data_hex", "Option data (hex)", "hex", False, "deadbeef", advanced=True),
            field("proto", "Protocol type", "hex", False, "6558", advanced=True),
            field("payload_hex", "Inner (hex)", "hex", False, "aabbccddeeff0200000000110800", advanced=True),
        ],
        build=_geneve_opts,
        template=TemplateMeta("GENEVE + TLV option", "NVO3 metadata path labs"),
    )
)


register(
    ProtocolEntry(
        id="vxlan_gpe",
        name="VXLAN-GPE",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("vni", "VNI", "int", True, 100),
            field(
                "next_proto",
                "Next protocol",
                "select",
                True,
                "ipv4",
                options=[
                    {"value": "ipv4", "label": "IPv4 (0x1)"},
                    {"value": "ipv6", "label": "IPv6 (0x2)"},
                    {"value": "ethernet", "label": "Ethernet (0x3)"},
                    {"value": "nsh", "label": "NSH (0x4)"},
                ],
            ),
            field("payload_hex", "Payload (hex)", "hex", False, "45000014000000004000deadbeef", advanced=True),
        ],
        build=lambda c: _base(c)
        / UDP(sport=4790, dport=4790)
        / Raw(
            bytes(
                [
                    0x0C,  # flags: I + P (GPE)
                    0x00,
                    0x00,
                    {"ipv4": 1, "ipv6": 2, "ethernet": 3, "nsh": 4}.get(str(cfg(c, "next_proto", "ipv4")), 1),
                ]
            )
            + struct.pack("!I", (int(cfg(c, "vni", 100)) & 0xFFFFFF) << 8)
            + hex_bytes(cfg(c, "payload_hex", "45000014000000004000deadbeef"))
        ),
        template=TemplateMeta("VXLAN-GPE (UDP/4790) with next-protocol", "Multi-protocol overlay labs"),
    )
)


register(
    ProtocolEntry(
        id="gue",
        name="GUE (Generic UDP Encapsulation)",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("dport", "UDP dport", "int", True, 6080),
            field("proto_ctype", "Proto/ctype", "int", True, 4, hint="4 = IPv4"),
            field("payload_hex", "Inner (hex)", "hex", False, "45000014000000004000", advanced=True),
        ],
        build=lambda c: _base(c)
        / UDP(sport=6080, dport=int(cfg(c, "dport", 6080)))
        / Raw(bytes([0x00, int(cfg(c, "proto_ctype", 4)) & 0xFF, 0x00, 0x00]) + hex_bytes(cfg(c, "payload_hex", "45000014"))),
        template=TemplateMeta("GUE header skeleton", "Generic UDP tunnel labs"),
    )
)


register(
    ProtocolEntry(
        id="fou",
        name="Foo-over-UDP (FOU)",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("dport", "UDP dport", "int", True, 5555),
            field("inner_proto", "Implied inner", "select", True, "ipip", options=[
                {"value": "ipip", "label": "IPIP-looking"},
                {"value": "gre", "label": "GRE-looking"},
            ]),
            field("payload_hex", "Inner (hex)", "hex", False, "45000014000000004000dead", advanced=True),
        ],
        build=lambda c: _base(c)
        / UDP(sport=int(cfg(c, "dport", 5555)), dport=int(cfg(c, "dport", 5555)))
        / Raw(hex_bytes(cfg(c, "payload_hex", "45000014000000004000dead"))),
        template=TemplateMeta("FOU — UDP directly wrapping inner IP/GRE bytes", "Linux FOU path labs"),
    )
)


register(
    ProtocolEntry(
        id="etherip",
        name="EtherIP",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("inner_dst", "Inner dst MAC", "mac", True, "aa:bb:cc:dd:ee:ff"),
            field("inner_src", "Inner src MAC", "mac", True, "02:00:00:00:00:11"),
            field("payload_hex", "Inner payload (hex)", "hex", False, "080045000014", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=97)
        / Raw(b"\x30\x00")
        / Ether(dst=cfg(c, "inner_dst"), src=cfg(c, "inner_src"))
        / Raw(hex_bytes(cfg(c, "payload_hex", "080045000014"))),
        template=TemplateMeta("EtherIP (IP proto 97) + Ethernet", "L2-over-IP labs"),
    )
)


def _nsh_build(c):
    eth_ip = _base(c) / UDP(sport=6633, dport=6633)
    spi = int(cfg(c, "spi", 1))
    si = int(cfg(c, "si", 255))
    if NSH is not None:
        try:
            return eth_ip / NSH(spi=spi, si=si, NextProto=1) / IP(src=cfg(c, "inner_src", "192.168.1.1"), dst=cfg(c, "inner_dst", "192.168.1.2")) / Raw(b"nsh")
        except Exception:
            pass
    # NSH MD-type 1 base header (8 bytes) + context (16)
    base = struct.pack("!HBBI", 0x0000 | (1 << 8) | 1, 1, 1, ((spi & 0xFFFFFF) << 8) | (si & 0xFF))
    # Simpler: ver=0, oam=0, ttl=63, length=6, MD type=1, next=1 (IPv4), spi/si
    hdr = bytes([0x0, 0x3F, 0x6, 0x1, 0x1]) + struct.pack("!I", ((spi & 0xFFFFFF) << 8) | (si & 0xFF))[0:3] + bytes([si & 0xFF])
    # 8-byte base
    hdr = struct.pack("!BBBB", 0x00, 0x3F, 0x06, 0x01) + struct.pack("!I", ((spi & 0xFFFFFF) << 8) | (si & 0xFF))
    ctx = b"\x00" * 16
    return eth_ip / Raw(hdr + ctx) / IP(src=cfg(c, "inner_src", "192.168.1.1"), dst=cfg(c, "inner_dst", "192.168.1.2")) / Raw(b"nsh")


register(
    ProtocolEntry(
        id="nsh",
        name="NSH (Network Service Header)",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("spi", "Service Path ID", "int", True, 1),
            field("si", "Service Index", "int", True, 255, min=0, max=255),
            field("inner_src", "Inner src IP", "ip", True, "192.168.1.1"),
            field("inner_dst", "Inner dst IP", "ip", True, "192.168.1.2"),
        ],
        build=_nsh_build,
        template=TemplateMeta("NSH over UDP + inner IPv4", "SFC / service chaining labs"),
    )
)


def _gtpc_build(c):
    # GTPv1-C on UDP/2123
    msg = {"echo_req": 1, "create_pdp_req": 16, "delete_pdp_req": 20}.get(str(cfg(c, "msg", "echo_req")), 1)
    teid = int(cfg(c, "teid", 0))
    try:
        return _base(c) / UDP(sport=2123, dport=2123) / GTPHeader(gtp_type=msg, teid=teid) / Raw(b"\x00" * 8)
    except Exception:
        hdr = struct.pack("!BBHI", 0x32, msg, 8, teid)
        return _base(c) / UDP(sport=2123, dport=2123) / Raw(hdr + b"\x00" * 8)


register(
    ProtocolEntry(
        id="gtpc",
        name="GTP-C (v1)",
        category="Telecom / mobile",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "echo_req",
                options=[
                    {"value": "echo_req", "label": "Echo Request"},
                    {"value": "create_pdp_req", "label": "Create PDP Context Req"},
                    {"value": "delete_pdp_req", "label": "Delete PDP Context Req"},
                ],
            ),
            field("teid", "TEID", "int", False, 0, advanced=True),
        ],
        build=_gtpc_build,
        template=TemplateMeta(
            "GTPv1-C control (UDP/2123)",
            "Mobile core control-plane labs",
            default_pps=5.0,
            soft_pps_cap=20.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


def _gtpv2c_build(c):
    msg = {"echo_req": 1, "create_session_req": 32, "modify_bearer_req": 34}.get(str(cfg(c, "msg", "echo_req")), 1)
    teid = int(cfg(c, "teid", 0))
    # GTPv2-C header: flags=0x48, type, length, teid, seq
    hdr = struct.pack("!BBH", 0x48, msg, 8) + struct.pack("!I", teid) + struct.pack("!I", int(cfg(c, "seq", 1)) << 8)
    return _base(c) / UDP(sport=2123, dport=2123) / Raw(hdr)


register(
    ProtocolEntry(
        id="gtpv2c",
        name="GTP-C (v2 / GTPv2-C)",
        category="Telecom / mobile",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "echo_req",
                options=[
                    {"value": "echo_req", "label": "Echo Request"},
                    {"value": "create_session_req", "label": "Create Session Req"},
                    {"value": "modify_bearer_req", "label": "Modify Bearer Req"},
                ],
            ),
            field("teid", "TEID", "int", False, 0, advanced=True),
            field("seq", "Sequence", "int", False, 1, advanced=True),
        ],
        build=_gtpv2c_build,
        template=TemplateMeta(
            "GTPv2-C control (UDP/2123)",
            "EPC/5GC control-plane labs",
            default_pps=5.0,
            soft_pps_cap=20.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="l2tpv3",
        name="L2TPv3",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("session_id", "Session ID", "int", True, 1),
            field("cookie_hex", "Cookie (hex, optional)", "hex", False, "", advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "ffffffffffff0200000000010800", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=115)
        / Raw(
            struct.pack("!I", int(cfg(c, "session_id", 1)))
            + hex_bytes(cfg(c, "cookie_hex", ""))
            + hex_bytes(cfg(c, "payload_hex", "ffffffffffff0200000000010800"))
        ),
        template=TemplateMeta("L2TPv3 data session (IP proto 115)", "L2VPN pseudowire labs"),
    )
)


register(
    ProtocolEntry(
        id="gre_key",
        name="GRE with key",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("key", "GRE key", "int", True, 100),
            field("inner_src", "Inner src IP", "ip", True, "192.168.1.1"),
            field("inner_dst", "Inner dst IP", "ip", True, "192.168.1.2"),
        ],
        build=lambda c: _base(c)
        / GRE(key_present=1, key=int(cfg(c, "key", 100)))
        / IP(src=cfg(c, "inner_src"), dst=cfg(c, "inner_dst"))
        / Raw(b"gre-key"),
        template=TemplateMeta("GRE with key field", "Keyed tunnel / VRF labs"),
    )
)

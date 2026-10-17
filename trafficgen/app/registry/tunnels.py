"""Tunnels / overlays."""
from __future__ import annotations

from scapy.contrib.geneve import GENEVE
from scapy.contrib.gtp import GTP_U_Header
from scapy.layers.inet import GRE, IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.vxlan import VXLAN
from scapy.contrib.mpls import MPLS
from scapy.packet import Raw

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "gre",
    "ipip",
    "vxlan",
    "geneve",
    "nvgre",
    "erspan",
    "mpls",
    "gtpu",
    "wireguard",
)


def _base_ip(c):
    return Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac")) / IP(
        src=cfg(c, "src_ip", "10.0.0.1"),
        dst=cfg(c, "dst_ip", "10.0.0.2"),
        ttl=int(cfg(c, "ttl", 64)),
    )


register(
    ProtocolEntry(
        id="gre",
        name="GRE",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("inner_src", "Inner src IP", "ip", True, "192.168.1.1"),
            field("inner_dst", "Inner dst IP", "ip", True, "192.168.1.2"),
            field("payload_hex", "Inner payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: _base_ip(c)
        / GRE()
        / IP(src=cfg(c, "inner_src"), dst=cfg(c, "inner_dst"))
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("GRE tunnel with inner IPv4", "Overlay path labs"),
    )
)

register(
    ProtocolEntry(
        id="ipip",
        name="IP-in-IP",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("inner_src", "Inner src IP", "ip", True, "192.168.1.1"),
            field("inner_dst", "Inner dst IP", "ip", True, "192.168.1.2"),
            field("payload_hex", "Inner payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: _base_ip(c)
        / IP(src=cfg(c, "inner_src"), dst=cfg(c, "inner_dst"), proto=253)
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("IP-in-IP encapsulation", "Simple tunnel labs"),
    )
)

register(
    ProtocolEntry(
        id="vxlan",
        name="VXLAN",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("sport", "UDP sport", "int", False, 4789, advanced=True),
            field("vni", "VNI", "int", True, 100, min=0, max=16777215),
            field("inner_dst", "Inner dst MAC", "mac", True, "aa:bb:cc:dd:ee:ff"),
            field("inner_src", "Inner src MAC", "mac", True, "02:00:00:00:00:11"),
            field("inner_payload_hex", "Inner payload (hex)", "hex", False, "0800" + "45" + "00" * 19, advanced=True),
        ],
        build=lambda c: _base_ip(c)
        / UDP(sport=int(cfg(c, "sport", 4789)), dport=4789)
        / VXLAN(vni=int(cfg(c, "vni", 100)), flags=0x08)
        / Ether(dst=cfg(c, "inner_dst"), src=cfg(c, "inner_src"), type=0x0800)
        / Raw(hex_bytes(cfg(c, "inner_payload_hex", "45000014000000004011f64c0a0000010a0000020000"))),
        template=TemplateMeta("VXLAN encapsulated Ethernet", "Overlay fabric labs"),
    )
)

register(
    ProtocolEntry(
        id="geneve",
        name="GENEVE",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("vni", "VNI", "int", True, 100),
            field("proto", "Protocol type", "hex", False, "6558", advanced=True, hint="6558 = Ethernet"),
            field("payload_hex", "Inner payload (hex)", "hex", False, "aabbccddeeff0200000000110800", advanced=True),
        ],
        build=lambda c: _base_ip(c)
        / UDP(sport=6081, dport=6081)
        / GENEVE(vni=int(cfg(c, "vni", 100)), proto=int(cfg(c, "proto", "6558"), 16))
        / Raw(hex_bytes(cfg(c, "payload_hex", "aabbccddeeff020000000011080045000014000000004000"))),
        template=TemplateMeta("GENEVE overlay", "NVF / cloud overlay labs"),
    )
)

register(
    ProtocolEntry(
        id="nvgre",
        name="NVGRE",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("vsid", "VSID", "int", True, 100, min=0, max=16777215),
            field("inner_dst", "Inner dst MAC", "mac", True, "aa:bb:cc:dd:ee:ff"),
            field("inner_src", "Inner src MAC", "mac", True, "02:00:00:00:00:11"),
        ],
        build=lambda c: _base_ip(c)
        / GRE(key_present=1, proto=0x6558, key=int(cfg(c, "vsid", 100)) << 8)
        / Ether(dst=cfg(c, "inner_dst"), src=cfg(c, "inner_src"), type=0x0800)
        / Raw(b"\x45\x00" + b"\x00" * 18),
        template=TemplateMeta("NVGRE with VSID key", "Hyper-V style overlay labs"),
    )
)

register(
    ProtocolEntry(
        id="erspan",
        name="ERSPAN / GRE-mirrored",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("session_id", "Session ID", "int", True, 1),
            field("mirrored_hex", "Mirrored frame (hex)", "hex", True, "ffffffffffff020000000001080045000014"),
        ],
        build=lambda c: _base_ip(c)
        / GRE(proto=0x88BE)
        / Raw(int(cfg(c, "session_id", 1)).to_bytes(4, "big") + hex_bytes(cfg(c, "mirrored_hex"))),
        template=TemplateMeta("ERSPAN-style GRE mirrored frame", "SPAN/mirror path labs"),
    )
)

register(
    ProtocolEntry(
        id="mpls",
        name="MPLS",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("label1", "Label 1", "int", True, 100, min=0, max=1048575),
            field("label2", "Label 2 (0=skip)", "int", False, 0, advanced=True),
            field("ttl", "MPLS TTL", "int", False, 255, advanced=True),
            field("inner_src", "Inner src IP", "ip", True, "10.1.1.1"),
            field("inner_dst", "Inner dst IP", "ip", True, "10.1.1.2"),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: (
            Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x8847)
            / MPLS(label=int(cfg(c, "label1", 100)), ttl=int(cfg(c, "ttl", 255)), s=0 if int(cfg(c, "label2", 0)) else 1)
            / (
                MPLS(label=int(cfg(c, "label2")), ttl=int(cfg(c, "ttl", 255)), s=1)
                if int(cfg(c, "label2", 0))
                else Raw(b"")
            )
            / IP(src=cfg(c, "inner_src"), dst=cfg(c, "inner_dst"))
            / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef")))
        ),
        template=TemplateMeta("MPLS unicast label stack", "Label-switched path labs"),
    )
)

register(
    ProtocolEntry(
        id="gtpu",
        name="GTP-U",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Outer src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Outer dst IP", "ip", True, "10.0.0.2"),
            field("teid", "TEID", "int", True, 0x12345678),
            field("inner_src", "Inner src IP", "ip", True, "192.0.2.1"),
            field("inner_dst", "Inner dst IP", "ip", True, "192.0.2.2"),
        ],
        build=lambda c: _base_ip(c)
        / UDP(sport=2152, dport=2152)
        / GTP_U_Header(teid=int(cfg(c, "teid", 0x12345678)))
        / IP(src=cfg(c, "inner_src"), dst=cfg(c, "inner_dst"))
        / Raw(b"gtpu-lab"),
        template=TemplateMeta("GTP-U with TEID + inner IP", "Mobile edge labs"),
    )
)

register(
    ProtocolEntry(
        id="wireguard",
        name="WireGuard-shaped UDP",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields()
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 51820),
            field("dport", "Dst port", "int", True, 51820),
            field(
                "msg_type",
                "Message type",
                "select",
                True,
                "4",
                options=[
                    {"value": "1", "label": "Handshake Init"},
                    {"value": "2", "label": "Handshake Resp"},
                    {"value": "4", "label": "Data"},
                ],
            ),
            field("payload_hex", "Body (hex)", "hex", False, "00" * 32, advanced=True),
        ],
        build=lambda c: _base_ip(c)
        / UDP(sport=int(cfg(c, "sport", 51820)), dport=int(cfg(c, "dport", 51820)))
        / Raw(bytes([int(cfg(c, "msg_type", 4)), 0, 0, 0]) + hex_bytes(cfg(c, "payload_hex", "00" * 32))),
        template=TemplateMeta("WireGuard header-shaped UDP", "VPN ACL path tests"),
    )
)

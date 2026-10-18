"""Escape hatches — always available in Craft + Templates."""
from __future__ import annotations

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect("raw_l2", "raw_ipv4", "raw_ipv6", "pcap_replay")

register(
    ProtocolEntry(
        id="raw_l2",
        name="Raw L2",
        category="Escape hatches",
        layer="escape",
        craft_slot="l2",
        fields=mac_fields()
        + [
            field("ethertype", "EtherType", "hex", True, "88b5", hint="Lab ethertype default"),
            field("payload_hex", "Payload (hex)", "hex", True, "deadbeef"),
        ],
        build=lambda c: Ether(
            dst=cfg(c, "dst_mac"),
            src=cfg(c, "src_mac"),
            type=int(str(cfg(c, "ethertype", "88b5")).replace("0x", ""), 16),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("Raw Ethernet + ethertype + hex", "Anything niche without a dedicated builder"),
    )
)

register(
    ProtocolEntry(
        id="raw_ipv4",
        name="Raw IPv4",
        category="Escape hatches",
        layer="escape",
        craft_slot="l3",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("proto", "Protocol number", "int", True, 253, min=0, max=255),
            field("ttl", "TTL", "int", False, 64, advanced=True),
            field("payload_hex", "L4 body (hex)", "hex", True, "deadbeef"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(
            src=cfg(c, "src_ip"),
            dst=cfg(c, "dst_ip"),
            proto=int(cfg(c, "proto", 253)),
            ttl=int(cfg(c, "ttl", 64)),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("Raw IPv4 + proto + hex L4", "Custom IP protocols"),
    )
)

register(
    ProtocolEntry(
        id="raw_ipv6",
        name="Raw IPv6",
        category="Escape hatches",
        layer="escape",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "2001:db8::2"),
            field("nh", "Next header", "int", True, 59, min=0, max=255),
            field("hlim", "Hop limit", "int", False, 64, advanced=True),
            field("payload_hex", "L4 body (hex)", "hex", True, "deadbeef"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IPv6(
            src=cfg(c, "src_ip"),
            dst=cfg(c, "dst_ip"),
            nh=int(cfg(c, "nh", 59)),
            hlim=int(cfg(c, "hlim", 64)),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("Raw IPv6 + next-header + hex", "Custom IPv6 protocols"),
    )
)


def _pcap_build(c):
    """Build returns first frame; replay worker uses file path from stream config."""
    path = cfg(c, "pcap_path", "")
    if path:
        try:
            pkts = rdpcap(path)
            if pkts:
                return pkts[0]
        except Exception:
            pass
    # Placeholder so catalog/build always works
    return Ether(dst=cfg(c, "dst_mac", "ff:ff:ff:ff:ff:ff"), src=cfg(c, "src_mac", "02:00:00:00:00:01")) / Raw(
        hex_bytes(cfg(c, "payload_hex", "deadbeef"))
    )


register(
    ProtocolEntry(
        id="pcap_replay",
        name="PCAP replay",
        category="Escape hatches",
        layer="escape",
        craft_slot="payload",
        fields=[
            field("pcap_path", "PCAP path (server)", "text", False, "", hint="Use Replay tab upload"),
            field("loop", "Loop forever", "bool", False, True),
            field("loop_count", "Loop count (0=∞)", "int", False, 0, min=0, hint="0 = until Stop"),
            field(
                "rate_mode",
                "Rate mode",
                "select",
                False,
                "pps",
                options=[
                    {"value": "pps", "label": "Fixed pps"},
                    {"value": "max", "label": "As fast as possible"},
                    {"value": "original", "label": "Original pcap timing"},
                ],
            ),
            field("payload_hex", "Fallback hex if no pcap", "hex", False, "deadbeef", advanced=True),
            field("dst_mac", "Fallback dst MAC", "mac", False, "ff:ff:ff:ff:ff:ff", advanced=True),
            field("src_mac", "Fallback src MAC", "mac", False, "02:00:00:00:00:01", advanced=True),
        ],
        build=_pcap_build,
        template=TemplateMeta(
            "Upload pcap/pcapng and replay on eth1 at pps, max, or original timing",
            "Replay real captures against stack/VC/DUT links — prefer low pps on shared labs",
            default_pps=10.0,
            soft_pps_cap=100.0,
            hard_pps_cap=2000.0,
            control_plane_risk=True,
        ),
    )
)

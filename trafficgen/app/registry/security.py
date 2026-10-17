"""Security-shaped header / stimulus templates (not exploits)."""
from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.ipsec import AH, ESP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect("ipsec_ah", "ipsec_esp", "tls_clienthello")

register(
    ProtocolEntry(
        id="ipsec_ah",
        name="IPsec AH",
        category="Security-shaped",
        layer="security",
        craft_slot="tunnel",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("spi", "SPI", "int", True, 0x1000),
            field("seq", "Sequence", "int", False, 1, advanced=True),
            field("icv_hex", "ICV (dummy hex)", "hex", False, "00" * 12, advanced=True),
            field("payload_hex", "Inner payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=51)
        / AH(spi=int(cfg(c, "spi", 0x1000)), seq=int(cfg(c, "seq", 1)), icv=hex_bytes(cfg(c, "icv_hex", "00" * 12)))
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("IPsec AH header + dummy payload", "ACL/firewall path tests"),
    )
)

register(
    ProtocolEntry(
        id="ipsec_esp",
        name="IPsec ESP",
        category="Security-shaped",
        layer="security",
        craft_slot="tunnel",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("spi", "SPI", "int", True, 0x2000),
            field("seq", "Sequence", "int", False, 1, advanced=True),
            field("payload_hex", "Encrypted-looking payload (hex)", "hex", False, "aa" * 32, advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=50)
        / ESP(spi=int(cfg(c, "spi", 0x2000)), seq=int(cfg(c, "seq", 1)))
        / Raw(hex_bytes(cfg(c, "payload_hex", "aa" * 32))),
        template=TemplateMeta("IPsec ESP header + dummy payload", "ACL/firewall path tests"),
    )
)

register(
    ProtocolEntry(
        id="tls_clienthello",
        name="TLS ClientHello probe",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.43"),
            field("dport", "Dst port", "int", True, 443),
            field("sni", "SNI", "text", False, "example.com", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40003, dport=int(cfg(c, "dport", 443)), flags="PA", seq=1, ack=1)
        / Raw(
            b"\x16\x03\x01\x00\x2c\x01\x00\x00\x28\x03\x03"
            + b"\x11" * 32
            + b"\x00\x00\x02\x00\x2f\x01\x00"
            + str(cfg(c, "sni", "example.com")).encode()[:16].ljust(16, b"\x00")
        ),
        template=TemplateMeta("TLS ClientHello-shaped stimulus", "Optional security app template"),
    )
)

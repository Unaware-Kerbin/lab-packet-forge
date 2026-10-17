"""Additional security-shaped stimuli (not exploits)."""
from __future__ import annotations

import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

try:
    from scapy.contrib.ikev2 import IKEv2, IKEv2_SA_INIT
except Exception:
    try:
        from scapy.contrib.ikev2 import IKEv2  # type: ignore

        IKEv2_SA_INIT = None  # type: ignore
    except Exception:
        IKEv2 = IKEv2_SA_INIT = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "ikev2",
    "isakmp",
    "eap_md5",
    "eap_tls",
    "radius_access",
    "dtls_clienthello",
    "ssh_banner",
    "http2_preface",
)


def _e(c):
    return Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


def _ikev2(c):
    if IKEv2 is not None:
        try:
            pkt = IKEv2(init_SPI=b"\x11" * 8, resp_SPI=b"\x00" * 8, exch_type=34, flags=0x08)
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / UDP(sport=500, dport=500)
                / pkt
                / Raw(hex_bytes(cfg(c, "payload_hex", "22" + "00" * 31)))
            )
        except Exception:
            pass
    # IKEv2 header: SPIi, SPIr, next, ver, exchange=34 SA_INIT, flags, msg id, length
    hdr = (
        b"\x11" * 8
        + b"\x00" * 8
        + bytes([0x22, 0x20, 34, 0x08])
        + struct.pack("!II", 0, 28 + 32)
    )
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / UDP(sport=500, dport=int(cfg(c, "dport", 500)))
        / Raw(hdr + hex_bytes(cfg(c, "payload_hex", "22" + "00" * 31)))
    )


register(
    ProtocolEntry(
        id="ikev2",
        name="IKEv2 SA_INIT",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 500),
            field("payload_hex", "Payloads (hex)", "hex", False, "22" + "00" * 31, advanced=True),
        ],
        build=_ikev2,
        template=TemplateMeta("IKEv2 SA_INIT-shaped UDP/500", "IPsec VPN bring-up path labs"),
    )
)


register(
    ProtocolEntry(
        id="isakmp",
        name="ISAKMP / IKEv1 Main Mode",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("payload_hex", "Payloads (hex)", "hex", False, "00" * 32, advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=500, dport=500)
        / Raw(
            b"\x11" * 8
            + b"\x00" * 8
            + bytes([0x01, 0x10, 2, 0x00])  # next=SA, ver=1.0, exchange=Identity Protection
            + struct.pack("!II", 0, 28 + 32)
            + hex_bytes(cfg(c, "payload_hex", "00" * 32))
        ),
        template=TemplateMeta("ISAKMP Main Mode skeleton", "Legacy IKE path labs"),
    )
)


def _eap_md5(c):
    chal = hex_bytes(cfg(c, "challenge_hex", "11" * 16))
    eap = bytes([1, int(cfg(c, "identifier", 1))]) + struct.pack("!H", 6 + len(chal)) + bytes([4, len(chal)]) + chal
    eapol = bytes([1, 0]) + struct.pack("!H", len(eap)) + eap
    return Ether(dst=cfg(c, "dst_mac", "01:80:c2:00:00:03"), src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x888E) / Raw(
        eapol
    )


def _eap_tls(c):
    eap = bytes([1, int(cfg(c, "identifier", 1))]) + struct.pack("!H", 6) + bytes([13, 0x20])
    eapol = bytes([1, 0]) + struct.pack("!H", len(eap)) + eap
    return Ether(dst=cfg(c, "dst_mac", "01:80:c2:00:00:03"), src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x888E) / Raw(
        eapol
    )


register(
    ProtocolEntry(
        id="eap_md5",
        name="EAP-MD5 Challenge",
        category="Security-shaped",
        layer="security",
        craft_slot="l2",
        fields=mac_fields("01:80:c2:00:00:03", "02:00:00:00:00:01")
        + [
            field("identifier", "Identifier", "int", True, 1, min=0, max=255),
            field("challenge_hex", "Challenge (hex)", "hex", False, "11" * 16, advanced=True),
        ],
        build=_eap_md5,
        template=TemplateMeta(
            "EAP-MD5 Challenge over EAPOL",
            "802.1X method labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="eap_tls",
        name="EAP-TLS Start",
        category="Security-shaped",
        layer="security",
        craft_slot="l2",
        fields=mac_fields("01:80:c2:00:00:03", "02:00:00:00:00:01")
        + [field("identifier", "Identifier", "int", True, 1)],
        build=_eap_tls,
        template=TemplateMeta(
            "EAP-TLS Start over EAPOL",
            "802.1X certificate method labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="radius_access",
        name="RADIUS Access-Request",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (NAS)", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (AAA)", "ip", True, "10.0.0.2"),
            field("user", "User-Name", "text", True, "forge"),
            field("nas_ip", "NAS-IP-Address", "ip", False, "10.0.0.1", advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=1812, dport=1812)
        / Raw(
            bytes([1, 1])  # Access-Request, id
            + struct.pack("!H", 20 + 2 + len(str(cfg(c, "user", "forge"))) + 6)
            + b"\x00" * 16  # authenticator
            + bytes([1, 2 + len(str(cfg(c, "user", "forge")))])
            + str(cfg(c, "user", "forge")).encode()
            + bytes([4, 6])
            + __import__("ipaddress").IPv4Address(cfg(c, "nas_ip", cfg(c, "src_ip", "10.0.0.1"))).packed
        ),
        template=TemplateMeta(
            "RADIUS Access-Request",
            "AAA / 802.1X backend labs",
            default_pps=5.0,
            soft_pps_cap=20.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="dtls_clienthello",
        name="DTLS ClientHello probe",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 4433),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=40000, dport=int(cfg(c, "dport", 4433)))
        / Raw(
            b"\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2c"
            + b"\x01\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x20"
            + b"\xfe\xfd"
            + b"\x11" * 32
        ),
        template=TemplateMeta("DTLS ClientHello-shaped UDP", "Datagram TLS path labs"),
    )
)


register(
    ProtocolEntry(
        id="ssh_banner",
        name="SSH banner probe",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 22),
            field("banner", "Banner", "text", True, "SSH-2.0-Forge_1.0"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 22)), flags="PA", seq=1, ack=1)
        / Raw(str(cfg(c, "banner", "SSH-2.0-Forge_1.0")).encode() + b"\r\n"),
        template=TemplateMeta("SSH protocol banner on established-looking TCP", "Mgmt-plane path labs"),
    )
)


register(
    ProtocolEntry(
        id="http2_preface",
        name="HTTP/2 connection preface",
        category="Security-shaped",
        layer="security",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 80),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 80)), flags="PA", seq=1, ack=1)
        / Raw(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"),
        template=TemplateMeta("HTTP/2 client connection preface + empty SETTINGS", "HTTP/2 path labs"),
    )
)

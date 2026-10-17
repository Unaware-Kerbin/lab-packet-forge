"""Additional discovery / ops / application probes."""
from __future__ import annotations

import struct

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

try:
    from scapy.contrib.stun import STUN
except Exception:
    STUN = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "dns_sec",
    "dhcp_inform",
    "dhcpv6_relay",
    "stun",
    "tftp",
    "ldap_bind",
    "kerberos_asreq",
    "netbios_ns",
    "ipmi_rmcp",
    "syslog_tcp",
    "grafana_probe",
)


def _e(c, dst="02:00:00:00:00:02"):
    return Ether(dst=cfg(c, "dst_mac", dst), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


register(
    ProtocolEntry(
        id="dns_sec",
        name="DNS DNSKEY query",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (resolver)", "ip", True, "10.0.0.2"),
            field("qname", "QNAME", "text", True, "example.com"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=40000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=str(cfg(c, "qname", "example.com")), qtype="DNSKEY")),
        template=TemplateMeta("DNS query for DNSKEY (DNSSEC-shaped)", "DNSSEC path labs"),
    )
)


register(
    ProtocolEntry(
        id="dhcp_inform",
        name="DHCP INFORM",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=[
            field("src_mac", "Client MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Client IP", "ip", True, "10.0.0.50"),
            field("dst_ip", "Server / broadcast", "ip", False, "255.255.255.255", advanced=True),
        ],
        build=lambda c: Ether(dst="ff:ff:ff:ff:ff:ff", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip", "255.255.255.255"))
        / UDP(sport=68, dport=67)
        / Raw(
            # BOOTP + DHCP INFORM (msg type 8)
            bytes([1, 1, 6, 0])
            + b"\x39\x03\xf3\x26"  # xid
            + b"\x00" * 20
            + __import__("ipaddress").IPv4Address(cfg(c, "src_ip")).packed
            + b"\x00" * 12
            + bytes.fromhex(cfg(c, "src_mac").replace(":", ""))
            + b"\x00" * 10
            + b"\x00" * 64
            + b"\x00" * 128
            + b"\x63\x82\x53\x63"
            + bytes([53, 1, 8, 55, 2, 1, 3, 255])
        ),
        template=TemplateMeta(
            "DHCP INFORM with parameter request",
            "DHCP option / renewal labs",
            default_pps=5.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="dhcpv6_relay",
        name="DHCPv6 Relay-Forward",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("33:33:00:01:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Relay IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Server IPv6", "ipv6", True, "2001:db8::2"),
            field("link_addr", "Link address", "ipv6", True, "2001:db8:1::1"),
            field("peer_addr", "Peer address", "ipv6", True, "fe80::50"),
        ],
        build=lambda c: _e(c, "33:33:00:01:00:02")
        / __import__("scapy.layers.inet6", fromlist=["IPv6"]).IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=547, dport=547)
        / Raw(
            bytes([12])  # Relay-Forward
            + b"\x00"
            + __import__("ipaddress").IPv6Address(cfg(c, "link_addr")).packed
            + __import__("ipaddress").IPv6Address(cfg(c, "peer_addr")).packed
            + bytes([9, 0, 0, 8, 1, 0, 0, 0, 0, 0, 0, 0])  # OPTION_RELAY_MSG stub
        ),
        template=TemplateMeta(
            "DHCPv6 Relay-Forward",
            "IPv6 DHCP relay labs",
            default_pps=5.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


def _stun(c):
    if STUN is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / UDP(sport=40000, dport=int(cfg(c, "dport", 3478)))
                / STUN()
            )
        except Exception:
            pass
    # Binding Request
    txn = hex_bytes(cfg(c, "txn_hex", "11" * 12))
    body = struct.pack("!HH", 0x0001, 0) + bytes.fromhex("2112A442") + txn.ljust(12, b"\x00")[:12]
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / UDP(sport=40000, dport=int(cfg(c, "dport", 3478)))
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="stun",
        name="STUN Binding Request",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 3478),
            field("txn_hex", "Transaction ID (hex)", "hex", False, "11" * 12, advanced=True),
        ],
        build=_stun,
        template=TemplateMeta("STUN Binding Request", "NAT discovery / WebRTC labs"),
    )
)


register(
    ProtocolEntry(
        id="tftp",
        name="TFTP Read Request",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("filename", "Filename", "text", True, "startup-config"),
            field("mode", "Mode", "text", False, "octet", advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=40000, dport=69)
        / Raw(
            struct.pack("!H", 1)
            + str(cfg(c, "filename", "startup-config")).encode()
            + b"\x00"
            + str(cfg(c, "mode", "octet")).encode()
            + b"\x00"
        ),
        template=TemplateMeta("TFTP RRQ", "Image / config transfer labs"),
    )
)


register(
    ProtocolEntry(
        id="ldap_bind",
        name="LDAP BindRequest",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 389),
            field("bind_dn", "Bind DN", "text", True, "cn=admin,dc=lab,dc=local"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 389)), flags="PA", seq=1, ack=1)
        / Raw(
            # Minimal BER: SEQUENCE { messageID 1, BindRequest }
            b"\x30\x2c\x02\x01\x01\x60\x27\x02\x01\x03"
            + bytes([0x04, len(str(cfg(c, "bind_dn")))])
            + str(cfg(c, "bind_dn")).encode()
            + b"\x80\x00"
        ),
        template=TemplateMeta("LDAP simple BindRequest skeleton", "Directory / AAA labs"),
    )
)


register(
    ProtocolEntry(
        id="kerberos_asreq",
        name="Kerberos AS-REQ",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (KDC)", "ip", True, "10.0.0.2"),
            field("realm", "Realm", "text", True, "LAB.LOCAL"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=40000, dport=88)
        / Raw(
            b"\x6a\x2a\x30\x28\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a"
            + b"\xa4\x1c\x30\x1a\xa0\x03\x02\x01\x01"
            + bytes([0xA1, 0x13, 0x30, 0x11, 0x1B, len(str(cfg(c, "realm")))])
            + str(cfg(c, "realm")).encode()
        ),
        template=TemplateMeta("Kerberos AS-REQ-shaped UDP/88", "AD / realm path labs"),
    )
)


register(
    ProtocolEntry(
        id="netbios_ns",
        name="NetBIOS Name Query",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("name", "NetBIOS name", "text", True, "FORGE"),
        ],
        build=lambda c: _e(c, "ff:ff:ff:ff:ff:ff")
        / IP(src=cfg(c, "src_ip"), dst="255.255.255.255")
        / UDP(sport=137, dport=137)
        / Raw(
            struct.pack("!HHHHHH", 0x1337, 0x0110, 1, 0, 0, 0)
            + b"\x20"
            + "".join(
                chr(((b >> 4) & 0xF) + ord("A")) + chr((b & 0xF) + ord("A"))
                for b in ((str(cfg(c, "name", "FORGE")).upper() + " " * 15)[:15] + "\x00").encode("ascii")
            ).encode("ascii")
            + b"\x00\x00\x20\x00\x01"
        ),
        template=TemplateMeta(
            "NetBIOS-NS name query broadcast",
            "Legacy Windows discovery labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="ipmi_rmcp",
        name="IPMI RMCP Ping",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (BMC)", "ip", True, "10.0.0.2"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=40000, dport=623)
        / Raw(b"\x06\x00\xff\x06\x00\x00\x11\xbe\x80\x00\x00\x00"),  # ASF Presence Ping
        template=TemplateMeta("RMCP/ASF Presence Ping (UDP/623)", "Out-of-band mgmt labs"),
    )
)


register(
    ProtocolEntry(
        id="syslog_tcp",
        name="Syslog (TCP)",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 514),
            field("message", "Message", "text", True, "<14>forge: lab event"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 514)), flags="PA", seq=1, ack=1)
        / Raw(str(cfg(c, "message", "<14>forge: lab event")).encode() + b"\n"),
        template=TemplateMeta("Syslog over TCP", "Logging path labs"),
    )
)


register(
    ProtocolEntry(
        id="grafana_probe",
        name="HTTP API probe",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 3000),
            field("path", "Path", "text", True, "/api/health"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 3000)), flags="PA", seq=1, ack=1)
        / Raw(
            f"GET {cfg(c, 'path', '/api/health')} HTTP/1.1\r\nHost: forge\r\nUser-Agent: LabPacketForge\r\nConnection: close\r\n\r\n".encode()
        ),
        template=TemplateMeta("HTTP GET health-style probe", "App / observability path labs"),
    )
)

"""Discovery / ops / app common lab traffic."""
from __future__ import annotations

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP, SNMPget, SNMPtrapv2, SNMPvarbind
from scapy.packet import Raw

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "dhcp",
    "dhcpv6",
    "dns",
    "mdns",
    "llmnr",
    "ssdp",
    "ntp",
    "snmp",
    "syslog",
    "http_probe",
    "https_probe",
    "radius",
    "tacacs",
)


def _udp(c, dport, sport=None, dst_mac=None, dst_ip=None):
    return (
        Ether(dst=cfg(c, "dst_mac", dst_mac or "ff:ff:ff:ff:ff:ff"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))
        / IP(src=cfg(c, "src_ip", "0.0.0.0"), dst=cfg(c, "dst_ip", dst_ip or "255.255.255.255"), ttl=64)
        / UDP(sport=int(cfg(c, "sport", sport or dport)), dport=int(dport))
    )


def _dhcp_options(c):
    msg = cfg(c, "msg", "discover")
    opts = [("message-type", {"discover": 1, "offer": 2, "request": 3, "ack": 5}[msg])]
    if msg in ("offer", "ack"):
        opts.append(("server_id", cfg(c, "server_id", "10.0.0.1")))
    if msg == "request":
        opts.append(("requested_addr", cfg(c, "requested_ip", "10.0.0.50")))
    if msg in ("discover", "request"):
        opts.append(("param_req_list", [1, 3, 6, 15]))
    opts.append("end")
    return opts


register(
    ProtocolEntry(
        id="dhcp",
        name="DHCP",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=[
            field("src_mac", "Client MAC", "mac", True, "02:00:00:00:00:01"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "discover",
                options=[
                    {"value": "discover", "label": "Discover"},
                    {"value": "offer", "label": "Offer"},
                    {"value": "request", "label": "Request"},
                    {"value": "ack", "label": "Ack"},
                ],
            ),
            field("yiaddr", "Your IP (offer/ack)", "ip", False, "10.0.0.50", advanced=True),
            field("server_id", "Server ID", "ip", False, "10.0.0.1", advanced=True),
            field("requested_ip", "Requested IP", "ip", False, "10.0.0.50", advanced=True),
        ],
        build=lambda c: (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=cfg(c, "src_mac"))
            / IP(src="0.0.0.0" if cfg(c, "msg") in ("discover", "request") else cfg(c, "server_id", "10.0.0.1"), dst="255.255.255.255")
            / UDP(sport=68 if cfg(c, "msg") in ("discover", "request") else 67, dport=67 if cfg(c, "msg") in ("discover", "request") else 68)
            / BOOTP(
                op=1 if cfg(c, "msg") in ("discover", "request") else 2,
                chaddr=bytes.fromhex(str(cfg(c, "src_mac")).replace(":", "")),
                yiaddr=cfg(c, "yiaddr", "0.0.0.0") if cfg(c, "msg") in ("offer", "ack") else "0.0.0.0",
                xid=0xF0A6E1,
            )
            / DHCP(
                options=_dhcp_options(c),
            )
        ),
        template=TemplateMeta("DHCP discover/offer/request/ack", "Address assignment labs"),
    )
)

register(
    ProtocolEntry(
        id="dhcpv6",
        name="DHCPv6",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IPv6", "ipv6", True, "fe80::1"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "solicit",
                options=[
                    {"value": "solicit", "label": "Solicit"},
                    {"value": "advertise", "label": "Advertise"},
                    {"value": "request", "label": "Request"},
                    {"value": "reply", "label": "Reply"},
                ],
            ),
        ],
        build=lambda c: (
            Ether(dst="33:33:00:01:00:02", src=cfg(c, "src_mac"))
            / IPv6(src=cfg(c, "src_ip"), dst="ff02::1:2", hlim=1)
            / UDP(sport=546, dport=547)
            / {
                "solicit": DHCP6_Solicit(trid=0x123456),
                "advertise": DHCP6_Advertise(trid=0x123456),
                "request": DHCP6_Request(trid=0x123456),
                "reply": DHCP6_Reply(trid=0x123456),
            }[cfg(c, "msg", "solicit")]
        ),
        template=TemplateMeta("DHCPv6 solicit/advertise/request/reply", "IPv6 addressing labs"),
    )
)

register(
    ProtocolEntry(
        id="dns",
        name="DNS",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.53"),
            field("qname", "Query name", "text", True, "example.com"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "query",
                options=[{"value": "query", "label": "Query"}, {"value": "response", "label": "Response"}],
            ),
            field("rdata", "Response A record", "ip", False, "93.184.216.34", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=12345, dport=53)
        / (
            DNS(rd=1, qd=DNSQR(qname=cfg(c, "qname")))
            if cfg(c, "msg") == "query"
            else DNS(
                qr=1,
                aa=1,
                rd=1,
                ra=1,
                qd=DNSQR(qname=cfg(c, "qname")),
                an=DNSRR(rrname=cfg(c, "qname"), ttl=60, rdata=cfg(c, "rdata", "93.184.216.34")),
            )
        ),
        template=TemplateMeta("DNS query/response", "Name resolution labs"),
    )
)

register(
    ProtocolEntry(
        id="mdns",
        name="mDNS",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("qname", "Query name", "text", True, "_http._tcp.local"),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:fb", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.251", ttl=255)
        / UDP(sport=5353, dport=5353)
        / DNS(rd=0, qd=DNSQR(qname=cfg(c, "qname"), qtype="PTR")),
        template=TemplateMeta("mDNS query", "Zeroconf discovery labs"),
    )
)

register(
    ProtocolEntry(
        id="llmnr",
        name="LLMNR",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("qname", "Query name", "text", True, "HOST"),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:fc", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.252", ttl=1)
        / UDP(sport=5355, dport=5355)
        / DNS(rd=0, qd=DNSQR(qname=cfg(c, "qname"))),
        template=TemplateMeta("LLMNR query", "Windows name resolution labs"),
    )
)

register(
    ProtocolEntry(
        id="ssdp",
        name="SSDP",
        category="Discovery / ops / app",
        layer="discovery",
        craft_slot="app",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("st", "Search target", "text", True, "ssdp:all"),
        ],
        build=lambda c: Ether(dst="01:00:5e:7f:ff:fa", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="239.255.255.250", ttl=1)
        / UDP(sport=1900, dport=1900)
        / Raw(
            f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {cfg(c, 'st')}\r\n\r\n".encode()
        ),
        template=TemplateMeta("SSDP M-SEARCH", "UPnP discovery labs"),
    )
)

register(
    ProtocolEntry(
        id="ntp",
        name="NTP",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.123"),
            field("mode", "Mode", "int", False, 3, advanced=True, hint="3=client"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=123, dport=123)
        / NTP(mode=int(cfg(c, "mode", 3)), version=4),
        template=TemplateMeta("NTP client request", "Time sync path labs"),
    )
)

register(
    ProtocolEntry(
        id="snmp",
        name="SNMP",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.161"),
            field("community", "Community", "text", True, "public"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "get",
                options=[{"value": "get", "label": "Get"}, {"value": "trap", "label": "Trap"}],
            ),
            field("oid", "OID", "text", False, "1.3.6.1.2.1.1.1.0", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=1161, dport=162 if cfg(c, "msg") == "trap" else 161)
        / (
            SNMP(community=cfg(c, "community"), PDU=SNMPget(varbindlist=[SNMPvarbind(oid=cfg(c, "oid", "1.3.6.1.2.1.1.1.0"))]))
            if cfg(c, "msg") == "get"
            else SNMP(community=cfg(c, "community"), PDU=SNMPtrapv2(varbindlist=[SNMPvarbind(oid=cfg(c, "oid", "1.3.6.1.2.1.1.1.0"))]))
        ),
        template=TemplateMeta("SNMP get/trap skeleton", "Management plane labs"),
    )
)

register(
    ProtocolEntry(
        id="syslog",
        name="Syslog",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.54"),
            field("facility", "Facility", "int", False, 16, advanced=True),
            field("severity", "Severity", "int", False, 6, advanced=True),
            field("message", "Message", "text", True, "forge: lab syslog event"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=514, dport=514)
        / Raw(f"<{int(cfg(c, 'facility', 16)) * 8 + int(cfg(c, 'severity', 6))}>{cfg(c, 'message')}\n".encode()),
        template=TemplateMeta("Syslog UDP message", "Logging path labs"),
    )
)

register(
    ProtocolEntry(
        id="http_probe",
        name="HTTP probe",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.80"),
            field("dport", "Dst port", "int", True, 80),
            field("method", "Method", "text", True, "GET"),
            field("path", "Path", "text", True, "/"),
            field("host", "Host header", "text", True, "example.com"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 80)), flags="PA", seq=1, ack=1)
        / Raw(f"{cfg(c, 'method')} {cfg(c, 'path')} HTTP/1.1\r\nHost: {cfg(c, 'host')}\r\nConnection: close\r\n\r\n".encode()),
        template=TemplateMeta("Single-request HTTP probe", "App ACL / DPI labs — not a browser"),
    )
)

register(
    ProtocolEntry(
        id="https_probe",
        name="HTTPS / TLS ClientHello probe",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.43"),
            field("dport", "Dst port", "int", True, 443),
            field("sni", "SNI hint (embedded)", "text", False, "example.com", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40001, dport=int(cfg(c, "dport", 443)), flags="PA", seq=1, ack=1)
        / Raw(
            # Minimal TLS 1.2 ClientHello-shaped record (stimulus only)
            b"\x16\x03\x01"
            + (40 + len(str(cfg(c, "sni", "example.com")))).to_bytes(2, "big")
            + b"\x01\x00"
            + (36 + len(str(cfg(c, "sni", "example.com")))).to_bytes(2, "big")
            + b"\x03\x03"
            + b"\x00" * 32
            + b"\x00"
            + b"\x00\x02\x00\x2f"
            + b"\x01\x00"
            + b"\x00\x00"
            + str(cfg(c, "sni", "example.com")).encode()
        ),
        template=TemplateMeta("TLS ClientHello-shaped probe", "HTTPS path / firewall labs"),
    )
)

register(
    ProtocolEntry(
        id="radius",
        name="RADIUS",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.181"),
            field("user", "User-Name", "text", True, "labuser"),
            field(
                "code",
                "Code",
                "select",
                True,
                "1",
                options=[
                    {"value": "1", "label": "Access-Request"},
                    {"value": "2", "label": "Access-Accept"},
                    {"value": "3", "label": "Access-Reject"},
                ],
            ),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=1812, dport=1812)
        / Raw(
            bytes([int(cfg(c, "code", 1)), 0x01])
            + (20 + 2 + len(str(cfg(c, "user")))).to_bytes(2, "big")
            + b"\x00" * 16
            + bytes([1, 2 + len(str(cfg(c, "user")))])
            + str(cfg(c, "user")).encode()
        ),
        template=TemplateMeta("RADIUS auth skeleton", "AAA lab stimulus"),
    )
)

register(
    ProtocolEntry(
        id="tacacs",
        name="TACACS+",
        category="Discovery / ops / app",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.10"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.49"),
            field("user", "User", "text", True, "labuser"),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40002, dport=49, flags="PA", seq=1, ack=1)
        / Raw(
            bytes([0xC0, 0x01, 0x01, 0x00])  # version/type/seq/flags
            + b"\x00\x00\x00\x01"
            + (8 + len(str(cfg(c, "user")))).to_bytes(4, "big")
            + str(cfg(c, "user")).encode().ljust(8, b"\x00")
        ),
        template=TemplateMeta("TACACS+ auth skeleton", "Device AAA labs"),
    )
)

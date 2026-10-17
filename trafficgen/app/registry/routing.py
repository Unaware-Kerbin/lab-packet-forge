"""Routing & first-hop protocols."""
from __future__ import annotations

from scapy.contrib.bfd import BFD
from scapy.contrib.eigrp import EIGRP, EIGRPIntRoute, EIGRPParam, EIGRPSwVer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

try:
    from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello, OSPF_LSAck, OSPF_LSReq, OSPF_LSUpd, OSPF_DBDesc
except ImportError:
    from scapy.layers.ospf import OSPF_Hdr, OSPF_Hello  # type: ignore

    OSPF_DBDesc = OSPF_LSReq = OSPF_LSUpd = OSPF_LSAck = None  # type: ignore

try:
    from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPKeepAlive, BGPNotification, BGPUpdate
except Exception:
    BGPHeader = BGPOpen = BGPKeepAlive = BGPNotification = BGPUpdate = None  # type: ignore

try:
    from scapy.contrib.isis import ISIS_CommonHdr, ISIS_P2P_Hello, ISIS_L1_LAN_Hello, ISIS_LSP_Entry
except Exception:
    ISIS_CommonHdr = ISIS_P2P_Hello = ISIS_L1_LAN_Hello = ISIS_LSP_Entry = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "ospfv2",
    "ospfv3",
    "isis",
    "bgp",
    "rip",
    "ripng",
    "eigrp",
    "vrrp",
    "hsrp",
    "glbp",
    "pim",
    "bfd",
)


def _eth_ip(c, dst_ip="224.0.0.5", proto=89):
    return Ether(dst=cfg(c, "dst_mac", "01:00:5e:00:00:05"), src=cfg(c, "src_mac", "02:00:00:00:00:01")) / IP(
        src=cfg(c, "src_ip", "10.0.0.1"),
        dst=cfg(c, "dst_ip", dst_ip),
        ttl=1,
        proto=proto,
    )


def _ospf_build(c):
    pdu = str(cfg(c, "pdu", "hello"))
    hdr = OSPF_Hdr(version=2, type={"hello": 1, "dbd": 2, "lsr": 3, "lsu": 4, "lsack": 5}.get(pdu, 1), area="0.0.0.0")
    if pdu == "hello" or OSPF_Hello is not None:
        body = OSPF_Hello(router=cfg(c, "router_id", "1.1.1.1"), backup="0.0.0.0", neighbors=[])
        if pdu == "hello":
            return _eth_ip(c) / hdr / body
    # Fallbacks for other PDUs as Raw skeletons if contrib pieces missing
    skeletons = {
        "dbd": b"\x00\x00\x00\x05\x01\x02\x00\x00" + b"\x00" * 8,
        "lsr": b"\x00\x00\x00\x01" + b"\x01\x01\x01\x01" + b"\x02\x02\x02\x02",
        "lsu": b"\x00\x00\x00\x00",
        "lsack": b"\x00" * 20,
    }
    return _eth_ip(c) / OSPF_Hdr(version=2, type={"dbd": 2, "lsr": 3, "lsu": 4, "lsack": 5}.get(pdu, 1)) / Raw(
        skeletons.get(pdu, b"")
    )


register(
    ProtocolEntry(
        id="ospfv2",
        name="OSPFv2",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", False, "224.0.0.5", advanced=True),
            field("router_id", "Router ID", "ip", True, "1.1.1.1"),
            field(
                "pdu",
                "PDU",
                "select",
                True,
                "hello",
                options=[
                    {"value": "hello", "label": "Hello"},
                    {"value": "dbd", "label": "DBD"},
                    {"value": "lsr", "label": "LSR"},
                    {"value": "lsu", "label": "LSU"},
                    {"value": "lsack", "label": "LSAck"},
                ],
            ),
        ],
        build=_ospf_build,
        template=TemplateMeta("OSPFv2 Hello / DBD / LSR / LSU / LSAck", "IGP adjacency labs"),
    )
)

register(
    ProtocolEntry(
        id="ospfv3",
        name="OSPFv3",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("dst_mac", "Dst MAC", "mac", False, "33:33:00:00:00:05", advanced=True),
            field("src_ip", "Src IPv6", "ipv6", True, "fe80::1"),
            field("dst_ip", "Dst IPv6", "ipv6", False, "ff02::5", advanced=True),
            field("router_id", "Router ID (hex)", "hex", True, "01010101"),
            field(
                "pdu",
                "PDU",
                "select",
                True,
                "hello",
                options=[
                    {"value": "hello", "label": "Hello"},
                    {"value": "dbd", "label": "DBD"},
                    {"value": "lsr", "label": "LSR"},
                    {"value": "lsu", "label": "LSU"},
                    {"value": "lsack", "label": "LSAck"},
                ],
            ),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), nh=89, hlim=1)
        / Raw(
            bytes([3, {"hello": 1, "dbd": 2, "lsr": 3, "lsu": 4, "lsack": 5}[cfg(c, "pdu", "hello")], 0, 0])
            + hex_bytes(cfg(c, "router_id", "01010101"))
            + b"\x00\x00\x00\x00"
            + b"\x00" * 16
        ),
        template=TemplateMeta("OSPFv3 PDU skeleton", "IPv6 IGP labs"),
    )
)


def _isis_build(c):
    pdu = str(cfg(c, "pdu", "hello"))
    eth = Ether(dst="01:80:c2:00:00:14", src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x22F4)
    # ISO 10589-ish common header + hello body skeleton
    sys_id = hex_bytes(cfg(c, "system_id", "010203040506").replace(".", ""))
    if len(sys_id) != 6:
        sys_id = b"\x01\x02\x03\x04\x05\x06"
    common = bytes([0x83, {"hello": 15, "lsp": 18, "csnp": 24, "psnp": 26}.get(pdu, 15), 1, 0, 0])
    if pdu == "hello":
        body = bytes([1, 0, 10]) + sys_id + b"\x00\x00" + b"\x00" * 8
    elif pdu == "lsp":
        body = b"\x00\x00" + sys_id + b"\x00\x00" + b"\x00" * 12
    else:
        body = sys_id + b"\x00" * 16
    return eth / Raw(common + body)


register(
    ProtocolEntry(
        id="isis",
        name="IS-IS",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("system_id", "System ID", "text", True, "0102.0304.0506"),
            field(
                "pdu",
                "PDU",
                "select",
                True,
                "hello",
                options=[
                    {"value": "hello", "label": "Hello"},
                    {"value": "lsp", "label": "LSP"},
                    {"value": "csnp", "label": "CSNP"},
                    {"value": "psnp", "label": "PSNP"},
                ],
            ),
        ],
        build=_isis_build,
        template=TemplateMeta("IS-IS Hello / LSP / CSNP / PSNP", "Also backs Juniper VCCP-style labs"),
    )
)


def _bgp_build(c):
    msg = str(cfg(c, "message", "open"))
    eth = Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
    ip = IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
    tcp = TCP(sport=int(cfg(c, "sport", 179)), dport=int(cfg(c, "dport", 179)), flags="PA", seq=1, ack=1)
    marker = b"\xff" * 16
    if msg == "keepalive":
        body = marker + (19).to_bytes(2, "big") + bytes([4])
    elif msg == "notification":
        body = marker + (21).to_bytes(2, "big") + bytes([3, 1, 1])
    elif msg == "update":
        body = marker + (23).to_bytes(2, "big") + bytes([2]) + b"\x00\x00" + b"\x00\x00"
    else:  # open
        asn = int(cfg(c, "asn", 65001))
        body = (
            marker
            + (29).to_bytes(2, "big")
            + bytes([1, 4])
            + asn.to_bytes(2, "big")
            + int(cfg(c, "hold", 90)).to_bytes(2, "big")
            + bytes(map(int, str(cfg(c, "bgp_id", "1.1.1.1")).split(".")))
            + bytes([0])
        )
    return eth / ip / tcp / Raw(body)


register(
    ProtocolEntry(
        id="bgp",
        name="BGP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("asn", "Local ASN", "int", True, 65001),
            field("bgp_id", "BGP Identifier", "ip", True, "1.1.1.1"),
            field(
                "message",
                "Message",
                "select",
                True,
                "open",
                options=[
                    {"value": "open", "label": "OPEN"},
                    {"value": "keepalive", "label": "KEEPALIVE"},
                    {"value": "notification", "label": "NOTIFICATION"},
                    {"value": "update", "label": "UPDATE"},
                ],
            ),
            field("hold", "Hold time", "int", False, 90, advanced=True),
            field("sport", "TCP sport", "int", False, 179, advanced=True),
            field("dport", "TCP dport", "int", False, 179, advanced=True),
        ],
        build=_bgp_build,
        template=TemplateMeta("BGP OPEN/KEEPALIVE/NOTIFICATION/UPDATE over TCP", "Peering labs"),
    )
)


def _rip_build(c):
    ver = int(cfg(c, "version", 2))
    cmd = 1 if cfg(c, "command", "request") == "request" else 2
    entry = (
        int(cfg(c, "afi", 2)).to_bytes(2, "big")
        + b"\x00\x00"
        + bytes(map(int, str(cfg(c, "prefix", "10.0.0.0")).split(".")))
        + bytes(map(int, str(cfg(c, "mask", "255.255.255.0")).split(".")))
        + bytes(map(int, str(cfg(c, "next_hop", "0.0.0.0")).split(".")))
        + int(cfg(c, "metric", 1)).to_bytes(4, "big")
    )
    return (
        Ether(dst="01:00:5e:00:00:09", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.9", ttl=1, proto=17)
        / UDP(sport=520, dport=520)
        / Raw(bytes([cmd, ver, 0, 0]) + entry)
    )


register(
    ProtocolEntry(
        id="rip",
        name="RIP v1/v2",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field(
                "version",
                "Version",
                "select",
                True,
                "2",
                options=[{"value": "1", "label": "v1"}, {"value": "2", "label": "v2"}],
            ),
            field(
                "command",
                "Command",
                "select",
                True,
                "response",
                options=[{"value": "request", "label": "Request"}, {"value": "response", "label": "Response"}],
            ),
            field("prefix", "Prefix", "ip", True, "10.0.0.0"),
            field("mask", "Mask", "ip", False, "255.255.255.0", advanced=True),
            field("metric", "Metric", "int", False, 1, advanced=True),
        ],
        build=_rip_build,
        template=TemplateMeta("RIP request/response", "Distance-vector labs"),
    )
)

register(
    ProtocolEntry(
        id="ripng",
        name="RIPng",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IPv6", "ipv6", True, "fe80::1"),
            field(
                "command",
                "Command",
                "select",
                True,
                "response",
                options=[{"value": "request", "label": "Request"}, {"value": "response", "label": "Response"}],
            ),
            field("prefix", "Prefix", "ipv6", True, "2001:db8::"),
            field("prefix_len", "Prefix length", "int", False, 64, advanced=True),
            field("metric", "Metric", "int", False, 1, advanced=True),
        ],
        build=lambda c: Ether(dst="33:33:00:00:00:09", src=cfg(c, "src_mac"))
        / IPv6(src=cfg(c, "src_ip"), dst="ff02::9", hlim=255, nh=17)
        / UDP(sport=521, dport=521)
        / Raw(
            bytes([1 if cfg(c, "command") == "request" else 2, 1, 0, 0])
            + b"\x20\x01\x0d\xb8"
            + b"\x00" * 12
            + int(cfg(c, "prefix_len", 64)).to_bytes(1, "big")
            + b"\x00\x00"
            + int(cfg(c, "metric", 1)).to_bytes(1, "big")
        ),
        template=TemplateMeta("RIPng over IPv6", "IPv6 distance-vector labs"),
    )
)


def _eigrp_build(c):
    kind = str(cfg(c, "pdu", "hello"))
    eth = Ether(dst="01:00:5e:00:00:0a", src=cfg(c, "src_mac"))
    ip = IP(src=cfg(c, "src_ip"), dst="224.0.0.10", ttl=2, proto=88)
    asn = int(cfg(c, "asn", 100))
    try:
        if kind == "hello":
            return eth / ip / EIGRP(opcode=5, asn=asn) / EIGRPParam() / EIGRPSwVer()
        return eth / ip / EIGRP(opcode=1, asn=asn) / EIGRPIntRoute(prefix=cfg(c, "prefix", "10.0.0.0/24"))
    except Exception:
        return eth / ip / Raw(bytes([2, 5 if kind == "hello" else 1, 0, 0]) + asn.to_bytes(2, "big") + b"\x00" * 20)


register(
    ProtocolEntry(
        id="eigrp",
        name="EIGRP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("asn", "ASN", "int", True, 100),
            field(
                "pdu",
                "PDU",
                "select",
                True,
                "hello",
                options=[{"value": "hello", "label": "Hello"}, {"value": "update", "label": "Update"}],
            ),
            field("prefix", "Update prefix", "text", False, "10.0.0.0/24", advanced=True),
        ],
        build=_eigrp_build,
        template=TemplateMeta("EIGRP Hello / Update skeletons", "Cisco IGP labs"),
    )
)

register(
    ProtocolEntry(
        id="vrrp",
        name="VRRP v2/v3",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "00:00:5e:00:01:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("vrid", "VRID", "int", True, 1, min=1, max=255),
            field("priority", "Priority", "int", True, 100, min=1, max=255),
            field(
                "version",
                "Version",
                "select",
                True,
                "2",
                options=[{"value": "2", "label": "v2"}, {"value": "3", "label": "v3"}],
            ),
            field("vip", "Virtual IP", "ip", True, "10.0.0.254"),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:12", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.18", ttl=255, proto=112)
        / Raw(
            bytes(
                [
                    (int(cfg(c, "version", 2)) << 4) | 1,
                    int(cfg(c, "vrid", 1)),
                    int(cfg(c, "priority", 100)),
                    1,
                ]
            )
            + b"\x00\x00\x00\x01"
            + bytes(map(int, str(cfg(c, "vip")).split(".")))
        ),
        template=TemplateMeta("VRRP advertisement", "First-hop redundancy labs"),
    )
)

register(
    ProtocolEntry(
        id="hsrp",
        name="HSRP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "00:00:0c:07:ac:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("group", "Group", "int", True, 1),
            field("priority", "Priority", "int", True, 100),
            field("vip", "Virtual IP", "ip", True, "10.0.0.254"),
            field(
                "state",
                "State",
                "select",
                False,
                "16",
                options=[
                    {"value": "0", "label": "Initial"},
                    {"value": "8", "label": "Standby"},
                    {"value": "16", "label": "Active"},
                ],
                advanced=True,
            ),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:02", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.2", ttl=1)
        / UDP(sport=1985, dport=1985)
        / Raw(
            bytes([0, int(cfg(c, "state", 16)), 0, 1, 0, int(cfg(c, "group", 1)), 0, int(cfg(c, "priority", 100))])
            + b"\x00\x00\x00\x00"
            + b"cisco\x00\x00\x00"
            + bytes(map(int, str(cfg(c, "vip")).split(".")))
        ),
        template=TemplateMeta("HSRP hello", "Cisco FHRP labs"),
    )
)

register(
    ProtocolEntry(
        id="glbp",
        name="GLBP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "00:00:0c:07:ac:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("group", "Group", "int", True, 1),
            field("priority", "Priority", "int", True, 100),
            field("vip", "Virtual IP", "ip", True, "10.0.0.254"),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:66", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.102", ttl=1)
        / UDP(sport=3222, dport=3222)
        / Raw(
            b"\x01\x01"
            + int(cfg(c, "group", 1)).to_bytes(2, "big")
            + int(cfg(c, "priority", 100)).to_bytes(1, "big")
            + b"\x00" * 7
            + bytes(map(int, str(cfg(c, "vip")).split(".")))
        ),
        template=TemplateMeta("GLBP hello skeleton", "Gateway load-balancing labs"),
    )
)

register(
    ProtocolEntry(
        id="pim",
        name="PIM",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field(
                "pdu",
                "PDU",
                "select",
                True,
                "hello",
                options=[{"value": "hello", "label": "Hello"}, {"value": "joinprune", "label": "Join/Prune"}],
            ),
            field("group", "Group (J/P)", "ip", False, "239.1.1.1", advanced=True),
        ],
        build=lambda c: Ether(dst="01:00:5e:00:00:0d", src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst="224.0.0.13", ttl=1, proto=103)
        / Raw(
            bytes([(0 << 4) | (1 if cfg(c, "pdu") == "hello" else 3), 0, 0, 0])
            + (b"\x01\x00\x00\x0e\x00\x01\x00\x00" if cfg(c, "pdu") == "hello" else b"\x00" * 16)
        ),
        template=TemplateMeta("PIM Hello / Join-Prune", "Multicast routing labs"),
    )
)

register(
    ProtocolEntry(
        id="bfd",
        name="BFD",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "UDP sport", "int", False, 49152, advanced=True),
            field("dport", "UDP dport", "int", False, 3784, advanced=True),
            field("my_discr", "My discriminator", "int", True, 1),
            field("your_discr", "Your discriminator", "int", False, 0),
            field(
                "state",
                "State",
                "select",
                True,
                "1",
                options=[
                    {"value": "0", "label": "AdminDown"},
                    {"value": "1", "label": "Down"},
                    {"value": "2", "label": "Init"},
                    {"value": "3", "label": "Up"},
                ],
            ),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), ttl=255)
        / UDP(sport=int(cfg(c, "sport", 49152)), dport=int(cfg(c, "dport", 3784)))
        / BFD(
            sta=int(cfg(c, "state", 1)),
            my_discriminator=int(cfg(c, "my_discr", 1)),
            your_discriminator=int(cfg(c, "your_discr", 0)),
            min_tx_interval=1000000,
            min_rx_interval=1000000,
            detect_mult=3,
        ),
        template=TemplateMeta("BFD control packet", "Fast failure detection labs"),
    )
)

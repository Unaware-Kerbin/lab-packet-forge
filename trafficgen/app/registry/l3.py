"""L3 / addressing & ICMP."""
from __future__ import annotations

from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import (
    ICMPv6EchoRequest,
    ICMPv6MLQuery,
    ICMPv6MLReport,
    ICMPv6ND_NA,
    ICMPv6ND_NS,
    ICMPv6ND_RA,
    ICMPv6ND_RS,
    ICMPv6PacketTooBig,
    ICMPv6TimeExceeded,
    IPv6,
)
from scapy.layers.l2 import ARP, Dot1Q, Ether
from scapy.packet import Raw
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mq, IGMPv3mr

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "arp",
    "garp",
    "ipv4",
    "ipv6",
    "icmp",
    "icmpv6",
    "igmp",
    "mld",
)


register(
    ProtocolEntry(
        id="arp",
        name="ARP",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01")
        + [
            field(
                "op",
                "Operation",
                "select",
                True,
                "who-has",
                options=[
                    {"value": "who-has", "label": "Request"},
                    {"value": "is-at", "label": "Reply"},
                    {"value": "1", "label": "Announcement (req)"},
                ],
            ),
            field("psrc", "Sender IP", "ip", True, "10.0.0.1"),
            field("pdst", "Target IP", "ip", True, "10.0.0.2"),
            field("hwsrc", "Sender MAC", "mac", False, "02:00:00:00:00:01", advanced=True),
            field("hwdst", "Target MAC", "mac", False, "00:00:00:00:00:00", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / ARP(
            op=cfg(c, "op", "who-has") if cfg(c, "op") != "1" else "who-has",
            hwsrc=cfg(c, "hwsrc", cfg(c, "src_mac")),
            psrc=cfg(c, "psrc", "10.0.0.1"),
            hwdst=cfg(c, "hwdst", "00:00:00:00:00:00"),
            pdst=cfg(c, "pdst", "10.0.0.2"),
        ),
        template=TemplateMeta(
            "ARP request/reply/announcement",
            "L2–L3 binding labs — keep pps low; floods can DoS switches",
            default_pps=10.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


def _garp_build(c):
    """Gratuitous ARP: SPA == TPA (sender protocol = target protocol)."""
    announced = cfg(c, "psrc", "10.0.0.1")
    tpa = cfg(c, "pdst", announced)
    op = cfg(c, "op", "who-has")
    src_mac = cfg(c, "src_mac", "02:00:00:00:00:01")
    eth = Ether(dst=cfg(c, "dst_mac", "ff:ff:ff:ff:ff:ff"), src=src_mac)
    vlan = cfg(c, "vlan", None)
    if vlan not in (None, "", 0, "0"):
        eth = eth / Dot1Q(vlan=int(vlan))
    # Request GARP: THA zeros; reply GARP: THA often broadcast
    default_hwdst = "00:00:00:00:00:00" if op in ("who-has", "1", 1) else "ff:ff:ff:ff:ff:ff"
    return eth / ARP(
        op=op if op != "1" else "who-has",
        hwsrc=cfg(c, "hwsrc", src_mac),
        psrc=announced,
        hwdst=cfg(c, "hwdst", default_hwdst),
        pdst=tpa,
    )


register(
    ProtocolEntry(
        id="garp",
        name="Gratuitous ARP",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01")
        + [
            field(
                "op",
                "Opcode",
                "select",
                True,
                "who-has",
                options=[
                    {"value": "who-has", "label": "Request GARP (who-has)"},
                    {"value": "is-at", "label": "Reply GARP (is-at)"},
                ],
                hint="SPA==TPA for both; request is most common for conflict detection",
            ),
            field("psrc", "Sender IP (SPA)", "ip", True, "10.0.0.1", hint="Announced IP; TPA defaults to same"),
            field("pdst", "Target IP (TPA)", "ip", True, "10.0.0.1", hint="Must equal SPA for true GARP"),
            field("vlan", "VLAN ID (optional)", "int", False, None, min=1, max=4094, hint="Leave empty for untagged"),
            field("hwsrc", "Sender MAC (SHA)", "mac", False, "02:00:00:00:00:01", advanced=True),
            field("hwdst", "Target MAC (THA)", "mac", False, "00:00:00:00:00:00", advanced=True),
        ],
        build=_garp_build,
        template=TemplateMeta(
            "Gratuitous ARP (SPA==TPA) — request or reply",
            "IP conflict detection, HA/failover VIP announce, and neighbor cache refresh — keep pps low",
            default_pps=10.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)

register(
    ProtocolEntry(
        id="ipv4",
        name="IPv4",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("ttl", "TTL", "int", False, 64, advanced=True),
            field("tos", "ToS/DSCP", "int", False, 0, advanced=True),
            field("proto", "Protocol", "int", False, 253, advanced=True, hint="253 = experimental"),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(
            src=cfg(c, "src_ip"),
            dst=cfg(c, "dst_ip"),
            ttl=int(cfg(c, "ttl", 64)),
            tos=int(cfg(c, "tos", 0)),
            proto=int(cfg(c, "proto", 253)),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("IPv4 header + payload", "Generic L3 path tests"),
    )
)

register(
    ProtocolEntry(
        id="ipv6",
        name="IPv6",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "2001:db8::2"),
            field("hlim", "Hop limit", "int", False, 64, advanced=True),
            field("nh", "Next header", "int", False, 59, advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IPv6(
            src=cfg(c, "src_ip"),
            dst=cfg(c, "dst_ip"),
            hlim=int(cfg(c, "hlim", 64)),
            nh=int(cfg(c, "nh", 59)),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("IPv6 header + payload", "IPv6 forwarding labs"),
    )
)


def _icmp_build(c):
    t = str(cfg(c, "icmp_type", "echo-request"))
    code = int(cfg(c, "code", 0))
    if t in ("echo-request", "8"):
        icmp = ICMP(type=8, code=0, id=int(cfg(c, "id", 0x1234)), seq=int(cfg(c, "seq", 1)))
    elif t in ("echo-reply", "0"):
        icmp = ICMP(type=0, code=0, id=int(cfg(c, "id", 0x1234)), seq=int(cfg(c, "seq", 1)))
    elif t in ("unreachable", "3"):
        icmp = ICMP(type=3, code=code)
    elif t in ("time-exceeded", "11"):
        icmp = ICMP(type=11, code=code)
    elif t in ("redirect", "5"):
        icmp = ICMP(type=5, code=code, gw=cfg(c, "gw", "10.0.0.254"))
    else:
        icmp = ICMP(type=int(t), code=code)
    return (
        Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), ttl=int(cfg(c, "ttl", 64)))
        / icmp
        / Raw(hex_bytes(cfg(c, "payload_hex", "01020304")) or b"forge")
    )


register(
    ProtocolEntry(
        id="icmp",
        name="ICMP",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field(
                "icmp_type",
                "Type",
                "select",
                True,
                "echo-request",
                options=[
                    {"value": "echo-request", "label": "Echo request"},
                    {"value": "echo-reply", "label": "Echo reply"},
                    {"value": "unreachable", "label": "Dest unreachable"},
                    {"value": "time-exceeded", "label": "Time exceeded"},
                    {"value": "redirect", "label": "Redirect"},
                ],
            ),
            field("code", "Code", "int", False, 0, advanced=True),
            field("gw", "Redirect GW", "ip", False, "10.0.0.254", advanced=True),
            field("id", "ID", "int", False, 0x1234, advanced=True),
            field("seq", "Seq", "int", False, 1, advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "01020304", advanced=True),
        ],
        build=_icmp_build,
        template=TemplateMeta("ICMP echo / unreachable / time exceeded / redirect", "Path & ACL tests"),
    )
)


def _icmpv6_build(c):
    kind = str(cfg(c, "kind", "echo"))
    eth = Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
    ip6 = IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), hlim=int(cfg(c, "hlim", 255)))
    if kind == "echo":
        return eth / ip6 / ICMPv6EchoRequest(id=int(cfg(c, "id", 1)), seq=int(cfg(c, "seq", 1)), data=b"forge")
    if kind == "ns":
        return eth / ip6 / ICMPv6ND_NS(tgt=cfg(c, "target", "2001:db8::2"))
    if kind == "na":
        return eth / ip6 / ICMPv6ND_NA(tgt=cfg(c, "target", cfg(c, "src_ip")), R=1, S=1, O=1)
    if kind == "rs":
        return eth / ip6 / ICMPv6ND_RS()
    if kind == "ra":
        return eth / ip6 / ICMPv6ND_RA(chlim=64, routerlifetime=1800)
    if kind == "mld-query":
        return eth / ip6 / ICMPv6MLQuery()
    if kind == "mld-report":
        return eth / ip6 / ICMPv6MLReport(mladdr=cfg(c, "maddr", "ff02::1"))
    if kind == "too-big":
        return eth / ip6 / ICMPv6PacketTooBig(mtu=1280)
    if kind == "time-exceeded":
        return eth / ip6 / ICMPv6TimeExceeded()
    return eth / ip6 / ICMPv6EchoRequest()


register(
    ProtocolEntry(
        id="icmpv6",
        name="ICMPv6 / NDP / MLD",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l4",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "ff02::1"),
            field(
                "kind",
                "Message",
                "select",
                True,
                "echo",
                options=[
                    {"value": "echo", "label": "Echo request"},
                    {"value": "ns", "label": "NDP NS"},
                    {"value": "na", "label": "NDP NA"},
                    {"value": "rs", "label": "NDP RS"},
                    {"value": "ra", "label": "NDP RA"},
                    {"value": "mld-query", "label": "MLD Query"},
                    {"value": "mld-report", "label": "MLD Report"},
                    {"value": "too-big", "label": "Packet Too Big"},
                    {"value": "time-exceeded", "label": "Time Exceeded"},
                ],
            ),
            field("target", "NDP target", "ipv6", False, "2001:db8::2", advanced=True),
            field("maddr", "MLD group", "ipv6", False, "ff02::1", advanced=True),
        ],
        build=_icmpv6_build,
        template=TemplateMeta("ICMPv6 echo, NDP, MLD", "IPv6 neighbor / multicast labs"),
    )
)


def _igmp_build(c):
    ver = str(cfg(c, "version", "2"))
    eth = Ether(dst=cfg(c, "dst_mac", "01:00:5e:00:00:01"), src=cfg(c, "src_mac"))
    ip = IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip", "224.0.0.1"), ttl=1, proto=2)
    g = cfg(c, "group", "224.0.0.1")
    if ver == "3":
        return eth / ip / IGMPv3(type=0x11) / IGMPv3mq(gaddr=g)
    typ = {"1": 0x12, "2": 0x16}.get(ver, 0x16)
    if str(cfg(c, "msg", "report")) == "query":
        typ = 0x11
    elif str(cfg(c, "msg", "report")) == "leave":
        typ = 0x17
    return eth / ip / IGMP(type=typ, gaddr=g)


register(
    ProtocolEntry(
        id="igmp",
        name="IGMP v1/v2/v3",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l4",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("dst_mac", "Dst MAC", "mac", False, "01:00:5e:00:00:01", advanced=True),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", False, "224.0.0.1", advanced=True),
            field(
                "version",
                "Version",
                "select",
                True,
                "2",
                options=[{"value": "1", "label": "v1"}, {"value": "2", "label": "v2"}, {"value": "3", "label": "v3"}],
            ),
            field(
                "msg",
                "Message",
                "select",
                False,
                "report",
                options=[
                    {"value": "query", "label": "Query"},
                    {"value": "report", "label": "Report"},
                    {"value": "leave", "label": "Leave"},
                ],
                advanced=True,
            ),
            field("group", "Group", "ip", True, "239.1.1.1"),
        ],
        build=_igmp_build,
        template=TemplateMeta(
            "IGMP membership query/report/leave",
            "Multicast join labs — flood rates can overwhelm IGMP snooping",
            default_pps=10.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)

register(
    ProtocolEntry(
        id="mld",
        name="MLD v1/v2",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l4",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("dst_mac", "Dst MAC", "mac", False, "33:33:00:00:00:01", advanced=True),
            field("src_ip", "Src IPv6", "ipv6", True, "fe80::1"),
            field("dst_ip", "Dst IPv6", "ipv6", False, "ff02::1", advanced=True),
            field(
                "kind",
                "Message",
                "select",
                True,
                "query",
                options=[{"value": "query", "label": "Query"}, {"value": "report", "label": "Report"}],
            ),
            field("maddr", "Multicast addr", "ipv6", False, "ff02::1", advanced=True),
        ],
        build=lambda c: (
            Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
            / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), hlim=1)
            / (ICMPv6MLQuery() if cfg(c, "kind") == "query" else ICMPv6MLReport(mladdr=cfg(c, "maddr", "ff02::1")))
        ),
        template=TemplateMeta(
            "MLD query/report",
            "IPv6 multicast labs — keep pps modest",
            default_pps=10.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)

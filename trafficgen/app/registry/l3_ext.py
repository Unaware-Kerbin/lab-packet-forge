"""Additional L3 / IPv6 / transport-adjacent protocols."""
from __future__ import annotations

import struct

from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrRouting,
    ICMPv6ND_NS,
    ICMPv6ND_NA,
    ICMPv6ND_RA,
    ICMPv6NDOptSrcLLAddr,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptMTU,
)
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "ipv6_hbh",
    "ipv6_destopt",
    "ipv6_frag",
    "ipv6_rh",
    "srv6",
    "ndp_opts",
    "hip",
    "mobile_ip",
    "dccp",
    "quic_probe",
    "rsvp",
    "l2tp",
    "pptp",
    "openvpn",
)


def _e4(c):
    return Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


def _e6(c):
    return Ether(dst=cfg(c, "dst_mac", "33:33:00:00:00:01"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


register(
    ProtocolEntry(
        id="ipv6_hbh",
        name="IPv6 Hop-by-Hop",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "2001:db8::2"),
            field("payload_hex", "Payload (hex)", "hex", False, "3a00", advanced=True),
        ],
        build=lambda c: _e6(c)
        / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), nh=0)
        / IPv6ExtHdrHopByHop(nh=59)
        / Raw(hex_bytes(cfg(c, "payload_hex", "")) or b""),
        template=TemplateMeta("IPv6 with Hop-by-Hop options header", "Extension-header path labs"),
    )
)

register(
    ProtocolEntry(
        id="ipv6_destopt",
        name="IPv6 Destination Options",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "2001:db8::2"),
        ],
        build=lambda c: _e6(c)
        / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), nh=60)
        / IPv6ExtHdrDestOpt(nh=59),
        template=TemplateMeta("IPv6 Destination Options header", "Extension-header ACL labs"),
    )
)

register(
    ProtocolEntry(
        id="ipv6_frag",
        name="IPv6 Fragment",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "2001:db8::2"),
            field("id", "Fragment ID", "int", True, 0x1234),
            field("offset", "Offset (8-byte units)", "int", False, 0, advanced=True),
            field("m", "More fragments", "bool", False, True, advanced=True),
            field("payload_hex", "Fragment body (hex)", "hex", False, "deadbeef" * 4, advanced=True),
        ],
        build=lambda c: _e6(c)
        / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), nh=44)
        / IPv6ExtHdrFragment(
            nh=59,
            offset=int(cfg(c, "offset", 0)),
            m=1 if cfg(c, "m", True) in (True, "true", "1", 1) else 0,
            id=int(cfg(c, "id", 0x1234)),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef" * 4))),
        template=TemplateMeta("IPv6 fragment header + body", "Reassembly / PMTU labs"),
    )
)

register(
    ProtocolEntry(
        id="ipv6_rh",
        name="IPv6 Routing Header",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Dst IPv6", "ipv6", True, "2001:db8::2"),
            field("seg0", "Segment 0", "ipv6", True, "2001:db8::10"),
            field("seg1", "Segment 1", "ipv6", False, "2001:db8::20", advanced=True),
        ],
        build=lambda c: _e6(c)
        / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), nh=43)
        / IPv6ExtHdrRouting(
            nh=59,
            type=0,
            segleft=1 if cfg(c, "seg1") else 0,
            addresses=[cfg(c, "seg0", "2001:db8::10")]
            + ([cfg(c, "seg1")] if cfg(c, "seg1") else []),
        ),
        template=TemplateMeta("IPv6 Routing Header (type 0 skeleton)", "Source-routing labs"),
    )
)


def _srv6_build(c):
    # SRv6 = IPv6 + Routing Header type 4 (SRH)
    segs = [cfg(c, "sid0", "2001:db8:1::1"), cfg(c, "sid1", "2001:db8:2::1")]
    if cfg(c, "sid2"):
        segs.append(cfg(c, "sid2"))
    try:
        rh = IPv6ExtHdrRouting(nh=59, type=4, segleft=len(segs) - 1, addresses=list(reversed(segs)))
    except Exception:
        # Manual SRH: next_hdr, hdr_ext_len, routing_type=4, segments_left, …
        addrs = b"".join(__import__("ipaddress").IPv6Address(s).packed for s in reversed(segs))
        rh = Raw(bytes([59, len(segs) * 2, 4, len(segs) - 1, 0, 0, 0, 0]) + addrs)
        return _e6(c) / IPv6(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), nh=43) / rh
    return _e6(c) / IPv6(src=cfg(c, "src_ip", "2001:db8::1"), dst=cfg(c, "dst_ip", segs[0]), nh=43) / rh


register(
    ProtocolEntry(
        id="srv6",
        name="SRv6 (SRH)",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IPv6", "ipv6", True, "2001:db8::1"),
            field("dst_ip", "Active SID (dst)", "ipv6", True, "2001:db8:1::1"),
            field("sid0", "SID 0", "ipv6", True, "2001:db8:1::1"),
            field("sid1", "SID 1", "ipv6", True, "2001:db8:2::1"),
            field("sid2", "SID 2 (optional)", "ipv6", False, "", advanced=True),
        ],
        build=_srv6_build,
        template=TemplateMeta("Segment Routing over IPv6 (SRH type 4)", "SRv6 underlay labs"),
    )
)


def _ndp_opts(c):
    kind = str(cfg(c, "msg", "ra"))
    base = _e6(c) / IPv6(src=cfg(c, "src_ip", "fe80::1"), dst=cfg(c, "dst_ip", "ff02::1"), hlim=255)
    if kind == "ns":
        return (
            base
            / ICMPv6ND_NS(tgt=cfg(c, "target", "2001:db8::2"))
            / ICMPv6NDOptSrcLLAddr(lladdr=cfg(c, "src_mac", "02:00:00:00:00:01"))
        )
    if kind == "na":
        return (
            base
            / ICMPv6ND_NA(tgt=cfg(c, "target", "2001:db8::1"), R=1, S=1, O=1)
            / ICMPv6NDOptSrcLLAddr(lladdr=cfg(c, "src_mac", "02:00:00:00:00:01"))
        )
    return (
        base
        / ICMPv6ND_RA(chlim=64, routerlifetime=1800)
        / ICMPv6NDOptSrcLLAddr(lladdr=cfg(c, "src_mac", "02:00:00:00:00:01"))
        / ICMPv6NDOptMTU(mtu=int(cfg(c, "mtu", 1500)))
        / ICMPv6NDOptPrefixInfo(
            prefixlen=int(cfg(c, "prefixlen", 64)),
            prefix=cfg(c, "prefix", "2001:db8::"),
            validlifetime=2592000,
            preferredlifetime=604800,
        )
    )


register(
    ProtocolEntry(
        id="ndp_opts",
        name="NDP with options",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("33:33:00:00:00:01", "02:00:00:00:00:01")
        + [
            field(
                "msg",
                "Message",
                "select",
                True,
                "ra",
                options=[
                    {"value": "ra", "label": "RA + prefix/MTU/SLL"},
                    {"value": "ns", "label": "NS + SLL"},
                    {"value": "na", "label": "NA + TLL"},
                ],
            ),
            field("src_ip", "Src IPv6", "ipv6", True, "fe80::1"),
            field("dst_ip", "Dst IPv6", "ipv6", False, "ff02::1", advanced=True),
            field("target", "Target", "ipv6", False, "2001:db8::2", advanced=True),
            field("prefix", "RA prefix", "ipv6", False, "2001:db8::", advanced=True),
            field("prefixlen", "Prefix length", "int", False, 64, advanced=True),
            field("mtu", "MTU option", "int", False, 1500, advanced=True),
        ],
        build=_ndp_opts,
        template=TemplateMeta(
            "ICMPv6 NDP with common options",
            "IPv6 first-hop / SLAAC labs",
            default_pps=2.0,
            soft_pps_cap=10.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="hip",
        name="HIP (Host Identity)",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field(
                "packet",
                "Packet type",
                "select",
                True,
                "i1",
                options=[
                    {"value": "i1", "label": "I1"},
                    {"value": "r1", "label": "R1"},
                    {"value": "i2", "label": "I2"},
                    {"value": "r2", "label": "R2"},
                ],
            ),
        ],
        build=lambda c: _e4(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=139)
        / Raw(
            bytes([1, {"i1": 1, "r1": 2, "i2": 3, "r2": 4}.get(str(cfg(c, "packet", "i1")), 1), 0, 0])
            + b"\x00" * 20
        ),
        template=TemplateMeta("HIP control packet skeleton (IP proto 139)", "Host Identity Protocol labs"),
    )
)


register(
    ProtocolEntry(
        id="mobile_ip",
        name="Mobile IPv4",
        category="L3 / addressing & ICMP",
        layer="l3",
        craft_slot="l3",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (CoA)", "ip", True, "10.0.0.50"),
            field("dst_ip", "HA IP", "ip", True, "10.0.0.1"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "rrq",
                options=[
                    {"value": "rrq", "label": "Registration Request"},
                    {"value": "rrp", "label": "Registration Reply"},
                ],
            ),
            field("home_addr", "Home address", "ip", True, "192.0.2.10"),
            field("ha_addr", "Home agent", "ip", True, "10.0.0.1"),
            field("coa", "Care-of address", "ip", True, "10.0.0.50"),
        ],
        build=lambda c: _e4(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=434, dport=434)
        / Raw(
            bytes([1 if str(cfg(c, "msg", "rrq")) == "rrq" else 3, 0, 0, 0])
            + __import__("ipaddress").IPv4Address(cfg(c, "home_addr", "192.0.2.10")).packed
            + __import__("ipaddress").IPv4Address(cfg(c, "ha_addr", "10.0.0.1")).packed
            + __import__("ipaddress").IPv4Address(cfg(c, "coa", "10.0.0.50")).packed
            + struct.pack("!I", 1800)
        ),
        template=TemplateMeta("Mobile IPv4 registration skeleton (UDP/434)", "Mobility agent labs"),
    )
)


register(
    ProtocolEntry(
        id="dccp",
        name="DCCP",
        category="L4 / transport",
        layer="l4",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 12345),
            field("dport", "Dst port", "int", True, 5001),
            field(
                "type",
                "Packet type",
                "select",
                True,
                "request",
                options=[
                    {"value": "request", "label": "Request"},
                    {"value": "response", "label": "Response"},
                    {"value": "data", "label": "Data"},
                    {"value": "ack", "label": "Ack"},
                ],
            ),
            field("payload", "Payload text", "text", False, "forge-dccp", advanced=True),
        ],
        build=lambda c: _e4(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=33)
        / Raw(
            struct.pack(
                "!HHBBH",
                int(cfg(c, "sport", 12345)),
                int(cfg(c, "dport", 5001)),
                1,
                {"request": 0, "response": 1, "data": 2, "ack": 3}.get(str(cfg(c, "type", "request")), 0) << 1,
                0,
            )
            + str(cfg(c, "payload", "forge-dccp")).encode()
        ),
        template=TemplateMeta("DCCP header skeleton (IP proto 33)", "Congestion-controlled datagram labs"),
    )
)


def _quic_probe(c):
    # QUIC long header Initial-shaped UDP/443
    version = bytes.fromhex(str(cfg(c, "version", "00000001")).replace("0x", "").zfill(8)[-8:])
    dcid = hex_bytes(cfg(c, "dcid_hex", "01" * 8))
    scid = hex_bytes(cfg(c, "scid_hex", "02" * 8))
    # long hdr: 0xc0 | version | dcid_len | dcid | scid_len | scid | token_len=0 | length | pktnum
    body = bytes([0xC0]) + version + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00" + b"\x40\x10" + b"\x00" * 16
    return (
        _e4(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / UDP(sport=int(cfg(c, "sport", 40000)), dport=int(cfg(c, "dport", 443)))
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="quic_probe",
        name="QUIC Initial probe",
        category="L4 / transport",
        layer="l4",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", False, 40000, advanced=True),
            field("dport", "Dst port", "int", True, 443),
            field("version", "QUIC version (hex)", "hex", False, "00000001", advanced=True),
            field("dcid_hex", "DCID (hex)", "hex", False, "01" * 8, advanced=True),
            field("scid_hex", "SCID (hex)", "hex", False, "02" * 8, advanced=True),
        ],
        build=_quic_probe,
        template=TemplateMeta("QUIC long-header Initial-shaped UDP", "HTTP/3 / firewall path labs"),
    )
)


def _rsvp_build(c):
    try:
        from scapy.contrib.rsvp import RSVP, RSVP_Path, RSVP_Resv
    except Exception:
        RSVP = RSVP_Path = RSVP_Resv = None  # type: ignore
    msg = str(cfg(c, "msg", "path"))
    if RSVP is not None:
        try:
            body = RSVP_Path() if msg == "path" else RSVP_Resv()
            return _e4(c) / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=46, tos=0xC0) / RSVP() / body
        except Exception:
            pass
    mtype = 1 if msg == "path" else 2
    return _e4(c) / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"), proto=46, tos=0xC0) / Raw(
        bytes([1, mtype, 0x0F, 0x01, 0, 20, 0, 0]) + b"\x00" * 12
    )


register(
    ProtocolEntry(
        id="rsvp",
        name="RSVP",
        category="Routing & first-hop",
        layer="routing",
        craft_slot="control",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "path",
                options=[{"value": "path", "label": "Path"}, {"value": "resv", "label": "Resv"}],
            ),
        ],
        build=_rsvp_build,
        template=TemplateMeta(
            "RSVP Path/Resv skeleton",
            "TE / reservation labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="l2tp",
        name="L2TPv2",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("tunnel_id", "Tunnel ID", "int", True, 1),
            field("session_id", "Session ID", "int", True, 1),
            field(
                "msg",
                "Message",
                "select",
                True,
                "sccrq",
                options=[
                    {"value": "sccrq", "label": "SCCRQ"},
                    {"value": "data", "label": "Data"},
                ],
            ),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: _e4(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=1701, dport=1701)
        / Raw(
            (
                struct.pack("!HHHH", 0xC802, 12, int(cfg(c, "tunnel_id", 1)), int(cfg(c, "session_id", 1)))
                if str(cfg(c, "msg", "sccrq")) == "sccrq"
                else struct.pack("!HH", int(cfg(c, "tunnel_id", 1)), int(cfg(c, "session_id", 1)))
            )
            + hex_bytes(cfg(c, "payload_hex", "deadbeef"))
        ),
        template=TemplateMeta("L2TPv2 control/data skeleton (UDP/1701)", "VPN / VPDN labs"),
    )
)


register(
    ProtocolEntry(
        id="pptp",
        name="PPTP (GRE call)",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("call_id", "Call ID", "int", True, 1),
            field("payload_hex", "PPP-looking body (hex)", "hex", False, "ff03c021", advanced=True),
        ],
        build=lambda c: _e4(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"), proto=47)
        / Raw(struct.pack("!BBHHH", 0x30, 0x01, 0x880B, int(cfg(c, "call_id", 1)), 0) + hex_bytes(cfg(c, "payload_hex", "ff03c021"))),
        template=TemplateMeta("PPTP-style GRE (ethertype 0x880B)", "Legacy VPN path labs"),
    )
)


register(
    ProtocolEntry(
        id="openvpn",
        name="OpenVPN-shaped UDP",
        category="Tunnels / overlays",
        layer="tunnel",
        craft_slot="tunnel",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 1194),
            field("dport", "Dst port", "int", True, 1194),
            field(
                "opcode",
                "Opcode",
                "select",
                True,
                "data",
                options=[
                    {"value": "p_control_v1", "label": "P_CONTROL_V1"},
                    {"value": "data", "label": "P_DATA_V1"},
                    {"value": "ack", "label": "P_ACK_V1"},
                ],
            ),
            field("payload_hex", "Body (hex)", "hex", False, "00" * 16, advanced=True),
        ],
        build=lambda c: _e4(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=int(cfg(c, "sport", 1194)), dport=int(cfg(c, "dport", 1194)))
        / Raw(
            bytes(
                [
                    {
                        "p_control_v1": 0x38,
                        "data": 0x48,
                        "ack": 0x28,
                    }.get(str(cfg(c, "opcode", "data")), 0x48)
                ]
            )
            + hex_bytes(cfg(c, "payload_hex", "00" * 16))
        ),
        template=TemplateMeta("OpenVPN opcode-shaped UDP/1194", "VPN ACL / DPI path tests"),
    )
)

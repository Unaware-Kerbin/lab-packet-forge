"""Telecom / voice / signaling lab templates."""
from __future__ import annotations

import struct

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.sctp import SCTP, SCTPChunkData
from scapy.packet import Raw

try:
    from scapy.contrib.diameter import DiamG
except Exception:
    DiamG = None  # type: ignore

try:
    from scapy.contrib.rtcp import RTCP
except Exception:
    RTCP = None  # type: ignore

try:
    from scapy.contrib.pfcp import PFCP
except Exception:
    PFCP = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "diameter",
    "sip_invite",
    "sip_options",
    "rtp",
    "rtcp",
    "pfcp",
    "sctp_data",
    "skinny",
    "megaco",
)


def _e(c):
    return Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))


def _diameter(c):
    if DiamG is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / SCTP(sport=int(cfg(c, "sport", 3868)), dport=int(cfg(c, "dport", 3868)), tag=1)
                / SCTPChunkData(data=bytes(DiamG(flags="R", cmd=257)))  # CER
            )
        except Exception:
            pass
    # Diameter CER-shaped header: version, length, flags, code=257, app-id, hop/end
    body = bytes([1]) + struct.pack("!I", 20)[1:] + bytes([0x80]) + struct.pack("!I", 257)[1:]
    body += struct.pack("!III", 0, int(cfg(c, "hbh", 1)), int(cfg(c, "e2e", 1)))
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / SCTP(sport=int(cfg(c, "sport", 3868)), dport=int(cfg(c, "dport", 3868)), tag=1)
        / SCTPChunkData(tsn=1, stream_id=0, stream_seq=0, proto_id=46, data=body)
    )


register(
    ProtocolEntry(
        id="diameter",
        name="Diameter CER",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "SCTP sport", "int", False, 3868, advanced=True),
            field("dport", "SCTP dport", "int", True, 3868),
            field("hbh", "Hop-by-hop ID", "int", False, 1, advanced=True),
            field("e2e", "End-to-end ID", "int", False, 1, advanced=True),
        ],
        build=_diameter,
        template=TemplateMeta(
            "Diameter Capabilities-Exchange Request over SCTP",
            "AAA / EPC signaling labs",
            default_pps=5.0,
            soft_pps_cap=20.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


def _sip(c, method="INVITE"):
    call_id = str(cfg(c, "call_id", "forge-call-1"))
    from_u = str(cfg(c, "from_uri", "sip:alice@10.0.0.1"))
    to_u = str(cfg(c, "to_uri", "sip:bob@10.0.0.2"))
    body = (
        f"{method} {to_u} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {cfg(c, 'src_ip', '10.0.0.1')}:5060;branch=z9hG4bK-forge\r\n"
        f"From: <{from_u}>;tag=forge\r\n"
        f"To: <{to_u}>\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: 1 {method}\r\n"
        f"Contact: <{from_u}>\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n\r\n"
    ).encode()
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / UDP(sport=5060, dport=int(cfg(c, "dport", 5060)))
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="sip_invite",
        name="SIP INVITE",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 5060),
            field("from_uri", "From URI", "text", True, "sip:alice@10.0.0.1"),
            field("to_uri", "To URI", "text", True, "sip:bob@10.0.0.2"),
            field("call_id", "Call-ID", "text", False, "forge-call-1", advanced=True),
        ],
        build=lambda c: _sip(c, "INVITE"),
        template=TemplateMeta("SIP INVITE", "VoIP signaling labs"),
    )
)

register(
    ProtocolEntry(
        id="sip_options",
        name="SIP OPTIONS",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 5060),
            field("from_uri", "From URI", "text", True, "sip:probe@10.0.0.1"),
            field("to_uri", "To URI", "text", True, "sip:proxy@10.0.0.2"),
        ],
        build=lambda c: _sip(c, "OPTIONS"),
        template=TemplateMeta("SIP OPTIONS probe", "SIP aliveness / ALG labs"),
    )
)


register(
    ProtocolEntry(
        id="rtp",
        name="RTP",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 10000),
            field("dport", "Dst port", "int", True, 10000),
            field("pt", "Payload type", "int", True, 0, hint="0=PCMU"),
            field("seq", "Sequence", "int", False, 1, advanced=True),
            field("ts", "Timestamp", "int", False, 160, advanced=True),
            field("ssrc", "SSRC", "int", False, 0x12345678, advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "ff" * 20, advanced=True),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=int(cfg(c, "sport", 10000)), dport=int(cfg(c, "dport", 10000)))
        / Raw(
            bytes([0x80, int(cfg(c, "pt", 0)) & 0x7F])
            + struct.pack("!HII", int(cfg(c, "seq", 1)), int(cfg(c, "ts", 160)), int(cfg(c, "ssrc", 0x12345678)))
            + hex_bytes(cfg(c, "payload_hex", "ff" * 20))
        ),
        template=TemplateMeta("RTP media packet", "Voice/video path labs", default_pps=50),
    )
)


def _rtcp_build(c):
    if RTCP is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / UDP(sport=int(cfg(c, "sport", 10001)), dport=int(cfg(c, "dport", 10001)))
                / RTCP()
            )
        except Exception:
            pass
    # SR packet skeleton
    body = bytes([0x80, 200, 0, 6]) + struct.pack("!I", int(cfg(c, "ssrc", 0x12345678))) + b"\x00" * 20
    return (
        _e(c)
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / UDP(sport=int(cfg(c, "sport", 10001)), dport=int(cfg(c, "dport", 10001)))
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="rtcp",
        name="RTCP SR",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 10001),
            field("dport", "Dst port", "int", True, 10001),
            field("ssrc", "SSRC", "int", False, 0x12345678, advanced=True),
        ],
        build=_rtcp_build,
        template=TemplateMeta("RTCP Sender Report skeleton", "Media control labs"),
    )
)


def _pfcp_build(c):
    if PFCP is not None:
        try:
            return (
                _e(c)
                / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
                / UDP(sport=8805, dport=8805)
                / PFCP()
            )
        except Exception:
            pass
    msg = {"hb_req": 1, "assoc_setup_req": 5, "session_est_req": 50}.get(str(cfg(c, "msg", "hb_req")), 1)
    # PFCP header: flags, type, length, SEID?, seq
    hdr = bytes([0x20, msg]) + struct.pack("!HI", 4, int(cfg(c, "seq", 1)) << 8)
    return _e(c) / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2")) / UDP(sport=8805, dport=8805) / Raw(hdr)


register(
    ProtocolEntry(
        id="pfcp",
        name="PFCP",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field(
                "msg",
                "Message",
                "select",
                True,
                "hb_req",
                options=[
                    {"value": "hb_req", "label": "Heartbeat Request"},
                    {"value": "assoc_setup_req", "label": "Association Setup Req"},
                    {"value": "session_est_req", "label": "Session Establishment Req"},
                ],
            ),
            field("seq", "Sequence", "int", False, 1, advanced=True),
        ],
        build=_pfcp_build,
        template=TemplateMeta(
            "PFCP control (UDP/8805)",
            "5GC / UPF control labs",
            default_pps=5.0,
            soft_pps_cap=20.0,
            hard_pps_cap=100.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="sctp_data",
        name="SCTP DATA (deep)",
        category="L4 / transport",
        layer="l4",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 2905),
            field("dport", "Dst port", "int", True, 2905),
            field("tag", "Verification tag", "int", False, 1, advanced=True),
            field("tsn", "TSN", "int", False, 1, advanced=True),
            field("ppid", "Payload Protocol ID", "int", True, 3, hint="3=M3UA"),
            field("payload", "Payload text", "text", False, "forge-sctp"),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / SCTP(sport=int(cfg(c, "sport", 2905)), dport=int(cfg(c, "dport", 2905)), tag=int(cfg(c, "tag", 1)))
        / SCTPChunkData(
            tsn=int(cfg(c, "tsn", 1)),
            stream_id=0,
            stream_seq=0,
            proto_id=int(cfg(c, "ppid", 3)),
            data=str(cfg(c, "payload", "forge-sctp")).encode(),
        ),
        template=TemplateMeta("SCTP DATA with PPID (e.g. M3UA)", "SS7/SIGTRAN path labs"),
    )
)


register(
    ProtocolEntry(
        id="skinny",
        name="Skinny (SCCP) KeepAlive",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 2000),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / TCP(sport=40000, dport=int(cfg(c, "dport", 2000)), flags="PA", seq=1, ack=1)
        / Raw(struct.pack("<III", 4, 0, 0x0000)),  # length, reserved, KeepAliveMsg
        template=TemplateMeta("Cisco Skinny KeepAlive", "CUCM / SCCP path labs"),
    )
)


register(
    ProtocolEntry(
        id="megaco",
        name="Megaco/H.248 Audit",
        category="Telecom / mobile",
        layer="app",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP (MGC)", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP (MG)", "ip", True, "10.0.0.2"),
            field("dport", "Dst port", "int", True, 2944),
        ],
        build=lambda c: _e(c)
        / IP(src=cfg(c, "src_ip"), dst=cfg(c, "dst_ip"))
        / UDP(sport=2944, dport=int(cfg(c, "dport", 2944)))
        / Raw(b'MEGACO/1 [10.0.0.1]:2944 Transaction = 1 { Context = - { AuditValue = * { Audit { Media } } } }'),
        template=TemplateMeta("Megaco text AuditValue", "Media gateway control labs"),
    )
)

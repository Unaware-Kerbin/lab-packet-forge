"""L4 / transport."""
from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.layers.sctp import SCTP, SCTPChunkData, SCTPChunkInit
from scapy.packet import Raw

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect("udp", "tcp", "sctp")


def _l3(c):
    eth = Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
    if cfg(c, "ip_version", "4") == "6":
        return eth / IPv6(src=cfg(c, "src_ip", "2001:db8::1"), dst=cfg(c, "dst_ip", "2001:db8::2"))
    return eth / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"), ttl=int(cfg(c, "ttl", 64)))


register(
    ProtocolEntry(
        id="udp",
        name="UDP",
        category="L4 / transport",
        layer="l4",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 12345, min=0, max=65535),
            field("dport", "Dst port", "int", True, 5001, min=0, max=65535),
            field("payload", "Payload text", "text", False, "forge-udp"),
            field("payload_hex", "Payload hex (overrides text)", "hex", False, "", advanced=True),
            field("ttl", "TTL", "int", False, 64, advanced=True),
        ],
        build=lambda c: _l3(c)
        / UDP(sport=int(cfg(c, "sport", 12345)), dport=int(cfg(c, "dport", 5001)))
        / Raw(hex_bytes(cfg(c, "payload_hex", "")) or str(cfg(c, "payload", "forge-udp")).encode()),
        template=TemplateMeta("UDP datagram", "Simple throughput / ACL labs", default_pps=100),
    )
)


def _tcp_flags(s: str) -> int:
    mapping = {"F": "F", "S": "S", "R": "R", "P": "P", "A": "A", "U": "U", "E": "E", "C": "C"}
    s = str(s).upper()
    if s.isdigit():
        return int(s)
    flags = ""
    for ch in s.replace("|", "").replace(",", "").replace(" ", ""):
        if ch in mapping:
            flags += ch
    return flags or "S"


register(
    ProtocolEntry(
        id="tcp",
        name="TCP",
        category="L4 / transport",
        layer="l4",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 40000, min=0, max=65535),
            field("dport", "Dst port", "int", True, 80, min=0, max=65535),
            field("flags", "Flags", "text", True, "S", hint="S, SA, A, FA, R, …"),
            field("seq", "Seq", "int", False, 1000, advanced=True),
            field("ack", "Ack", "int", False, 0, advanced=True),
            field("window", "Window", "int", False, 8192, advanced=True),
            field("options_mss", "MSS option", "int", False, 1460, advanced=True),
            field("payload", "Payload text", "text", False, "", advanced=True),
        ],
        build=lambda c: _l3(c)
        / TCP(
            sport=int(cfg(c, "sport", 40000)),
            dport=int(cfg(c, "dport", 80)),
            flags=_tcp_flags(cfg(c, "flags", "S")),
            seq=int(cfg(c, "seq", 1000)),
            ack=int(cfg(c, "ack", 0)),
            window=int(cfg(c, "window", 8192)),
            options=[("MSS", int(cfg(c, "options_mss", 1460)))] if int(cfg(c, "options_mss", 0) or 0) else [],
        )
        / Raw(str(cfg(c, "payload", "")).encode()),
        template=TemplateMeta("TCP with flags/seq/ack/options", "Handshake & firewall labs"),
    )
)


def _sctp_build(c):
    kind = str(cfg(c, "chunk", "data"))
    eth_ip = _l3(c)
    if kind == "init":
        chunk = SCTPChunkInit(init_tag=int(cfg(c, "init_tag", 1)), a_rwnd=65535, n_out_stream=1, n_in_stream=1, init_tsn=1)
    else:
        chunk = SCTPChunkData(
            tsn=int(cfg(c, "tsn", 1)),
            stream_id=0,
            stream_seq=0,
            proto_id=0,
            data=str(cfg(c, "payload", "forge-sctp")).encode(),
        )
    return eth_ip / SCTP(sport=int(cfg(c, "sport", 10000)), dport=int(cfg(c, "dport", 10000)), tag=int(cfg(c, "tag", 0))) / chunk


register(
    ProtocolEntry(
        id="sctp",
        name="SCTP",
        category="L4 / transport",
        layer="l4",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", True, 10000),
            field("dport", "Dst port", "int", True, 10000),
            field(
                "chunk",
                "Chunk",
                "select",
                True,
                "data",
                options=[{"value": "init", "label": "INIT"}, {"value": "data", "label": "DATA"}],
            ),
            field("tag", "Verification tag", "int", False, 0, advanced=True),
            field("init_tag", "Init tag", "int", False, 1, advanced=True),
            field("tsn", "TSN", "int", False, 1, advanced=True),
            field("payload", "DATA payload", "text", False, "forge-sctp", advanced=True),
        ],
        build=_sctp_build,
        template=TemplateMeta("SCTP INIT / DATA chunks", "Telecom / multi-homing labs"),
    )
)

"""Additional L2 / bridging / DC fabric protocols."""
from __future__ import annotations

import struct

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.packet import Raw

try:
    from scapy.contrib.lldp import (
        LLDPDU,
        LLDPDUChassisID,
        LLDPDUPortID,
        LLDPDUTimeToLive,
        LLDPDUSystemName,
        LLDPDUSystemDescription,
        LLDPDUPortDescription,
        LLDPDUManagementAddress,
        LLDPDUEndOfLLDPDU,
    )
except Exception:
    LLDPDU = None  # type: ignore

try:
    from scapy.contrib.macsec import MACsec
except Exception:
    MACsec = None  # type: ignore

try:
    from scapy.contrib.ptp import PTPv2
except Exception:
    try:
        from scapy.contrib.ptp_v2 import PTPv2  # type: ignore
    except Exception:
        PTPv2 = None  # type: ignore

try:
    from scapy.contrib.carp import CARP
except Exception:
    CARP = None  # type: ignore

try:
    from scapy.contrib.esmc import ESMC
except Exception:
    ESMC = None  # type: ignore

try:
    from scapy.contrib.roce import BTH
except Exception:
    BTH = None  # type: ignore

try:
    from scapy.contrib.openflow import _ofp_header as OFPHeader  # type: ignore
except Exception:
    try:
        from scapy.contrib.openflow3 import OpenFlow  # type: ignore

        OFPHeader = None
    except Exception:
        OFPHeader = OpenFlow = None  # type: ignore

from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

expect(
    "lldp_full",
    "macsec",
    "ptp",
    "carp",
    "mrp_mmrp",
    "mrp_mvrp",
    "erp_g8032",
    "trill",
    "fcoe",
    "fip",
    "rocev2",
    "esmc",
    "openflow_hello",
    "spb_isid",
    "pbb_itag",
)


def _eth(c, type_=None):
    pkt = Ether(dst=cfg(c, "dst_mac", "01:80:c2:00:00:0e"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))
    if type_ is not None:
        pkt.type = int(type_)
    return pkt


def _lldp_full(c):
    if LLDPDU is None:
        return _eth(c, 0x88CC) / Raw(b"\x02\x07\x04" + b"\x02\x00\x00\x00\x00\x01" + b"\x00\x00")
    chassis = LLDPDUChassisID(subtype=4, id=bytes.fromhex(cfg(c, "src_mac", "02:00:00:00:00:01").replace(":", "")))
    port = LLDPDUPortID(subtype=5, id=str(cfg(c, "port_id", "eth1")).encode())
    ttl = LLDPDUTimeToLive(ttl=int(cfg(c, "ttl", 120)))
    layers = [
        LLDPDU(),
        chassis,
        port,
        ttl,
        LLDPDUSystemName(system_name=str(cfg(c, "sys_name", "forge-sw1"))),
        LLDPDUPortDescription(description=str(cfg(c, "port_desc", "lab-uplink"))),
        LLDPDUSystemDescription(description=str(cfg(c, "sys_desc", "Lab Packet Forge LLDP"))),
    ]
    try:
        import ipaddress

        layers.append(
            LLDPDUManagementAddress(
                management_address_subtype=1,
                management_address=ipaddress.IPv4Address(cfg(c, "mgmt_ip", "10.0.0.1")).packed,
                interface_numbering_subtype=1,
                interface_number=1,
            )
        )
    except Exception:
        pass
    layers.append(LLDPDUEndOfLLDPDU())
    pkt = _eth(c, 0x88CC)
    for ly in layers:
        pkt = pkt / ly
    return pkt


register(
    ProtocolEntry(
        id="lldp_full",
        name="LLDP (full TLVs)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("01:80:c2:00:00:0e", "02:00:00:00:00:01")
        + [
            field("sys_name", "System name", "text", True, "forge-sw1"),
            field("port_id", "Port ID", "text", True, "eth1"),
            field("port_desc", "Port description", "text", False, "lab-uplink", advanced=True),
            field("sys_desc", "System description", "text", False, "Lab Packet Forge LLDP", advanced=True),
            field("mgmt_ip", "Mgmt address", "ip", False, "10.0.0.1", advanced=True),
            field("ttl", "TTL (s)", "int", False, 120, advanced=True),
        ],
        build=_lldp_full,
        template=TemplateMeta(
            "LLDP with chassis/port/TTL/name/desc/mgmt TLVs",
            "Neighbor discovery / topology labs",
            default_pps=2.0,
            soft_pps_cap=2.0,
            hard_pps_cap=20.0,
            control_plane_risk=True,
        ),
    )
)


def _macsec_build(c):
    body = hex_bytes(cfg(c, "payload_hex", "080045000014"))
    if MACsec is not None:
        try:
            return _eth(c, 0x88E5) / MACsec(SCI=int(cfg(c, "sci", 1)), AN=int(cfg(c, "an", 0))) / Raw(body)
        except Exception:
            pass
    # SecTAG skeleton: TCI/AN | SL | PN | SCI
    sectag = bytes([0x0C | (int(cfg(c, "an", 0)) & 3), 0x00]) + struct.pack(
        "!I", int(cfg(c, "pn", 1))
    ) + int(cfg(c, "sci", 1)).to_bytes(8, "big")
    return _eth(c, 0x88E5) / Raw(sectag + body)


register(
    ProtocolEntry(
        id="macsec",
        name="MACsec (802.1AE)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("an", "Association number", "int", False, 0, min=0, max=3),
            field("pn", "Packet number", "int", False, 1, advanced=True),
            field("sci", "SCI", "int", False, 1, advanced=True),
            field("payload_hex", "Encrypted-looking body (hex)", "hex", False, "080045000014", advanced=True),
        ],
        build=_macsec_build,
        template=TemplateMeta("MACsec SecTAG + opaque body", "Secure L2 path / ACL labs"),
    )
)


def _ptp_build(c):
    msg = str(cfg(c, "msg", "sync"))
    msg_type = {"sync": 0, "delay_req": 1, "follow_up": 8, "announce": 0xB}.get(msg, 0)
    if PTPv2 is not None:
        try:
            return (
                Ether(dst=cfg(c, "dst_mac", "01:1b:19:00:00:00"), src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x88F7)
                / PTPv2(type=msg_type, versionPTP=2, sequenceId=int(cfg(c, "seq", 1)))
            )
        except Exception:
            pass
    # Minimal PTPv2 header
    hdr = bytes([msg_type & 0x0F, 0x02, 0x00, 0x2C]) + b"\x00" * 4 + struct.pack("!H", int(cfg(c, "seq", 1))) + b"\x00" * 30
    return Ether(dst=cfg(c, "dst_mac", "01:1b:19:00:00:00"), src=cfg(c, "src_mac"), type=0x88F7) / Raw(hdr)


register(
    ProtocolEntry(
        id="ptp",
        name="PTP (IEEE 1588v2)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("01:1b:19:00:00:00", "02:00:00:00:00:01")
        + [
            field(
                "msg",
                "Message",
                "select",
                True,
                "sync",
                options=[
                    {"value": "sync", "label": "Sync"},
                    {"value": "delay_req", "label": "Delay_Req"},
                    {"value": "follow_up", "label": "Follow_Up"},
                    {"value": "announce", "label": "Announce"},
                ],
            ),
            field("seq", "Sequence ID", "int", False, 1, advanced=True),
        ],
        build=_ptp_build,
        template=TemplateMeta("PTP event/general messages", "Timing / SyncE lab stimulus", default_pps=5.0),
    )
)


def _carp_build(c):
    if CARP is not None:
        try:
            return (
                Ether(dst="01:00:5e:00:00:12", src=cfg(c, "src_mac", "02:00:00:00:00:01"))
                / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst="224.0.0.18", proto=112, ttl=255)
                / CARP(version=2, type=1, vhid=int(cfg(c, "vhid", 1)), advskew=0, authpass=str(cfg(c, "pass", "forge"))[:7])
            )
        except Exception:
            pass
    body = bytes([0x21, int(cfg(c, "vhid", 1)), 0, 0]) + b"\x00" * 12
    return (
        Ether(dst="01:00:5e:00:00:12", src=cfg(c, "src_mac", "02:00:00:00:00:01"))
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst="224.0.0.18", proto=112, ttl=255)
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="carp",
        name="CARP / VRRP-like",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("vhid", "VHID", "int", True, 1, min=1, max=255),
            field("pass", "Auth pass (lab)", "text", False, "forge", advanced=True),
        ],
        build=_carp_build,
        template=TemplateMeta(
            "CARP advertisement skeleton",
            "First-hop redundancy labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


def _mrp_build(c, attribute_type: int):
    # IEEE 802.1Q MRP common PDU skeleton over LLC
    version = 1
    msg = bytes([attribute_type, 0x00, int(cfg(c, "attr", 1)) & 0xFF]) + b"\x00" * 4
    end = b"\x00"
    payload = bytes([version]) + msg + end
    return (
        Ether(dst=cfg(c, "dst_mac", "01:80:c2:00:00:21"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))
        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
        / Raw(payload)
    )


register(
    ProtocolEntry(
        id="mrp_mmrp",
        name="MRP / MMRP",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("01:80:c2:00:00:20", "02:00:00:00:00:01")
        + [field("attr", "Attribute byte", "int", False, 1, advanced=True)],
        build=lambda c: _mrp_build(c, 1),
        template=TemplateMeta(
            "MMRP registration skeleton",
            "MAC registration protocol labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)

register(
    ProtocolEntry(
        id="mrp_mvrp",
        name="MRP / MVRP",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("01:80:c2:00:00:21", "02:00:00:00:00:01")
        + [
            field("vlan", "VLAN attribute", "int", True, 100, min=1, max=4094),
            field("attr", "Attribute byte", "int", False, 1, advanced=True),
        ],
        build=lambda c: _mrp_build({**c, "attr": cfg(c, "vlan", 100)}, 2),
        template=TemplateMeta(
            "MVRP VLAN registration skeleton",
            "Dynamic VLAN registration labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="erp_g8032",
        name="ERP / G.8032 R-APS",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("01:19:a7:00:00:01", "02:00:00:00:00:01")
        + [
            field("ring_id", "Ring ID", "int", True, 1, min=1, max=255),
            field(
                "request",
                "Request/state",
                "select",
                True,
                "nr",
                options=[
                    {"value": "nr", "label": "NR (no request)"},
                    {"value": "sf", "label": "SF (signal fail)"},
                    {"value": "fs", "label": "FS (forced switch)"},
                ],
            ),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x8902)
        / Raw(
            bytes(
                [
                    {"nr": 0x00, "sf": 0xB0, "fs": 0xD0}.get(str(cfg(c, "request", "nr")), 0x00),
                    int(cfg(c, "ring_id", 1)) & 0xFF,
                ]
            )
            + b"\x00" * 30
        ),
        template=TemplateMeta(
            "Ethernet Ring Protection R-APS skeleton",
            "G.8032 ring labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


register(
    ProtocolEntry(
        id="trill",
        name="TRILL",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("ingress_nickname", "Ingress nickname", "int", True, 0x1111, min=1, max=65535),
            field("egress_nickname", "Egress nickname", "int", True, 0x2222, min=1, max=65535),
            field("hop_count", "Hop count", "int", False, 8, advanced=True),
            field("inner_hex", "Inner Ethernet (hex)", "hex", False, "ffffffffffff0200000000010800", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x22F3)
        / Raw(
            struct.pack(
                "!BBHH",
                0x00,
                int(cfg(c, "hop_count", 8)) & 0xFF,
                int(cfg(c, "egress_nickname", 0x2222)),
                int(cfg(c, "ingress_nickname", 0x1111)),
            )
            + hex_bytes(cfg(c, "inner_hex", "ffffffffffff020000000001080045000014"))
        ),
        template=TemplateMeta("TRILL encapsulation skeleton", "Campus fabric / RBridge labs"),
    )
)


register(
    ProtocolEntry(
        id="fcoe",
        name="FCoE",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("sof", "SOF", "hex", False, "2e", advanced=True),
            field("fc_hex", "FC frame (hex)", "hex", False, "22000000000000000000000000000000" + "00" * 24, advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x8906)
        / Raw(bytes([int(cfg(c, "sof", "2e"), 16)]) + hex_bytes(cfg(c, "fc_hex", "22" + "00" * 31)) + b"\x41"),
        template=TemplateMeta("FCoE Ethernet + SOF/EOF skeleton", "Storage fabric labs"),
    )
)


register(
    ProtocolEntry(
        id="fip",
        name="FIP (FCoE Initialization)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("01:10:18:01:00:01", "02:00:00:00:00:01")
        + [
            field(
                "opcode",
                "Opcode",
                "select",
                True,
                "disc_sol",
                options=[
                    {"value": "disc_sol", "label": "Discovery Solicitation"},
                    {"value": "disc_adv", "label": "Discovery Advertisement"},
                    {"value": "els", "label": "FLOGI/ELS-shaped"},
                ],
            ),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x8914)
        / Raw(
            struct.pack(
                "!BBH",
                1,
                {"disc_sol": 1, "disc_adv": 2, "els": 3}.get(str(cfg(c, "opcode", "disc_sol")), 1),
                0,
            )
            + b"\x00" * 20
        ),
        template=TemplateMeta(
            "FIP discovery/ELS-shaped frames",
            "FCoE fabric bring-up labs",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


def _rocev2_build(c):
    eth_ip = (
        Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"), ttl=64)
        / UDP(sport=int(cfg(c, "sport", 49152)), dport=4791)
    )
    if BTH is not None:
        try:
            return eth_ip / BTH(opcode=int(cfg(c, "opcode", 0x0A)), destQP=int(cfg(c, "dqpn", 1)), psn=int(cfg(c, "psn", 1))) / Raw(
                hex_bytes(cfg(c, "payload_hex", "deadbeef"))
            )
        except Exception:
            pass
    # 12-byte BTH skeleton: opcode, flags, pkey, dqpn, psn
    bth = (
        bytes([int(cfg(c, "opcode", 0x0A)) & 0xFF, 0x00, 0xFF, 0xFF])
        + (int(cfg(c, "dqpn", 1)) & 0xFFFFFF).to_bytes(4, "big")
        + (int(cfg(c, "psn", 1)) & 0xFFFFFF).to_bytes(4, "big")
    )
    return eth_ip / Raw(bth + hex_bytes(cfg(c, "payload_hex", "deadbeef")))


register(
    ProtocolEntry(
        id="rocev2",
        name="RoCEv2",
        category="L2 / switching",
        layer="l2",
        craft_slot="l4",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "UDP sport", "int", False, 49152, advanced=True),
            field("opcode", "BTH opcode", "int", True, 0x0A, hint="0x0A = RC SEND Only"),
            field("dqpn", "Dest QP", "int", True, 1),
            field("psn", "PSN", "int", False, 1, advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=_rocev2_build,
        template=TemplateMeta("RoCEv2 UDP/4791 + BTH", "RDMA / AI fabric labs"),
    )
)


def _esmc_build(c):
    if ESMC is not None:
        try:
            return Ether(dst="01:80:c2:00:00:02", src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x8809) / ESMC(
                version=1, event=int(cfg(c, "event", 0)), QL=int(cfg(c, "ql", 0x0B))
            )
        except Exception:
            pass
    # Slow protocol subtype 0x0A ESMC
    body = bytes([0x0A, 0x00, 0x19, 0xA7, 0x00, 0x01, int(cfg(c, "event", 0)) & 1, 0x00]) + bytes(
        [0x01, 0x00, 0x04, int(cfg(c, "ql", 0x0B))]
    )
    return Ether(dst="01:80:c2:00:00:02", src=cfg(c, "src_mac", "02:00:00:00:00:01"), type=0x8809) / Raw(body)


register(
    ProtocolEntry(
        id="esmc",
        name="ESMC (SyncE)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("ql", "SSM QL", "int", True, 0x0B, hint="0x0B = SEC"),
            field("event", "Event flag", "int", False, 0, advanced=True, min=0, max=1),
        ],
        build=_esmc_build,
        template=TemplateMeta("Ethernet Synchronization Messaging Channel", "SyncE timing labs", default_pps=1.0),
    )
)


def _of_hello(c):
    from scapy.layers.inet import TCP

    # OpenFlow 1.3 Hello: version=4, type=0, length=8, xid
    body = struct.pack("!BBHI", 4, 0, 8, int(cfg(c, "xid", 1)))
    return (
        Ether(dst=cfg(c, "dst_mac", "02:00:00:00:00:02"), src=cfg(c, "src_mac", "02:00:00:00:00:01"))
        / IP(src=cfg(c, "src_ip", "10.0.0.1"), dst=cfg(c, "dst_ip", "10.0.0.2"))
        / TCP(sport=int(cfg(c, "sport", 6653)), dport=int(cfg(c, "dport", 6653)), flags="PA", seq=1, ack=1)
        / Raw(body)
    )


register(
    ProtocolEntry(
        id="openflow_hello",
        name="OpenFlow Hello",
        category="L2 / switching",
        layer="l2",
        craft_slot="app",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("src_ip", "Src IP", "ip", True, "10.0.0.1"),
            field("dst_ip", "Dst IP", "ip", True, "10.0.0.2"),
            field("sport", "Src port", "int", False, 6653, advanced=True),
            field("dport", "Dst port", "int", True, 6653),
            field("xid", "XID", "int", False, 1, advanced=True),
        ],
        build=_of_hello,
        template=TemplateMeta("OpenFlow 1.3 Hello on TCP/6653", "SDN controller path labs"),
    )
)


register(
    ProtocolEntry(
        id="spb_isid",
        name="SPB I-SID (skeleton)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("isid", "I-SID", "int", True, 100, min=1, max=16777215),
            field("bvid", "B-VID", "int", True, 100, min=1, max=4094),
            field("inner_hex", "Customer frame (hex)", "hex", False, "ffffffffffff0200000000010800", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x88A8)
        / Raw(struct.pack("!H", (int(cfg(c, "bvid", 100)) & 0xFFF) | 0xE000))
        / Ether(dst="00:00:00:00:00:00", src=cfg(c, "src_mac"), type=0x88E7)
        / Raw(struct.pack("!I", int(cfg(c, "isid", 100)) & 0xFFFFFF)[1:] + hex_bytes(cfg(c, "inner_hex", "ffffffffffff0200000000010800"))),
        template=TemplateMeta("SPB/PBB I-SID encapsulation skeleton", "Provider Backbone Bridge labs"),
    )
)


register(
    ProtocolEntry(
        id="pbb_itag",
        name="PBB I-TAG",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields("02:00:00:00:00:02", "02:00:00:00:00:01")
        + [
            field("isid", "I-SID", "int", True, 200),
            field("pcp", "PCP", "int", False, 0, advanced=True, min=0, max=7),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x88E7)
        / Raw(
            struct.pack("!I", ((int(cfg(c, "pcp", 0)) & 7) << 29) | (int(cfg(c, "isid", 200)) & 0xFFFFFF))
            + hex_bytes(cfg(c, "payload_hex", "deadbeef"))
        ),
        template=TemplateMeta("802.1ah I-TAG with I-SID", "PBB service instance labs"),
    )
)

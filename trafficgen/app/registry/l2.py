"""L2 / switching protocols."""
from __future__ import annotations

import os
import random

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import (
    Dot1Q,
    Ether,
    LLC,
    SNAP,
    STP,
)
from scapy.packet import Packet, Raw
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUEndOfLLDPDU,
    LLDPDUSystemName,
)
from scapy.contrib.lacp import LACP

from .base import (
    ProtocolEntry,
    TemplateMeta,
    cfg,
    expect,
    field,
    hex_bytes,
    mac_fields,
    register,
)

expect(
    "eth_ii",
    "eth_8023_llc_snap",
    "dot1q",
    "qinq",
    "mac_pause",
    "stp",
    "rstp",
    "mstp",
    "pvst",
    "pvst_plus",
    "vstp",
    "lldp",
    "lacp",
    "lacp_marker",
    "eapol",
    "cdp",
    "vtp",
    "dtp",
    "mac_in_mac",
    "bum_spam",
    "uuf",
)


def _eth(config, type_=None, payload=None) -> Packet:
    pkt = Ether(dst=cfg(config, "dst_mac", "ff:ff:ff:ff:ff:ff"), src=cfg(config, "src_mac", "02:00:00:00:00:01"))
    if type_ is not None:
        pkt.type = int(type_)
    if payload is not None:
        pkt = pkt / payload
    return pkt


register(
    ProtocolEntry(
        id="eth_ii",
        name="Ethernet II",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields()
        + [
            field("ethertype", "EtherType", "hex", True, "0800", "e.g. 0800 IPv4"),
            field("payload_hex", "Payload (hex)", "hex", False, "", advanced=True),
        ],
        build=lambda c: _eth(c, int(str(cfg(c, "ethertype", "0800")).replace("0x", ""), 16))
        / Raw(hex_bytes(cfg(c, "payload_hex", "")) or b"\x00"),
        template=TemplateMeta("Classic Ethernet II frame", "General L2 lab frames"),
    )
)

register(
    ProtocolEntry(
        id="eth_8023_llc_snap",
        name="802.3 + LLC / SNAP",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields()
        + [
            field("oui", "SNAP OUI", "hex", False, "000000", advanced=True),
            field("pid", "SNAP PID", "hex", False, "0800", advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "deadbeef", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=len(hex_bytes(cfg(c, "payload_hex", "deadbeef"))) + 8)
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=int(cfg(c, "oui", "000000"), 16), code=int(cfg(c, "pid", "0800"), 16))
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("802.3 length + LLC/SNAP", "Legacy / SNAP encapsulation labs"),
    )
)

register(
    ProtocolEntry(
        id="dot1q",
        name="802.1Q VLAN",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields()
        + [
            field("vlan", "VLAN ID", "int", True, 100, min=1, max=4094),
            field("pcp", "PCP", "int", False, 0, advanced=True, min=0, max=7),
            field("ethertype", "Inner EtherType", "hex", False, "0800", advanced=True),
            field("payload_hex", "Payload (hex)", "hex", False, "45000014000000004000", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / Dot1Q(vlan=int(cfg(c, "vlan", 100)), prio=int(cfg(c, "pcp", 0)), type=int(cfg(c, "ethertype", "0800"), 16))
        / Raw(hex_bytes(cfg(c, "payload_hex", "45000014000000004000"))),
        template=TemplateMeta("Single-tagged 802.1Q", "VLAN path / ACL tests"),
    )
)

register(
    ProtocolEntry(
        id="qinq",
        name="QinQ (802.1ad)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=mac_fields()
        + [
            field("outer_vlan", "Outer VLAN (S-TAG)", "int", True, 100, min=1, max=4094),
            field("inner_vlan", "Inner VLAN (C-TAG)", "int", True, 200, min=1, max=4094),
            field("payload_hex", "Payload (hex)", "hex", False, "45000014000000004000", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"))
        / Dot1Q(vlan=int(cfg(c, "outer_vlan", 100)), type=0x8100)
        / Dot1Q(vlan=int(cfg(c, "inner_vlan", 200)))
        / Raw(hex_bytes(cfg(c, "payload_hex", "45000014000000004000"))),
        template=TemplateMeta("Double-tagged QinQ", "Provider bridging labs"),
    )
)

register(
    ProtocolEntry(
        id="mac_pause",
        name="MAC Control (Pause)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("quanta", "Pause quanta", "int", True, 0xFFFF, min=0, max=65535),
        ],
        build=lambda c: Ether(dst="01:80:c2:00:00:01", src=cfg(c, "src_mac"), type=0x8808)
        / Raw(b"\x00\x01" + int(cfg(c, "quanta", 0xFFFF)).to_bytes(2, "big")),
        template=TemplateMeta(
            "802.3x Pause frame",
            "Flow-control stimulus — floods can stall links",
            default_pps=2.0,
            soft_pps_cap=5.0,
            hard_pps_cap=50.0,
            control_plane_risk=True,
        ),
    )
)


STP_FAMILY_TEMPLATE = dict(
    default_pps=2.0,
    soft_pps_cap=5.0,
    hard_pps_cap=50.0,
    control_plane_risk=True,
)

# Cisco / Juniper per-VLAN STP (PVST+, VSTP): SNAP PID 0x010b → 01:00:0c:cc:cc:cd
CISCO_PVST_DST = "01:00:0c:cc:cc:cd"
CISCO_PVST_SNAP = (0x00000C, 0x010B)
IEEE_STP_DST = "01:80:c2:00:00:00"


def _stp_layer(config, version=0, bpdu_type=0) -> Packet:
    """IEEE 802.1D/w Configuration / RSTP BPDU body (Scapy STP)."""
    root = cfg(config, "root_mac", "00:00:00:00:00:01")
    bridge = cfg(config, "bridge_mac", "00:00:00:00:00:02")
    root_prio = int(cfg(config, "root_priority", 0x8000))
    bridge_prio = int(cfg(config, "bridge_priority", 0x8000))
    try:
        return STP(
            proto=0,
            version=version,
            bpdutype=bpdu_type,
            bpduflags=int(cfg(config, "flags", 0)),
            rootid=root_prio,
            rootmac=root,
            pathcost=int(cfg(config, "path_cost", 0)),
            bridgeid=bridge_prio,
            bridgemac=bridge,
            portid=int(cfg(config, "port_id", 0x8001)),
            age=float(cfg(config, "message_age", 0)),
            maxage=float(cfg(config, "max_age", 20)),
            hellotime=float(cfg(config, "hello_time", 2)),
            fwddelay=float(cfg(config, "forward_delay", 15)),
        )
    except Exception:
        return Raw(
            bytes([0, version, bpdu_type, int(cfg(config, "flags", 0))]) + b"\x00" * 35
        )


def _as_bool(v, default: bool = False) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _stp_common_fields(*, flags_default: int = 0, include_timers: bool = False) -> list:
    fields = [
        field("src_mac", "Src MAC", "mac", True, "00:00:00:00:00:02"),
        field("root_mac", "Root MAC", "mac", True, "00:00:00:00:00:01"),
        field("bridge_mac", "Bridge MAC", "mac", True, "00:00:00:00:00:02"),
        field("path_cost", "Path cost", "int", False, 0, advanced=True),
        field("port_id", "Port ID", "int", False, 0x8001, advanced=True),
        field("flags", "Flags", "int", False, flags_default, advanced=True),
        field("root_priority", "Root priority", "int", False, 0x8000, advanced=True),
        field("bridge_priority", "Bridge priority", "int", False, 0x8000, advanced=True),
    ]
    if include_timers:
        fields.extend(
            [
                field("message_age", "Message age", "float", False, 0, advanced=True),
                field("max_age", "Max age", "float", False, 20, advanced=True),
                field("hello_time", "Hello time", "float", False, 2, advanced=True),
                field("forward_delay", "Forward delay", "float", False, 15, advanced=True),
            ]
        )
    return fields


def _stp_bpdu(config, version=0, bpdu_type=0) -> Packet:
    bridge = cfg(config, "bridge_mac", "00:00:00:00:00:02")
    return (
        Ether(dst=IEEE_STP_DST, src=cfg(config, "src_mac", bridge))
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / _stp_layer(config, version=version, bpdu_type=bpdu_type)
    )


def _mstp_extension(config) -> bytes:
    """802.1Q MSTP fields after the RSTP BPDU (version 3).

    Layout: version1_len(1)=0 | version3_len(2) | MST Config ID (51) |
            CIST internal path cost(4) | CIST bridge id(8) | CIST port id(2) |
            remaining hops(1) | optional MSTI config messages.
    """
    name = str(cfg(config, "mst_config_name", "region1")).encode("ascii", "replace")[:32]
    name = name.ljust(32, b"\x00")
    revision = int(cfg(config, "mst_revision", 0)) & 0xFFFF
    digest = hex_bytes(str(cfg(config, "mst_digest", "00" * 16)))
    if len(digest) < 16:
        digest = digest.ljust(16, b"\x00")
    else:
        digest = digest[:16]

    # MST Configuration Identifier: format selector (0) + name + revision + digest
    mst_config_id = b"\x00" + name + revision.to_bytes(2, "big") + digest

    bridge = cfg(config, "bridge_mac", "00:00:00:00:00:02")
    bridge_mac = bytes.fromhex(str(bridge).replace(":", ""))
    bridge_prio = int(cfg(config, "bridge_priority", 0x8000)) & 0xFFFF
    cist_internal_cost = int(cfg(config, "cist_internal_path_cost", 0)) & 0xFFFFFFFF
    cist_bridge_id = bridge_prio.to_bytes(2, "big") + bridge_mac
    cist_port_id = int(cfg(config, "port_id", 0x8001)) & 0xFFFF
    remaining_hops = int(cfg(config, "remaining_hops", 20)) & 0xFF
    msti_extra = hex_bytes(cfg(config, "payload_hex", ""))

    body = (
        mst_config_id
        + cist_internal_cost.to_bytes(4, "big")
        + cist_bridge_id
        + cist_port_id.to_bytes(2, "big")
        + bytes([remaining_hops])
        + msti_extra
    )
    # version_1_length = 0; version_3_length = len(body)
    return b"\x00" + len(body).to_bytes(2, "big") + body


def _mstp_bpdu(config) -> Packet:
    bridge = cfg(config, "bridge_mac", "00:00:00:00:00:02")
    return (
        Ether(dst=IEEE_STP_DST, src=cfg(config, "src_mac", bridge))
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / _stp_layer(config, version=3, bpdu_type=2)
        / Raw(_mstp_extension(config))
    )


def _pvst_pvid_tlv(vlan: int) -> bytes:
    """Cisco Originating-VLAN (PVID) TLV after the STP BPDU (type 0, len 2)."""
    # Optional 2-byte pad seen in many captures, then TLV
    return b"\x00\x00" + b"\x00\x00\x00\x02" + (int(vlan) & 0xFFF).to_bytes(2, "big")


def _cisco_per_vlan_stp(
    config,
    *,
    version: int = 0,
    bpdu_type: int = 0,
    tag_frame: bool = True,
    dst: str = CISCO_PVST_DST,
) -> Packet:
    """PVST / PVST+ / VSTP-style SNAP BPDU (Cisco OUI, PID 0x010b)."""
    vlan = int(cfg(config, "vlan", 100))
    bridge = cfg(config, "bridge_mac", "00:00:00:00:00:02")
    src = cfg(config, "src_mac", bridge)
    oui, pid = CISCO_PVST_SNAP
    eth = Ether(dst=dst, src=src)
    if tag_frame:
        eth = eth / Dot1Q(vlan=vlan)
    pkt = (
        eth
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=oui, code=pid)
        / _stp_layer(config, version=version, bpdu_type=bpdu_type)
        / Raw(_pvst_pvid_tlv(vlan))
    )
    return pkt


register(
    ProtocolEntry(
        id="stp",
        name="STP BPDU",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=_stp_common_fields(),
        build=lambda c: _stp_bpdu(c, version=0, bpdu_type=0),
        template=TemplateMeta(
            "Classic STP Configuration BPDU",
            "STP topology labs — BPDUs at high rate can destabilize the fabric",
            **STP_FAMILY_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="rstp",
        name="RSTP BPDU",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=_stp_common_fields(flags_default=0x7C),
        build=lambda c: _stp_bpdu(c, version=2, bpdu_type=2),
        template=TemplateMeta(
            "RSTP Rapid BPDU",
            "Rapid spanning-tree labs — keep pps low",
            **STP_FAMILY_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="mstp",
        name="MSTP BPDU",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=_stp_common_fields(flags_default=0x7C)
        + [
            field("mst_config_name", "MST region name", "text", True, "region1"),
            field("mst_revision", "MST revision", "int", False, 0, advanced=True, min=0, max=65535),
            field(
                "mst_digest",
                "MST config digest (hex)",
                "hex",
                False,
                "00" * 16,
                advanced=True,
                hint="16-byte MD5 digest of VLAN→MSTI map; zeros OK for lab stimulus",
            ),
            field("cist_internal_path_cost", "CIST internal path cost", "int", False, 0, advanced=True),
            field("remaining_hops", "Remaining hops", "int", False, 20, advanced=True, min=0, max=255),
            field("payload_hex", "Extra MSTI hex", "hex", False, "", advanced=True),
        ],
        build=_mstp_bpdu,
        template=TemplateMeta(
            "802.1Q MSTP BPDU (v3) with MST config name/revision/digest",
            "Multiple spanning-tree labs — keep pps low",
            **STP_FAMILY_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="pvst",
        name="PVST BPDU",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=_stp_common_fields()
        + [
            field("vlan", "VLAN ID (PVID)", "int", True, 100, min=1, max=4094),
            field(
                "tagged",
                "802.1Q tag frame",
                "bool",
                False,
                True,
                advanced=True,
                hint="Untagged SSTP is typical for native VLAN",
            ),
        ],
        build=lambda c: _cisco_per_vlan_stp(
            c,
            version=0,
            bpdu_type=0,
            tag_frame=_as_bool(cfg(c, "tagged", True), True),
        ),
        template=TemplateMeta(
            "Cisco PVST — SNAP/LLC per-VLAN STP BPDU with PVID TLV",
            "Per-VLAN STP labs (Cisco) — keep pps low",
            **STP_FAMILY_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="pvst_plus",
        name="PVST+ BPDU",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=_stp_common_fields(flags_default=0x7C)
        + [
            field("vlan", "VLAN ID (PVID)", "int", True, 100, min=1, max=4094),
            field(
                "tagged",
                "802.1Q tag frame",
                "bool",
                False,
                True,
                advanced=True,
                hint="False = native-VLAN style untagged SSTP to 01:00:0c:cc:cc:cd",
            ),
        ],
        build=lambda c: _cisco_per_vlan_stp(
            c,
            version=2,
            bpdu_type=2,
            tag_frame=_as_bool(cfg(c, "tagged", True), True),
        ),
        template=TemplateMeta(
            "Cisco PVST+ / Rapid-PVST+ — dst 01:00:0c:cc:cc:cd, SNAP 0x010b",
            "Per-VLAN rapid STP labs (Cisco) — keep pps low",
            **STP_FAMILY_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="vstp",
        name="VSTP BPDU",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        stack_hint=(
            "Juniper VSTP is PVST+-interoperable: tagged SNAP BPDUs to "
            "01:00:0c:cc:cc:cd (PID 0x010b). Lab simulation — proprietary "
            "Juniper extensions beyond the shared SSTP/PVST+ envelope are not modeled."
        ),
        fields=_stp_common_fields(flags_default=0x7C)
        + [
            field("vlan", "VLAN ID", "int", True, 100, min=1, max=4094),
            field(
                "tagged",
                "802.1Q tag frame",
                "bool",
                False,
                True,
                advanced=True,
                hint="Juniper VSTP per-VLAN BPDUs are normally VLAN-tagged",
            ),
        ],
        build=lambda c: _cisco_per_vlan_stp(
            c,
            version=2,
            bpdu_type=2,
            tag_frame=_as_bool(cfg(c, "tagged", True), True),
        ),
        template=TemplateMeta(
            "Juniper VSTP lab frame (PVST+-compatible SNAP/VLAN STP)",
            "VLAN STP labs vs Juniper/Cisco mixed fabrics — keep pps low",
            **STP_FAMILY_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="lldp",
        name="LLDP",
        category="L2 / switching",
        layer="discovery",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("chassis_id", "Chassis ID", "text", True, "forge-chassis"),
            field("port_id", "Port ID", "text", True, "eth1"),
            field("system_name", "System name", "text", False, "lab-packet-forge"),
            field("ttl", "TTL", "int", False, 120, advanced=True),
        ],
        build=lambda c: Ether(dst="01:80:c2:00:00:0e", src=cfg(c, "src_mac"), type=0x88CC)
        / LLDPDU()
        / LLDPDUChassisID(subtype=7, id=str(cfg(c, "chassis_id")))
        / LLDPDUPortID(subtype=7, id=str(cfg(c, "port_id")))
        / LLDPDUTimeToLive(ttl=int(cfg(c, "ttl", 120)))
        / LLDPDUSystemName(system_name=str(cfg(c, "system_name", "lab-packet-forge")))
        / LLDPDUEndOfLLDPDU(),
        template=TemplateMeta("LLDP with chassis/port/system TLVs", "Neighbor discovery labs"),
    )
)

register(
    ProtocolEntry(
        id="lacp",
        name="LACP",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("actor_sys_prio", "Actor sys prio", "int", False, 0x8000, advanced=True),
            field("actor_key", "Actor key", "int", False, 1, advanced=True),
            field("actor_port", "Actor port", "int", False, 1, advanced=True),
        ],
        build=lambda c: Ether(dst="01:80:c2:00:00:02", src=cfg(c, "src_mac"), type=0x8809)
        / LACP(
            version=1,
            actor_system_priority=int(cfg(c, "actor_sys_prio", 0x8000)),
            actor_system=cfg(c, "src_mac"),
            actor_key=int(cfg(c, "actor_key", 1)),
            actor_port_priority=0x8000,
            actor_port_number=int(cfg(c, "actor_port", 1)),
            actor_state=0x3D,
            partner_system_priority=0xFFFF,
            partner_system="00:00:00:00:00:00",
            partner_key=0,
            partner_port_priority=0xFFFF,
            partner_port_number=0,
            partner_state=0x01,
            collector_max_delay=0,
        ),
        template=TemplateMeta("LACP PDU", "LAG / MLAG peer labs"),
    )
)

register(
    ProtocolEntry(
        id="lacp_marker",
        name="LACP Marker",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("requester_port", "Requester port", "int", False, 1),
            field("transaction_id", "Transaction ID", "int", False, 1),
        ],
        build=lambda c: Ether(dst="01:80:c2:00:00:02", src=cfg(c, "src_mac"), type=0x8809)
        / Raw(
            b"\x02\x01"  # Marker subtype/version
            + b"\x01\x10"
            + int(cfg(c, "requester_port", 1)).to_bytes(2, "big")
            + bytes.fromhex(str(cfg(c, "src_mac")).replace(":", ""))
            + int(cfg(c, "transaction_id", 1)).to_bytes(2, "big")
            + b"\x00" * 4
            + b"\x00\x00"
        ),
        template=TemplateMeta("LACP Marker PDU", "LAG marker protocol labs"),
    )
)

register(
    ProtocolEntry(
        id="eapol",
        name="EAPOL / 802.1X",
        category="L2 / switching",
        layer="security",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("dst_mac", "Dst MAC", "mac", True, "01:80:c2:00:00:03"),
            field(
                "packet_type",
                "Packet type",
                "select",
                True,
                "1",
                options=[
                    {"value": "0", "label": "EAP"},
                    {"value": "1", "label": "Start"},
                    {"value": "2", "label": "Logoff"},
                    {"value": "3", "label": "Key"},
                ],
            ),
            field("payload_hex", "Body (hex)", "hex", False, "", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x888E)
        / Raw(b"\x01" + bytes([int(cfg(c, "packet_type", 1))]) + b"\x00\x00" + hex_bytes(cfg(c, "payload_hex", ""))),
        template=TemplateMeta("EAPOL Start/Logoff/Key", "802.1X port-auth labs"),
    )
)

# Cisco discovery / trunking (lab-oriented)
CDP_SNAP = (0x00000C, 0x2000)
VTP_SNAP = (0x00000C, 0x2003)
DTP_SNAP = (0x00000C, 0x2004)


def _cisco_snap(config, oui_pid, payload: bytes) -> Packet:
    oui, pid = oui_pid
    return (
        Ether(dst="01:00:0c:cc:cc:cc", src=cfg(config, "src_mac", "02:00:00:00:00:01"))
        / LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03)
        / SNAP(OUI=oui, code=pid)
        / Raw(payload)
    )


register(
    ProtocolEntry(
        id="cdp",
        name="Cisco CDP",
        category="L2 / switching",
        layer="discovery",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("device_id", "Device ID", "text", True, "forge-sw1"),
            field("platform", "Platform", "text", False, "Lab Packet Forge", advanced=True),
        ],
        build=lambda c: _cisco_snap(
            c,
            CDP_SNAP,
            b"\x02\x01"  # version/ttl placeholder
            + b"\x00\x00"
            + b"\x00\x01"
            + (2 + len(str(cfg(c, "device_id")))).to_bytes(2, "big")
            + str(cfg(c, "device_id")).encode()
            + b"\x00\x06"
            + (2 + len(str(cfg(c, "platform", "Lab Packet Forge")))).to_bytes(2, "big")
            + str(cfg(c, "platform", "Lab Packet Forge")).encode(),
        ),
        template=TemplateMeta("CDP advertisement skeleton", "Cisco neighbor labs"),
    )
)

register(
    ProtocolEntry(
        id="vtp",
        name="Cisco VTP",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("domain", "Domain", "text", True, "LAB"),
            field(
                "msg_type",
                "Message type",
                "select",
                False,
                "1",
                options=[
                    {"value": "1", "label": "Summary-Adv"},
                    {"value": "2", "label": "Subset-Adv"},
                    {"value": "3", "label": "Advert-Request"},
                ],
                advanced=True,
            ),
        ],
        build=lambda c: _cisco_snap(
            c,
            VTP_SNAP,
            bytes([1, int(cfg(c, "msg_type", 1)), len(str(cfg(c, "domain"))), 0])
            + str(cfg(c, "domain")).encode().ljust(32, b"\x00")
            + b"\x00" * 16,
        ),
        template=TemplateMeta("VTP advertisement skeleton", "VLAN trunking protocol labs"),
    )
)

register(
    ProtocolEntry(
        id="dtp",
        name="Cisco DTP",
        category="L2 / switching",
        layer="l2",
        craft_slot="control",
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field("domain", "Domain", "text", True, "LAB"),
            field(
                "status",
                "Status",
                "select",
                False,
                "03",
                options=[
                    {"value": "03", "label": "trunk"},
                    {"value": "04", "label": "access"},
                ],
                advanced=True,
            ),
        ],
        build=lambda c: _cisco_snap(
            c,
            DTP_SNAP,
            b"\x01"
            + b"\x01\x00"
            + len(str(cfg(c, "domain"))).to_bytes(1, "big")
            + str(cfg(c, "domain")).encode()
            + bytes.fromhex(str(cfg(c, "status", "03")))
            + b"\x00" * 8,
        ),
        template=TemplateMeta("DTP negotiation skeleton", "Dynamic trunking labs"),
    )
)

register(
    ProtocolEntry(
        id="mac_in_mac",
        name="MAC-in-MAC (advanced)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        stack_hint="Provider bridging style: outer Ether + inner Ether",
        fields=mac_fields("00:11:22:33:44:55", "02:00:00:00:00:01")
        + [
            field("inner_dst", "Inner dst MAC", "mac", True, "aa:bb:cc:dd:ee:ff"),
            field("inner_src", "Inner src MAC", "mac", True, "02:00:00:00:00:02"),
            field("inner_type", "Inner EtherType", "hex", False, "0800", advanced=True),
            field("payload_hex", "Inner payload (hex)", "hex", False, "45000014000000004000", advanced=True),
        ],
        build=lambda c: Ether(dst=cfg(c, "dst_mac"), src=cfg(c, "src_mac"), type=0x88E7)
        / Ether(dst=cfg(c, "inner_dst"), src=cfg(c, "inner_src"), type=int(cfg(c, "inner_type", "0800"), 16))
        / Raw(hex_bytes(cfg(c, "payload_hex", "45000014000000004000"))),
        template=TemplateMeta("Provider MAC-in-MAC style frame", "Advanced bridging labs"),
    )
)


def _as_bool(v, default: bool = True) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _fmt_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _random_unknown_unicast_mac() -> str:
    """Locally administered unicast MAC (I/G=0, U/L=1) — unknown to CAM → flood."""
    b = bytearray(os.urandom(6))
    b[0] = (b[0] & 0xFE) | 0x02
    return _fmt_mac(bytes(b))


def _random_multicast_mac(mode: str, fixed: str | None = None) -> str:
    mode = (mode or "ipv4").lower()
    if mode == "fixed" and fixed:
        return str(fixed)
    if mode == "ipv6":
        return _fmt_mac(b"\x33\x33" + os.urandom(4))
    if mode == "random":
        b = bytearray(os.urandom(6))
        b[0] = (b[0] & 0xFE) | 0x01  # multicast, keep U/L from random
        return _fmt_mac(bytes(b))
    # ipv4-mapped L2 mcast 01:00:5e:0x:xx:xx (23 bits; clear high bit of octet 3)
    return _fmt_mac(b"\x01\x00\x5e" + bytes([os.urandom(1)[0] & 0x7F]) + os.urandom(2))


def _pick_bum_dst(config, *, force_kind: str | None = None) -> tuple[str, str]:
    """Return (kind, dst_mac). kind is broadcast | unknown_unicast | multicast."""
    if force_kind:
        kinds = [force_kind]
    else:
        kinds = []
        if _as_bool(cfg(config, "include_broadcast", True), True):
            kinds.append("broadcast")
        if _as_bool(cfg(config, "include_unknown_unicast", True), True):
            kinds.append("unknown_unicast")
        if _as_bool(cfg(config, "include_multicast", True), True):
            kinds.append("multicast")
        if not kinds:
            kinds = ["broadcast"]
    kind = random.choice(kinds)
    if kind == "broadcast":
        return kind, "ff:ff:ff:ff:ff:ff"
    if kind == "unknown_unicast":
        return kind, _random_unknown_unicast_mac()
    return kind, _random_multicast_mac(
        str(cfg(config, "mcast_mode", "ipv4")),
        cfg(config, "mcast_mac", "01:00:5e:00:00:01"),
    )


def _pad_to_size(pkt: Packet, size: int) -> Packet:
    """Pad with Raw so wire length (excl. FCS) reaches size (min Ethernet 60)."""
    target = max(int(size), 60)
    cur = len(bytes(pkt))
    if cur >= target:
        return pkt
    return pkt / Raw(b"\x00" * (target - cur))


def _build_bum_frame(config, *, force_kind: str | None = None) -> Packet:
    """BUM spam frame: random B/U/M dst each build (TX sets rebuild_each)."""
    _kind, dst = _pick_bum_dst(config, force_kind=force_kind)
    src = str(cfg(config, "src_mac", "02:00:00:00:00:01"))
    vlan = cfg(config, "vlan", None)
    try:
        vlan_id = int(vlan) if vlan not in (None, "", False) else 0
    except (TypeError, ValueError):
        vlan_id = 0
    # Default ip_udp: experimental EtherType 0x88b5 (eth mode) is often dropped or
    # omitted from switch interface counters even when frames hit the wire.
    payload_mode = str(cfg(config, "payload_mode", "ip_udp")).lower()
    size = int(cfg(config, "frame_size", 128) or 128)

    if payload_mode in ("ip_udp", "udp", "ipv4_udp"):
        l2 = Ether(dst=dst, src=src) / Dot1Q(vlan=vlan_id) if vlan_id > 0 else Ether(dst=dst, src=src)
        pkt = (
            l2
            / IP(
                src=str(cfg(config, "src_ip", "10.0.0.1")),
                dst=str(cfg(config, "dst_ip", "10.0.0.2")),
                ttl=int(cfg(config, "ttl", 64)),
            )
            / UDP(
                sport=int(cfg(config, "sport", 12345)),
                dport=int(cfg(config, "dport", 5001)),
            )
            / Raw(b"bum")
        )
    else:
        ethertype = int(str(cfg(config, "ethertype", "88b5")).replace("0x", ""), 16)
        if vlan_id > 0:
            pkt = Ether(dst=dst, src=src) / Dot1Q(vlan=vlan_id, type=ethertype) / Raw(b"bum")
        else:
            pkt = Ether(dst=dst, src=src, type=ethertype) / Raw(b"bum")

    return _pad_to_size(pkt, size)


_BUM_FIELDS = [
    field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
    field("include_broadcast", "Include broadcast (B)", "bool", False, True),
    field("include_unknown_unicast", "Include unknown unicast (U)", "bool", False, True),
    field(
        "include_multicast",
        "Include multicast (M)",
        "bool",
        False,
        True,
        hint="Random L2 mcast per packet when enabled",
    ),
    field(
        "mcast_mode",
        "Multicast MAC mode",
        "select",
        False,
        "ipv4",
        options=[
            {"value": "ipv4", "label": "01:00:5e:… (IPv4-mapped)"},
            {"value": "ipv6", "label": "33:33:… (IPv6)"},
            {"value": "random", "label": "Random multicast"},
            {"value": "fixed", "label": "Fixed mcast MAC"},
        ],
    ),
    field("mcast_mac", "Fixed mcast MAC", "mac", False, "01:00:5e:00:00:01", advanced=True),
    field(
        "payload_mode",
        "Payload",
        "select",
        False,
        "ip_udp",
        options=[
            {"value": "ip_udp", "label": "Eth + optional VLAN + IPv4/UDP (switch-visible)"},
            {"value": "eth", "label": "Ethernet only (+ optional VLAN)"},
        ],
        hint="Default ip_udp — many ASICs drop/ignore experimental EtherType 0x88b5 so counters stay flat",
    ),
    field("vlan", "VLAN ID (0 = untagged)", "int", False, 0, min=0, max=4094),
    field("frame_size", "Frame size (bytes, excl. FCS)", "int", False, 128, min=60, max=1518),
    field(
        "ethertype",
        "EtherType (eth payload only)",
        "hex",
        False,
        "88b5",
        "Only used when Payload=eth. 88b5 is local-exp; switches often drop it — prefer ip_udp",
        advanced=True,
    ),
    field("src_ip", "Src IP (ip_udp)", "ip", False, "10.0.0.1", advanced=True),
    field("dst_ip", "Dst IP (ip_udp)", "ip", False, "10.0.0.2", advanced=True),
    field("sport", "UDP sport", "int", False, 12345, advanced=True, min=0, max=65535),
    field("dport", "UDP dport", "int", False, 5001, advanced=True, min=0, max=65535),
    field("ttl", "IP TTL", "int", False, 64, advanced=True),
]

_BUM_TEMPLATE = dict(
    default_pps=10.0,
    soft_pps_cap=50.0,
    hard_pps_cap=500.0,
    control_plane_risk=True,
)

register(
    ProtocolEntry(
        id="bum_spam",
        name="BUM spam (B/U/M flood)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        rebuild_each=True,
        fields=list(_BUM_FIELDS),
        build=_build_bum_frame,
        template=TemplateMeta(
            "Random Broadcast / Unknown-unicast / Multicast frames (weighted toggles)",
            "CAM / flood-domain stress — can overwhelm switch MAC tables and CPU; keep pps low",
            **_BUM_TEMPLATE,
        ),
    )
)

register(
    ProtocolEntry(
        id="uuf",
        name="UUF (unknown unicast flood)",
        category="L2 / switching",
        layer="l2",
        craft_slot="l2",
        rebuild_each=True,
        fields=[
            field("src_mac", "Src MAC", "mac", True, "02:00:00:00:00:01"),
            field(
                "payload_mode",
                "Payload",
                "select",
                False,
                "ip_udp",
                options=[
                    {"value": "ip_udp", "label": "Eth + optional VLAN + IPv4/UDP (switch-visible)"},
                    {"value": "eth", "label": "Ethernet only (+ optional VLAN)"},
                ],
                hint="Default ip_udp — eth/0x88b5 is often dropped or uncounted on ASICs",
            ),
            field("vlan", "VLAN ID (0 = untagged)", "int", False, 0, min=0, max=4094),
            field("frame_size", "Frame size (bytes, excl. FCS)", "int", False, 128, min=60, max=1518),
            field(
                "ethertype",
                "EtherType (eth payload only)",
                "hex",
                False,
                "88b5",
                "Only used when Payload=eth; prefer ip_udp for switch visibility",
                advanced=True,
            ),
            field("src_ip", "Src IP (ip_udp)", "ip", False, "10.0.0.1", advanced=True),
            field("dst_ip", "Dst IP (ip_udp)", "ip", False, "10.0.0.2", advanced=True),
            field("sport", "UDP sport", "int", False, 12345, advanced=True, min=0, max=65535),
            field("dport", "UDP dport", "int", False, 5001, advanced=True, min=0, max=65535),
            field("ttl", "IP TTL", "int", False, 64, advanced=True),
        ],
        build=lambda c: _build_bum_frame(
            {
                **c,
                "include_broadcast": False,
                "include_unknown_unicast": True,
                "include_multicast": False,
            },
            force_kind="unknown_unicast",
        ),
        template=TemplateMeta(
            "Unknown-unicast-only flood (thin UUF wrapper over BUM)",
            "Same as bum_spam with only unknown unicast — locally administered random dst MACs flood if not learned",
            **_BUM_TEMPLATE,
        ),
    )
)

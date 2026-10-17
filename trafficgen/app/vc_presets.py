"""Vendor Virtual Chassis / stacking simulation presets."""
from __future__ import annotations

from typing import Any

from scapy.layers.l2 import Ether, LLC, SNAP
from scapy.packet import Raw
from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUPortID,
    LLDPDUTimeToLive,
    LLDPDUEndOfLLDPDU,
)
from scapy.contrib.lacp import LACP

from .registry.base import cfg, hex_bytes


def _mac(c: dict[str, Any], key: str, default: str) -> str:
    return str(cfg(c, key, default))


def _override_or(pkt, c: dict[str, Any]):
    extra = hex_bytes(cfg(c, "payload_hex", ""))
    if extra:
        return pkt / Raw(extra)
    return pkt


def juniper_vccp(c: dict[str, Any]):
    """IS-IS Hello-style on L2 (Juniper VC / VCCP lab approximation)."""
    sys_id = b"\x01\x02\x03\x04\x05\x06"
    common = bytes([0x83, 15, 1, 0, 0])  # IS-IS Hello-ish
    body = bytes([1, 0, 10]) + sys_id + b"\x00\x00" + b"VCCP-LAB\x00"
    return _override_or(
        Ether(dst="01:80:c2:00:00:14", src=_mac(c, "src_mac", "02:00:00:00:00:01"), type=0x22F4) / Raw(common + body),
        c,
    )


def cisco_svl(c: dict[str, Any]):
    """StackWise Virtual–like L2 control + hex body."""
    body = b"SVL\x01" + b"\x00" * 20 + b"STACKWISE-VIRTUAL"
    return _override_or(
        Ether(dst="01:00:0c:cc:cc:cc", src=_mac(c, "src_mac", "02:00:00:00:00:01"), type=0x88B5) / Raw(body),
        c,
    )


def extreme_summit(c: dict[str, Any]):
    body = b"EXOS-SS" + b"\x01\x00" + b"\x00" * 16
    return _override_or(
        Ether(dst="01:e0:52:00:00:00", src=_mac(c, "src_mac", "02:00:00:00:00:01"), type=0x88B6) / Raw(body),
        c,
    )


def _mlag_peer(c: dict[str, Any], chassis: str):
    """LACP + LLDP style peer-link stimulus (two frames concatenated via LACP primary)."""
    lacp = Ether(dst="01:80:c2:00:00:02", src=_mac(c, "src_mac", "02:00:00:00:00:01"), type=0x8809) / LACP(
        version=1,
        actor_system_priority=0x8000,
        actor_system=_mac(c, "src_mac", "02:00:00:00:00:01"),
        actor_key=1,
        actor_port_priority=0x8000,
        actor_port_number=1,
        actor_state=0x3D,
        partner_system_priority=0xFFFF,
        partner_system="00:00:00:00:00:00",
        partner_key=0,
        partner_port_priority=0xFFFF,
        partner_port_number=0,
        partner_state=0x01,
        collector_max_delay=0,
    )
    # Prefer LACP as TX unit; LLDP available via separate template
    return _override_or(lacp / Raw(f"MLAG:{chassis}".encode()), c)


def hpe_style(c: dict[str, Any], tag: bytes):
    return _override_or(
        Ether(dst="01:00:00:00:00:01", src=_mac(c, "src_mac", "02:00:00:00:00:01"), type=0x88B7) / Raw(tag + b"\x00" * 24),
        c,
    )


def generic_vc(c: dict[str, Any]):
    et = int(str(cfg(c, "ethertype", "88b5")).replace("0x", ""), 16) if cfg(c, "ethertype", None) else 0x88B5
    payload = hex_bytes(cfg(c, "payload_hex", "deadbeefcafebabe")) or b"\xde\xad\xbe\xef"
    return Ether(dst=_mac(c, "dst_mac", "ff:ff:ff:ff:ff:ff"), src=_mac(c, "src_mac", "02:00:00:00:00:01"), type=et) / Raw(
        payload
    )


PRESETS = {
    "vc_juniper": juniper_vccp,
    "vc_cisco_svl": cisco_svl,
    "vc_extreme": extreme_summit,
    "vc_arista_mlag": lambda c: _mlag_peer(c, "arista"),
    "vc_dell_mlag": lambda c: _mlag_peer(c, "dell"),
    "vc_hpe_irf": lambda c: hpe_style(c, b"IRF"),
    "vc_aruba_vsf": lambda c: hpe_style(c, b"VSF"),
    "vc_huawei_istack": lambda c: hpe_style(c, b"iSTK"),
    "vc_huawei_css": lambda c: hpe_style(c, b"CSS"),
    "vc_generic": generic_vc,
}


def build_vc_packet(preset_id: str, config: dict[str, Any]):
    fn = PRESETS.get(preset_id, generic_vc)
    return fn(config)


def list_presets() -> list[dict[str, str]]:
    return [
        {"id": k, "name": k.replace("vc_", "").replace("_", " ").title()}
        for k in PRESETS
    ]

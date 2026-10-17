"""Virtual Chassis / stacking — registry entries backed by vc_presets."""
from __future__ import annotations

from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ..vc_presets import PRESETS, build_vc_packet
from .base import ProtocolEntry, TemplateMeta, cfg, expect, field, hex_bytes, mac_fields, register

VC_IDS = [
    "vc_juniper",
    "vc_cisco_svl",
    "vc_extreme",
    "vc_arista_mlag",
    "vc_dell_mlag",
    "vc_hpe_irf",
    "vc_aruba_vsf",
    "vc_huawei_istack",
    "vc_huawei_css",
    "vc_generic",
    "vc_hex",
]

expect(*VC_IDS)


def _vc_fields(extra=None):
    base = mac_fields("01:00:00:00:00:01", "02:00:00:00:00:01") + [
        field("payload_hex", "Extra / override hex", "hex", False, "", advanced=True),
    ]
    return base + (extra or [])


def _make_vc(pid: str, name: str, blurb: str, when: str):
    register(
        ProtocolEntry(
            id=pid,
            name=name,
            category="Virtual Chassis / stacking",
            layer="vc",
            craft_slot="control",
            fields=_vc_fields(),
            build=lambda c, _pid=pid: build_vc_packet(_pid, c),
            template=TemplateMeta(blurb, when, default_pps=1.0),
        )
    )


_make_vc("vc_juniper", "Juniper VC / VCCP", "IS-IS Hello-style on L2", "Juniper Virtual Chassis labs")
_make_vc("vc_cisco_svl", "Cisco StackWise Virtual", "SVL-like L2 control + hex body", "StackWise Virtual link labs")
_make_vc("vc_extreme", "Extreme SummitStack", "Proprietary L2 keepalive preset", "SummitStack labs")
_make_vc("vc_arista_mlag", "Arista MLAG-peer", "LACP + LLDP flavor", "Arista MLAG peer-link labs")
_make_vc("vc_dell_mlag", "Dell MLAG-peer", "LACP + LLDP flavor", "Dell VLT/MLAG labs")
_make_vc("vc_hpe_irf", "HPE IRF", "L2 skeleton + hex", "HPE IRF stacking labs")
_make_vc("vc_aruba_vsf", "Aruba VSF", "L2 skeleton + hex", "Aruba VSF labs")
_make_vc("vc_huawei_istack", "Huawei iStack", "L2 skeleton + hex", "Huawei iStack labs")
_make_vc("vc_huawei_css", "Huawei CSS", "L2 skeleton + hex", "Huawei CSS labs")
_make_vc("vc_generic", "Generic / Other VC", "Raw L2 + ethertype + hex", "Any vendor without a preset")

register(
    ProtocolEntry(
        id="vc_hex",
        name="VC hex payload stream",
        category="Virtual Chassis / stacking",
        layer="vc",
        craft_slot="control",
        fields=mac_fields("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01")
        + [
            field("ethertype", "EtherType", "hex", True, "88b5"),
            field("payload_hex", "Payload (hex)", "hex", True, "deadbeefcafebabe"),
        ],
        build=lambda c: Ether(
            dst=cfg(c, "dst_mac"),
            src=cfg(c, "src_mac"),
            type=int(str(cfg(c, "ethertype", "88b5")).replace("0x", ""), 16),
        )
        / Raw(hex_bytes(cfg(c, "payload_hex", "deadbeef"))),
        template=TemplateMeta("Universal hex on L2", "Capture-derived VC/stack frames"),
    )
)

# Ensure presets module IDs align
assert set(PRESETS.keys()) >= {
    "vc_juniper",
    "vc_cisco_svl",
    "vc_extreme",
    "vc_arista_mlag",
    "vc_dell_mlag",
    "vc_hpe_irf",
    "vc_aruba_vsf",
    "vc_huawei_istack",
    "vc_huawei_css",
    "vc_generic",
}

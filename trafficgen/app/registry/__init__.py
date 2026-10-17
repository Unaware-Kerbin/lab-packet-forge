"""Load all protocol family modules into the registry."""
from __future__ import annotations

from . import base
from . import l2  # noqa: F401
from . import l2_ext  # noqa: F401
from . import l3  # noqa: F401
from . import l3_ext  # noqa: F401
from . import l4  # noqa: F401
from . import tunnels  # noqa: F401
from . import tunnels_ext  # noqa: F401
from . import routing  # noqa: F401
from . import routing_ext  # noqa: F401
from . import discovery  # noqa: F401
from . import ops_ext  # noqa: F401
from . import industrial  # noqa: F401
from . import telecom  # noqa: F401
from . import security  # noqa: F401
from . import security_ext  # noqa: F401
from . import escape  # noqa: F401
from . import vc  # noqa: F401

from .base import (
    ProtocolEntry,
    all_protocols,
    by_category,
    expected_ids,
    get,
)
from ..safety import PROTOCOL_PPS_CAPS, is_risky_protocol

CATEGORY_ORDER = [
    "Virtual Chassis / stacking",
    "L2 / switching",
    "L3 / addressing & ICMP",
    "L4 / transport",
    "Routing & first-hop",
    "Tunnels / overlays",
    "Telecom / mobile",
    "Industrial / OT",
    "Discovery / ops / app",
    "Security-shaped",
    "Escape hatches",
]


def protocol_to_dict(p: ProtocolEntry) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "category": p.category,
        "layer": p.layer,
        "craftable": p.craftable,
        "craft_slot": p.craft_slot,
        "stack_hint": p.stack_hint,
        "rebuild_each": p.rebuild_each,
        "fields": [
            {
                "name": f.name,
                "label": f.label,
                "type": f.type,
                "required": f.required,
                "default": f.default,
                "hint": f.hint,
                "options": f.options,
                "advanced": f.advanced,
                "min": f.min,
                "max": f.max,
            }
            for f in p.fields
        ],
        "template": {
            "blurb": p.template.blurb,
            "when_to_use": p.template.when_to_use,
            "default_pps": p.template.default_pps,
            "default_count": p.template.default_count,
            "soft_pps_cap": p.template.soft_pps_cap
            if p.template.soft_pps_cap is not None
            else (PROTOCOL_PPS_CAPS.get(p.id, (None, None))[0]),
            "hard_pps_cap": p.template.hard_pps_cap
            if p.template.hard_pps_cap is not None
            else (PROTOCOL_PPS_CAPS.get(p.id, (None, None))[1]),
            "control_plane_risk": p.template.control_plane_risk or is_risky_protocol(p.id),
        },
    }


def catalog() -> list[dict]:
    return [protocol_to_dict(p) for p in all_protocols()]


def templates_by_category() -> dict[str, list[dict]]:
    grouped = by_category()
    ordered: dict[str, list[dict]] = {}
    for cat in CATEGORY_ORDER:
        if cat in grouped:
            ordered[cat] = [protocol_to_dict(p) for p in grouped[cat]]
    for cat, items in grouped.items():
        if cat not in ordered:
            ordered[cat] = [protocol_to_dict(p) for p in items]
    return ordered


__all__ = [
    "ProtocolEntry",
    "all_protocols",
    "by_category",
    "catalog",
    "expected_ids",
    "get",
    "protocol_to_dict",
    "templates_by_category",
    "CATEGORY_ORDER",
]

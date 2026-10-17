"""Protocol registry primitives."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from scapy.packet import Packet


FieldType = str  # text | mac | ip | ipv6 | int | hex | select | bool | float


@dataclass
class FieldSpec:
    name: str
    label: str
    type: FieldType = "text"
    required: bool = False
    default: Any = None
    hint: str = ""
    options: list[dict[str, str]] = field(default_factory=list)
    advanced: bool = False
    min: Optional[float] = None
    max: Optional[float] = None


@dataclass
class TemplateMeta:
    blurb: str
    when_to_use: str = ""
    default_pps: float = 10.0
    default_count: int = 0  # 0 = continuous
    # Soft/hard pps guidance for control-plane / broadcast-heavy templates.
    # None = inherit from app.safety.PROTOCOL_PPS_CAPS when protocol is listed.
    soft_pps_cap: float | None = None
    hard_pps_cap: float | None = None
    control_plane_risk: bool = False


BuildFn = Callable[[dict[str, Any]], Packet]


@dataclass
class ProtocolEntry:
    id: str
    name: str
    category: str
    layer: str  # l2 | l3 | l4 | tunnel | routing | discovery | security | app | vc | escape
    fields: list[FieldSpec]
    build: BuildFn
    template: TemplateMeta
    craftable: bool = True
    craft_slot: str = "payload"  # l2 | l3 | l4 | tunnel | payload | control
    stack_hint: str = ""
    # When True, TX rebuilds via build() on every send (random dst MAC, etc.).
    rebuild_each: bool = False


_REGISTRY: dict[str, ProtocolEntry] = {}
_EXPECTED_IDS: list[str] = []


def register(entry: ProtocolEntry) -> ProtocolEntry:
    if entry.id in _REGISTRY:
        raise ValueError(f"duplicate protocol id: {entry.id}")
    _REGISTRY[entry.id] = entry
    return entry


def expect(*ids: str) -> None:
    """Declare catalog IDs that must exist (for check_catalog)."""
    _EXPECTED_IDS.extend(ids)


def get(proto_id: str) -> ProtocolEntry:
    return _REGISTRY[proto_id]


def all_protocols() -> list[ProtocolEntry]:
    return list(_REGISTRY.values())


def by_category() -> dict[str, list[ProtocolEntry]]:
    out: dict[str, list[ProtocolEntry]] = {}
    for p in _REGISTRY.values():
        out.setdefault(p.category, []).append(p)
    for cat in out:
        out[cat].sort(key=lambda x: x.name.lower())
    return out


def expected_ids() -> list[str]:
    return list(_EXPECTED_IDS)


def field(
    name: str,
    label: str,
    type: FieldType = "text",
    required: bool = False,
    default: Any = None,
    hint: str = "",
    options: Optional[list[dict[str, str]]] = None,
    advanced: bool = False,
    min: Optional[float] = None,
    max: Optional[float] = None,
) -> FieldSpec:
    return FieldSpec(
        name=name,
        label=label,
        type=type,
        required=required,
        default=default,
        hint=hint,
        options=options or [],
        advanced=advanced,
        min=min,
        max=max,
    )


def mac_fields(dst="ff:ff:ff:ff:ff:ff", src="02:00:00:00:00:01") -> list[FieldSpec]:
    return [
        field("dst_mac", "Dst MAC", "mac", True, dst),
        field("src_mac", "Src MAC", "mac", True, src),
    ]


def cfg(config: dict[str, Any], name: str, default: Any = None) -> Any:
    v = config.get(name, default)
    if v is None or v == "":
        return default
    return v


def hex_bytes(s: str) -> bytes:
    if not s:
        return b""
    s = s.replace(" ", "").replace(":", "").replace("-", "")
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)

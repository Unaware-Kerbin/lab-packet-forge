"""Compose registry layers / template configs into Scapy packets."""
from __future__ import annotations

from typing import Any

from scapy.packet import Packet

from .registry import get
from .registry.base import cfg

_LAYER_PRIORITY = {
    "escape": 0,
    "l2": 1,
    "vc": 2,
    "l3": 3,
    "l4": 4,
    "tunnel": 5,
    "routing": 6,
    "discovery": 7,
    "security": 8,
    "app": 9,
}


class BuildError(Exception):
    pass


def merge_field_defaults(proto_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Fill missing/blank config keys from ProtocolEntry field defaults."""
    entry = get(proto_id)
    merged: dict[str, Any] = {
        f.name: f.default for f in entry.fields if f.default is not None
    }
    if config:
        for k, v in config.items():
            if v is None or v == "":
                continue
            merged[k] = v
    return merged


def build_from_protocol(proto_id: str, config: dict[str, Any] | None = None) -> Packet:
    entry = get(proto_id)
    return entry.build(merge_field_defaults(proto_id, config))


def _primary_protocol_id(stream: dict[str, Any]) -> str | None:
    mode = stream.get("mode", "template")
    if mode == "craft":
        layers = stream.get("layers") or []
        if not layers:
            return None
        if len(layers) == 1:
            return layers[0].get("protocol")
        best = max(layers, key=lambda L: _LAYER_PRIORITY.get(get(L["protocol"]).layer, 0))
        return best.get("protocol")
    if mode == "replay" or stream.get("protocol") == "pcap_replay":
        return "pcap_replay"
    return stream.get("protocol")


def stream_rebuild_each(stream: dict[str, Any]) -> bool:
    """True when the stream's primary protocol regenerates frames every TX send."""
    proto = _primary_protocol_id(stream)
    if not proto:
        return False
    try:
        return bool(get(proto).rebuild_each)
    except KeyError:
        return False


def build_from_stream(stream: dict[str, Any]) -> Packet | list[Packet]:
    """
    Stream shapes:
      {"mode": "template", "protocol": "udp", "config": {...}}
      {"mode": "craft", "layers": [{"protocol": "eth_ii", "config": {...}}, ...]}
      {"mode": "replay", "pcap_path": "..."}
    """
    mode = stream.get("mode", "template")
    if mode == "replay" or stream.get("protocol") == "pcap_replay":
        path = stream.get("pcap_path") or cfg(stream.get("config") or {}, "pcap_path", "")
        from .replay import load_pcap

        return load_pcap(path)

    if mode == "craft":
        layers = stream.get("layers") or []
        if not layers:
            raise BuildError("craft stream has no layers")
        # Prefer a single composed build: use the last (outermost application) protocol's build
        # if it already includes lower layers; otherwise chain Raw-style by taking the
        # highest-level dedicated builder that embeds L2.
        # V1: craft UI selects one primary protocol (like template) OR a stack where
        # the outermost registered builder is used with merged config.
        if len(layers) == 1:
            layer = layers[0]
            return build_from_protocol(layer["protocol"], layer.get("config") or {})

        # Multi-layer: merge configs bottom-up and call the topmost protocol build if it
        # is a full-frame builder; else fall back to the first full-frame protocol.
        merged: dict[str, Any] = {}
        for layer in layers:
            merged.update(layer.get("config") or {})
        # Soft warning encoded as optional stack_warnings on stream — builder just builds primary
        # with merged fields; if user stacked UDP on Ethernet, prefer UDP which includes Ether.
        # Prefer L4/app/tunnel protocols over bare L2 when multiple present.
        best = max(layers, key=lambda L: _LAYER_PRIORITY.get(get(L["protocol"]).layer, 0))
        return build_from_protocol(best["protocol"], {**(best.get("config") or {}), **merged})

    # template mode
    proto = stream.get("protocol")
    if not proto:
        raise BuildError("stream missing protocol")
    return build_from_protocol(proto, stream.get("config") or {})


def stack_warnings(layers: list[dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    ids = [L.get("protocol") for L in layers]
    layers_meta = []
    for i in ids:
        try:
            layers_meta.append(get(i).layer)
        except KeyError:
            warnings.append(f"unknown protocol: {i}")
    if "l4" in layers_meta and "l3" not in layers_meta and not any(
        get(i).layer in ("l4", "app", "tunnel", "routing", "discovery") and True for i in ids
    ):
        pass
    # Soft checks: TCP/UDP without IP in craft stack of separate L2-only layers
    has_transport = any(get(i).layer == "l4" for i in ids if i in [x for x in ids])
    # Many builders embed IP — only warn when craft has tcp/udp alone as separate eth_ii + tcp
    if "tcp" in ids or "udp" in ids or "sctp" in ids:
        if "ipv4" not in ids and "ipv6" not in ids:
            # Still OK — tcp/udp builders include IP
            if not any(x in ids for x in ("tcp", "udp", "sctp")):
                warnings.append("Transport without IP")
    if "tcp" in ids and not any(x in ids for x in ("ipv4", "ipv6", "tcp")):
        warnings.append("TCP without IP")
    return warnings

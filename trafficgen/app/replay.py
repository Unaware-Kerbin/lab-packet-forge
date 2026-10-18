"""PCAP load / upload helpers for L2 replay."""
from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from scapy.utils import rdpcap

UPLOAD_DIR = Path(os.environ.get("FORGE_UPLOAD_DIR", "/tmp/forge-pcaps"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Soft guidance for floody captures; hard rejects unless allow_dangerous_rate.
REPLAY_SOFT_FRAMES = int(os.environ.get("FORGE_REPLAY_SOFT_FRAMES", "5000"))
REPLAY_HARD_FRAMES = int(os.environ.get("FORGE_REPLAY_HARD_FRAMES", "100000"))
REPLAY_SOFT_BYTES = int(os.environ.get("FORGE_REPLAY_SOFT_BYTES", str(25 * 1024 * 1024)))
REPLAY_HARD_BYTES = int(os.environ.get("FORGE_REPLAY_HARD_BYTES", str(200 * 1024 * 1024)))

ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".cap"}


def save_upload(data: bytes, filename: str | None = None) -> str:
    suffix = Path(filename or "capture.pcap").suffix.lower() or ".pcap"
    if suffix not in ALLOWED_SUFFIXES:
        raise ValueError(f"unsupported capture type {suffix!r}; use .pcap or .pcapng")
    path = UPLOAD_DIR / f"{uuid.uuid4().hex}{suffix}"
    path.write_bytes(data)
    return str(path)


def load_pcap(path: str):
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"pcap not found: {path}")
    pkts = list(rdpcap(path))
    if not pkts:
        raise ValueError("pcap is empty")
    return pkts


def _pkt_time(pkt) -> float | None:
    t = getattr(pkt, "time", None)
    if t is None:
        return None
    try:
        return float(t)
    except (TypeError, ValueError):
        return None


def inspect_pcap(path: str) -> dict[str, Any]:
    """Return frame count, duration, and soft/hard size warnings (does not load forever)."""
    if not path or not os.path.isfile(path):
        raise FileNotFoundError(f"pcap not found: {path}")
    size = os.path.getsize(path)
    pkts = load_pcap(path)
    n = len(pkts)
    t0 = _pkt_time(pkts[0])
    t1 = _pkt_time(pkts[-1])
    duration_s = None
    avg_pps = None
    if t0 is not None and t1 is not None and t1 >= t0:
        duration_s = max(0.0, t1 - t0)
        if duration_s > 0:
            avg_pps = (n - 1) / duration_s if n > 1 else None
        else:
            avg_pps = None
    warnings: list[str] = []
    if n >= REPLAY_SOFT_FRAMES:
        warnings.append(
            f"Capture has {n} frames (≥ soft {REPLAY_SOFT_FRAMES}); "
            "high loop rates can flood the lab fabric."
        )
    if size >= REPLAY_SOFT_BYTES:
        warnings.append(
            f"Capture is {size / (1024 * 1024):.1f} MiB (≥ soft "
            f"{REPLAY_SOFT_BYTES / (1024 * 1024):.0f} MiB)."
        )
    if avg_pps and avg_pps >= 500:
        warnings.append(
            f"Original capture average ~{avg_pps:.0f} pps — original-timing replay "
            "may stress switches; prefer a low pps rate on shared labs."
        )
    return {
        "path": path,
        "frames": n,
        "bytes": size,
        "duration_s": duration_s,
        "avg_pps": avg_pps,
        "warnings": warnings,
        "soft_frames": REPLAY_SOFT_FRAMES,
        "hard_frames": REPLAY_HARD_FRAMES,
        "soft_bytes": REPLAY_SOFT_BYTES,
        "hard_bytes": REPLAY_HARD_BYTES,
    }


def evaluate_replay_size(
    meta: dict[str, Any],
    *,
    allow_dangerous_rate: bool = False,
) -> tuple[bool, str | None]:
    """Return (blocked, warning). Hard frame/byte caps need allow_dangerous_rate."""
    frames = int(meta.get("frames") or 0)
    size = int(meta.get("bytes") or 0)
    if frames > REPLAY_HARD_FRAMES and not allow_dangerous_rate:
        return True, (
            f"Capture has {frames} frames (hard cap {REPLAY_HARD_FRAMES}). "
            "Enable allow_dangerous_rate to arm, or trim the pcap."
        )
    if size > REPLAY_HARD_BYTES and not allow_dangerous_rate:
        return True, (
            f"Capture is {size / (1024 * 1024):.1f} MiB "
            f"(hard cap {REPLAY_HARD_BYTES / (1024 * 1024):.0f} MiB). "
            "Enable allow_dangerous_rate to arm, or trim the pcap."
        )
    warns = list(meta.get("warnings") or [])
    return False, "; ".join(warns) if warns else None

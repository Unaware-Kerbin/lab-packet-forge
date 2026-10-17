"""PCAP load / upload helpers."""
from __future__ import annotations

import os
import uuid
from pathlib import Path

from scapy.utils import rdpcap

UPLOAD_DIR = Path(os.environ.get("FORGE_UPLOAD_DIR", "/tmp/forge-pcaps"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def save_upload(data: bytes, filename: str | None = None) -> str:
    suffix = Path(filename or "capture.pcap").suffix or ".pcap"
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

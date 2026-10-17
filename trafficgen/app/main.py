"""Lab Packet Forge API + static UI."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import registry
from .builder import BuildError, build_from_stream, stack_warnings
from .replay import save_upload
from .safety import (
    default_pps_for_protocol,
    evaluate_pps,
    policy_dict,
    safety_catalog,
)
from .tx import WORKER
from .vc_presets import list_presets

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("forge.api")

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Lab Packet Forge", version="1.2.0")


class StreamBody(BaseModel):
    mode: str = "template"
    protocol: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    layers: list[dict[str, Any]] = Field(default_factory=list)
    pps: float | None = None
    count: int | None = None
    loop: bool = True
    pcap_path: str | None = None
    iface: str | None = None
    allow_dangerous_rate: bool = False


class StartBody(BaseModel):
    stream: StreamBody | None = None
    iface: str | None = None
    pps: float | None = None
    allow_dangerous_rate: bool = False


class KillswitchBody(BaseModel):
    """Configure gateway killswitch probe target / timeout (runtime)."""

    enabled: bool | None = None
    timeout_s: float | None = None
    interval_s: float | None = None
    # empty / "auto" = container default route GW; or IPv4 / comma-list
    target: str | None = None
    # optional extras; "auto" adds eth1/lab nexthop when known
    secondary: str | None = None


def _list_ifaces() -> list[str]:
    try:
        from scapy.arch import get_if_list

        return sorted(get_if_list())
    except Exception:
        # fallback
        names = []
        sys_class = Path("/sys/class/net")
        if sys_class.is_dir():
            names = sorted(p.name for p in sys_class.iterdir())
        return names or ["eth1", "eth0", "lo"]


def _resolve_protocol(stream: dict[str, Any] | None, fallback: str | None = None) -> str | None:
    if not stream:
        return fallback
    proto = stream.get("protocol")
    if proto:
        return proto
    layers = stream.get("layers") or []
    if layers:
        return layers[-1].get("protocol")
    return fallback


def _enforce_pps(
    protocol: str | None,
    pps: float | None,
    *,
    allow_dangerous_rate: bool = False,
) -> tuple[float, dict[str, Any]]:
    rate = float(pps) if pps is not None else default_pps_for_protocol(protocol)
    policy = evaluate_pps(protocol, rate, allow_dangerous_rate=allow_dangerous_rate)
    info = policy_dict(policy)
    if policy.blocked:
        log.warning("pps blocked: %s", policy.warning)
        raise HTTPException(400, detail={"message": policy.warning, "pps_policy": info})
    if policy.warning:
        log.warning("pps warning: %s", policy.warning)
    return policy.effective, info


@app.get("/api/health")
def health():
    return {"ok": True, "service": "lab-packet-forge", "protocols": len(registry.all_protocols()), "version": "1.2.0"}


@app.get("/api/safety")
def safety():
    return {
        **safety_catalog(),
        "killswitch": WORKER.killswitch.snapshot(),
    }


@app.post("/api/safety/killswitch")
def configure_killswitch(body: KillswitchBody):
    """Update killswitch settings. Takes effect on next TX start (or immediately if idle)."""
    try:
        snap = WORKER.killswitch.configure(
            enabled=body.enabled,
            timeout_s=body.timeout_s,
            interval_s=body.interval_s,
            target=body.target,
            secondary=body.secondary,
        )
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    # If TX is running, re-arm with new settings so the probe thread picks them up.
    if WORKER.running and WORKER.killswitch.enabled:
        WORKER.killswitch.arm()
        snap = WORKER.killswitch.snapshot()
    log.info("killswitch configured: %s", {k: snap.get(k) for k in ("enabled", "timeout_s", "target_spec", "secondary_spec", "targets", "armed")})
    return {"ok": True, "killswitch": snap}


@app.get("/api/protocols")
def protocols(q: str | None = None, category: str | None = None):
    items = registry.catalog()
    if category:
        items = [p for p in items if p["category"] == category]
    if q:
        ql = q.lower()
        items = [
            p
            for p in items
            if ql in p["id"].lower() or ql in p["name"].lower() or ql in p["category"].lower() or ql in (p["template"]["blurb"] or "").lower()
        ]
    return {"protocols": items, "count": len(items)}


@app.get("/api/templates")
def templates(q: str | None = None):
    grouped = registry.templates_by_category()
    if q:
        ql = q.lower()
        filtered = {}
        for cat, items in grouped.items():
            keep = [
                p
                for p in items
                if ql in p["id"].lower() or ql in p["name"].lower() or ql in cat.lower() or ql in (p["template"]["blurb"] or "").lower()
            ]
            if keep:
                filtered[cat] = keep
        grouped = filtered
    return {"categories": grouped, "order": registry.CATEGORY_ORDER}


@app.get("/api/vc/presets")
def vc_presets():
    return {"presets": list_presets()}


@app.get("/api/ifaces")
def ifaces():
    return {"ifaces": _list_ifaces(), "default": os.environ.get("FORGE_IFACE", "eth1")}


@app.post("/api/stream")
def set_stream(body: StreamBody):
    data = body.model_dump()
    if body.mode == "craft" and body.layers:
        data["warnings"] = stack_warnings(body.layers)
    # Validate build early
    try:
        build_from_stream(data)
    except KeyError as e:
        raise HTTPException(400, f"unknown protocol: {e}") from e
    except BuildError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(400, f"build failed: {e}") from e
    proto = _resolve_protocol(data)
    pps, pps_policy = _enforce_pps(proto, body.pps, allow_dangerous_rate=body.allow_dangerous_rate)
    data["pps"] = pps
    WORKER.configure(data, iface=body.iface, pps=pps)
    return {"ok": True, "stream": data, "warnings": data.get("warnings", []), "pps_policy": pps_policy}


@app.post("/api/start")
def start(body: StartBody | None = None):
    allow = bool(body and body.allow_dangerous_rate)
    pps_policy = None
    if body and body.stream:
        data = body.stream.model_dump()
        try:
            build_from_stream(data)
        except Exception as e:
            raise HTTPException(400, f"build failed: {e}") from e
        proto = _resolve_protocol(data)
        pps, pps_policy = _enforce_pps(
            proto,
            body.pps if body.pps is not None else body.stream.pps,
            allow_dangerous_rate=allow or body.stream.allow_dangerous_rate,
        )
        data["pps"] = pps
        WORKER.configure(data, iface=body.iface or body.stream.iface, pps=pps)
    elif body:
        if body.iface:
            WORKER.iface = body.iface
        proto = _resolve_protocol(WORKER.stream)
        pps, pps_policy = _enforce_pps(
            proto,
            body.pps if body.pps is not None else WORKER.pps,
            allow_dangerous_rate=allow,
        )
        WORKER.pps = pps
    else:
        proto = _resolve_protocol(WORKER.stream)
        pps, pps_policy = _enforce_pps(proto, WORKER.pps, allow_dangerous_rate=False)
        WORKER.pps = pps
    if not WORKER.stream:
        raise HTTPException(400, "no stream configured")
    WORKER.start()
    snap = WORKER.snapshot()
    return {"ok": True, "stats": snap, "pps_policy": pps_policy}


@app.post("/api/stop")
def stop():
    WORKER.stop(reason="user_stop")
    return {"ok": True, "stats": WORKER.snapshot()}


@app.get("/api/stats")
def stats():
    return WORKER.snapshot()


@app.post("/api/replay")
async def replay_upload(
    file: UploadFile = File(...),
    iface: str | None = None,
    pps: float = 10.0,
    loop: bool = True,
    allow_dangerous_rate: bool = False,
):
    data = await file.read()
    if not data:
        raise HTTPException(400, "empty upload")
    path = save_upload(data, file.filename)
    _, pps_policy = _enforce_pps("pcap_replay", pps, allow_dangerous_rate=allow_dangerous_rate)
    stream = {
        "mode": "replay",
        "protocol": "pcap_replay",
        "pcap_path": path,
        "config": {"pcap_path": path, "loop": loop},
        "loop": loop,
        "pps": pps,
        "iface": iface or os.environ.get("FORGE_IFACE", "eth1"),
    }
    WORKER.configure(stream, iface=stream["iface"], pps=pps)
    return {"ok": True, "pcap_path": path, "stream": stream, "pps_policy": pps_policy}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def main():
    import uvicorn

    host = os.environ.get("FORGE_HOST", "0.0.0.0")
    port = int(os.environ.get("FORGE_PORT", "8080"))
    uvicorn.run("app.main:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()

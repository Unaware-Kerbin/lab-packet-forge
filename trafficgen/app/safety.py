"""PPS caps for control-plane / broadcast-heavy templates + gateway killswitch."""
from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any

log = logging.getLogger("forge.safety")

# Soft default when template doesn't specify; hard = reject without override.
DANGEROUS_RATE_WARN_PPS = float(os.environ.get("FORGE_DANGEROUS_RATE_PPS", "50"))

# Protocol-specific soft/hard caps (pps). Soft is the UI/default recommendation;
# hard is enforced unless allow_dangerous_rate=True.
PROTOCOL_PPS_CAPS: dict[str, tuple[float, float]] = {
    # Soft, hard
    "arp": (10.0, 100.0),
    "garp": (10.0, 100.0),
    "stp": (5.0, 50.0),
    "rstp": (5.0, 50.0),
    "mstp": (5.0, 50.0),
    "pvst": (5.0, 50.0),
    "pvst_plus": (5.0, 50.0),
    "vstp": (5.0, 50.0),
    "igmp": (10.0, 100.0),
    "mld": (10.0, 100.0),
    "lldp": (2.0, 20.0),
    "cdp": (2.0, 20.0),
    "lacp": (5.0, 50.0),
    "lacp_marker": (5.0, 50.0),
    "mac_pause": (5.0, 50.0),
    "vtp": (2.0, 20.0),
    "dtp": (2.0, 20.0),
    "eapol": (5.0, 50.0),
    "mdns": (10.0, 100.0),
    "llmnr": (10.0, 100.0),
    "ssdp": (10.0, 100.0),
    "dhcp": (10.0, 100.0),
    "dhcpv6": (10.0, 100.0),
    # L2 BUM / unknown-unicast floods — stress CAM/CPU; soft default 50, hard 500.
    "bum_spam": (50.0, 500.0),
    "uuf": (50.0, 500.0),
    # Expanded control-plane / discovery protocols
    "lldp_full": (2.0, 20.0),
    "carp": (5.0, 50.0),
    "mrp_mmrp": (5.0, 50.0),
    "mrp_mvrp": (5.0, 50.0),
    "erp_g8032": (5.0, 50.0),
    "fip": (5.0, 50.0),
    "ndp_opts": (10.0, 100.0),
    "rsvp": (5.0, 50.0),
    "rsvp_te": (5.0, 50.0),
    "ldp": (5.0, 50.0),
    "msdp": (10.0, 50.0),
    "bmp": (10.0, 50.0),
    "pcep": (10.0, 50.0),
    "babel": (10.0, 50.0),
    "eigrp_update": (5.0, 50.0),
    "isis_lsp": (5.0, 20.0),
    "isis_csnp": (5.0, 20.0),
    "ospf_lsa": (5.0, 20.0),
    "bgp_notification": (5.0, 20.0),
    "bgp_update": (5.0, 20.0),
    "pim_join": (10.0, 50.0),
    "pim_register": (10.0, 50.0),
    "igmpv3": (10.0, 100.0),
    "mldv2": (10.0, 100.0),
    "dvmrp": (5.0, 20.0),
    "gtpc": (20.0, 100.0),
    "gtpv2c": (20.0, 100.0),
    "diameter": (20.0, 100.0),
    "pfcp": (20.0, 100.0),
    "bacnet": (10.0, 50.0),
    "profinet_dcp": (5.0, 20.0),
    "eap_md5": (5.0, 50.0),
    "eap_tls": (5.0, 50.0),
    "radius_access": (20.0, 100.0),
    "dhcp_inform": (10.0, 100.0),
    "dhcpv6_relay": (10.0, 100.0),
    "netbios_ns": (10.0, 50.0),
}

# Categories / craft layers treated as L2 broadcast / control-plane risky.
RISKY_PROTOCOL_IDS = frozenset(PROTOCOL_PPS_CAPS.keys())

GATEWAY_KILL_ENABLED = os.environ.get("FORGE_GATEWAY_KILL", "1").lower() not in ("0", "false", "no", "off")
GATEWAY_KILL_TIMEOUT_S = float(os.environ.get("FORGE_GATEWAY_KILL_TIMEOUT_S", "120"))
GATEWAY_PROBE_INTERVAL_S = float(os.environ.get("FORGE_GATEWAY_PROBE_INTERVAL_S", "5"))
# Primary probe: explicit IP, comma-list, "auto"/empty → default route GW.
GATEWAY_KILL_TARGET = (os.environ.get("FORGE_GATEWAY_KILL_TARGET") or "").strip()
# Optional extras: IP list, or "auto" to add eth1/lab nexthop when discoverable.
GATEWAY_KILL_SECONDARY = (os.environ.get("FORGE_GATEWAY_KILL_SECONDARY") or "").strip()
LAB_GATEWAY = (os.environ.get("FORGE_LAB_GATEWAY") or "").strip()
LAB_IFACE = os.environ.get("FORGE_IFACE", "eth1")

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


@dataclass
class PpsPolicy:
    protocol: str | None
    soft_cap: float | None
    hard_cap: float | None
    requested: float
    effective: float
    dangerous: bool
    warning: str | None
    blocked: bool
    requires_override: bool


def caps_for(protocol: str | None) -> tuple[float | None, float | None]:
    if not protocol:
        return None, None
    return PROTOCOL_PPS_CAPS.get(protocol, (None, None))


def is_risky_protocol(protocol: str | None) -> bool:
    return bool(protocol and protocol in RISKY_PROTOCOL_IDS)


def evaluate_pps(
    protocol: str | None,
    pps: float,
    *,
    allow_dangerous_rate: bool = False,
) -> PpsPolicy:
    soft, hard = caps_for(protocol)
    requested = float(pps)
    warning = None
    blocked = False
    requires_override = False
    effective = requested
    dangerous = False

    if hard is not None and requested > hard and not allow_dangerous_rate:
        blocked = True
        requires_override = True
        dangerous = True
        warning = (
            f"{protocol} hard cap is {hard:g} pps "
            f"(requested {requested:g}). Set allow_dangerous_rate to override."
        )
    elif soft is not None and requested > soft:
        dangerous = True
        warning = (
            f"{protocol} soft cap is {soft:g} pps; {requested:g} pps can stress "
            f"switch control planes / flood tables."
        )
    elif is_risky_protocol(protocol) and requested >= DANGEROUS_RATE_WARN_PPS:
        dangerous = True
        warning = (
            f"High rate ({requested:g} pps) for control-plane/broadcast template "
            f"{protocol}; prefer ≤{DANGEROUS_RATE_WARN_PPS:g} pps in shared labs."
        )
    elif requested >= DANGEROUS_RATE_WARN_PPS * 10:
        dangerous = True
        warning = f"Very high TX rate ({requested:g} pps); confirm lab isolation."

    return PpsPolicy(
        protocol=protocol,
        soft_cap=soft,
        hard_cap=hard,
        requested=requested,
        effective=effective,
        dangerous=dangerous,
        warning=warning,
        blocked=blocked,
        requires_override=requires_override,
    )


def policy_dict(p: PpsPolicy) -> dict[str, Any]:
    return {
        "protocol": p.protocol,
        "soft_cap": p.soft_cap,
        "hard_cap": p.hard_cap,
        "requested": p.requested,
        "effective": p.effective,
        "dangerous": p.dangerous,
        "warning": p.warning,
        "blocked": p.blocked,
        "requires_override": p.requires_override,
        "risky": is_risky_protocol(p.protocol),
        "dangerous_rate_warn_pps": DANGEROUS_RATE_WARN_PPS,
    }


def default_pps_for_protocol(protocol: str | None, template_default: float | None = None) -> float:
    soft, _ = caps_for(protocol)
    if soft is not None:
        return soft
    if template_default is not None:
        return float(template_default)
    return 10.0


def detect_default_gateway() -> str | None:
    """Return IPv4 default gateway from the container/host route table (mgmt path)."""
    try:
        out = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True, timeout=2)
    except Exception as e:
        log.debug("ip route failed: %s", e)
        return None
    m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    return None


def detect_iface_nexthop(iface: str | None = None) -> str | None:
    """Best-effort nexthop for the lab TX iface (eth1), if any route via it exists."""
    iface = iface or LAB_IFACE
    if LAB_GATEWAY and _IPV4_RE.match(LAB_GATEWAY):
        return LAB_GATEWAY
    try:
        out = subprocess.check_output(["ip", "-4", "route", "show"], text=True, timeout=2)
    except Exception as e:
        log.debug("ip route show failed: %s", e)
        return None
    # Prefer default via <gw> dev eth1, else any via <gw> dev eth1
    for pat in (
        rf"default\s+via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+{re.escape(iface)}\b",
        rf"via\s+(\d+\.\d+\.\d+\.\d+)\s+dev\s+{re.escape(iface)}\b",
    ):
        m = re.search(pat, out)
        if m:
            return m.group(1)
    return None


def _parse_target_spec(spec: str | None) -> list[str] | None:
    """None => auto (default GW). Empty list after parse of blank tokens treated as auto."""
    if spec is None:
        return None
    s = str(spec).strip()
    if not s or s.lower() in ("auto", "default", "gw", "default_gw"):
        return None
    out: list[str] = []
    for part in s.split(","):
        p = part.strip()
        if not p:
            continue
        if p.lower() in ("auto", "default", "gw", "default_gw"):
            continue
        if not _IPV4_RE.match(p):
            raise ValueError(f"invalid killswitch target IP: {p}")
        if p not in out:
            out.append(p)
    return out or None


def resolve_probe_targets(
    primary_spec: str | None = None,
    secondary_spec: str | None = None,
    *,
    lab_iface: str | None = None,
) -> tuple[list[str], str]:
    """
    Resolve concrete IPs to probe.

    Returns (targets, mode) where mode is 'configured' | 'auto' | 'auto+secondary'.
    Primary unset/auto → default route GW. Killswitch fails if ANY target is unreachable
    (all must be reachable for the probe to pass).
    """
    primary = _parse_target_spec(primary_spec if primary_spec is not None else GATEWAY_KILL_TARGET)
    secondary_raw = secondary_spec if secondary_spec is not None else GATEWAY_KILL_SECONDARY

    targets: list[str] = []
    mode = "configured"

    if primary is None:
        mode = "auto"
        gw = detect_default_gateway()
        if gw:
            targets.append(gw)
    else:
        targets.extend(primary)

    sec_parts = [p.strip() for p in (secondary_raw or "").split(",") if p.strip()]
    want_auto_lab = any(p.lower() in ("auto", "lab", "eth1") for p in sec_parts) or (
        (secondary_raw or "").strip().lower() in ("auto", "lab", "eth1")
    )
    for p in sec_parts:
        if p.lower() in ("auto", "lab", "eth1"):
            continue
        if not _IPV4_RE.match(p):
            raise ValueError(f"invalid secondary killswitch target: {p}")
        if p not in targets:
            targets.append(p)

    if want_auto_lab:
        lab_gw = detect_iface_nexthop(lab_iface or LAB_IFACE)
        if lab_gw and lab_gw not in targets:
            targets.append(lab_gw)
            if mode == "auto":
                mode = "auto+secondary"
            elif "secondary" not in mode:
                mode = mode + "+secondary"

    return targets, mode


def probe_host(ip: str, timeout_s: float = 2.0) -> bool:
    """True only if ICMP echo succeeds. No ARP/neigh fallback (STALE would false-pass)."""
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout_s + 1.0,
            check=False,
        )
        return r.returncode == 0
    except Exception as e:
        log.debug("ping %s failed: %s", ip, e)
        return False


# Back-compat alias
def probe_gateway(gw: str, timeout_s: float = 2.0) -> bool:
    return probe_host(gw, timeout_s)


class GatewayKillswitch:
    """While TX runs, stop TX if probe target(s) unreachable for timeout_s continuously."""

    def __init__(
        self,
        stop_cb,
        *,
        enabled: bool = GATEWAY_KILL_ENABLED,
        timeout_s: float = GATEWAY_KILL_TIMEOUT_S,
        interval_s: float = GATEWAY_PROBE_INTERVAL_S,
        target: str | None = None,
        secondary: str | None = None,
    ) -> None:
        self._stop_cb = stop_cb
        self.enabled = enabled
        self.timeout_s = float(timeout_s)
        self.interval_s = float(interval_s)
        # None means inherit env / auto each resolve
        self.target_spec: str | None = GATEWAY_KILL_TARGET if target is None else target
        self.secondary_spec: str | None = GATEWAY_KILL_SECONDARY if secondary is None else secondary
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.status: dict[str, Any] = {
            "enabled": enabled,
            "timeout_s": self.timeout_s,
            "interval_s": self.interval_s,
            "target_spec": self.target_spec or "auto",
            "secondary_spec": self.secondary_spec or "",
            "target_mode": "auto",
            "targets": [],
            "gateway": None,  # primary display IP (first target)
            "reachable": None,
            "failing_since": None,
            "fail_seconds": 0.0,
            "seconds_until_stop": None,
            "armed": False,
            "last_check_at": None,
            "last_ok_at": None,
            "last_fail_detail": None,
            "last_stop_reason": None,
        }

    def configure(
        self,
        *,
        enabled: bool | None = None,
        timeout_s: float | None = None,
        interval_s: float | None = None,
        target: str | None = None,
        secondary: str | None = None,
    ) -> dict[str, Any]:
        """Update settings. Disarms if currently armed (caller should re-arm with TX)."""
        was_armed = False
        with self._lock:
            was_armed = bool(self.status.get("armed"))
        if was_armed:
            self.disarm()
        with self._lock:
            if enabled is not None:
                self.enabled = bool(enabled)
                self.status["enabled"] = self.enabled
            if timeout_s is not None:
                if float(timeout_s) < 1:
                    raise ValueError("timeout_s must be >= 1")
                self.timeout_s = float(timeout_s)
                self.status["timeout_s"] = self.timeout_s
            if interval_s is not None:
                if float(interval_s) < 0.5:
                    raise ValueError("interval_s must be >= 0.5")
                self.interval_s = float(interval_s)
                self.status["interval_s"] = self.interval_s
            if target is not None:
                _parse_target_spec(target)  # validate
                self.target_spec = target.strip()
                self.status["target_spec"] = self.target_spec or "auto"
            if secondary is not None:
                # validate secondary tokens
                for p in secondary.split(","):
                    p = p.strip()
                    if not p or p.lower() in ("auto", "lab", "eth1"):
                        continue
                    if not _IPV4_RE.match(p):
                        raise ValueError(f"invalid secondary killswitch target: {p}")
                self.secondary_spec = secondary.strip()
                self.status["secondary_spec"] = self.secondary_spec
            # Refresh resolved preview
            try:
                targets, mode = resolve_probe_targets(self.target_spec, self.secondary_spec)
            except ValueError:
                targets, mode = [], "invalid"
            self.status["targets"] = targets
            self.status["target_mode"] = mode
            self.status["gateway"] = targets[0] if targets else None
        return self.snapshot()

    def arm(self) -> None:
        if not self.enabled:
            with self._lock:
                self.status["armed"] = False
                self.status["enabled"] = False
            return
        self.disarm()
        self._stop.clear()
        try:
            targets, mode = resolve_probe_targets(self.target_spec, self.secondary_spec)
        except ValueError as e:
            log.error("killswitch arm failed: %s", e)
            with self._lock:
                self.status["armed"] = False
                self.status["last_fail_detail"] = str(e)
            return
        with self._lock:
            self.status.update(
                {
                    "enabled": True,
                    "armed": True,
                    "target_spec": self.target_spec or "auto",
                    "secondary_spec": self.secondary_spec or "",
                    "target_mode": mode,
                    "targets": targets,
                    "gateway": targets[0] if targets else None,
                    "reachable": None,
                    "failing_since": None,
                    "fail_seconds": 0.0,
                    "seconds_until_stop": None,
                    "last_fail_detail": None if targets else "no probe targets resolved",
                    "last_stop_reason": None,
                }
            )
        self._thread = threading.Thread(target=self._run, name="gw-killswitch", daemon=True)
        self._thread.start()
        log.info(
            "gateway killswitch armed (timeout=%.0fs targets=%s mode=%s)",
            self.timeout_s,
            targets,
            mode,
        )

    def disarm(self) -> None:
        self._stop.set()
        t = self._thread
        # Never join ourselves — stop_cb may run on this thread.
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=2.0)
        if threading.current_thread() is not t:
            self._thread = None
        with self._lock:
            self.status["armed"] = False
            self.status["seconds_until_stop"] = None

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            snap = dict(self.status)
        # Live preview of resolved targets even when disarmed
        if not snap.get("armed"):
            try:
                targets, mode = resolve_probe_targets(self.target_spec, self.secondary_spec)
                snap["targets"] = targets
                snap["target_mode"] = mode
                snap["gateway"] = targets[0] if targets else snap.get("gateway")
                snap["target_spec"] = self.target_spec or "auto"
                snap["secondary_spec"] = self.secondary_spec or ""
                snap["timeout_s"] = self.timeout_s
                snap["interval_s"] = self.interval_s
                snap["enabled"] = self.enabled
            except ValueError as e:
                snap["last_fail_detail"] = str(e)
        return snap

    def _probe_all(self, targets: list[str]) -> tuple[bool, str | None]:
        if not targets:
            return False, "no probe targets"
        failed: list[str] = []
        for ip in targets:
            if not probe_host(ip):
                failed.append(ip)
        if failed:
            return False, "unreachable: " + ",".join(failed)
        return True, None

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                targets, mode = resolve_probe_targets(self.target_spec, self.secondary_spec)
            except ValueError as e:
                targets, mode = [], "invalid"
                detail = str(e)
                ok = False
            else:
                ok, detail = self._probe_all(targets)
            now = time.time()
            with self._lock:
                self.status["targets"] = targets
                self.status["target_mode"] = mode
                self.status["gateway"] = targets[0] if targets else None
                self.status["reachable"] = ok
                self.status["last_check_at"] = now
                self.status["last_fail_detail"] = None if ok else detail
                if ok:
                    self.status["failing_since"] = None
                    self.status["fail_seconds"] = 0.0
                    self.status["seconds_until_stop"] = None
                    self.status["last_ok_at"] = now
                    continue
                if self.status["failing_since"] is None:
                    self.status["failing_since"] = now
                fail_s = now - float(self.status["failing_since"])
                self.status["fail_seconds"] = fail_s
                self.status["seconds_until_stop"] = max(0.0, self.timeout_s - fail_s)
                if fail_s < self.timeout_s:
                    log.warning(
                        "probe unreachable (%.0fs / %.0fs) targets=%s detail=%s — TX continues",
                        fail_s,
                        self.timeout_s,
                        targets,
                        detail,
                    )
                    continue
                reason = "gateway_unreachable"
                self.status["last_stop_reason"] = reason
                self.status["armed"] = False
                self.status["seconds_until_stop"] = 0.0
            log.error(
                "TX auto-stopped: probe unreachable for %.0fs (targets=%s) — killswitch",
                self.timeout_s,
                targets,
            )
            try:
                self._stop_cb(reason=reason)
            except Exception as e:
                log.exception("killswitch stop_cb failed: %s", e)
            return


def safety_catalog() -> dict[str, Any]:
    return {
        "protocol_caps": {
            k: {"soft_pps": soft, "hard_pps": hard} for k, (soft, hard) in PROTOCOL_PPS_CAPS.items()
        },
        "dangerous_rate_warn_pps": DANGEROUS_RATE_WARN_PPS,
        "gateway_kill": {
            "enabled_default": GATEWAY_KILL_ENABLED,
            "timeout_s": GATEWAY_KILL_TIMEOUT_S,
            "interval_s": GATEWAY_PROBE_INTERVAL_S,
            "target_default": GATEWAY_KILL_TARGET or "auto",
            "secondary_default": GATEWAY_KILL_SECONDARY or "",
            "lab_gateway_env": LAB_GATEWAY or None,
            "notes": (
                "Probes ICMP reachability of target(s). "
                "auto = container default route GW (often clab mgmt 172.20.20.1). "
                "For lab/DUT protection set target to DUT or lab GW (e.g. 10.1.0.1). "
                "secondary=auto adds eth1/lab nexthop when discoverable."
            ),
        },
    }

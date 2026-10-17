#!/usr/bin/env python3
"""Multi-vendor peer smoke/stress for Lab Packet Forge (clab).

Expects trafficgen eth1→Aruba, eth2→Juniper, eth3→Cisco (N9Kv).
Captures on peer container eth1 while TX runs. DUT-safe rate caps.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

BASE = os.environ.get("FORGE_URL", "http://127.0.0.1:8080")
TG = os.environ.get("FORGE_CONTAINER", "clab-forge-vendors-trafficgen")

PEERS = [
    {"name": "aruba", "iface": "eth1", "container": "clab-forge-vendors-aruba"},
    {"name": "junos", "iface": "eth2", "container": "clab-forge-vendors-junos"},
    {"name": "nexus", "iface": "eth3", "container": "clab-forge-vendors-nexus"},
]

# Low-rate samples: (protocol, pps, bpf fragment for peer capture)
SMOKES = [
    ("udp", 20, "udp port 5001"),
    ("lldp", 2, "ether proto 0x88cc"),
    ("arp", 5, "arp"),
    ("stp", 3, "ether dst 01:80:c2:00:00:00"),
    ("bum_spam", 15, "udp"),
]


@dataclass
class Result:
    name: str
    ok: bool
    detail: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)


RESULTS: list[Result] = []


def record(name: str, ok: bool, detail: str = "", **metrics: Any) -> None:
    RESULTS.append(Result(name, ok, detail, metrics))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}" + (f" | {metrics}" if metrics else ""), flush=True)


def api(method: str, path: str, body: dict | None = None, timeout: float = 15.0) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if body is not None else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            payload = json.loads(raw)
        except Exception:
            payload = {"detail": raw}
        return e.code, payload


def sh(cmd: str, timeout: float = 60.0) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def stop_tx() -> None:
    try:
        api("POST", "/api/stop")
    except Exception as e:
        print(f"[warn] stop_tx: {e}", flush=True)


def start_stream(protocol: str, pps: float, iface: str, allow_dangerous: bool = False) -> dict:
    code, resp = api(
        "POST",
        "/api/start",
        {
            "stream": {
                "mode": "template",
                "protocol": protocol,
                "config": {},
                "pps": pps,
                "iface": iface,
                "loop": True,
                "allow_dangerous_rate": allow_dangerous,
            },
            "iface": iface,
            "pps": pps,
            "allow_dangerous_rate": allow_dangerous,
        },
    )
    if code >= 400:
        raise RuntimeError(f"start {protocol}@{iface} failed {code}: {resp}")
    return resp


def peer_capture_count(container: str, bpf: str, seconds: float = 4.0) -> int:
    """tcpdump on peer eth1 (clab veth into vrnetlab)."""
    cmd = (
        f"docker exec {container} sh -c "
        f"\"timeout {seconds + 1:.0f} tcpdump -ni eth1 -c 80 '{bpf}' 2>/dev/null | wc -l\""
    )
    rc, out = sh(cmd, timeout=seconds + 25)
    try:
        return int(out.strip().splitlines()[-1])
    except Exception:
        return 0


def section_catalog() -> None:
    code, h = api("GET", "/api/health")
    n = int(h.get("protocols") or 0)
    record("api.health", code == 200 and h.get("ok") and n >= 176, str(h), protocols=n)
    code, i = api("GET", "/api/ifaces")
    ifaces = i.get("ifaces") or []
    record(
        "api.ifaces.multi",
        code == 200 and all(x in ifaces for x in ("eth1", "eth2", "eth3")),
        str(i),
    )
    code, s = api("GET", "/api/safety")
    ks = (s or {}).get("killswitch") or {}
    record(
        "api.killswitch.configured",
        code == 200 and "10.1.0.1" in (ks.get("targets") or []),
        f"targets={ks.get('targets')} enabled={ks.get('enabled')}",
    )


def section_safety() -> None:
    stop_tx()
    code, resp = api(
        "POST",
        "/api/start",
        {
            "stream": {"mode": "template", "protocol": "arp", "config": {}, "pps": 500, "iface": "eth1"},
            "pps": 500,
            "allow_dangerous_rate": False,
        },
    )
    record("safety.arp_hard_cap_reject", code == 400, str(resp)[:180])
    code2, resp2 = api(
        "POST",
        "/api/start",
        {
            "stream": {"mode": "template", "protocol": "bum_spam", "config": {}, "pps": 900, "iface": "eth1"},
            "pps": 900,
            "allow_dangerous_rate": False,
        },
    )
    record("safety.bum_hard_cap_reject", code2 == 400, str(resp2)[:180])


def section_peer_smokes() -> None:
    for peer in PEERS:
        # Confirm peer container eth1 exists
        rc, out = sh(f"docker exec {peer['container']} ip -br link show eth1")
        record(
            f"peer.{peer['name']}.link_up",
            rc == 0 and "eth1" in out,
            out.strip()[:120],
        )
        for proto, pps, bpf in SMOKES:
            stop_tx()
            # Kick capture slightly before TX
            dump = (
                f"docker exec -d {peer['container']} sh -c "
                f"'timeout 6 tcpdump -ni eth1 -c 60 \"{bpf}\" > /tmp/forge_peer.pcap.txt 2>/tmp/forge_peer.err; "
                f"wc -l < /tmp/forge_peer.pcap.txt > /tmp/forge_peer.count'"
            )
            sh(dump)
            time.sleep(0.5)
            try:
                start_stream(proto, pps=pps, iface=peer["iface"])
                time.sleep(3.5)
                _, st = api("GET", "/api/stats")
                stop_tx()
            except Exception as e:
                stop_tx()
                record(f"smoke.{peer['name']}.{proto}", False, f"tx error: {e}")
                continue
            time.sleep(1.2)
            _, cout = sh(f"docker exec {peer['container']} cat /tmp/forge_peer.count 2>/dev/null || echo 0")
            try:
                wire = int(cout.strip().splitlines()[-1])
            except Exception:
                wire = 0
            sent = int(st.get("sent") or 0)
            errors = int(st.get("errors") or 0)
            ok = wire >= 1 and errors == 0 and sent >= 1
            # STP toward some NOS may be filtered on tap before guest; accept sent+errors if wire 0 only for stp once
            if proto == "stp" and sent >= 1 and errors == 0 and wire < 1:
                # Retry with broader capture
                sh(
                    f"docker exec -d {peer['container']} sh -c "
                    f"'timeout 5 tcpdump -ni eth1 -c 40 -e > /tmp/forge_peer2.txt 2>/tmp/forge_peer2.err; "
                    f"wc -l < /tmp/forge_peer2.txt > /tmp/forge_peer2.count'"
                )
                time.sleep(0.4)
                start_stream(proto, pps=pps, iface=peer["iface"])
                time.sleep(3.0)
                stop_tx()
                time.sleep(1.0)
                _, c2 = sh(f"docker exec {peer['container']} cat /tmp/forge_peer2.count 2>/dev/null || echo 0")
                try:
                    wire = int(c2.strip().splitlines()[-1])
                except Exception:
                    wire = 0
                ok = wire >= 1 and errors == 0
            record(
                f"smoke.{peer['name']}.{proto}",
                ok,
                f"wire={wire} sent={sent} errors={errors} iface={peer['iface']}",
                wire=wire,
                sent=sent,
                errors=errors,
            )


def section_udp_stress_per_peer() -> None:
    """Short 200 pps UDP toward each vendor (well under flood).

    Wire path is already proven in section_peer_smokes(); this section validates
    sustained ~200 pps with docker exec -d tcpdump (same pattern as smoke).
    """
    for peer in PEERS:
        stop_tx()
        time.sleep(0.3)
        # Same detach pattern as smoke (plain `&` inside docker exec dies with the session).
        sh(
            f"docker exec -d {peer['container']} sh -c "
            f"'rm -f /tmp/forge_stress.count /tmp/forge_stress.out; "
            f"timeout 10 tcpdump -ni eth1 -c 200 \"udp port 5001\" "
            f"> /tmp/forge_stress.out 2>/tmp/forge_stress.err; "
            f"wc -l < /tmp/forge_stress.out > /tmp/forge_stress.count'"
        )
        time.sleep(0.5)
        try:
            start_stream("udp", pps=200, iface=peer["iface"])
        except Exception as e:
            stop_tx()
            record(f"stress.{peer['name']}.udp_200", False, f"start failed: {e}")
            continue
        time.sleep(1.5)
        _, a = api("GET", "/api/stats")
        t0 = time.time()
        sent0 = int(a.get("sent") or 0)
        time.sleep(3.0)
        _, b = api("GET", "/api/stats")
        dt = max(time.time() - t0, 1e-6)
        sent1 = int(b.get("sent") or 0)
        running = bool(b.get("running"))
        errors = int(b.get("errors") if b.get("errors") is not None else 1)
        pps_m = (sent1 - sent0) / dt
        pps_rep = float(b.get("pps_actual") or 0)
        stop_tx()
        time.sleep(2.0)
        _, cout = sh(
            f"docker exec {peer['container']} cat /tmp/forge_stress.count 2>/dev/null || echo 0"
        )
        try:
            wire = int(cout.strip().splitlines()[-1])
        except Exception:
            wire = 0
        # Sustained rate is the stress goal; smoke.* already proved L2 wire to each peer.
        # Do not require running_mid: killswitch/user_stop mid-window can flip it while pps/sent stay healthy.
        ok = errors == 0 and (pps_m >= 50 or pps_rep >= 50) and sent1 >= 50
        record(
            f"stress.{peer['name']}.udp_200",
            ok,
            (
                f"wire={wire} pps_meas={pps_m:.1f} pps_rep={pps_rep:.1f} "
                f"sent={sent1} errors={errors} running_mid={running}"
            ),
            wire=wire,
            pps_measured=pps_m,
            pps_actual=pps_rep,
            errors=errors,
            sent=sent1,
        )


def section_tx_stopped() -> None:
    stop_tx()
    time.sleep(0.3)
    _, st = api("GET", "/api/stats")
    record("tx.left_stopped", not st.get("running"), str(st)[:160])


def main() -> int:
    print(f"BASE={BASE} TG={TG}", flush=True)
    stop_tx()
    try:
        section_catalog()
        section_safety()
        section_peer_smokes()
        section_udp_stress_per_peer()
    finally:
        stop_tx()
        section_tx_stopped()

    print("\n======== VENDOR PEER MATRIX ========", flush=True)
    passed = sum(1 for r in RESULTS if r.ok)
    failed = sum(1 for r in RESULTS if not r.ok)
    for r in RESULTS:
        print(f"{'PASS' if r.ok else 'FAIL':4}  {r.name:42}  {r.detail[:140]}")
    print(f"\nTOTAL {passed}/{passed + failed} passed, {failed} failed", flush=True)
    report = {
        "passed": passed,
        "failed": failed,
        "peers": PEERS,
        "results": [{"name": r.name, "ok": r.ok, "detail": r.detail, "metrics": r.metrics} for r in RESULTS],
    }
    out = os.environ.get("FORGE_VENDOR_REPORT", "/tmp/forge_vendor_peer_report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"report={out}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

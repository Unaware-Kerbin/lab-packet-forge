"""Single-stream TX worker using Scapy L2 socket.

Rate control uses a monotonic budget. A persistent L2socket is required:
calling sendp() once per packet opens+closes AF_PACKET each time, which
collapses high pps targets to a handful of packets/sec.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

from scapy.config import conf

from .builder import build_from_stream, stream_rebuild_each
from .safety import GatewayKillswitch

log = logging.getLogger("forge.tx")

# Sleep until this close to the deadline, then busy-wait for accuracy.
# (Pure Event.wait/sleep is too coarse for multi-k PPS.)
_BUSY_TAIL_S = 0.00015
# Soft ceiling for docs/ops: pure Python+Scapy on a simple UDP stream.
# Beyond this, prefer sendpfast/tcpreplay for wire-rate.
SOFT_PPS_CEILING = 5000


class TxWorker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.stream: dict[str, Any] = {}
        self.iface: str = "eth1"
        self.pps: float = 10.0
        self.running: bool = False
        self.stopped_reason: str | None = None
        self.stats = {
            "sent": 0,
            "errors": 0,
            "last_error": "",
            "started_at": None,
            "pps_actual": 0.0,
            "iface": "eth1",
            "protocol": None,
        }
        self.killswitch = GatewayKillswitch(self._auto_stop)

    def _auto_stop(self, reason: str = "gateway_unreachable") -> None:
        """Called from killswitch thread — signal TX stop without joining killswitch."""
        log.error("auto-stop TX reason=%s", reason)
        with self._lock:
            self.stopped_reason = reason
            self.stats["last_error"] = f"auto-stop: {reason}"
        self._stop.set()
        t = self._thread
        if t and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=2.0)
        with self._lock:
            self.running = False
            self._thread = None

    def configure(self, stream: dict[str, Any], iface: str | None = None, pps: float | None = None) -> None:
        with self._lock:
            self.stream = stream
            if iface:
                self.iface = iface
            if pps is not None:
                self.pps = float(pps)
            elif stream.get("pps") is not None:
                self.pps = float(stream["pps"])
            self.stats["iface"] = self.iface
            self.stats["protocol"] = stream.get("protocol") or (
                (stream.get("layers") or [{}])[-1].get("protocol") if stream.get("layers") else None
            )

    def start(self) -> None:
        with self._lock:
            if self.running:
                return
            self._stop.clear()
            self.running = True
            self.stopped_reason = None
            self.stats["sent"] = 0
            self.stats["errors"] = 0
            self.stats["last_error"] = ""
            self.stats["started_at"] = time.time()
            self.stats["pps_actual"] = 0.0
            self._thread = threading.Thread(target=self._run, name="tx-worker", daemon=True)
            self._thread.start()
        self.killswitch.arm()

    def stop(self, reason: str | None = None) -> None:
        self.killswitch.disarm()
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=2.0)
        with self._lock:
            if reason and not self.stopped_reason:
                self.stopped_reason = reason
            elif reason is None and self.running and not self.stopped_reason:
                self.stopped_reason = "user_stop"
            self.running = False
            self._thread = None

    def _open_l2socket(self):
        # conf.L2socket is PF_PACKET on Linux; reuse across packets (sendp opens+closes).
        return conf.L2socket(iface=self.iface or conf.iface)

    def _pace(self, next_t: float, interval: float) -> float:
        """Advance the send budget; sleep then busy-wait the tail. Returns new next_t."""
        if interval <= 0:
            return next_t
        next_t += interval
        while not self._stop.is_set():
            now = time.monotonic()
            delay = next_t - now
            if delay <= 0:
                # Behind schedule: don't try to catch up in a burst.
                return now
            # Sleep most of the wait (capped for stop responsiveness), then pace the
            # busy-tail with tiny sleeps so we release the GIL — a tight spin starves
            # uvicorn/API threads under multi-k PPS.
            sleep_for = delay - _BUSY_TAIL_S
            if sleep_for > 0:
                self._stop.wait(min(sleep_for, 0.25))
                continue
            while not self._stop.is_set():
                remain = next_t - time.monotonic()
                if remain <= 0:
                    break
                time.sleep(min(remain, 0.00005))
            return next_t
        return next_t

    def _run(self) -> None:
        try:
            built = build_from_stream(self.stream)
        except Exception as e:
            with self._lock:
                self.stats["errors"] += 1
                self.stats["last_error"] = f"build: {e}"
                self.running = False
            self.killswitch.disarm()
            return

        packets = built if isinstance(built, list) else [built]
        if not packets:
            with self._lock:
                self.stats["last_error"] = "no packets to send"
                self.running = False
            self.killswitch.disarm()
            return

        # Protocols like bum_spam regenerate dst MAC / frame body on every send.
        rebuild_each = stream_rebuild_each(self.stream)
        count = int(self.stream.get("count") or 0)
        interval = 1.0 / self.pps if self.pps > 0 else 0.0
        sent_window = 0
        window_t0 = time.monotonic()
        idx = 0
        loop = bool(self.stream.get("loop", True))
        next_t = time.monotonic()
        sock = None

        try:
            sock = self._open_l2socket()
        except Exception as e:
            with self._lock:
                self.stats["errors"] += 1
                self.stats["last_error"] = f"socket: {e}"
                self.running = False
            self.killswitch.disarm()
            return

        try:
            while not self._stop.is_set():
                if rebuild_each:
                    try:
                        rebuilt = build_from_stream(self.stream)
                        pkt = rebuilt[0] if isinstance(rebuilt, list) else rebuilt
                    except Exception as e:
                        with self._lock:
                            self.stats["errors"] += 1
                            self.stats["last_error"] = f"rebuild: {e}"
                        break
                else:
                    pkt = packets[idx % len(packets)]
                try:
                    sock.send(pkt)
                    with self._lock:
                        self.stats["sent"] += 1
                    sent_window += 1
                except Exception as e:
                    with self._lock:
                        self.stats["errors"] += 1
                        self.stats["last_error"] = str(e)
                idx += 1
                if count and idx >= count:
                    break
                if not loop and not rebuild_each and idx >= len(packets):
                    break
                if not loop and rebuild_each and count == 0 and idx >= 1:
                    # rebuild_each + loop=false + no count → send one regenerated frame
                    break
                now = time.monotonic()
                if now - window_t0 >= 1.0:
                    with self._lock:
                        self.stats["pps_actual"] = sent_window / (now - window_t0)
                    sent_window = 0
                    window_t0 = now
                next_t = self._pace(next_t, interval)
        finally:
            try:
                sock.close()
            except Exception:
                pass
            # Final window sample so UI isn't stuck on 0 after a short run.
            now = time.monotonic()
            if sent_window and now > window_t0:
                with self._lock:
                    self.stats["pps_actual"] = sent_window / (now - window_t0)
            with self._lock:
                self.running = False
            self.killswitch.disarm()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self.running,
                "iface": self.iface,
                "pps": self.pps,
                "pps_soft_ceiling": SOFT_PPS_CEILING,
                "stream": self.stream,
                "stopped_reason": self.stopped_reason,
                "killswitch": self.killswitch.snapshot(),
                **self.stats,
            }


WORKER = TxWorker()

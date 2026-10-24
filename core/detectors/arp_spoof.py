import queue
import threading
import time

from core.alerts.alert import Alert
from core.utils.sliding_window import SlidingWindow, prune_idle_windows


class ArpSpoofDetector:
    """
    Detects ARP-based attacks by monitoring two indicators:

    1. MAC Conflict – a known IP suddenly appears with a different MAC,
       which is the fingerprint of ARP cache poisoning.

    2. Gratuitous ARP Flood – unsolicited ARP Replies (op=2, src_ip==dst_ip)
       sent at high frequency from the same MAC, which is how arpspoof
       continuously overwrites victim caches.
    """

    def __init__(
        self,
        packet_queue:              queue.Queue,
        alert_queue:               queue.Queue,
        gratuitous_threshold:      int = 3,
        gratuitous_window_seconds: int = 60,
    ):
        self._packets                   = packet_queue
        self._alerts                    = alert_queue
        self._gratuitous_threshold      = gratuitous_threshold
        self._gratuitous_window_seconds = gratuitous_window_seconds

        # IP → MAC mapping. This is real network state, not a time window,
        # so it stays a plain dict. Growth is bounded by the host count
        # on the local segment.
        self._arp_table: dict[str, str] = {}

        # src_mac → SlidingWindow of gratuitous ARP events
        self._gratuitous: dict[str, SlidingWindow] = {}
        self._last_sweep: float = 0.0

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="detector-arp-spoof",
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                packet = self._packets.get(timeout=1)
                self._process(packet)
            except queue.Empty:
                continue

    def _process(self, packet: dict) -> None:
        if packet.get("protocol") != "ARP":
            return

        src_ip  = packet.get("src_ip")
        src_mac = packet.get("src_mac")
        dst_ip  = packet.get("dst_ip")
        arp_op  = packet.get("arp_op")
        now     = packet.get("timestamp") or time.time()

        self._maybe_sweep(now)

        if not src_ip or not src_mac:
            return

        self._check_mac_conflict(src_ip, src_mac, now)
        self._check_gratuitous_flood(src_ip, src_mac, dst_ip, arp_op, now)

    def _check_mac_conflict(self, src_ip: str, src_mac: str, now: float) -> None:
        known_mac = self._arp_table.get(src_ip)

        if known_mac is None:
            self._arp_table[src_ip] = src_mac
            return

        if known_mac != src_mac:
            self._emit(
                src_ip   = src_ip,
                severity = "HIGH",
                now      = now,
                details  = {
                    "reason":    "mac_conflict",
                    "known_mac": known_mac,
                    "new_mac":   src_mac,
                },
            )
            self._arp_table[src_ip] = src_mac

    def _check_gratuitous_flood(
        self,
        src_ip:  str,
        src_mac: str,
        dst_ip:  str | None,
        arp_op:  int | None,
        now:     float,
    ) -> None:
        if arp_op != 2 or src_ip != dst_ip:
            return

        window = self._gratuitous.get(src_mac)
        if window is None:
            window = SlidingWindow(self._gratuitous_window_seconds)
            self._gratuitous[src_mac] = window

        count = window.add(now)
        if count > self._gratuitous_threshold:
            self._emit(
                src_ip   = src_ip,
                severity = "MEDIUM",
                now      = now,
                details  = {
                    "reason":  "gratuitous_arp_flood",
                    "src_mac": src_mac,
                    "count":   count,
                },
            )
            window.clear()

    def _maybe_sweep(self, now: float) -> None:
        """Drop idle per-MAC windows, at most once per gratuitous window."""
        if now - self._last_sweep < self._gratuitous_window_seconds:
            return
        prune_idle_windows(self._gratuitous, now)
        self._last_sweep = now

    def _emit(self, src_ip: str, severity: str, details: dict, now: float) -> None:
        self._alerts.put(Alert(
            type      = "ARP_SPOOF",
            severity  = severity,
            src_ip    = src_ip,
            timestamp = now,
            details   = details,
        ))

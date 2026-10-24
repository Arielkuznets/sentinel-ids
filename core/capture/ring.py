import threading
from collections import deque


class PacketRing:
    """Holds the last `window_seconds` of raw packets, and never more than `max_packets`.

    An alert is always late - a detector only calls a port scan once it has seen
    enough ports - so the packets that prove it have already gone by. The ring is
    what lets an alert look backwards at them.

    Both bounds are load-bearing. Time alone would leave the ring unbounded under
    a flood, which is the exact moment we can least afford to grow: the deque's
    maxlen evicts the oldest packet in O(1) once the ceiling is reached.

    The capture thread writes and the alert thread reads, so every access is
    locked. Each packet is stored beside the addresses the parser already pulled
    from it, so packets_for can select a source's traffic by string match without
    the ring ever reopening a packet - the one place that knows where an address
    lives (psrc for ARP, src for IP) stays the parser.
    """

    def __init__(self, window_seconds: float, max_packets: int):
        self._window = window_seconds
        self._packets: deque[tuple[float, str | None, str | None, object]] = deque(maxlen=max_packets)
        self._lock = threading.Lock()

    def add(self, timestamp: float, src_ip: str | None, dst_ip: str | None, packet) -> None:
        with self._lock:
            self._packets.append((timestamp, src_ip, dst_ip, packet))
            self._prune(timestamp)

    def packets_for(self, ip: str, now: float) -> list:
        """Every packet still in the window that `ip` sent or received, oldest first."""
        with self._lock:
            self._prune(now)
            return [pkt for _, src, dst, pkt in self._packets if ip in (src, dst)]

    def __len__(self) -> int:
        with self._lock:
            return len(self._packets)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._packets and self._packets[0][0] < cutoff:
            self._packets.popleft()

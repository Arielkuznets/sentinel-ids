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
    locked. The ring stores packets and does not read them - filtering by address
    belongs to whoever writes the file.
    """

    def __init__(self, window_seconds: float, max_packets: int):
        self._window = window_seconds
        self._packets: deque[tuple[float, object]] = deque(maxlen=max_packets)
        self._lock = threading.Lock()

    def add(self, timestamp: float, packet) -> None:
        with self._lock:
            self._packets.append((timestamp, packet))
            self._prune(timestamp)

    def snapshot(self, now: float) -> list[tuple[float, object]]:
        """The packets still inside the window at `now`, oldest first."""
        with self._lock:
            self._prune(now)
            return list(self._packets)

    def __len__(self) -> int:
        with self._lock:
            return len(self._packets)

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        while self._packets and self._packets[0][0] < cutoff:
            self._packets.popleft()

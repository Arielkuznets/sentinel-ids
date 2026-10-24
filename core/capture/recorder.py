import queue
import threading
import time

from db.queries import delete_packets_before, save_packets


class PacketRecorder:
    """Writes every packet's header fields to the packets table, in batches.

    One more subscriber on the fan-out queue, so it sees exactly what the
    detectors see - and like them it can only fall behind on its own queue: a
    slow disk costs rows in the log, never packets in detection. Rows are
    buffered and written when batch_size fills or flush_seconds pass, whichever
    comes first, so a flood is written in a few large transactions and a quiet
    network still reaches the dashboard within a second.

    Retention runs on packet time, like every window in the system: at most once
    per cleanup_seconds, rows more than retention_hours older than the newest
    packet are deleted, so the table stays bounded however long the IDS runs.
    """

    def __init__(
        self,
        packet_queue:    queue.Queue,
        session_factory,
        batch_size:      int   = 500,
        flush_seconds:   float = 1.0,
        retention_hours: float = 48,
        cleanup_seconds: float = 60,
    ):
        self._packets         = packet_queue
        self._session_factory = session_factory
        self._batch_size      = batch_size
        self._flush_seconds   = flush_seconds
        self._retention       = retention_hours * 3600
        self._cleanup_seconds = cleanup_seconds

        self._batch: list[dict] = []
        self._last_cleanup: float | None = None

        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="packet-recorder",
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the loop; it writes everything already queued before it exits."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _run(self) -> None:
        deadline = time.monotonic() + self._flush_seconds
        while not self._stop_event.is_set():
            try:
                self._process(self._packets.get(timeout=max(0.0, deadline - time.monotonic())))
            except queue.Empty:
                pass
            if time.monotonic() >= deadline:
                self._flush()
                deadline = time.monotonic() + self._flush_seconds

        # The tail is drained and written by this thread itself, so the batch is
        # never touched from two threads.
        while True:
            try:
                self._batch.append(self._packets.get_nowait())
            except queue.Empty:
                break
        self._flush()

    def _process(self, packet: dict) -> None:
        self._batch.append(packet)
        if len(self._batch) >= self._batch_size:
            self._flush()

    def _flush(self) -> None:
        if not self._batch:
            return
        batch, self._batch = self._batch, []
        save_packets(self._session_factory, batch)
        self._maybe_cleanup(float(max(packet["timestamp"] for packet in batch)))

    def _maybe_cleanup(self, now: float) -> None:
        if self._last_cleanup is not None and now - self._last_cleanup < self._cleanup_seconds:
            return
        delete_packets_before(self._session_factory, now - self._retention)
        self._last_cleanup = now

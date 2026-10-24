import threading

from scapy.sendrecv import sniff
from scapy.utils import PcapReader

from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.ring import PacketRing


class PacketCapture:
    """
    Manages the lifecycle of the packet sniffing process.
    Operates on a dedicated daemon thread to ensure non-blocking
    packet ingestion for the rest of the application.

    The source is chosen at construction: the live interface, or - given a
    replay_path - a capture file played back through the very same handler, so
    nothing downstream can tell a replay from live traffic.

    The ring, when present, is fed the raw packet here - the last point in the
    pipeline where one exists, since the parser flattens it into a dict of fields
    from which no .pcap can be written.
    """

    def __init__(self, interface: str, parser: PacketParser, queue: PacketQueue,
                 ring: PacketRing | None = None, replay_path: str | None = None,
                 replay_speed: float = 1.0):
        self._interface = interface
        self._parser = parser
        self._queue = queue
        self._ring = ring
        self._replay_path = replay_path
        self._replay_speed = replay_speed
        self._seen = 0
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Starts the capture loop on a background thread if not already running."""
        if self._thread and self._thread.is_alive():
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._replay_loop if self._replay_path else self._capture_loop,
            daemon=True,
            name="packet-capture"
        )
        self._thread.start()

    def stop(self) -> None:
        """Signals the capture loop to terminate and waits for clean shutdown."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)

    @property
    def is_running(self) -> bool:
        """Returns True if the capture thread is currently active."""
        return self._thread is not None and self._thread.is_alive()

    @property
    def packets_seen(self) -> int:
        """Every packet that entered the pipeline - what any one consumer kept may be less.

        Only the capture thread writes it, and an int read is atomic in CPython,
        so the UI can poll it from its own thread without a lock.
        """
        return self._seen

    def replay_pcap(self, path: str, speed: float = 0.0) -> None:
        """Push every packet of a capture file through the pipeline, in order.

        PcapReader streams the file one packet at a time, so a capture of any size
        replays in constant memory where rdpcap would load it whole. With speed > 0
        the recorded gaps are waited out, divided by speed: 1 is the original pace,
        10 is ten times faster. 0 sends as fast as Python can, and a consumer that
        falls a queue's length behind then drops packets - fine for a small file,
        lossy for a large one. stop() ends a replay early, even mid-gap.
        """
        previous = None
        with PcapReader(path) as reader:
            for pkt in reader:
                if speed > 0 and previous is not None:
                    self._pause(max(0.0, float(pkt.time - previous)) / speed)
                if self._stop_event.is_set():       # checked after the gap: a stop
                    return                          # mid-gap must not let one more through
                previous = pkt.time
                self._handle_packet(pkt)

    def _replay_loop(self) -> None:
        self.replay_pcap(self._replay_path, self._replay_speed)

    def _pause(self, seconds: float) -> None:
        # wait(), not sleep(): stop() cuts a long gap short instead of waiting it out
        self._stop_event.wait(seconds)

    def _capture_loop(self) -> None:
        sniff(
            iface=self._interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set()
        )

    def _handle_packet(self, raw_packet) -> None:
        self._seen += 1
        # parse() always returns a dict - no None to guard against.
        parsed = self._parser.parse(raw_packet)
        if self._ring is not None:
            self._ring.add(parsed["timestamp"], parsed["src_ip"], parsed["dst_ip"], raw_packet)
        self._queue.put(parsed)
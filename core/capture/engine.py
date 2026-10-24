import threading

from scapy.sendrecv import sniff
from scapy.utils import rdpcap

from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.ring import PacketRing


class PacketCapture:
    """
    Manages the lifecycle of the packet sniffing process.
    Operates on a dedicated daemon thread to ensure non-blocking
    packet ingestion for the rest of the application.

    The ring, when present, is fed the raw packet here - the last point in the
    pipeline where one exists, since the parser flattens it into a dict of fields
    from which no .pcap can be written.
    """

    def __init__(self, interface: str, parser: PacketParser, queue: PacketQueue,
                 ring: PacketRing | None = None):
        self._interface = interface
        self._parser = parser
        self._queue = queue
        self._ring = ring
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """Starts the capture loop on a background thread if not already running."""
        if self._thread and self._thread.is_alive():
            return
            
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._capture_loop,
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

    def replay_pcap(self, path: str) -> None:
        """
        Synchronously processes a PCAP file through the pipeline.
        Intended for testing and development environments.
        """
        packets = rdpcap(path)
        for pkt in packets:
            self._handle_packet(pkt)

    def _capture_loop(self) -> None:
        sniff(
            iface=self._interface,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda _: self._stop_event.is_set()
        )

    def _handle_packet(self, raw_packet) -> None:
        # parse() always returns a dict - no None to guard against.
        parsed = self._parser.parse(raw_packet)
        if self._ring is not None:
            self._ring.add(parsed["timestamp"], parsed["src_ip"], parsed["dst_ip"], raw_packet)
        self._queue.put(parsed)
import re
from datetime import datetime
from pathlib import Path

from scapy.utils import wrpcap

from core.alerts.alert import Alert
from core.capture.ring import PacketRing


class PcapExporter:
    """Writes an attacker's recent traffic to a .pcap file when an episode opens.

    The evidence behind an alert - the packets that tripped the detector - is
    pulled from the ring by source IP and written where Wireshark can open it.
    Nothing is written when the ring holds none of that source's traffic (a
    replay, or an attack faster than the window): no evidence is a state, not a
    failure, so export returns None rather than leaving an empty file.

    A single writer, the alert loop, so no lock here; the ring guards its own
    reads. After each write the directory is trimmed to max_files, oldest first,
    so evidence cannot fill the disk the way every other buffer here is bounded.
    """

    def __init__(self, ring: PacketRing, output_dir: str, max_files: int):
        self._ring = ring
        self._dir = Path(output_dir)
        self._max_files = max_files

    def export(self, alert: Alert) -> str | None:
        if not alert.src_ip:
            return None
        packets = self._ring.packets_for(alert.src_ip, alert.timestamp)
        if not packets:
            return None

        self._dir.mkdir(parents=True, exist_ok=True)
        path = self._dir / self._filename(alert)
        wrpcap(str(path), packets)
        self._trim()
        return str(path)

    def _filename(self, alert: Alert) -> str:
        ts = datetime.fromtimestamp(alert.timestamp).strftime("%Y%m%d_%H%M%S")
        # ':' from an IPv6 address is illegal in a Windows filename; keep only the safe set.
        ip = re.sub(r"[^0-9A-Za-z.]", "_", alert.src_ip)
        return f"{ts}_{alert.type}_{ip}.pcap"

    def _trim(self) -> None:
        files = sorted(self._dir.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
        if len(files) <= self._max_files:
            return
        for old in files[: len(files) - self._max_files]:
            old.unlink(missing_ok=True)

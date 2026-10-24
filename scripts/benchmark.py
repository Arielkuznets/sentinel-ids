"""Measure where SENTINEL spends its time - the numbers behind docs/BENCHMARKS.md.

Run from the sentinel/ folder:
    python scripts/benchmark.py

Every stage is timed on its own, on one core, over packets built from the
reference scenarios (scripts/make_samples.py) plus a slice of IPv6 - no NIC and
no Npcap. The database is a throwaway file, so sentinel.db is never touched.
"""
import os
import platform
import queue
import sys
import tempfile
import time
import tracemalloc

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import scapy
from scapy.layers.inet import TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from core.alerts.alert import Alert
from core.alerts.deduplicator import Deduplicator
from core.alerts.scoring import ThreatScorer
from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.ring import PacketRing
from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.baseline import BaselineDetector
from core.detectors.brute_force import BruteForceDetector
from core.detectors.dns_anomaly import DnsAnomalyDetector
from core.detectors.port_scan import PortScanDetector
from core.detectors.syn_flood import SynFloodDetector
from db.database import init_db
from db.queries import save_packets
from main import _handle_alert
from scripts import make_samples

ROUNDS = 40          # all_attacks has 236 packets; with the IPv6 slice, ~11,000 per stage

DETECTORS = {"port_scan": PortScanDetector, "arp_spoof": ArpSpoofDetector,
             "brute_force": BruteForceDetector, "dns_anomaly": DnsAnomalyDetector,
             "syn_flood": SynFloodDetector, "baseline": BaselineDetector}


class _QuietApp:
    """The alert path pushes to a UI; this one accepts every call and draws nothing."""

    def call_from_thread(self, fn, *args):
        pass

    def push_alert(self, alert):
        pass

    def push_alert_count(self, alert, count):
        pass


def _rate(count: int, seconds: float) -> str:
    return f"{count / seconds:>12,.0f}/s   {seconds / count * 1e6:>7.1f} µs each"


def _timed(label: str, count: int, work) -> float:
    start = time.perf_counter()
    work()
    seconds = time.perf_counter() - start
    print(f"{label:<22}{_rate(count, seconds)}")
    return seconds / count


def main() -> None:
    root   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config = yaml.safe_load(open(os.path.join(root, "config", "config.yaml")))
    print(f"CPU      {platform.processor()}")
    print(f"OS       {platform.platform()}")
    print(f"Python   {platform.python_version()}, Scapy {scapy.VERSION}\n")

    scenario = make_samples.all_attacks()
    scenario += [Ether() / IPv6(src="2001:db8::5", dst="2001:db8::1") / TCP(dport=443, flags="PA")
                 for _ in range(40)]
    wire = [bytes(pkt) for pkt in scenario] * ROUNDS
    n = len(wire)

    # What sniff() and PcapReader do to every frame before SENTINEL sees it.
    raw = []
    per_dissect = _timed("dissect (Scapy)", n, lambda: raw.extend(Ether(b) for b in wire))

    parser, parsed = PacketParser(), []
    for pkt, original in zip(raw, scenario * ROUNDS):
        pkt.time = original.time
    per_parse = _timed("parse", n, lambda: parsed.extend(parser.parse(p) for p in raw))

    per_detectors = 0.0
    for name, cls in DETECTORS.items():
        detector = cls(queue.Queue(), queue.Queue(), **config["detectors"][name])
        per_detectors += _timed(f"detector {name}", n,
                                lambda: [detector._process(p) for p in parsed])

    ceiling = config["alerts"]["pcap"]["max_packets"]
    ring = PacketRing(window_seconds=10**9, max_packets=ceiling)
    per_ring = _timed("ring add", n, lambda: [ring.add(p["timestamp"], p["src_ip"], p["dst_ip"], r)
                                              for p, r in zip(parsed, raw)])
    start = time.perf_counter()
    ring.packets_for("10.0.0.99", parsed[-1]["timestamp"])
    print(f"ring lookup           {(time.perf_counter() - start) * 1e3:>8.1f} ms to pick one source "
          f"out of {len(ring):,} packets")

    # Live, the ring holds the only reference to each dissected packet, so its real
    # cost is the packets themselves.
    tracemalloc.start()
    sample = [Ether(b) for b in wire[:2000]]
    per_packet_bytes = tracemalloc.get_traced_memory()[0] / len(sample)
    tracemalloc.stop()
    print(f"ring memory           {per_packet_bytes / 1024:>8.1f} KiB per dissected packet, "
          f"~{per_packet_bytes * ceiling / 2**20:,.0f} MiB at the {ceiling:,}-packet ceiling")

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        session_factory = init_db(os.path.join(tmp, "bench.db").replace("\\", "/"))
        batch = config["database"]["packet_batch_size"]
        _timed(f"packet log ({batch}/txn)", n,
               lambda: [save_packets(session_factory, parsed[i:i + batch])
                        for i in range(0, n, batch)])

        deduper = Deduplicator(config["alerts"]["dedup_window_seconds"])
        scorer  = ThreatScorer(**config["alerts"]["scoring"])
        alerts  = [Alert("PORT_SCAN", "HIGH", f"10.0.{i // 250}.{i % 250}", timestamp=1000.0 + i)
                   for i in range(500)]
        _timed("alert, new episode", len(alerts),
               lambda: [_handle_alert(a, session_factory, deduper, scorer, lambda ip, now: None,
                                      lambda ip: None, lambda alert: None, _QuietApp())
                        for a in alerts])

        # The whole capture side at once: read, dissect, parse, ring, fan out to eight
        # consumers (six detectors, the recorder, the TUI). The queues are sized to
        # hold the whole run, since nothing drains them here: a full queue would pay
        # an exception per consumer per packet, which a drained one never does.
        path = os.path.join(tmp, "bench.pcap")
        wrpcap(path, raw)
        fan_out = PacketQueue(maxsize=n + 1)
        for _ in range(8):
            fan_out.subscribe()
        capture = PacketCapture(interface=None, parser=parser, queue=fan_out,
                                ring=PacketRing(window_seconds=30, max_packets=ceiling))
        per_replay = _timed("replay end to end", n, lambda: capture.replay_pcap(path))

    per_core = per_replay + per_detectors
    print(f"\none core, capture side + all six detectors: ~{1 / per_core:,.0f} packets/s "
          f"({per_core * 1e6:.0f} µs per packet - dissect {per_dissect / per_core:.0%}, "
          f"parse {per_parse / per_core:.0%}, ring {per_ring / per_core:.0%}, "
          f"detectors {per_detectors / per_core:.0%}, the rest reading the file and fanning out)")


if __name__ == "__main__":
    main()

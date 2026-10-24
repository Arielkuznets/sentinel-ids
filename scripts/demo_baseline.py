"""Watch the baseline detector fire in the TUI - no Npcap and no admin needed.

Feeds synthetic packets for one host through the real pipeline: a steady rate
for a few seconds (so the baseline learns), then a burst that spikes the z-score.
The baseline is tuned fast here (1s buckets, 5-sample warm-up) so you don't wait.

Run from the sentinel/ folder:
    python scripts/demo_baseline.py

Watch the Packet Log stream, then a red BASELINE_ANOMALY land in Active Alerts
about seven seconds in. Press q to quit.
"""
import os
import queue
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml

from core.alerts.deduplicator import Deduplicator
from core.alerts.geoip import GeoIPResolver
from core.alerts.scoring import ThreatScorer
from core.capture.queue import PacketQueue
from core.detectors.baseline import BaselineDetector
from core.response.engine import ResponseEngine
from core.response.firewall import FirewallManager
from db.database import init_db
from main import _alert_loop
from ui.tui.app import SentinelApp


def _packet(src_ip: str, now: float) -> dict:
    return {
        "timestamp": now, "size": 64,
        "src_mac": None, "dst_mac": None,
        "src_ip": src_ip, "dst_ip": "10.0.0.9",
        "ttl": 64, "protocol": "TCP",
        "src_port": 51000, "dst_port": 443, "flags": "PA",
        "seq": None, "payload": b"", "arp_op": None,
        "dns_qname": None, "dns_qtype": None,
    }


def _feeder(pkt_queue: PacketQueue, stop: threading.Event) -> None:
    # per-second packet counts: a steady baseline, then a burst that spikes the z-score
    plan = [10, 11, 9, 10, 12, 60, 10, 10]
    for count in plan:
        if stop.is_set():
            return
        now = time.time()
        for i in range(count):
            pkt_queue.put(_packet("10.0.0.5", now + i * 0.002))
        time.sleep(1.0)
    while not stop.is_set():          # keep the process alive so the alert stays on screen
        time.sleep(0.5)


def main() -> None:
    config = yaml.safe_load(
        open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "config", "config.yaml"))
    )

    session_factory = init_db(os.path.join(tempfile.mkdtemp(), "demo.db"))
    pkt_queue   = PacketQueue()
    alert_queue = queue.Queue()
    deduper     = Deduplicator(window_seconds=60)
    scorer      = ThreatScorer(**config["alerts"]["scoring"])

    consumer = pkt_queue.subscribe()
    detector = BaselineDetector(
        pkt_queue.subscribe(), alert_queue,
        interval_seconds=1, min_samples=5, z_medium=3.0, z_high=5.0,
    )

    firewall = FirewallManager(direction="in")
    response = ResponseEngine(firewall, session_factory, whitelist=["10.0.0.5", "127.0.0.1"])
    app = SentinelApp(packet_queue=consumer, session_factory=session_factory, response_engine=response)

    geoip = GeoIPResolver.from_path(config["alerts"]["geoip"]["database_path"])

    threading.Thread(
        target=_alert_loop,
        args=(alert_queue, session_factory, deduper, scorer, detector.deviation_for,
              geoip.lookup, lambda alert: None, app),
        daemon=True,
    ).start()
    detector.start()

    stop = threading.Event()
    threading.Thread(target=_feeder, args=(pkt_queue, stop), daemon=True).start()

    app.run()
    stop.set()


if __name__ == "__main__":
    main()

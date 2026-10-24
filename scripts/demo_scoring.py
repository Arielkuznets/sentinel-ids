"""Watch a threat score climb in the TUI - no Npcap and no admin needed.

Feeds one host's traffic through the real pipeline in three acts:

  1. quiet     - 10.0.0.5 sends steady benign traffic, and the baseline learns it
  2. spoofing  - it starts an ARP spoof, flipping its MAC every second. Each flip
                 is a repeat, so the score climbs on frequency alone and crosses
                 from amber into red
  3. flooding  - it also floods, so it now deviates from the baseline it just
                 taught us, the third term kicks in and the score pins at 100

The baseline is tuned fast here (1s buckets, 5-sample warm-up) so you don't wait
five minutes for it to learn.

Run from the sentinel/ folder:
    python scripts/demo_scoring.py

Watch the ARP_SPOOF line in Active Alerts: its ×count rises, its score climbs
past 70 and turns red, and z= goes from a flat reading to a saturated one.
Press q to quit.
"""
import os
import queue
import sys
import tempfile
import threading
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alerts.deduplicator import Deduplicator
from core.alerts.geoip import GeoIPResolver
from core.alerts.scoring import ThreatScorer
from core.capture.queue import PacketQueue
from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.baseline import BaselineDetector
from core.response.engine import ResponseEngine
from core.response.firewall import FirewallManager
from db.database import init_db
from main import _alert_loop
from ui.tui.app import SentinelApp

ATTACKER = "10.0.0.5"
GATEWAY  = "10.0.0.1"
REAL_MAC = "aa:aa:aa:aa:aa:aa"
FAKE_MAC = "bb:bb:bb:bb:bb:bb"

_BASE = {
    "size": 64, "src_mac": None, "dst_mac": None, "ttl": 64,
    "src_port": None, "dst_port": None, "flags": None,
    "seq": None, "payload": b"", "arp_op": None,
    "dns_qname": None, "dns_qtype": None,
}


def _benign(now: float) -> dict:
    return {**_BASE, "timestamp": now, "src_ip": ATTACKER, "dst_ip": "10.0.0.9",
            "protocol": "TCP", "src_port": 51000, "dst_port": 443, "flags": "PA"}


def _arp(now: float, mac: str) -> dict:
    # dst_ip is the gateway, not the source, so this is a plain reply and not a
    # gratuitous one - it trips the MAC-conflict check alone, keeping the demo to
    # a single climbing episode instead of two.
    return {**_BASE, "timestamp": now, "src_ip": ATTACKER, "dst_ip": GATEWAY,
            "protocol": "ARP", "src_mac": mac, "arp_op": 2}


def _feeder(pkt_queue: PacketQueue, stop: threading.Event) -> None:
    quiet_rate = [10, 11, 9, 10, 12, 10]          # act 1: the baseline learns ~10/s
    spoof_secs = 14                                # act 2: repeats alone drive the score
    flood_secs = 10                                # act 3: the rate spikes on top

    def send(count: int, arp_mac: str | None) -> None:
        if stop.is_set():
            return
        now = time.time()
        for i in range(count):
            pkt_queue.put(_benign(now + i * 0.002))
        if arp_mac:
            pkt_queue.put(_arp(now + 0.5, arp_mac))
        time.sleep(1.0)

    for rate in quiet_rate:
        send(rate, arp_mac=None)

    for i in range(spoof_secs):                    # the MAC ping-pongs: every flip conflicts
        send(10, FAKE_MAC if i % 2 == 0 else REAL_MAC)

    for i in range(flood_secs):
        send(60, FAKE_MAC if i % 2 == 0 else REAL_MAC)

    while not stop.is_set():                       # keep the alert on screen
        time.sleep(0.5)


def main() -> None:
    root   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config = yaml.safe_load(open(os.path.join(root, "config", "config.yaml")))

    session_factory = init_db(os.path.join(tempfile.mkdtemp(), "demo.db"))
    pkt_queue   = PacketQueue()
    alert_queue = queue.Queue()
    deduper     = Deduplicator(config["alerts"]["dedup_window_seconds"])
    scorer      = ThreatScorer(**config["alerts"]["scoring"])

    consumer = pkt_queue.subscribe()
    baseline = BaselineDetector(
        pkt_queue.subscribe(), alert_queue,
        interval_seconds=1, min_samples=5, z_medium=3.0, z_high=5.0,
    )
    arp = ArpSpoofDetector(pkt_queue.subscribe(), alert_queue)

    firewall = FirewallManager(direction="in")
    response = ResponseEngine(firewall, session_factory, whitelist=[ATTACKER, "127.0.0.1"])
    app = SentinelApp(
        packet_queue=consumer,
        session_factory=session_factory,
        response_engine=response,
        score_high   = config["ui"]["score_high"],
        score_medium = config["ui"]["score_medium"],
    )

    geoip = GeoIPResolver.from_path(config["alerts"]["geoip"]["database_path"])

    threading.Thread(
        target=_alert_loop,
        args=(alert_queue, session_factory, deduper, scorer, baseline.deviation_for,
              geoip.lookup, lambda alert: None, app),
        daemon=True,
    ).start()
    baseline.start()
    arp.start()

    stop = threading.Event()
    threading.Thread(target=_feeder, args=(pkt_queue, stop), daemon=True).start()

    app.run()
    stop.set()


if __name__ == "__main__":
    main()

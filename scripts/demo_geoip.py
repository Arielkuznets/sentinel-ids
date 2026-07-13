"""Watch alerts arrive with a country attached - no Npcap and no admin needed.

Five sources port-scan the same host, one after another, and each one shows a
different face of the lookup:

  5.255.255.70    Russia / Moscow          - country and city
  223.5.5.5       China / Hangzhou         - country and city
  185.220.101.1   Germany                  - a known Tor exit: geo names the exit
                                             node's country, never the attacker's
  1.1.1.1         nothing                  - public, but anycast: the database
                                             holds no country for it
  192.168.1.50    nothing                  - private: it is not a place at all

Run from the sentinel/ folder:
    python scripts/demo_geoip.py

The alerts land in the configured database, so the dashboard shows the same five
with their flags:
    python -m ui.web       (in a second terminal, then open localhost:8888)

Press q to quit.
"""
import os
import queue
import sys
import threading
import time

import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alerts.deduplicator import Deduplicator
from core.alerts.geoip import GeoIPResolver
from core.alerts.scoring import ThreatScorer
from core.capture.queue import PacketQueue
from core.detectors.port_scan import PortScanDetector
from core.response.engine import ResponseEngine
from core.response.firewall import FirewallManager
from db.database import init_db
from main import _alert_loop
from ui.tui.app import SentinelApp

SCANNERS = ["5.255.255.70", "223.5.5.5", "185.220.101.1", "1.1.1.1", "192.168.1.50"]
TARGET   = "192.168.1.20"

_BASE = {
    "size": 64, "src_mac": None, "dst_mac": None, "ttl": 64,
    "src_port": 51000, "flags": "S", "seq": None, "payload": b"",
    "arp_op": None, "dns_qname": None, "dns_qtype": None,
    "protocol": "TCP", "dst_ip": TARGET,
}


def _syn(src_ip: str, port: int, now: float) -> dict:
    return {**_BASE, "timestamp": now, "src_ip": src_ip, "dst_port": port}


def _feeder(pkt_queue: PacketQueue, stop: threading.Event) -> None:
    for src in SCANNERS:
        if stop.is_set():
            return
        for port in range(20, 45):          # 25 ports > the threshold of 15
            pkt_queue.put(_syn(src, port, time.time()))
            time.sleep(0.06)
        time.sleep(1.5)

    while not stop.is_set():                # keep the alerts on screen
        time.sleep(0.5)


def main() -> None:
    root   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    config = yaml.safe_load(open(os.path.join(root, "config", "config.yaml")))

    session_factory = init_db(config["database"]["path"])
    pkt_queue   = PacketQueue()
    alert_queue = queue.Queue()
    deduper     = Deduplicator(config["alerts"]["dedup_window_seconds"])
    scorer      = ThreatScorer(**config["alerts"]["scoring"])
    geoip       = GeoIPResolver.from_path(config["alerts"]["geoip"]["database_path"])

    ps_cfg   = config["detectors"]["port_scan"]
    consumer = pkt_queue.subscribe()
    detector = PortScanDetector(
        pkt_queue.subscribe(), alert_queue,
        threshold_ports  = ps_cfg["threshold_ports"],
        window_seconds   = ps_cfg["window_seconds"],
        cooldown_seconds = ps_cfg["cooldown_seconds"],
    )

    firewall = FirewallManager(direction="in")
    response = ResponseEngine(firewall, session_factory, whitelist=config["response"]["whitelist"])
    app = SentinelApp(
        packet_queue=consumer,
        session_factory=session_factory,
        response_engine=response,
        score_high   = config["ui"]["score_high"],
        score_medium = config["ui"]["score_medium"],
    )

    threading.Thread(
        target=_alert_loop,
        args=(alert_queue, session_factory, deduper, scorer, lambda ip, now: None,
              geoip.lookup, app),
        daemon=True,
    ).start()
    detector.start()

    stop = threading.Event()
    threading.Thread(target=_feeder, args=(pkt_queue, stop), daemon=True).start()

    app.run()
    stop.set()
    detector.stop()


if __name__ == "__main__":
    main()

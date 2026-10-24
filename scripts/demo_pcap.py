"""Watch an alert carry its own evidence - no Npcap and no admin needed.

Real Scapy packets enter the real capture engine, so the packet ring fills exactly
as it does live, and the moment an episode opens, that source's recent traffic is
written to captures/ as a file Wireshark opens. Three sources, three answers:

  5.255.255.70   port-scans 192.168.1.20    PORT_SCAN, pcap: its SYNs only - the
                                            benign host chatting beside it is
                                            left out of the file
  192.168.1.1    claimed by a second MAC    ARP_SPOOF, pcap: both replies, picked
                                            by the ARP sender address
  (spoofed)      SYN-floods 192.168.1.10    SYN_FLOOD, no pcap: every source is
                                            fake, so there is no one to capture

Run from the sentinel/ folder:
    python scripts/demo_pcap.py

The alerts land in the configured database, so the dashboard names each file:
    python -m ui.web       (in a second terminal, then open localhost:8888)

Press q to quit; the files written are listed on the way out.
"""
import os
import queue
import random
import sys
import threading
import time

import yaml
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.alerts.deduplicator import Deduplicator
from core.alerts.geoip import GeoIPResolver
from core.alerts.pcap_export import PcapExporter
from core.alerts.scoring import ThreatScorer
from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.ring import PacketRing
from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.port_scan import PortScanDetector
from core.detectors.syn_flood import SynFloodDetector
from core.response.engine import ResponseEngine
from core.response.firewall import FirewallManager
from db.database import init_db
from main import _alert_loop
from ui.tui.app import SentinelApp

SCANNER      = "5.255.255.70"
VICTIM       = "192.168.1.20"
BENIGN       = "192.168.1.30"
GATEWAY      = "192.168.1.1"
FLOOD_TARGET = "192.168.1.10"
REAL_MAC     = "aa:bb:cc:11:22:33"
FAKE_MAC     = "dd:ee:ff:44:55:66"

# Explicit MACs on every frame: left empty, Scapy would ARP the real network to
# fill them in the moment the parser measures the packet.
_ETH = {"src": "02:00:00:00:00:01", "dst": "02:00:00:00:00:02"}


def _benign():
    return Ether(**_ETH) / IP(src=BENIGN, dst=VICTIM) / TCP(sport=51000, dport=443, flags="PA")


def _syn(src: str, dst: str, port: int):
    return Ether(**_ETH) / IP(src=src, dst=dst) / TCP(sport=40000, dport=port, flags="S")


def _arp_reply(mac: str):
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc=mac, psrc=GATEWAY, hwdst="00:00:00:00:00:00", pdst=VICTIM)


def _spoofed_ip() -> str:
    return f"{random.randint(11, 250)}.{random.randint(0, 255)}." \
           f"{random.randint(0, 255)}.{random.randint(1, 254)}"


def _feeder(capture: PacketCapture, stop: threading.Event) -> None:
    # _handle_packet is the callback sniff() calls, so every packet takes the live
    # path: parsed for the detectors, and kept raw in the ring for the exporter.
    def send(pkt, pause: float) -> None:
        capture._handle_packet(pkt)
        time.sleep(pause)

    for _ in range(8):                          # quiet: only the benign host talks
        send(_benign(), 0.25)

    # 19 ports: past the scan threshold of 15, under the flood detector's floor of
    # 20 SYNs - a faster, wider scan also reads as a small SYN flood on its victim.
    for port in range(20, 39):
        send(_syn(SCANNER, VICTIM, port), 0.06)
        if port % 4 == 0:
            send(_benign(), 0.0)

    for _ in range(6):
        send(_benign(), 0.25)

    send(_arp_reply(REAL_MAC), 1.0)             # the gateway's real MAC is learned...
    send(_arp_reply(FAKE_MAC), 0.0)             # ...then a second MAC claims its IP

    for _ in range(6):
        send(_benign(), 0.25)

    # Spread over six seconds: the flood detector judges once per 5s window, so a
    # burst that ends before the next judgement could age out of the window first.
    for i in range(120):
        send(_syn(_spoofed_ip(), FLOOD_TARGET, 80), 0.05)
        if i % 10 == 0:
            send(_benign(), 0.0)

    for _ in range(24):                         # keep packet time moving past the window
        if stop.is_set():
            return
        send(_benign(), 0.25)

    while not stop.is_set():                    # keep the alerts on screen
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

    pcap_cfg = config["alerts"]["pcap"]
    ring     = PacketRing(window_seconds=pcap_cfg["buffer_seconds"],
                          max_packets=pcap_cfg["max_packets"])
    exporter = PcapExporter(ring, output_dir=pcap_cfg["output_dir"],
                            max_files=pcap_cfg["max_files"])
    capture  = PacketCapture(interface=None, parser=PacketParser(), queue=pkt_queue, ring=ring)

    written = []

    def export(alert):
        path = exporter.export(alert)
        if path:
            written.append(path)
        return path

    consumer = pkt_queue.subscribe()
    ps_cfg   = config["detectors"]["port_scan"]
    syn_cfg  = config["detectors"]["syn_flood"]
    detectors = [
        PortScanDetector(pkt_queue.subscribe(), alert_queue,
                         threshold_ports  = ps_cfg["threshold_ports"],
                         window_seconds   = ps_cfg["window_seconds"],
                         cooldown_seconds = ps_cfg["cooldown_seconds"]),
        ArpSpoofDetector(pkt_queue.subscribe(), alert_queue),
        SynFloodDetector(pkt_queue.subscribe(), alert_queue,
                         ratio_medium     = syn_cfg["ratio_medium"],
                         ratio_high       = syn_cfg["ratio_high"],
                         window_seconds   = syn_cfg["window_seconds"],
                         min_syn          = syn_cfg["min_syn"],
                         cooldown_seconds = syn_cfg["cooldown_seconds"]),
    ]

    # The demo's sources are whitelisted, so a stray 'b' never writes a real firewall rule.
    firewall = FirewallManager(direction="in")
    response = ResponseEngine(firewall, session_factory,
                              whitelist=[*config["response"]["whitelist"], SCANNER])
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
              geoip.lookup, export, app),
        daemon=True,
    ).start()
    for detector in detectors:
        detector.start()

    stop = threading.Event()
    threading.Thread(target=_feeder, args=(capture, stop), daemon=True).start()

    app.run()
    stop.set()
    for detector in detectors:
        detector.stop()

    for path in written:
        print(f"evidence: {path}")
    if written:
        print("open one in Wireshark, or: tshark -r <file>")


if __name__ == "__main__":
    main()

"""Regression tests for the two deferred alert-storm bugs, closed by dedup.

Both detectors still emit one alert per event (a DNS tunnel varies the qname so
the per-qname cooldown never bites; ARP has no cooldown at all). These tests run
the real detector -> queue -> _handle_alert path and assert the central dedup
collapses the storm into a single persisted row carrying the full count.
"""
import queue

from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.dns_anomaly import DnsAnomalyDetector
from core.alerts.deduplicator import Deduplicator
from db.queries import alerts_since
from main import _handle_alert


class _FakeApp:
    def call_from_thread(self, fn, *args):
        fn(*args)

    def push_alert(self, alert):
        pass

    def push_alert_count(self, alert, count):
        pass


def _drain_through_dedup(alerts: queue.Queue, session_factory, scorer, no_baseline, no_geo, no_pcap) -> int:
    """Feed every queued alert through the dedup routing; return how many fired."""
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)
    emitted = 0
    while True:
        try:
            alert = alerts.get_nowait()
        except queue.Empty:
            break
        emitted += 1
        _handle_alert(alert, session_factory, deduper, scorer, no_baseline, no_geo, no_pcap, app)
    return emitted


def test_dns_tunnel_storm_collapses_to_one_row(session_factory, scorer, no_baseline, no_geo, no_pcap):
    alerts   = queue.Queue()
    detector = DnsAnomalyDetector(queue.Queue(), alerts, subdomain_max_length=10)

    for i in range(100):   # a tunnel: 100 unique long subdomains, same source
        detector._process({
            "protocol": "UDP", "dst_port": 53, "src_ip": "10.0.0.5",
            "dns_qname": f"{'a' * 20}{i}.evil.com", "dns_qtype": 1,
            "timestamp": 1000.0 + i * 0.1,
        })

    emitted = _drain_through_dedup(alerts, session_factory, scorer, no_baseline, no_geo, no_pcap)
    assert emitted == 100          # the per-qname cooldown never suppressed -> a storm

    rows = alerts_since(session_factory, seconds=3600, now=1010.0)
    assert len(rows) == 1          # dedup collapsed the storm to one episode
    assert rows[0].count == 100


def test_arp_flip_flop_storm_collapses_to_one_row(session_factory, scorer, no_baseline, no_geo, no_pcap):
    alerts   = queue.Queue()
    detector = ArpSpoofDetector(queue.Queue(), alerts)

    base = {"protocol": "ARP", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "arp_op": 2}
    detector._process({**base, "src_mac": "aa:aa:aa:aa:aa:aa", "timestamp": 1000.0})  # learn

    for i in range(100):   # attacker vs real host: the MAC ping-pongs, each flip conflicts
        mac = "bb:bb:bb:bb:bb:bb" if i % 2 == 0 else "aa:aa:aa:aa:aa:aa"
        detector._process({**base, "src_mac": mac, "timestamp": 1000.0 + (i + 1) * 0.1})

    emitted = _drain_through_dedup(alerts, session_factory, scorer, no_baseline, no_geo, no_pcap)
    assert emitted == 100          # ARP has no cooldown -> every flip fired

    rows = alerts_since(session_factory, seconds=3600, now=1011.0)
    assert len(rows) == 1
    assert rows[0].count == 100

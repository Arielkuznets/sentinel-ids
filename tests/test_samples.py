"""Every reference capture fires the alerts DEMO.md promises.

scripts/make_samples.py builds the captures into tmp_path; each one is replayed
through the real capture engine into the six detectors, every detector built
from the real config.yaml - so a threshold change that would silence a sample
fails here, not halfway through a demo.
"""
import hashlib
import queue
from collections import Counter
from pathlib import Path

import pytest
import yaml

from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.baseline import BaselineDetector
from core.detectors.brute_force import BruteForceDetector
from core.detectors.dns_anomaly import DnsAnomalyDetector
from core.detectors.port_scan import PortScanDetector
from core.detectors.syn_flood import SynFloodDetector
from scripts import make_samples

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "config.yaml"

_DETECTORS = {
    "port_scan":   PortScanDetector,
    "arp_spoof":   ArpSpoofDetector,
    "brute_force": BruteForceDetector,
    "dns_anomaly": DnsAnomalyDetector,
    "syn_flood":   SynFloodDetector,
    "baseline":    BaselineDetector,
}

# (type, severity, source) of every alert a detector raises - before the
# dedup collapses repeats - per sample.
_EXPECTED = {
    "port_scan":   [("PORT_SCAN", "HIGH", "10.0.0.99")] + [("PORT_SCAN", "LOW", "10.0.0.98")] * 3,
    "arp_spoof":   [("ARP_SPOOF", "HIGH", "192.168.1.1"), ("ARP_SPOOF", "MEDIUM", "192.168.1.200")],
    "brute_force": [("BRUTE_FORCE", "HIGH", "10.0.0.77"), ("BRUTE_FORCE", "HIGH", "10.0.0.78")],
    "dns_tunnel":  [("DNS_ANOMALY", "HIGH", "10.0.0.88")] * 2 + [("DNS_ANOMALY", "MEDIUM", "10.0.0.88")],
    "syn_flood":   [("SYN_FLOOD", "HIGH", None)],
}
_EXPECTED["all_attacks"] = [alert for alerts in _EXPECTED.values() for alert in alerts]


def _replay(path: Path) -> Counter:
    """Every alert the six detectors raise on one capture file."""
    config  = yaml.safe_load(_CONFIG.read_text())["detectors"]
    packets = PacketQueue()
    alerts  = queue.Queue()
    wired   = []
    for name, detector_class in _DETECTORS.items():
        inbox = packets.subscribe()
        wired.append((detector_class(inbox, alerts, **config[name]), inbox))

    PacketCapture(interface=None, parser=PacketParser(), queue=packets).replay_pcap(str(path))

    for detector, inbox in wired:               # each detector on its own share, in order
        while not inbox.empty():
            detector._process(inbox.get_nowait())

    raised = Counter()
    while not alerts.empty():
        alert = alerts.get_nowait()
        raised[(alert.type, alert.severity, alert.src_ip)] += 1
    return raised


@pytest.fixture(scope="module")
def samples(tmp_path_factory):
    out_dir = tmp_path_factory.mktemp("pcap_samples")
    return {path.stem: path for path in make_samples.write_samples(out_dir)}


@pytest.mark.parametrize("name", list(_EXPECTED))
def test_each_sample_fires_exactly_the_alerts_it_is_built_for(samples, name):
    assert _replay(samples[name]) == Counter(_EXPECTED[name])


def test_the_samples_are_byte_identical_on_every_build(tmp_path):
    # Fixed timestamps and a seeded RNG: a replay in an interview room is the same
    # replay that passed here.
    first  = make_samples.write_samples(tmp_path / "a")
    second = make_samples.write_samples(tmp_path / "b")

    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    assert [digest(p) for p in first] == [digest(p) for p in second]

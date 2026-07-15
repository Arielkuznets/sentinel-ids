"""Unit tests for the PcapExporter.

Real Scapy packets go into a real ring, and the written file is read back with
rdpcap - the contract is that Wireshark could open it, so the test opens it too.
Each test writes into pytest's tmp_path, never the real captures/ directory.
"""
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.utils import rdpcap

from core.alerts.alert import Alert
from core.alerts.pcap_export import PcapExporter
from core.capture.ring import PacketRing


def _syn(src, dst="10.0.0.20", port=80):
    return IP(src=src, dst=dst) / TCP(dport=port, flags="S")


def _alert(src_ip="5.255.255.70", atype="PORT_SCAN", ts=1000.0):
    return Alert(type=atype, severity="HIGH", src_ip=src_ip, timestamp=ts)


def _exporter(tmp_path, ring, max_files=50):
    return PcapExporter(ring, output_dir=(tmp_path / "captures").as_posix(), max_files=max_files)


def test_the_attackers_packets_are_written_and_readable(tmp_path):
    ring = PacketRing(window_seconds=30, max_packets=100)
    for port in range(20, 25):
        ring.add(1000.0, "5.255.255.70", "10.0.0.20", _syn("5.255.255.70", port=port))

    path = _exporter(tmp_path, ring).export(_alert())

    assert path is not None
    written = rdpcap(path)
    assert len(written) == 5
    assert all(p[IP].src == "5.255.255.70" for p in written)


def test_only_the_attackers_traffic_lands_in_the_file(tmp_path):
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "5.255.255.70", "10.0.0.20", _syn("5.255.255.70"))
    ring.add(1000.0, "8.8.8.8",      "10.0.0.20", _syn("8.8.8.8"))

    path = _exporter(tmp_path, ring).export(_alert())

    written = rdpcap(path)
    assert len(written) == 1
    assert written[0][IP].src == "5.255.255.70"


def test_an_empty_ring_writes_no_file(tmp_path):
    exporter = _exporter(tmp_path, PacketRing(window_seconds=30, max_packets=100))

    assert exporter.export(_alert()) is None
    assert not (tmp_path / "captures").exists()


def test_an_alert_without_a_source_writes_no_file(tmp_path):
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "5.255.255.70", "10.0.0.20", _syn("5.255.255.70"))

    assert _exporter(tmp_path, ring).export(_alert(src_ip=None)) is None


def test_the_filename_carries_time_type_and_source(tmp_path):
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "5.255.255.70", "10.0.0.20", _syn("5.255.255.70"))

    path = _exporter(tmp_path, ring).export(_alert(atype="PORT_SCAN"))

    assert Path(path).name.endswith("_PORT_SCAN_5.255.255.70.pcap")


def test_an_ipv6_source_is_sanitised_into_a_legal_filename(tmp_path):
    # ':' is legal in an address and illegal in a Windows filename; without
    # sanitising, wrpcap would raise on every IPv6 alert.
    ring = PacketRing(window_seconds=30, max_packets=100)
    pkt = _syn("5.255.255.70")            # payload is irrelevant; the name is what we test
    ring.add(1000.0, "2001:db8::1", "10.0.0.20", pkt)

    path = _exporter(tmp_path, ring).export(_alert(src_ip="2001:db8::1"))

    assert ":" not in Path(path).name
    assert rdpcap(path)                    # the file is still valid


def test_the_ceiling_deletes_the_oldest_file(tmp_path):
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "5.255.255.70", "10.0.0.20", _syn("5.255.255.70"))
    exporter = _exporter(tmp_path, ring, max_files=3)

    paths = []
    for i in range(5):                    # five distinct episodes, ceiling of three
        paths.append(exporter.export(_alert(atype=f"T{i}")))

    remaining = {p.name for p in (tmp_path / "captures").glob("*.pcap")}
    assert len(remaining) == 3
    assert Path(paths[0]).name not in remaining   # oldest gone
    assert Path(paths[4]).name in remaining       # newest kept

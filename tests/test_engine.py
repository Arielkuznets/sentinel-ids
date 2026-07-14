"""Unit tests for the capture engine's handling of a single packet.

Packets are pushed straight into _handle_packet, so no NIC, no Npcap and no
admin rights are involved - the same shape as the detector tests.
"""
from scapy.layers.inet import IP, TCP

from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.ring import PacketRing


def _capture(ring=None):
    return PacketCapture(interface=None, parser=PacketParser(), queue=PacketQueue(), ring=ring)


def _syn(src="1.2.3.4", port=80):
    return IP(src=src, dst="10.0.0.9") / TCP(dport=port, flags="S")


def test_the_raw_packet_reaches_the_ring():
    # The ring has to be fed here: one step later the parser has flattened the
    # packet into a dict, and no .pcap can be written from that.
    ring = PacketRing(window_seconds=30, max_packets=100)
    _capture(ring)._handle_packet(_syn())

    assert len(ring) == 1


def test_detectors_still_receive_the_parsed_packet():
    ring     = PacketRing(window_seconds=30, max_packets=100)
    capture  = _capture(ring)
    consumer = capture._queue.subscribe()

    capture._handle_packet(_syn(port=443))

    assert consumer.get_nowait()["dst_port"] == 443


def test_capture_runs_without_a_ring():
    # The ring is optional: a replay or a test rig may not want one.
    capture  = _capture(ring=None)
    consumer = capture._queue.subscribe()

    capture._handle_packet(_syn())

    assert consumer.get_nowait()["src_ip"] == "1.2.3.4"

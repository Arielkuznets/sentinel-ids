"""Unit tests for the capture engine's handling of a single packet.

Packets are pushed straight into _handle_packet, so no NIC, no Npcap and no
admin rights are involved - the same shape as the detector tests.
"""
import time

from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap

from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.ring import PacketRing


def _capture(ring=None):
    return PacketCapture(interface=None, parser=PacketParser(), queue=PacketQueue(), ring=ring)


def _syn(src="1.2.3.4", port=80):
    return IP(src=src, dst="10.0.0.9") / TCP(dport=port, flags="S")


def test_the_raw_packet_reaches_the_ring_selectable_by_address():
    # The ring has to be fed here: one step later the parser has flattened the
    # packet into a dict, and no .pcap can be written from that. The engine also
    # hands over the addresses the parser found, so the ring can select by them.
    ring = PacketRing(window_seconds=30, max_packets=100)
    _capture(ring)._handle_packet(_syn(src="4.3.2.1"))

    assert ring.packets_for("4.3.2.1", time.time()) != []
    assert ring.packets_for("9.9.9.9", time.time()) == []


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


def _capture_file(tmp_path, times):
    """A capture file with one SYN per timestamp, to port 1, 2, 3..."""
    packets = []
    for port, ts in enumerate(times, start=1):
        pkt = _syn(port=port)
        pkt.time = ts
        packets.append(pkt)
    path = (tmp_path / "capture.pcap").as_posix()
    wrpcap(path, packets)
    return path


def _drain(consumer):
    out = []
    while not consumer.empty():
        out.append(consumer.get_nowait())
    return out


def test_a_replay_delivers_every_packet_in_recorded_order(tmp_path):
    capture  = _capture()
    consumer = capture._queue.subscribe()

    capture.replay_pcap(_capture_file(tmp_path, [1000.0, 1000.5, 1001.0]))

    packets = _drain(consumer)
    assert [p["dst_port"] for p in packets] == [1, 2, 3]
    assert [p["timestamp"] for p in packets] == [1000.0, 1000.5, 1001.0]   # packet time kept


def test_a_paced_replay_waits_out_the_recorded_gaps_divided_by_speed(tmp_path):
    capture = _capture()
    pauses  = []
    capture._pause = pauses.append

    capture.replay_pcap(_capture_file(tmp_path, [1000.0, 1001.0, 1003.0]), speed=2.0)

    assert pauses == [0.5, 1.0]                 # gaps of 1s and 2s, played twice as fast


def test_speed_zero_replays_without_pausing(tmp_path):
    capture = _capture()
    pauses  = []
    capture._pause = pauses.append

    capture.replay_pcap(_capture_file(tmp_path, [1000.0, 1060.0]), speed=0)

    assert pauses == []


def test_stop_ends_a_replay_early(tmp_path):
    capture  = _capture()
    consumer = capture._queue.subscribe()
    capture._pause = lambda seconds: capture._stop_event.set()   # stop() lands mid-gap

    capture.replay_pcap(_capture_file(tmp_path, [1000.0, 1001.0, 1002.0]), speed=1.0)

    assert len(_drain(consumer)) == 1


def test_start_plays_the_replay_file_on_the_capture_thread(tmp_path):
    path     = _capture_file(tmp_path, [1000.0, 1000.001])
    capture  = PacketCapture(interface=None, parser=PacketParser(), queue=PacketQueue(),
                             replay_path=path, replay_speed=0)
    consumer = capture._queue.subscribe()

    capture.start()
    capture._thread.join(timeout=5)

    assert len(_drain(consumer)) == 2

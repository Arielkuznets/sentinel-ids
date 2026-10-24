"""Unit tests for SynFloodDetector.

This detector splits work in two: `_process` only accumulates SYN/ACK counts
per destination, and `_evaluate_all(now)` checks the ratio and fires. So each
test feeds packets, then calls `_evaluate_all` explicitly - calling `_process`
alone never alerts.
"""
import queue

from core.detectors.syn_flood import SynFloodDetector


def make_tcp(flags="S", **overrides):
    """A pure-SYN TCP packet to a fixed destination; override fields per test."""
    packet = {
        "protocol": "TCP",
        "dst_ip": "10.0.0.1",
        "src_ip": "1.2.3.4",
        "flags": flags,
        "timestamp": 1000.0,
    }
    packet.update(overrides)
    return packet


def test_syn_flood_fires_medium():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts,
                                ratio_medium=10, ratio_high=50, min_syn=20)

    for _ in range(30):   # 30 SYN, 0 ACK -> ratio 30: above medium (10), below high (50)
        detector._process(make_tcp("S"))
    detector._evaluate_all(now=1000.0)

    alert = alerts.get_nowait()
    assert alert.type == "SYN_FLOOD"
    assert alert.severity == "MEDIUM"
    assert alert.src_ip is None   # source is spoofed; the target is what matters
    assert alert.details["dst_ip"] == "10.0.0.1"
    assert alert.details["syn_count"] == 30
    assert alert.details["ack_count"] == 0
    assert alert.details["ratio"] == 30.0
    assert alerts.empty()


def test_syn_flood_fires_high():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts,
                                ratio_medium=10, ratio_high=50, min_syn=20)

    for _ in range(60):   # ratio 60 > high threshold of 50
        detector._process(make_tcp("S"))
    detector._evaluate_all(now=1000.0)

    alert = alerts.get_nowait()
    assert alert.severity == "HIGH"
    assert alert.details["syn_count"] == 60
    assert alert.details["ratio"] == 60.0
    assert alerts.empty()


def test_below_min_syn_floor_is_quiet():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts, min_syn=20, ratio_medium=10)

    for _ in range(10):   # 10 < min_syn floor of 20, so the ratio is never checked
        detector._process(make_tcp("S"))
    detector._evaluate_all(now=1000.0)

    assert alerts.empty()


def test_healthy_handshakes_are_quiet():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts, min_syn=20, ratio_medium=10)

    # Every SYN is matched by a completing ACK -> ratio 1, well under any threshold.
    for _ in range(30):
        detector._process(make_tcp("S"))
    for _ in range(30):
        detector._process(make_tcp("A"))
    detector._evaluate_all(now=1000.0)

    assert alerts.empty()


def test_mixed_flags_are_not_counted():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts, min_syn=20, ratio_medium=10)

    # Only pure SYN and pure ACK count; SYN-ACK ("SA") is noise for this ratio.
    for _ in range(30):
        detector._process(make_tcp("SA"))
    detector._evaluate_all(now=1000.0)

    assert alerts.empty()


def test_flood_detected_on_packet_time_without_wall_clock():
    # Regression: a flood is detected through _process alone, driven by packet
    # timestamps as in a PCAP replay - no wall-clock _evaluate_all() call. A
    # packet crossing the window boundary in packet time triggers the evaluation.
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts,
                                ratio_medium=10, min_syn=20, window_seconds=5)

    t = 1000.0
    for _ in range(31):   # 31 SYN spread over 6 packet-seconds at 5/sec
        detector._process(make_tcp("S", timestamp=t))
        t += 0.2

    alert = alerts.get_nowait()
    assert alert.type == "SYN_FLOOD"
    assert alert.details["dst_ip"] == "10.0.0.1"


def test_non_tcp_and_missing_fields_ignored():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts, min_syn=20, ratio_medium=10)

    # 30 of each would cross the floor and fire if any guard leaked them through.
    for _ in range(30):
        detector._process(make_tcp("S", protocol="UDP"))   # not TCP
    for _ in range(30):
        detector._process(make_tcp("S", dst_ip=None))      # no destination
    for _ in range(30):
        detector._process(make_tcp(flags=None))            # no flags
    detector._evaluate_all(now=1000.0)

    assert alerts.empty()


def test_a_flood_judged_early_in_its_ramp_still_escalates_to_high():
    # Other TCP traffic decides where a judgement lands. Judged early, a flood
    # reads MEDIUM; the next judgement must still be free to say HIGH, rather
    # than the MEDIUM's cooldown holding the target down for a whole minute.
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts, ratio_medium=10, ratio_high=50,
                                min_syn=20, window_seconds=5, cooldown_seconds=60)

    for i in range(30):
        detector._process(make_tcp("S", timestamp=1000.0 + i * 0.05))
    detector._evaluate_all(now=1001.5)          # 30 SYNs so far: MEDIUM
    for i in range(70):
        detector._process(make_tcp("S", timestamp=1001.5 + i * 0.05))
    detector._evaluate_all(now=1005.0)          # 100 SYNs in the window: HIGH

    assert [alerts.get_nowait().severity for _ in range(alerts.qsize())] == ["MEDIUM", "HIGH"]


def test_the_same_severity_stays_quiet_through_the_cooldown():
    alerts = queue.Queue()
    detector = SynFloodDetector(queue.Queue(), alerts, ratio_medium=10, ratio_high=50,
                                min_syn=20, window_seconds=5, cooldown_seconds=60)

    for second in range(10):                    # ten seconds of a steady HIGH flood
        for i in range(60):
            detector._process(make_tcp("S", timestamp=1000.0 + second + i / 60))
        detector._evaluate_all(now=1001.0 + second)

    assert alerts.qsize() == 1                  # one HIGH; the rest cooled down

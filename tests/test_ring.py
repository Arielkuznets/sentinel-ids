"""Unit tests for the PacketRing.

Time is injected on every call, so expiry is asserted against a fixed clock and
never a sleep. The ring stores whatever it is handed - the tests use plain
strings as stand-in packets, which is the point: it never reopens them, it
selects on the addresses passed in beside them.
"""
import threading

from core.capture.ring import PacketRing


def _add(ring, ts, packet, src="1.1.1.1", dst="2.2.2.2"):
    ring.add(ts, src, dst, packet)


def test_a_source_gets_back_its_own_packets_oldest_first():
    ring = PacketRing(window_seconds=30, max_packets=100)
    _add(ring, 1000.0, "a", src="1.1.1.1")
    _add(ring, 1001.0, "b", src="1.1.1.1")

    assert ring.packets_for("1.1.1.1", 1002.0) == ["a", "b"]


def test_a_packet_matches_on_the_destination_too():
    # The attacker's conversation is both directions: replies are addressed to it.
    ring = PacketRing(window_seconds=30, max_packets=100)
    _add(ring, 1000.0, "reply", src="9.9.9.9", dst="1.1.1.1")

    assert ring.packets_for("1.1.1.1", 1000.0) == ["reply"]


def test_other_sources_are_left_out():
    ring = PacketRing(window_seconds=30, max_packets=100)
    _add(ring, 1000.0, "mine",  src="1.1.1.1", dst="2.2.2.2")
    _add(ring, 1000.0, "other", src="8.8.8.8", dst="9.9.9.9")

    assert ring.packets_for("1.1.1.1", 1000.0) == ["mine"]


def test_packets_older_than_the_window_are_gone():
    ring = PacketRing(window_seconds=30, max_packets=100)
    _add(ring, 1000.0, "old",    src="1.1.1.1")
    _add(ring, 1045.0, "recent", src="1.1.1.1")

    assert ring.packets_for("1.1.1.1", 1045.0) == ["recent"]


def test_the_window_expires_packets_even_when_nothing_new_arrives():
    # A quiet network still ages the ring: a query prunes, it does not only read.
    ring = PacketRing(window_seconds=30, max_packets=100)
    _add(ring, 1000.0, "a", src="1.1.1.1")

    assert ring.packets_for("1.1.1.1", 1060.0) == []


def test_the_ceiling_drops_the_oldest_packet():
    # The bound that survives a flood: time alone would let the ring grow without
    # limit exactly when traffic peaks.
    ring = PacketRing(window_seconds=30, max_packets=3)
    for i in range(5):
        _add(ring, 1000.0 + i * 0.001, f"p{i}", src="1.1.1.1")

    assert ring.packets_for("1.1.1.1", 1000.1) == ["p2", "p3", "p4"]
    assert len(ring) == 3


def test_a_source_with_nothing_in_the_ring_gets_an_empty_list():
    ring = PacketRing(window_seconds=30, max_packets=100)
    _add(ring, 1000.0, "a", src="1.1.1.1")

    assert ring.packets_for("5.5.5.5", 1000.0) == []


def test_concurrent_writers_do_not_corrupt_the_ring():
    # The capture thread writes while the alert thread reads; without the lock a
    # deque can be observed mid-append.
    ring = PacketRing(window_seconds=30, max_packets=10_000)

    def writer(base: int) -> None:
        for i in range(500):
            _add(ring, 1000.0 + i * 0.001, f"{base}-{i}", src="1.1.1.1")

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ring) == 4000
    assert len(ring.packets_for("1.1.1.1", 1000.5)) == 4000

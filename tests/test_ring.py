"""Unit tests for the PacketRing.

Time is injected on every call, so expiry is asserted against a fixed clock and
never a sleep. The ring stores whatever it is handed - the tests use plain
strings as stand-in packets, which is the point: it never reads them.
"""
import threading

from core.capture.ring import PacketRing


def test_packets_inside_the_window_come_back_oldest_first():
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "a")
    ring.add(1001.0, "b")

    assert [p for _, p in ring.snapshot(1002.0)] == ["a", "b"]


def test_packets_older_than_the_window_are_gone():
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "old")
    ring.add(1045.0, "recent")

    assert [p for _, p in ring.snapshot(1045.0)] == ["recent"]


def test_the_window_expires_packets_even_when_nothing_new_arrives():
    # A quiet network still ages the ring: snapshot prunes, it does not only read.
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "a")

    assert ring.snapshot(1060.0) == []


def test_the_ceiling_drops_the_oldest_packet():
    # The bound that survives a flood: time alone would let the ring grow without
    # limit exactly when traffic peaks.
    ring = PacketRing(window_seconds=30, max_packets=3)
    for i in range(5):
        ring.add(1000.0 + i * 0.001, f"p{i}")

    assert [p for _, p in ring.snapshot(1000.1)] == ["p2", "p3", "p4"]
    assert len(ring) == 3


def test_a_snapshot_is_a_copy():
    ring = PacketRing(window_seconds=30, max_packets=100)
    ring.add(1000.0, "a")

    ring.snapshot(1000.0).clear()

    assert len(ring) == 1


def test_an_empty_ring_has_nothing_to_show():
    assert PacketRing(window_seconds=30, max_packets=100).snapshot(1000.0) == []


def test_concurrent_writers_do_not_corrupt_the_ring():
    # The capture thread writes while the alert thread reads; without the lock a
    # deque can be observed mid-append.
    ring = PacketRing(window_seconds=30, max_packets=10_000)

    def writer(base: int) -> None:
        for i in range(500):
            ring.add(1000.0 + i * 0.001, f"{base}-{i}")

    threads = [threading.Thread(target=writer, args=(t,)) for t in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(ring) == 4000
    assert len(ring.snapshot(1000.5)) == 4000

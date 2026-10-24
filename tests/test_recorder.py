"""Unit tests for the PacketRecorder.

Packets go straight into _process and _flush with injected timestamps, so no
capture and no sleeps are involved; one test runs the real thread end to end.
"""
import queue

from sqlalchemy import select

from core.capture.recorder import PacketRecorder
from db.models import PacketRecord
from db.queries import save_packets


def _packet(ts: float, src: str = "10.0.0.5") -> dict:
    return {"timestamp": ts, "size": 60, "src_ip": src, "dst_ip": "10.0.0.9",
            "protocol": "TCP", "src_port": 51000, "dst_port": 443, "flags": "S",
            "payload": b""}


def _recorder(session_factory, **kwargs) -> PacketRecorder:
    return PacketRecorder(queue.Queue(), session_factory, **kwargs)


def _timestamps(session_factory) -> list[float]:
    with session_factory() as session:
        return list(session.scalars(select(PacketRecord.timestamp).order_by(PacketRecord.timestamp)))


def test_a_full_batch_is_written_at_once(session_factory):
    recorder = _recorder(session_factory, batch_size=3)

    recorder._process(_packet(1000.0))
    recorder._process(_packet(1001.0))
    assert _timestamps(session_factory) == []            # still buffered

    recorder._process(_packet(1002.0))                   # the third fills the batch
    assert _timestamps(session_factory) == [1000.0, 1001.0, 1002.0]


def test_a_partial_batch_waits_for_the_flush(session_factory):
    recorder = _recorder(session_factory, batch_size=500)

    recorder._process(_packet(1000.0))
    assert _timestamps(session_factory) == []

    recorder._flush()                                    # what the flush_seconds tick calls
    assert _timestamps(session_factory) == [1000.0]


def test_rows_past_the_retention_window_are_deleted(session_factory):
    # Retention counts back from the newest packet, not the wall clock, so a
    # replayed capture from last year is not wiped the moment it is written.
    recorder = _recorder(session_factory, retention_hours=1)

    recorder._process(_packet(1000.0))
    recorder._flush()
    recorder._process(_packet(1000.0 + 2 * 3600))
    recorder._flush()

    assert _timestamps(session_factory) == [1000.0 + 2 * 3600]


def test_cleanup_runs_at_most_once_per_cleanup_interval(session_factory):
    recorder = _recorder(session_factory, retention_hours=1, cleanup_seconds=60)
    recorder._process(_packet(10_000.0))
    recorder._flush()                                    # first flush cleans up

    save_packets(session_factory, [_packet(1.0)])        # an expired row appears
    recorder._process(_packet(10_030.0))
    recorder._flush()                                    # 30s later: too soon
    assert 1.0 in _timestamps(session_factory)

    recorder._process(_packet(10_070.0))
    recorder._flush()                                    # 70s later: cleaned
    assert 1.0 not in _timestamps(session_factory)


def test_stop_writes_everything_already_queued(session_factory):
    packets  = queue.Queue()
    recorder = PacketRecorder(packets, session_factory, batch_size=500, flush_seconds=60)
    recorder.start()

    for i in range(5):
        packets.put(_packet(1000.0 + i))
    recorder.stop()                                      # long before the 60s flush

    assert len(_timestamps(session_factory)) == 5

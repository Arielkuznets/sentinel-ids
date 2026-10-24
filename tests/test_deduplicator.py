"""Unit tests for the alert Deduplicator.

The deduper is pure: every test drives it with Alert objects carrying an
explicit timestamp, so windowing is deterministic with no clock and no sleeps.
"""
from core.alerts.alert import Alert
from core.alerts.deduplicator import Deduplicator


def _alert(t, src="1.1.1.1", atype="PORT_SCAN", sev="HIGH"):
    return Alert(type=atype, severity=sev, src_ip=src, timestamp=t)


def test_first_alert_of_a_key_is_new():
    d = Deduplicator(window_seconds=60)
    decision = d.process(_alert(1000.0))
    assert decision.is_new is True
    assert decision.count == 1


def test_repeat_within_window_bumps_count_not_new():
    d = Deduplicator(window_seconds=60)
    d.process(_alert(1000.0))
    second = d.process(_alert(1030.0))
    assert second.is_new is False
    assert second.count == 2


def test_repeat_returns_attached_row_id():
    d = Deduplicator(window_seconds=60)
    first = d.process(_alert(1000.0))
    assert first.row_id is None
    d.attach_row_id(_alert(1000.0), row_id=42)

    second = d.process(_alert(1005.0))
    assert second.row_id == 42
    assert second.count == 2


def test_alert_at_window_edge_opens_new_episode():
    d = Deduplicator(window_seconds=60)
    d.process(_alert(1000.0))
    later = d.process(_alert(1060.0))   # 60s later, exactly the edge -> new episode
    assert later.is_new is True
    assert later.count == 1


def test_different_sources_are_counted_separately():
    d = Deduplicator(window_seconds=60)
    a = d.process(_alert(1000.0, src="1.1.1.1"))
    b = d.process(_alert(1001.0, src="2.2.2.2"))
    assert a.is_new and b.is_new
    assert a.count == 1 and b.count == 1


def test_severity_escalation_is_a_separate_episode():
    d = Deduplicator(window_seconds=60)
    med  = d.process(_alert(1000.0, sev="MEDIUM"))
    high = d.process(_alert(1001.0, sev="HIGH"))
    assert med.is_new and high.is_new


def test_none_src_ip_dedups_by_type_and_severity():
    d = Deduplicator(window_seconds=60)
    d.process(_alert(1000.0, src=None, atype="SYN_FLOOD"))
    second = d.process(_alert(1010.0, src=None, atype="SYN_FLOOD"))
    assert second.is_new is False
    assert second.count == 2


def test_expired_episodes_are_pruned():
    d = Deduplicator(window_seconds=60)
    d.process(_alert(1000.0, src="1.1.1.1"))
    # A later alert well past the window sweeps out the now-expired first episode.
    d.process(_alert(2000.0, src="2.2.2.2"))
    assert len(d._episodes) == 1

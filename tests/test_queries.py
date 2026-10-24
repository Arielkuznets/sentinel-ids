"""Unit tests for db/queries.

Each test runs against a fresh, file-backed SQLite database provided by the
`session_factory` fixture, so tests are fully isolated. The queries take `now`
explicitly, so time-based filtering is deterministic.
"""
from sqlalchemy import select

from core.alerts.alert import Alert
from db.models import PacketRecord
from db.queries import (
    active_blocks,
    alerts_since,
    delete_packets_before,
    is_blocked,
    load_baselines,
    record_block,
    record_unblock,
    save_alert,
    save_baselines,
    save_packets,
    update_alert_repeat,
)


def _packet(ts: float, src: str = "10.0.0.5", **fields) -> dict:
    """A parsed packet as PacketParser emits it, payload and MACs included."""
    return {"timestamp": ts, "size": 60, "src_mac": "aa:aa", "dst_mac": "bb:bb",
            "src_ip": src, "dst_ip": "10.0.0.9", "ttl": 64, "protocol": "TCP",
            "src_port": 51000, "dst_port": 443, "flags": "S", "seq": 1,
            "payload": b"secret", "arp_op": None, "dns_qname": None,
            "dns_qtype": None, **fields}


def _stored_packets(session_factory) -> list[PacketRecord]:
    with session_factory() as session:
        return list(session.scalars(select(PacketRecord).order_by(PacketRecord.timestamp)))


def test_save_alert_and_query_back(session_factory):
    alert = Alert(type="PORT_SCAN", severity="HIGH", src_ip="1.2.3.4",
                  timestamp=1000.0, details={"ports": [22, 80]})
    save_alert(session_factory, alert)

    rows = alerts_since(session_factory, seconds=3600, now=1000.0)
    assert len(rows) == 1
    assert rows[0].type == "PORT_SCAN"
    assert rows[0].severity == "HIGH"
    assert rows[0].src_ip == "1.2.3.4"
    assert rows[0].details == {"ports": [22, 80]}


def test_save_alert_returns_id_and_dedup_defaults(session_factory):
    alert_id = save_alert(session_factory, Alert("ARP_SPOOF", "HIGH", "1.2.3.4", timestamp=1000.0))

    row = alerts_since(session_factory, seconds=3600, now=1000.0)[0]
    assert alert_id == row.id
    assert row.count == 1            # a fresh alert has been seen exactly once
    assert row.last_seen == 1000.0   # first sighting == its own timestamp


def test_save_alert_persists_the_score(session_factory):
    save_alert(session_factory, Alert("PORT_SCAN", "HIGH", "1.2.3.4", timestamp=1000.0, score=63))

    row = alerts_since(session_factory, seconds=3600, now=1000.0)[0]
    assert row.score == 63


def test_update_alert_repeat_persists_count_score_and_last_seen(session_factory):
    alert_id = save_alert(session_factory,
                          Alert("DNS_ANOMALY", "HIGH", "5.5.5.5", timestamp=1000.0, score=31))

    update_alert_repeat(session_factory, alert_id, count=47, score=52, deviation=2.0, now=1030.0)

    row = alerts_since(session_factory, seconds=3600, now=1030.0)[0]
    assert row.count == 47
    assert row.score == 52           # the score climbs with the count, not frozen at 31
    assert row.last_seen == 1030.0
    assert row.timestamp == 1000.0   # the window's start stays put


def test_update_alert_repeat_refreshes_the_deviation_but_not_the_details(session_factory):
    # A stale deviation would leave the row claiming a score of 100 next to the
    # 0.6 that could not have produced it. The detector's own findings stay put.
    alert_id = save_alert(session_factory, Alert(
        "ARP_SPOOF", "HIGH", "10.0.0.5", timestamp=1000.0, score=64,
        details={"reason": "mac_conflict", "known_mac": "aa:aa", "deviation": 0.6},
    ))

    update_alert_repeat(session_factory, alert_id, count=15, score=100, deviation=81.5, now=1030.0)

    row = alerts_since(session_factory, seconds=3600, now=1030.0)[0]
    assert row.details["deviation"] == 81.5           # moved with the score
    assert row.details["known_mac"] == "aa:aa"        # the episode's opening findings
    assert row.details["reason"] == "mac_conflict"


def test_update_alert_repeat_missing_row_is_noop(session_factory):
    update_alert_repeat(session_factory, alert_id=999, count=5, score=40,
                        deviation=None, now=1000.0)   # must not raise


def test_save_alert_with_null_src_ip(session_factory):
    # A SYN flood carries a spoofed source, so its alert has no src_ip. Storing
    # it must succeed – the column is nullable – and read back as None.
    alert = Alert(type="SYN_FLOOD", severity="HIGH", src_ip=None,
                  timestamp=2000.0, details={"dst_ip": "10.0.0.5", "ratio": 60.0})
    save_alert(session_factory, alert)

    rows = alerts_since(session_factory, seconds=3600, now=2000.0)
    assert len(rows) == 1
    assert rows[0].type == "SYN_FLOOD"
    assert rows[0].src_ip is None


def test_alerts_since_filters_window_and_orders_newest_first(session_factory):
    save_alert(session_factory, Alert("OLD", "LOW", "0.0.0.0", timestamp=1000.0))
    save_alert(session_factory, Alert("A", "LOW", "1.1.1.1", timestamp=4000.0))
    save_alert(session_factory, Alert("B", "LOW", "2.2.2.2", timestamp=4500.0))

    rows = alerts_since(session_factory, seconds=3600, now=5000.0)   # cutoff = 1400
    # OLD (t=1000 < 1400) is excluded; the rest come back newest-first.
    assert [r.type for r in rows] == ["B", "A"]


def test_record_block_makes_ip_blocked(session_factory):
    assert is_blocked(session_factory, "1.2.3.4") is False
    record_block(session_factory, "1.2.3.4", reason="port scan", blocked_by="user", now=1000.0)
    assert is_blocked(session_factory, "1.2.3.4") is True


def test_unblock_lifts_block_and_returns_true(session_factory):
    record_block(session_factory, "1.2.3.4", "scan", "user", now=1000.0)

    lifted = record_unblock(session_factory, "1.2.3.4", now=1100.0)
    assert lifted is True
    assert is_blocked(session_factory, "1.2.3.4") is False


def test_unblock_when_not_blocked_returns_false(session_factory):
    assert record_unblock(session_factory, "9.9.9.9") is False


def test_active_blocks_lists_only_active(session_factory):
    record_block(session_factory, "1.1.1.1", "scan", "user", now=1000.0)
    record_block(session_factory, "2.2.2.2", "flood", "user", now=2000.0)
    record_unblock(session_factory, "1.1.1.1", now=1500.0)

    active = active_blocks(session_factory)
    assert [b.ip for b in active] == ["2.2.2.2"]


def test_reblock_after_unblock_creates_new_active_row(session_factory):
    record_block(session_factory, "1.1.1.1", "scan", "user", now=1000.0)
    record_unblock(session_factory, "1.1.1.1", now=1100.0)
    assert is_blocked(session_factory, "1.1.1.1") is False

    # Blocking again adds a NEW row; the lifted one stays as an audit record.
    record_block(session_factory, "1.1.1.1", "scan again", "user", now=2000.0)
    assert is_blocked(session_factory, "1.1.1.1") is True
    assert len(active_blocks(session_factory)) == 1


def test_save_and_load_baselines_round_trip(session_factory):
    items = {"1.1.1.1": (30, 100.0, 250.0), "2.2.2.2": (5, 3.0, 8.0)}
    save_baselines(session_factory, items, now=1000.0)

    assert load_baselines(session_factory) == items


def test_save_baselines_upserts_existing_ip(session_factory):
    save_baselines(session_factory, {"1.1.1.1": (30, 100.0, 250.0)}, now=1000.0)
    save_baselines(session_factory, {"1.1.1.1": (31, 101.0, 260.0)}, now=1100.0)

    assert load_baselines(session_factory) == {"1.1.1.1": (31, 101.0, 260.0)}


def test_load_baselines_empty_is_empty_dict(session_factory):
    assert load_baselines(session_factory) == {}


def test_save_packets_writes_the_whole_batch(session_factory):
    save_packets(session_factory, [_packet(1000.0 + i) for i in range(50)])

    rows = _stored_packets(session_factory)
    assert len(rows) == 50
    assert rows[0].timestamp == 1000.0
    assert (rows[0].src_ip, rows[0].dst_port, rows[0].flags) == ("10.0.0.5", 443, "S")


def test_save_packets_keeps_header_fields_never_the_payload(session_factory):
    # The packets table answers "how much, from whom" - the bytes belong to the
    # ring and the pcap evidence, and keeping them here would bloat every row.
    save_packets(session_factory, [_packet(1000.0)])

    row = _stored_packets(session_factory)[0]
    assert not hasattr(row, "payload")
    assert row.size == 60


def test_save_packets_accepts_a_packet_without_ports(session_factory):
    # ARP has no transport layer; its ports and flags arrive as None.
    arp = _packet(1000.0, src="10.0.0.1", protocol="ARP", src_port=None,
                  dst_port=None, flags=None, arp_op=2)
    save_packets(session_factory, [arp])

    row = _stored_packets(session_factory)[0]
    assert row.protocol == "ARP"
    assert row.dst_port is None


def test_save_packets_with_an_empty_batch_is_a_noop(session_factory):
    save_packets(session_factory, [])
    assert _stored_packets(session_factory) == []


def test_delete_packets_before_keeps_the_retention_window(session_factory):
    save_packets(session_factory, [_packet(ts) for ts in (1000.0, 2000.0, 3000.0)])

    removed = delete_packets_before(session_factory, cutoff=2000.0)

    assert removed == 1                                       # only t=1000 is older
    assert [r.timestamp for r in _stored_packets(session_factory)] == [2000.0, 3000.0]

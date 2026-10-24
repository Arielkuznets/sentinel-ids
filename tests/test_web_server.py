"""Unit tests for the dashboard server: its wire format and its endpoints.

_alert_to_message is the whole contract between the server and the browser: the
client paints only what this dict carries, so a field missing here is a field
missing on screen. The endpoints run in-process through FastAPI's TestClient,
against the real config.yaml with the database moved into tmp_path.
"""
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from core.alerts.alert import Alert
from db.database import init_db
from db.models import AlertRecord
from db.queries import record_block, save_alert, save_packets
from ui.web.server import _alert_to_message, collect_stats, create_app

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "config.yaml"

_WEB_CFG = {"traffic_seconds": 3, "top_sources": 2, "top_sources_seconds": 60,
            "alert_stats_hours": 2}


def _packet(ts: float, src: str = "10.0.0.5") -> dict:
    return {"timestamp": ts, "size": 60, "src_ip": src, "dst_ip": "10.0.0.9",
            "protocol": "TCP", "src_port": 51000, "dst_port": 443, "flags": "S"}


@pytest.fixture
def web(tmp_path):
    """The real app on the real config with its database moved into tmp_path, and
    a session factory onto that same file to seed it."""
    config = yaml.safe_load(_CONFIG.read_text())
    config["database"]["path"] = (tmp_path / "web.db").as_posix()
    return TestClient(create_app(config)), init_db(config["database"]["path"])


def _record(score: int) -> AlertRecord:
    return AlertRecord(
        id=1, timestamp=1000.0, type="ARP_SPOOF", severity="HIGH",
        src_ip="10.0.0.5", details={"deviation": 3.5}, count=4,
        last_seen=1030.0, score=score,
    )


def test_message_carries_the_score():
    msg = _alert_to_message(_record(63), score_high=70, score_medium=40)
    assert msg["score"] == 63
    assert msg["count"] == 4


def test_message_carries_the_band_the_server_resolved():
    # The browser cannot read config.yaml, so it must not be the one deciding
    # where 70 sits - it only paints the band it is handed.
    assert _alert_to_message(_record(89), 70, 40)["score_level"] == "high"
    assert _alert_to_message(_record(63), 70, 40)["score_level"] == "medium"
    assert _alert_to_message(_record(14), 70, 40)["score_level"] == "low"


def test_the_band_follows_the_configured_thresholds_not_a_hardcoded_70():
    # Same score, thresholds lowered: the band has to move with the config.
    assert _alert_to_message(_record(63), score_high=60, score_medium=30)["score_level"] == "high"


def test_message_carries_the_source_location():
    record = _record(63)
    record.details = {"deviation": 3.5, "geo": {"country": "Russia", "iso": "RU", "city": "Moscow"}}

    msg = _alert_to_message(record, score_high=70, score_medium=40)

    assert msg["details"]["geo"] == {"country": "Russia", "iso": "RU", "city": "Moscow"}


def test_message_carries_the_pcap_path():
    record = _record(63)
    record.details = {"deviation": 3.5, "pcap": "captures/20260715_x_PORT_SCAN_5.255.255.70.pcap"}

    msg = _alert_to_message(record, score_high=70, score_medium=40)

    assert msg["details"]["pcap"] == "captures/20260715_x_PORT_SCAN_5.255.255.70.pcap"


def test_stats_carry_every_series_the_dashboard_draws(session_factory):
    save_packets(session_factory, [_packet(1000.2), _packet(1000.8), _packet(1001.5, src="10.0.0.6")])
    save_alert(session_factory, Alert("PORT_SCAN", "HIGH", "10.0.0.5", timestamp=1001.0))
    record_block(session_factory, "10.0.0.5", reason="PORT_SCAN", blocked_by="tui", now=1001.5)

    stats = collect_stats(session_factory, _WEB_CFG, lag_seconds=0, now=1002.0)

    assert stats["traffic"] == [{"t": 1000, "packets": 2}, {"t": 1001, "packets": 1},
                                {"t": 1002, "packets": 0}]
    assert stats["top_sources"] == [{"ip": "10.0.0.5", "packets": 2},
                                    {"ip": "10.0.0.6", "packets": 1}]
    assert stats["alert_types"] == {"PORT_SCAN": 1}
    assert sum(h["alerts"] for h in stats["alerts_per_hour"]) == 1
    assert stats["blocked"] == [{"ip": "10.0.0.5", "blocked_at": 1001.5, "reason": "PORT_SCAN"}]
    assert stats["windows"]["traffic_seconds"] == 3     # the page labels its charts from these


def test_the_traffic_series_stops_short_of_the_second_still_being_written(session_factory):
    stats = collect_stats(session_factory, _WEB_CFG, lag_seconds=2, now=1010.0)

    assert [point["t"] for point in stats["traffic"]] == [1006, 1007, 1008]


def test_the_stats_endpoint_serves_the_collected_json(web):
    client, _ = web
    response = client.get("/api/stats")

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"traffic", "top_sources", "alerts_per_hour", "alert_types",
                         "blocked", "windows"}
    assert len(body["traffic"]) == body["windows"]["traffic_seconds"]


def test_the_incident_log_narrows_by_type_and_severity(web):
    client, session_factory = web
    now = time.time()
    save_alert(session_factory, Alert("PORT_SCAN", "HIGH", "1.1.1.1", timestamp=now - 60))
    save_alert(session_factory, Alert("PORT_SCAN", "LOW",  "1.1.1.1", timestamp=now - 50))
    save_alert(session_factory, Alert("ARP_SPOOF", "HIGH", "2.2.2.2", timestamp=now - 40))

    rows = client.get("/api/alerts", params={"type": "PORT_SCAN", "severity": "HIGH"}).json()

    assert [(r["type"], r["severity"]) for r in rows] == [("PORT_SCAN", "HIGH")]
    assert rows[0]["score_level"] in {"high", "medium", "low"}   # the same wire format as /ws


def test_the_incident_log_window_leaves_older_alerts_out(web):
    client, session_factory = web
    now = time.time()
    save_alert(session_factory, Alert("PORT_SCAN", "HIGH", "1.1.1.1", timestamp=now - 7200))
    save_alert(session_factory, Alert("PORT_SCAN", "HIGH", "2.2.2.2", timestamp=now - 60))

    rows = client.get("/api/alerts", params={"seconds": 3600}).json()

    assert [r["src_ip"] for r in rows] == ["2.2.2.2"]


def test_a_malformed_filter_is_turned_away_before_any_query_runs(web):
    client, _ = web

    assert client.get("/api/alerts", params={"severity": "CRITICAL"}).status_code == 422
    assert client.get("/api/alerts", params={"seconds": -5}).status_code == 422

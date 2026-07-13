"""Unit tests for the dashboard's wire format.

_alert_to_message is the whole contract between the server and the browser: the
client paints only what this dict carries, so a field missing here is a field
missing on screen.
"""
from db.models import AlertRecord
from ui.web.server import _alert_to_message


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

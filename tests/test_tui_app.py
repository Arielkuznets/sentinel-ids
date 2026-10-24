"""Unit tests for SentinelApp's alert-episode state.

The app is constructed but never mounted, so only methods that touch plain state
are exercised here – no Textual event loop, no widgets.
"""
import queue

from core.alerts.alert import Alert
from core.alerts.deduplicator import dedup_key
from ui.tui.app import SentinelApp


def _app() -> SentinelApp:
    return SentinelApp(packet_queue=queue.Queue(), session_factory=None, response_engine=None)


def test_a_repeat_refreshes_the_displayed_score():
    # The episode keeps the first sighting's line, so the score has to be copied
    # onto it - otherwise the stored row climbs while the screen stays at 63.
    app    = _app()
    first  = Alert("ARP_SPOOF", "HIGH", "10.0.0.5", timestamp=1000.0, score=63,
                   details={"deviation": None})
    repeat = Alert("ARP_SPOOF", "HIGH", "10.0.0.5", timestamp=1005.0, score=89,
                   details={"deviation": 4.2})

    app._alert_episodes[dedup_key(first)] = (first, 1)
    app.push_alert_count(repeat, count=20)

    shown, count = app._alert_episodes[dedup_key(first)]
    assert count == 20
    assert shown.score == 89                      # climbed, not frozen at 63
    assert shown.details["deviation"] == 4.2      # and so did the reading behind it
    assert shown.timestamp == 1000.0              # the episode still opens where it began

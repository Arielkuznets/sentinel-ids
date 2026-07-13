"""Integration tests for _handle_alert – the dedup routing in the alert loop.

Drives the real Deduplicator and a real per-test DB against a fake TUI app that
only records push_alert calls, so we can assert what reaches persistence and the
live feed without a running Textual app.
"""
from core.alerts.alert import Alert
from core.alerts.deduplicator import Deduplicator
from db.queries import alerts_since
from main import _handle_alert


class _FakeApp:
    """Stand-in for the TUI: call_from_thread runs the callback inline."""

    def __init__(self):
        self.pushed = []
        self.counts = []

    def call_from_thread(self, fn, *args):
        fn(*args)

    def push_alert(self, alert):
        self.pushed.append(alert)

    def push_alert_count(self, alert, count):
        self.counts.append((alert, count))


def _alert(t, src="1.1.1.1", atype="DNS_ANOMALY", sev="HIGH"):
    return Alert(type=atype, severity=sev, src_ip=src, timestamp=t)


def test_new_alert_is_persisted_and_pushed(session_factory, scorer, no_baseline, no_geo):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    _handle_alert(_alert(1000.0), session_factory, deduper, scorer, no_baseline, no_geo, app)

    rows = alerts_since(session_factory, seconds=3600, now=1000.0)
    assert len(rows) == 1
    assert rows[0].count == 1
    assert len(app.pushed) == 1


def test_storm_collapses_to_one_row_and_one_push(session_factory, scorer, no_baseline, no_geo):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    for i in range(500):   # a DNS-tunnel storm: 500 identical alerts in the window
        _handle_alert(_alert(1000.0 + i * 0.01), session_factory, deduper,
                      scorer, no_baseline, no_geo, app)

    rows = alerts_since(session_factory, seconds=3600, now=1010.0)
    assert len(rows) == 1                       # one row, not 500
    assert rows[0].count == 500                 # the counter carries the magnitude
    assert rows[0].last_seen == 1000.0 + 499 * 0.01
    assert len(app.pushed) == 1                 # live feed saw one new alert – storm suppressed
    assert len(app.counts) == 499               # the repeats arrived as count bumps
    assert app.counts[-1][1] == 500             # the last bump carries the final total


def test_new_episode_after_window_makes_a_second_row(session_factory, scorer, no_baseline, no_geo):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    _handle_alert(_alert(1000.0), session_factory, deduper, scorer, no_baseline, no_geo, app)
    _handle_alert(_alert(1100.0), session_factory, deduper, scorer, no_baseline, no_geo, app)

    rows = alerts_since(session_factory, seconds=3600, now=1100.0)
    assert len(rows) == 2
    assert len(app.pushed) == 2


def test_a_scored_alert_reaches_the_database(session_factory, scorer, no_baseline, no_geo):
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    _handle_alert(_alert(1000.0, atype="ARP_SPOOF"), session_factory, deduper,
                  scorer, no_baseline, no_geo, app)

    rows = alerts_since(session_factory, seconds=3600, now=1000.0)
    assert rows[0].score == 63                     # HIGH, no repeats, no baseline
    assert rows[0].details["deviation"] is None    # never measured, and it shows


def test_a_repeat_rescores_higher_than_the_first_sighting(session_factory, scorer, no_baseline, no_geo):
    # The count feeds the score, so an attack that keeps firing keeps climbing.
    app     = _FakeApp()
    deduper = Deduplicator(window_seconds=60)

    _handle_alert(_alert(1000.0, atype="ARP_SPOOF"), session_factory, deduper,
                  scorer, no_baseline, no_geo, app)
    first = alerts_since(session_factory, seconds=3600, now=1000.0)[0].score

    for i in range(1, 20):
        _handle_alert(_alert(1000.0 + i, atype="ARP_SPOOF"), session_factory, deduper,
                      scorer, no_baseline, no_geo, app)

    row = alerts_since(session_factory, seconds=3600, now=1030.0)[0]
    assert row.count == 20
    assert row.score > first        # the stored score climbed with the count


def test_the_source_location_is_stored_with_the_alert(session_factory, scorer, no_baseline):
    app = _FakeApp()
    tel_aviv = lambda ip: {"country": "Israel", "city": "Tel Aviv"}

    _handle_alert(_alert(1000.0, src="8.8.8.8"), session_factory,
                  Deduplicator(window_seconds=60), scorer, no_baseline, tel_aviv, app)

    row = alerts_since(session_factory, seconds=3600, now=1000.0)[0]
    assert row.details["geo"] == {"country": "Israel", "city": "Tel Aviv"}


def test_a_repeat_keeps_the_location_of_the_episode(session_factory, scorer, no_baseline):
    # A repeat rewrites the score and the deviation on the row. The location must
    # survive that rewrite: it is looked up once, when the episode opens.
    app      = _FakeApp()
    deduper  = Deduplicator(window_seconds=60)
    tel_aviv = lambda ip: {"country": "Israel", "city": "Tel Aviv"}

    for i in range(5):
        _handle_alert(_alert(1000.0 + i, src="8.8.8.8"), session_factory, deduper,
                      scorer, no_baseline, tel_aviv, app)

    row = alerts_since(session_factory, seconds=3600, now=1005.0)[0]
    assert row.count == 5
    assert row.details["geo"] == {"country": "Israel", "city": "Tel Aviv"}


def test_a_deviating_source_scores_above_a_normal_one(session_factory, scorer, no_geo):
    # Same alert, same count - only the source's deviation from its own baseline
    # differs. This is the whole point of asking the baseline at all.
    app     = _FakeApp()
    spiking = lambda src_ip, now: 8.0
    normal  = lambda src_ip, now: 0.0

    _handle_alert(_alert(1000.0, src="1.1.1.1"), session_factory,
                  Deduplicator(window_seconds=60), scorer, spiking, no_geo, app)
    _handle_alert(_alert(1000.0, src="2.2.2.2"), session_factory,
                  Deduplicator(window_seconds=60), scorer, normal, no_geo, app)

    by_ip = {row.src_ip: row for row in alerts_since(session_factory, seconds=3600, now=1000.0)}
    assert by_ip["1.1.1.1"].score > by_ip["2.2.2.2"].score
    assert by_ip["1.1.1.1"].details["deviation"] == 8.0

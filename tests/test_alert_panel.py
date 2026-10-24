"""Unit tests for the alert line formatter.

Pure string formatting – no Textual app is mounted; we only assert what a
rendered alert line contains: the repeat counter, the score and its colour.
"""
from core.alerts.alert import Alert
from ui.tui.widgets.alert_panel import format_alert_line


def _alert(score=0, **details):
    return Alert(type="ARP_SPOOF", severity="HIGH", src_ip="10.0.0.1",
                 timestamp=1000.0, score=score, details=details)


def test_count_of_one_shows_no_multiplier():
    line = format_alert_line(_alert(), count=1)
    assert "×" not in line
    assert "ARP_SPOOF" in line


def test_count_above_one_shows_multiplier():
    line = format_alert_line(_alert(), count=473)
    assert "×473" in line


def test_score_is_shown():
    line = format_alert_line(_alert(score=63), count=1)
    assert "63" in line


def test_score_carries_its_own_colour_not_the_severity_colour():
    # The detector's label and the cross-type ranking can disagree, and the line
    # has to show it: a HIGH (red) alert that only ranks 43 gets an amber score.
    line = format_alert_line(_alert(score=43), count=1, score_high=70, score_medium=40)
    assert "[yellow][ 43][/yellow]" in line
    assert "[red][HIGH  ][/red]" in line


def test_score_at_the_high_threshold_is_red():
    line = format_alert_line(_alert(score=70), count=1, score_high=70, score_medium=40)
    assert "[red][ 70][/red]" in line


def test_score_below_the_medium_threshold_is_green():
    line = format_alert_line(_alert(score=39), count=1, score_high=70, score_medium=40)
    assert "[green][ 39][/green]" in line


def test_a_measured_deviation_is_shown():
    line = format_alert_line(_alert(score=63, deviation=3.5), count=1)
    assert "z=3.5" in line


def test_an_unmeasured_deviation_reads_as_not_available():
    # None means the source has no usable baseline - it must not render as z=0,
    # which would claim the host was measured and found normal.
    line = format_alert_line(_alert(score=63, deviation=None), count=1)
    assert "z=n/a" in line
    assert "z=0" not in line


def test_deviation_is_not_repeated_in_the_details_dump():
    line = format_alert_line(_alert(score=63, mac="aa:bb:cc", deviation=3.5), count=1)
    assert line.count("z=3.5") == 1
    assert "deviation=" not in line


def test_a_located_source_shows_its_country_and_city():
    geo  = {"country": "Russia", "iso": "RU", "city": "Moscow"}
    line = format_alert_line(_alert(score=63, geo=geo), count=1)
    assert "(RU/Moscow)" in line


def test_a_country_without_a_city_shows_the_country_alone():
    geo  = {"country": "United States", "iso": "US", "city": None}
    line = format_alert_line(_alert(score=63, geo=geo), count=1)
    assert "(US)" in line
    assert "None" not in line


def test_a_source_with_no_location_shows_nothing():
    # Every source on an internal network is private and has no location. A
    # placeholder on each of those lines would be noise, not information.
    line = format_alert_line(_alert(score=63, geo=None), count=1)
    assert "(" not in line.split("src=")[1]


def test_the_location_is_not_dumped_raw_beside_the_detector_details():
    geo  = {"country": "Russia", "iso": "RU", "city": "Moscow"}
    line = format_alert_line(_alert(score=63, mac="aa:bb:cc", geo=geo), count=1)
    assert "geo=" not in line


def test_a_captured_alert_shows_a_pcap_marker():
    line = format_alert_line(_alert(score=63, pcap="captures/20260715_x_PORT_SCAN_1.1.1.1.pcap"), count=1)
    assert "pcap✓" in line


def test_an_alert_without_a_pcap_shows_no_marker():
    # No traffic captured (a replay, or an attack faster than the window) - and
    # the marker claims evidence, so it must be absent when there is none.
    line = format_alert_line(_alert(score=63, pcap=None), count=1)
    assert "pcap" not in line


def test_the_pcap_path_is_a_marker_not_a_raw_dump():
    line = format_alert_line(_alert(score=63, mac="aa:bb:cc", pcap="captures/x.pcap"), count=1)
    assert "pcap✓" in line
    assert "pcap=" not in line
    assert "captures/" not in line
    assert "mac=aa:bb:cc" in line

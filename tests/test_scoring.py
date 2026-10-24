"""Unit tests for the ThreatScorer.

The scorer is pure: every test hands it an Alert plus an explicit count and
deviation, so a score is a function of its inputs alone - no clock, no DB, no
detector. Scorers are built from the same numbers config.yaml ships with, so a
score asserted here is the score the running system produces.
"""
import pytest

from core.alerts.alert import Alert
from core.alerts.scoring import ThreatScorer, score_level


def _scorer(**overrides) -> ThreatScorer:
    kwargs = dict(
        severity_points = {"LOW": 15, "MEDIUM": 25, "HIGH": 35},
        type_weights    = {"ARP_SPOOF": 1.8, "SYN_FLOOD": 1.5, "PORT_SCAN": 1.2,
                           "BRUTE_FORCE": 1.0, "DNS_ANOMALY": 0.9, "BASELINE_ANOMALY": 1.0},
        frequency_max   = 20,
        frequency_cap   = 64,
        deviation_max   = 10,
        deviation_cap   = 8.0,
        default_type_weight = 1.0,
    )
    kwargs.update(overrides)
    return ThreatScorer(**kwargs)


def _alert(atype="PORT_SCAN", sev="HIGH"):
    return Alert(type=atype, severity=sev, src_ip="1.1.1.1", timestamp=1000.0)


def test_lone_arp_spoof_without_a_baseline_still_scores_high():
    # The reason the terms are summed and not multiplied: a first-sighting ARP
    # spoof has no repeats and no deviation, and a product would score it zero.
    s = _scorer()
    assert s.score(_alert("ARP_SPOOF", "HIGH"), count=1, deviation=None) == 63


def test_score_is_clamped_to_100():
    s = _scorer()
    assert s.score(_alert("ARP_SPOOF", "HIGH"), count=64, deviation=8.0) == 100


def test_repeats_raise_the_score():
    s = _scorer()
    once  = s.score(_alert("PORT_SCAN", "MEDIUM"), count=1, deviation=None)
    often = s.score(_alert("PORT_SCAN", "MEDIUM"), count=8, deviation=None)
    assert often > once


def test_frequency_saturates_at_the_cap():
    s = _scorer()
    at_cap  = s.score(_alert(), count=64,   deviation=None)
    way_past = s.score(_alert(), count=5000, deviation=None)
    assert at_cap == way_past


def test_deviation_raises_the_score():
    s = _scorer()
    flat    = s.score(_alert("PORT_SCAN", "MEDIUM"), count=1, deviation=0.0)
    spiking = s.score(_alert("PORT_SCAN", "MEDIUM"), count=1, deviation=8.0)
    assert spiking > flat


def test_deviation_saturates_at_the_cap():
    s = _scorer()
    at_cap   = s.score(_alert(), count=1, deviation=8.0)
    way_past = s.score(_alert(), count=1, deviation=99.0)
    assert at_cap == way_past


def test_missing_baseline_scores_the_same_as_a_measured_zero():
    # Absence of evidence is not evidence of guilt - and not evidence of innocence
    # either. An unmeasured host is neither boosted nor penalised.
    s = _scorer()
    unmeasured = s.score(_alert(), count=3, deviation=None)
    measured   = s.score(_alert(), count=3, deviation=0.0)
    assert unmeasured == measured


def test_a_host_below_its_own_normal_is_not_penalised():
    s = _scorer()
    quiet  = s.score(_alert(), count=3, deviation=-4.0)
    normal = s.score(_alert(), count=3, deviation=0.0)
    assert quiet == normal


def test_attack_type_amplifies_identical_evidence():
    s = _scorer()
    arp = s.score(_alert("ARP_SPOOF",   "HIGH"), count=1, deviation=None)
    dns = s.score(_alert("DNS_ANOMALY", "HIGH"), count=1, deviation=None)
    assert arp > dns


def test_unweighted_attack_type_falls_back_to_the_default_weight():
    # A seventh detector added without a config entry must still score, not crash.
    s = _scorer()
    assert s.score(_alert("ICMP_SWEEP", "HIGH"), count=1, deviation=None) == 35


def test_frequency_cap_of_one_is_rejected():
    # log2(1) is 0 and would divide the frequency curve by zero.
    with pytest.raises(ValueError):
        _scorer(frequency_cap=1)


def test_score_bands_are_inclusive_at_their_lower_edge():
    assert score_level(70, score_high=70, score_medium=40) == "high"
    assert score_level(69, score_high=70, score_medium=40) == "medium"
    assert score_level(40, score_high=70, score_medium=40) == "medium"
    assert score_level(39, score_high=70, score_medium=40) == "low"

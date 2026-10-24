"""Unit tests for the Welford online mean/variance helper.

Values are fed one at a time and the running stats read back. Sample variance
(n-1, Bessel's correction) is used, so it is 0 until at least two values exist.
"""
import pytest

from core.utils.welford import Welford


def test_empty_has_no_stats():
    w = Welford()
    assert w.n == 0
    assert w.mean == 0.0
    assert w.variance == 0.0
    assert w.std == 0.0


def test_single_value_has_no_spread_yet():
    w = Welford()
    w.update(5.0)
    assert w.n == 1
    assert w.mean == 5.0
    assert w.variance == 0.0   # sample variance needs >= 2 values


def test_mean_and_sample_variance():
    w = Welford()
    for x in (2.0, 4.0, 6.0):
        w.update(x)
    assert w.mean == pytest.approx(4.0)
    assert w.variance == pytest.approx(4.0)   # sum of sq dev 8 / (3-1)
    assert w.std == pytest.approx(2.0)


def test_constant_values_have_zero_spread():
    w = Welford()
    for _ in range(5):
        w.update(5.0)
    assert w.mean == pytest.approx(5.0)
    assert w.std == pytest.approx(0.0)


def test_state_round_trip_preserves_stats():
    w = Welford()
    for x in (2.0, 4.0, 6.0, 8.0):
        w.update(x)
    restored = Welford.from_state(*w.state())
    assert restored.n == w.n
    assert restored.mean == pytest.approx(w.mean)
    assert restored.variance == pytest.approx(w.variance)


def test_resumed_welford_keeps_learning():
    w = Welford()
    for x in (10.0, 12.0, 8.0):
        w.update(x)
    resumed = Welford.from_state(*w.state())

    # a value fed to both after the restore must land them on identical stats,
    # proving learning continues from the saved point rather than restarting
    w.update(20.0)
    resumed.update(20.0)
    assert resumed.mean == pytest.approx(w.mean)
    assert resumed.variance == pytest.approx(w.variance)


def test_numerically_stable_on_large_offset():
    # Same spread as (1, 2, 3) but shifted by 1e9. The naive Var = E[x^2]-E[x]^2
    # form loses this to catastrophic cancellation; Welford keeps variance ~= 1.
    w = Welford()
    for x in (1_000_000_001.0, 1_000_000_002.0, 1_000_000_003.0):
        w.update(x)
    assert w.mean == pytest.approx(1_000_000_002.0)
    assert w.variance == pytest.approx(1.0)

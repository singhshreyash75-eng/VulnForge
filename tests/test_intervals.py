
"""Offline tests for statistical confidence intervals."""

import math

import pytest

from vulnforge.statistics.intervals import wilson_interval


def test_zero_successes():
    result = wilson_interval(0, 3)

    assert result["rate"] == 0
    assert result["lower"] == 0
    assert result["upper"] > 0


def test_all_successes():
    result = wilson_interval(3, 3)

    assert result["rate"] == 1
    assert result["upper"] == 1
    assert result["lower"] < 1


def test_half_successes():
    result = wilson_interval(5, 10)

    assert result["rate"] == 0.5
    assert result["lower"] < 0.5
    assert result["upper"] > 0.5


def test_known_reference_zero_of_three():
    result = wilson_interval(0, 3)

    assert result["upper"] == pytest.approx(
        0.5615,
        abs=0.001,
    )


def test_known_reference_five_of_ten():
    result = wilson_interval(5, 10)

    assert result["lower"] == pytest.approx(
        0.2366,
        abs=0.001,
    )

    assert result["upper"] == pytest.approx(
        0.7634,
        abs=0.001,
    )


def test_single_trial():
    result = wilson_interval(0, 1)

    assert 0 <= result["lower"] <= result["upper"] <= 1


def test_large_sample():
    result = wilson_interval(500, 1000)

    assert result["rate"] == 0.5
    assert result["upper"] - result["lower"] < 0.1


def test_higher_confidence_wider_interval():
    low = wilson_interval(5, 10, confidence=0.90)
    high = wilson_interval(5, 10, confidence=0.99)

    assert high["lower"] < low["lower"]
    assert high["upper"] > low["upper"]


def test_zero_trials_rejected():
    with pytest.raises(ValueError):
        wilson_interval(0, 0)


def test_negative_trials_rejected():
    with pytest.raises(ValueError):
        wilson_interval(0, -1)


def test_negative_successes_rejected():
    with pytest.raises(ValueError):
        wilson_interval(-1, 10)


def test_successes_exceed_trials_rejected():
    with pytest.raises(ValueError):
        wilson_interval(11, 10)


def test_float_counts_rejected():
    with pytest.raises(ValueError):
        wilson_interval(1.5, 10)


def test_boolean_counts_rejected():
    with pytest.raises(ValueError):
        wilson_interval(True, 10)


def test_invalid_confidence_rejected():
    for value in (0, 1, -0.5, 1.5):
        with pytest.raises(ValueError):
            wilson_interval(1, 10, confidence=value)


def test_nan_confidence_rejected():
    with pytest.raises(ValueError):
        wilson_interval(
            1,
            10,
            confidence=math.nan,
        )


def test_infinite_confidence_rejected():
    with pytest.raises(ValueError):
        wilson_interval(
            1,
            10,
            confidence=math.inf,
        )


def test_interval_contains_estimate():
    for successes in range(11):
        result = wilson_interval(successes, 10)

        assert (
            result["lower"]
            <= result["rate"]
            <= result["upper"]
        )

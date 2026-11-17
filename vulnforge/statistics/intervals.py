
"""Binomial confidence intervals for VulnForge benchmarks.

Wilson score intervals avoid the pathological zero-width
interval produced by a naive normal approximation when
the observed success rate is zero or one.
"""

import math
from statistics import NormalDist


def wilson_interval(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> dict:
    """Calculate a two-sided Wilson score confidence interval.

    Returns proportions between zero and one.
    """

    if (
        isinstance(successes, bool)
        or isinstance(trials, bool)
        or not isinstance(successes, int)
        or not isinstance(trials, int)
    ):
        raise ValueError("Counts must be integers")

    if trials <= 0:
        raise ValueError("Trials must be positive")

    if successes < 0 or successes > trials:
        raise ValueError("Invalid success count")

    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(confidence)
        or not 0 < confidence < 1
    ):
        raise ValueError("Confidence must be between 0 and 1")

    z = NormalDist().inv_cdf(
        1 - (1 - confidence) / 2
    )

    p = successes / trials
    z2 = z * z

    denominator = 1 + z2 / trials

    center = (
        p + z2 / (2 * trials)
    ) / denominator

    margin = (
        z
        * math.sqrt(
            p * (1 - p) / trials
            + z2 / (4 * trials * trials)
        )
        / denominator
    )

    return {
        "successes": successes,
        "trials": trials,
        "rate": p,
        "confidence": confidence,
        "lower": max(0.0, center - margin),
        "upper": min(1.0, center + margin),
        "method": "wilson_score",
    }

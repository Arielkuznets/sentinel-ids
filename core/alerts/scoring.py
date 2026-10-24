import math

from core.alerts.alert import Alert


def score_level(score: int, score_high: int, score_medium: int) -> str:
    """Which band a score falls into. A band, not a colour – each UI paints it itself."""
    if score >= score_high:
        return "high"
    if score >= score_medium:
        return "medium"
    return "low"


class ThreatScorer:
    """Ranks an alert 0-100 so alerts of different types can be compared.

    Severity, repeat count and the source's deviation from its own baseline are
    evidence: each adds a bounded slice of points, so no weak signal can cancel
    the strong ones out – a pure product of the three would score a lone ARP
    spoof zero. The attack type is not evidence but an amplifier, so it
    multiplies the evidence total, and the result is clamped to 100. Pure – it
    holds no state; the caller supplies the count and the deviation.

    deviation is None when the source has no usable baseline yet. That earns the
    same nothing as a measured zero, but the caller records which of the two it
    was, so an analyst can tell a host proven normal from one never measured.
    """

    def __init__(
        self,
        severity_points:     dict[str, int],
        type_weights:        dict[str, float],
        frequency_max:       float,
        frequency_cap:       int,
        deviation_max:       float,
        deviation_cap:       float,
        default_type_weight: float = 1.0,
    ):
        if frequency_cap <= 1:
            raise ValueError("frequency_cap must exceed 1 - the frequency curve is log-scaled")
        self._severity_points = severity_points
        self._type_weights    = type_weights
        self._frequency_max   = frequency_max
        self._frequency_cap   = frequency_cap
        self._deviation_max   = deviation_max
        self._deviation_cap   = deviation_cap
        self._default_weight  = default_type_weight

    def score(self, alert: Alert, count: int, deviation: float | None) -> int:
        evidence = (
            self._severity_points.get(alert.severity, 0)
            + self._frequency_points(count)
            + self._deviation_points(deviation)
        )
        weight = self._type_weights.get(alert.type, self._default_weight)
        return max(0, min(100, round(evidence * weight)))

    def _frequency_points(self, count: int) -> float:
        """Log-scaled: going from 1 occurrence to 10 means far more than 200 to 210."""
        if count <= 1:
            return 0.0
        ratio = math.log2(count) / math.log2(self._frequency_cap)
        return self._frequency_max * min(1.0, ratio)

    def _deviation_points(self, deviation: float | None) -> float:
        # No baseline, and a host sitting at or below its own normal, both earn nothing.
        if deviation is None or deviation <= 0:
            return 0.0
        return self._deviation_max * min(1.0, deviation / self._deviation_cap)

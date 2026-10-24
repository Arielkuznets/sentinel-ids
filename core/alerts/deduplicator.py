from dataclasses import dataclass

from core.alerts.alert import Alert


def dedup_key(alert: Alert) -> tuple:
    return (alert.src_ip, alert.type, alert.severity)


@dataclass
class Decision:
    is_new: bool
    count:  int
    row_id: int | None = None


@dataclass
class _Episode:
    window_start: float
    count:        int
    row_id:       int | None


class Deduplicator:
    """Collapses repeats of (src_ip, type, severity) within a fixed time window.

    The first alert of a key opens an episode; repeats inside window_seconds bump
    its count instead of firing a new alert, and a fresh episode opens once the
    window elapses. Pure – it only decides; the caller runs the DB/UI side effects
    and hands the new row id back via attach_row_id.
    """

    def __init__(self, window_seconds: float):
        self._window      = window_seconds
        self._episodes:   dict[tuple, _Episode] = {}
        self._last_prune: float = 0.0

    def process(self, alert: Alert) -> Decision:
        now = alert.timestamp
        self._maybe_prune(now)

        key = dedup_key(alert)
        ep  = self._episodes.get(key)
        if ep is None or (now - ep.window_start) >= self._window:
            self._episodes[key] = _Episode(window_start=now, count=1, row_id=None)
            return Decision(is_new=True, count=1)

        ep.count += 1
        return Decision(is_new=False, count=ep.count, row_id=ep.row_id)

    def attach_row_id(self, alert: Alert, row_id: int) -> None:
        ep = self._episodes.get(dedup_key(alert))
        if ep is not None:
            ep.row_id = row_id

    def _maybe_prune(self, now: float) -> None:
        if (now - self._last_prune) <= self._window:
            return
        expired = [k for k, ep in self._episodes.items()
                   if (now - ep.window_start) >= self._window]
        for k in expired:
            del self._episodes[k]
        self._last_prune = now

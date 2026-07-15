from datetime import datetime

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import RichLog

from core.alerts.alert import Alert
from core.alerts.scoring import score_level

_SEVERITY_COLOR = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}
_SCORE_COLOR    = {"high": "red", "medium": "yellow", "low": "green"}


def format_location(geo: dict | None) -> str:
    """A source's location, or nothing at all when it has none.

    Unlike the deviation, an absent location says nothing worth a slot on the
    line: on an internal network every source is private, and 'geo=n/a' on every
    row would be pure noise. The iso code, not the country name, keeps a narrow
    panel readable.
    """
    if not geo:
        return ""
    place = geo.get("iso") or geo.get("country")
    city  = geo.get("city")
    return f" ({place}/{city})" if city else f" ({place})"


def format_alert_line(alert: Alert, count: int, score_high: int = 70,
                      score_medium: int = 40) -> str:
    """One alert as a line: score, severity, time, type, source, details, repeats.

    The score carries its own colour rather than the severity's, so the gap
    between them is legible: a detector shouting HIGH on something that ranks 43
    overall shows up as a red label beside an amber score.
    """
    color       = _SEVERITY_COLOR.get(alert.severity, "white")
    score_color = _SCORE_COLOR[score_level(alert.score, score_high, score_medium)]
    ts          = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
    line = (
        f"[{score_color}][{alert.score:>3}][/{score_color}] "
        f"[{color}][{alert.severity:<6}][/{color}] "
        f"{ts}  [{color}]{alert.type:<14}[/{color}] "
        f"src={alert.src_ip}[dim]{format_location(alert.details.get('geo'))}[/dim]"
    )

    # deviation, geo and pcap are rendered on their own, so keep them out of the dump.
    details = {k: v for k, v in alert.details.items() if k not in ("deviation", "geo", "pcap")}
    if details:
        extra = "  ".join(f"{k}={v}" for k, v in list(details.items())[:2])
        line += f"  {extra}"

    deviation = alert.details.get("deviation")
    line += "  z=n/a" if deviation is None else f"  z={deviation}"

    # A marker, not the path: the file is 45 chars and nobody reads it off a
    # narrow panel - the dashboard names it, this only says one exists.
    if alert.details.get("pcap"):
        line += "  [dim]pcap✓[/dim]"

    if count > 1:
        line += f"  [bold]×{count}[/bold]"
    return line


class AlertPanel(Widget):
    """Right-side panel showing active alerts by severity, each with a repeat count."""

    BORDER_TITLE = "Active Alerts"

    def __init__(self, score_high: int = 70, score_medium: int = 40, **kwargs):
        super().__init__(**kwargs)
        self._score_high   = score_high
        self._score_medium = score_medium

    def compose(self) -> ComposeResult:
        yield RichLog(highlight=True, markup=True, max_lines=100, id="alert-richlog")

    def render_episodes(self, episodes) -> None:
        log = self.query_one(RichLog)
        log.clear()
        for alert, count in episodes:
            log.write(format_alert_line(alert, count, self._score_high, self._score_medium))

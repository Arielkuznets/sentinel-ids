import queue

from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Header, Footer

from core.alerts.alert import Alert
from core.alerts.deduplicator import dedup_key
from ui.tui.widgets.stats_bar import StatsBar
from ui.tui.widgets.packet_log import PacketLog
from ui.tui.widgets.alert_panel import AlertPanel


_MAX_EPISODES = 100


class SentinelApp(App):
    CSS_PATH = "sentinel.tcss"
    TITLE = "SENTINEL IDS"

    BINDINGS = [
        ("q", "quit",          "Quit"),
        ("p", "toggle_pause",  "Pause log"),
        ("f", "toggle_filter", "Filter"),
        ("b", "block_last",    "Block IP"),
        ("u", "unblock_last",  "Unblock IP"),
    ]

    def __init__(self, packet_queue: queue.Queue, session_factory, response_engine,
                 score_high: int = 70, score_medium: int = 40):
        super().__init__()
        self._packet_queue    = packet_queue
        self._session_factory = session_factory
        self._response_engine = response_engine
        self._score_high      = score_high
        self._score_medium    = score_medium
        self._packet_count    = 0
        self._alert_count     = 0
        self._last_alert: Alert | None = None   # the IP that 'b' will act on
        self._alert_episodes: dict[tuple, tuple[Alert, int]] = {}
        self._alerts_dirty    = False

    def compose(self) -> ComposeResult:
        yield Header()
        yield StatsBar(id="stats-bar")
        with Horizontal(id="main-panel"):
            yield PacketLog(id="packet-log")
            yield AlertPanel(id="alert-panel",
                             score_high=self._score_high, score_medium=self._score_medium)
        yield Footer()

    def on_mount(self) -> None:
        # Drain the packet queue every 500 ms from the async event loop.
        # No call_from_thread needed here – set_interval runs in the event loop.
        self.set_interval(0.5, self._drain_packet_queue)
        self.set_interval(0.5, self._refresh_alerts)

    async def _drain_packet_queue(self) -> None:
        packet_log = self.query_one(PacketLog)
        stats_bar  = self.query_one(StatsBar)
        drained    = 0
        while drained < 50:   # cap per tick to avoid starving the event loop
            try:
                packet = self._packet_queue.get_nowait()
            except queue.Empty:
                break
            self._packet_count += 1
            packet_log.add_packet(packet)
            drained += 1
        if drained:
            stats_bar.update_packets(self._packet_count)

    def push_alert(self, alert: Alert) -> None:
        # A new alert episode. Called via app.call_from_thread() from the loop.
        self._alert_count += 1
        self._last_alert = alert   # remember it so 'b' knows which IP to block
        self._alert_episodes[dedup_key(alert)] = (alert, 1)
        self._cap_episodes()
        self._alerts_dirty = True
        self.query_one(StatsBar).update_alerts(self._alert_count)

    def push_alert_count(self, alert: Alert, count: int) -> None:
        # A repeat: keep the episode's first line, but the score moves with the count.
        key      = dedup_key(alert)
        shown, _ = self._alert_episodes.get(key, (alert, count))
        shown.score = alert.score
        shown.details["deviation"] = alert.details.get("deviation")
        self._alert_episodes[key] = (shown, count)
        self._last_alert   = shown
        self._alerts_dirty = True

    def _refresh_alerts(self) -> None:
        if not self._alerts_dirty:
            return
        self.query_one(AlertPanel).render_episodes(self._alert_episodes.values())
        self._alerts_dirty = False

    def _cap_episodes(self) -> None:
        while len(self._alert_episodes) > _MAX_EPISODES:
            del self._alert_episodes[next(iter(self._alert_episodes))]

    def action_toggle_pause(self) -> None:
        self.query_one(PacketLog).toggle_pause()

    def action_toggle_filter(self) -> None:
        self.query_one(PacketLog).toggle_filter()

    def action_block_last(self) -> None:
        """Block the source IP of the most recent alert (with confirmation via
        the result message). The ResponseEngine enforces every safety check."""
        if self._last_alert is None:
            self.notify("No alert to block yet", severity="warning")
            return
        alert  = self._last_alert
        result = self._response_engine.block(alert.src_ip, reason=alert.type, blocked_by="tui")
        self.notify(result.message, severity="information" if result.ok else "warning")

    def action_unblock_last(self) -> None:
        """Lift the block on the most recent alert's source IP."""
        if self._last_alert is None:
            self.notify("No alert to unblock yet", severity="warning")
            return
        result = self._response_engine.unblock(self._last_alert.src_ip)
        self.notify(result.message, severity="information" if result.ok else "warning")

    def action_quit(self) -> None:
        self.exit()

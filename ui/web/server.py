"""FastAPI server for the SENTINEL web dashboard.

Runs as its own process (`python -m ui.web`), fully decoupled from the
capture core. The core (main.py) writes alerts to SQLite; this server only
*reads* them. Nothing here touches the detectors, the packet queue, or the TUI.

This file is the application factory. The actual server launch lives in
__main__.py, so create_app() stays importable (e.g. for tests) without the
side effect of binding a port.
"""
import asyncio
import contextlib
import time
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from core.alerts.scoring import score_level
from db.database import init_db
from db.models import AlertRecord
from db.queries import (
    active_blocks,
    alert_type_counts,
    alerts_per_hour,
    alerts_since,
    find_alerts,
    packet_rate,
    top_sources,
)

STATIC_DIR = Path(__file__).parent / "static"


class ConnectionManager:
    """Keeps the set of open WebSocket connections.

    Each browser tab on the dashboard is one live connection. Holding them in
    a set lets us push a new alert to every tab at once (broadcast).
    """

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accepts the handshake and registers the connection."""
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Drops a connection that has closed."""
        self._connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Sends one message to every open connection, dropping any that have died.

        We iterate over a copy (list(...)) so disconnect() can mutate the set
        mid-loop. A send to a socket the browser already closed raises; we
        swallow it and drop that socket, so one dead tab can't stop the rest
        from receiving the alert.
        """
        for websocket in list(self._connections):
            try:
                await websocket.send_json(message)
            except Exception:
                self.disconnect(websocket)


def _alert_to_message(record: AlertRecord, score_high: int, score_medium: int) -> dict[str, Any]:
    """Turns a stored alert row into a JSON-serialisable dict for the wire.

    The band is resolved here rather than in the browser so the two UIs cannot
    drift apart on where the boundaries sit; the client only paints what it gets.
    """
    return {
        "id":          record.id,
        "timestamp":   record.timestamp,
        "type":        record.type,
        "severity":    record.severity,
        "src_ip":      record.src_ip,
        "count":       record.count,
        "score":       record.score,
        "score_level": score_level(record.score, score_high, score_medium),
        "details":     record.details,
    }


def collect_stats(session_factory, web_cfg: dict, lag_seconds: float, now: float) -> dict[str, Any]:
    """Everything the dashboard's charts draw, read in one pass.

    The traffic series stops lag_seconds short of now: the newest second is still
    being written by the packet log, and drawing it would show a dip that is only
    a flush on its way.
    """
    hours   = web_cfg["alert_stats_hours"]
    traffic = packet_rate(session_factory, web_cfg["traffic_seconds"], now=now - lag_seconds)
    talkers = top_sources(session_factory, web_cfg["top_sources_seconds"],
                          limit=web_cfg["top_sources"], now=now)
    return {
        "traffic":         [{"t": t, "packets": n} for t, n in traffic],
        "top_sources":     [{"ip": ip, "packets": n} for ip, n in talkers],
        "alerts_per_hour": [{"t": t, "alerts": n}
                            for t, n in alerts_per_hour(session_factory, hours, now=now)],
        "alert_types":     alert_type_counts(session_factory, hours * 3600, now=now),
        "blocked":         [{"ip": b.ip, "blocked_at": b.blocked_at, "reason": b.reason}
                            for b in active_blocks(session_factory)],
        "windows":         {"traffic_seconds":     web_cfg["traffic_seconds"],
                            "top_sources_seconds": web_cfg["top_sources_seconds"],
                            "alert_stats_hours":   hours},
    }


def create_app(config: dict) -> FastAPI:
    """Builds the FastAPI application from runtime config."""
    history_seconds = config["web"]["alert_history_seconds"]
    poll_seconds = config["web"]["poll_seconds"]
    score_high = config["ui"]["score_high"]
    score_medium = config["ui"]["score_medium"]
    session_factory = init_db(config["database"]["path"])
    manager = ConnectionManager()

    # The packet log writes at most packet_flush_seconds late, and the current
    # second is still filling: the traffic chart stops that far short of now.
    traffic_lag = config["database"]["packet_flush_seconds"] + 1

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        """Runs the live-push broadcaster for the whole life of the server.

        Code before `yield` is startup; code after is shutdown. We seed the
        sent counts from the DB so the broadcaster only pushes what arrives or
        changes *after* boot — the /ws handler replays old history to a tab on
        connect, not this loop.
        """
        seed = await asyncio.to_thread(alerts_since, session_factory, history_seconds)
        sent = {record.id: record.count for record in seed}

        async def broadcaster() -> None:
            """Poll the DB every poll_seconds, pushing new alerts and count bumps."""
            nonlocal sent
            while True:
                await asyncio.sleep(poll_seconds)
                records = await asyncio.to_thread(alerts_since, session_factory, history_seconds)
                for record in reversed(records):  # oldest-first so the client stacks newest on top
                    if sent.get(record.id) != record.count:
                        await manager.broadcast(
                            _alert_to_message(record, score_high, score_medium))
                sent = {record.id: record.count for record in records}

        task = asyncio.create_task(broadcaster())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    app = FastAPI(title="SENTINEL IDS Dashboard", lifespan=lifespan)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/")
    def index() -> FileResponse:
        """Serves the dashboard page."""
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/api/stats")
    async def stats() -> dict[str, Any]:
        """The aggregates behind the charts.

        Polled rather than pushed: a count refreshed every few seconds needs no
        socket of its own, while an alert is an event, and events ride /ws.
        """
        return await asyncio.to_thread(collect_stats, session_factory, config["web"],
                                       traffic_lag, time.time())

    @app.get("/api/alerts")
    async def incidents(
        seconds:    int = Query(3600, gt=0),
        alert_type: str | None = Query(None, alias="type", max_length=32),
        severity:   Literal["HIGH", "MEDIUM", "LOW"] | None = None,
    ) -> list[dict[str, Any]]:
        """The incident log: alerts from the last `seconds`, optionally narrowed to
        one type and one severity, newest first. A malformed parameter is turned
        away with a 422 by FastAPI's validation, before any query runs.
        """
        records = await asyncio.to_thread(find_alerts, session_factory, time.time() - seconds,
                                          alert_type, severity, config["web"]["incident_limit"])
        return [_alert_to_message(record, score_high, score_medium) for record in records]

    @app.websocket("/ws")
    async def alert_stream(websocket: WebSocket) -> None:
        """Streams alerts to one browser tab.

        On connect we replay the recent alert history so the page is not empty.
        Then we park on receive() with one purpose: to notice when the tab
        closes, so we can drop it from the manager.
        """
        await manager.connect(websocket)

        # alerts_since() is synchronous SQLAlchemy. Running it directly here
        # would block the single event loop and freeze every other connection,
        # so we hand it to a worker thread and await the result instead.
        history = await asyncio.to_thread(alerts_since, session_factory, history_seconds)
        for record in reversed(history):  # newest-first from the DB -> send oldest-first
            await websocket.send_json(_alert_to_message(record, score_high, score_medium))

        try:
            while True:
                await websocket.receive_text()  # we expect nothing; this raises on disconnect
        except WebSocketDisconnect:
            manager.disconnect(websocket)

    return app

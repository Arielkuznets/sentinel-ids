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
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from core.alerts.scoring import score_level
from db.database import init_db
from db.models import AlertRecord
from db.queries import alerts_since

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


def create_app(config: dict) -> FastAPI:
    """Builds the FastAPI application from runtime config."""
    history_seconds = config["web"]["alert_history_seconds"]
    poll_seconds = config["web"]["poll_seconds"]
    score_high = config["ui"]["score_high"]
    score_medium = config["ui"]["score_medium"]
    session_factory = init_db(config["database"]["path"])
    manager = ConnectionManager()

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

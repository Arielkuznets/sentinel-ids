"""Opening the web dashboard from the terminal UI.

The dashboard runs as its own process, and an operator who presses 'd' should not
have to know whether it is up: the launcher starts it only when nothing answers on
its port, waits for it to come up, then opens the browser.
"""
import socket
import subprocess
import sys
import threading
import time
import webbrowser


def is_listening(host: str, port: int, timeout: float = 0.3) -> bool:
    """True if something accepts a TCP connection on host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _spawn_server() -> subprocess.Popen:
    # The child shares the TUI's console, so its streams go nowhere: one uvicorn
    # log line printed there would tear through the terminal UI.
    return subprocess.Popen([sys.executable, "-m", "ui.web"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class DashboardLauncher:
    """Starts the dashboard server on demand, and stops it with the TUI.

    Only a server this launcher started is stopped: one the operator launched by
    hand is theirs and keeps running. The port probe, the spawn, the browser and
    the sleep are injected so the behaviour is testable without any of them.
    """

    def __init__(self, host: str, port: int, startup_seconds: float,
                 listening=is_listening, spawn=_spawn_server,
                 open_browser=webbrowser.open, sleep=time.sleep):
        self._host            = host
        self._port            = port
        self._startup_seconds = startup_seconds
        self._listening       = listening
        self._spawn           = spawn
        self._open_browser    = open_browser
        self._sleep           = sleep
        self._process: subprocess.Popen | None = None
        # Two quick presses must not race to start two servers: the second waits,
        # then finds the first one listening.
        self._lock = threading.Lock()

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}/"

    def open(self) -> str:
        """Bring the dashboard up and open it; returns a one-line status for the UI.

        Blocks while the server starts, so the TUI calls it from a worker thread.
        """
        with self._lock:
            if not self._listening(self._host, self._port):
                self._process = self._spawn()
                waited = 0.0
                while not self._listening(self._host, self._port):
                    if waited >= self._startup_seconds:
                        return f"Dashboard did not come up on {self.url}"
                    self._sleep(0.1)
                    waited += 0.1
        self._open_browser(self.url)
        return f"Dashboard open at {self.url}"

    def close(self) -> None:
        if self._process is not None and self._process.poll() is None:
            self._process.terminate()

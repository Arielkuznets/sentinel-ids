"""Unit tests for the DashboardLauncher behind the TUI's 'd' key.

The port probe, the spawn, the browser and the sleep are all fakes, so nothing
binds a port, starts a process or opens a window; one test probes a real socket.
"""
import socket

from ui.tui.dashboard import DashboardLauncher, is_listening


class _FakeProcess:
    def __init__(self):
        self.terminated = False

    def poll(self):
        return 0 if self.terminated else None   # None: still running

    def terminate(self):
        self.terminated = True


def _launcher(listening_answers, startup_seconds=5.0):
    """A launcher whose port probe replays `listening_answers`, then repeats the last."""
    answers, spawned, opened = list(listening_answers), [], []

    def listening(host, port):
        return answers.pop(0) if len(answers) > 1 else answers[0]

    def spawn():
        spawned.append(_FakeProcess())
        return spawned[-1]

    launcher = DashboardLauncher("127.0.0.1", 8888, startup_seconds, listening=listening,
                                 spawn=spawn, open_browser=opened.append, sleep=lambda s: None)
    return launcher, spawned, opened


def test_a_running_dashboard_is_only_opened():
    launcher, spawned, opened = _launcher([True])

    message = launcher.open()

    assert spawned == []                          # the operator's own server is reused
    assert opened == ["http://127.0.0.1:8888/"]
    assert "open" in message


def test_a_missing_dashboard_is_started_then_opened_once_it_listens():
    launcher, spawned, opened = _launcher([False, False, False, True])

    launcher.open()

    assert len(spawned) == 1
    assert opened == ["http://127.0.0.1:8888/"]   # only after the port answered


def test_a_server_that_never_comes_up_opens_no_browser():
    launcher, spawned, opened = _launcher([False], startup_seconds=1.0)

    message = launcher.open()

    assert opened == []                           # a browser on a dead port helps nobody
    assert "did not come up" in message


def test_close_stops_only_a_server_the_launcher_started():
    launcher, spawned, _ = _launcher([False, True])
    launcher.open()

    launcher.close()

    assert spawned[0].terminated


def test_close_leaves_an_operators_own_server_running():
    launcher, spawned, _ = _launcher([True])
    launcher.open()

    launcher.close()                              # nothing was spawned, nothing to stop

    assert spawned == []


def test_is_listening_probes_a_real_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))                 # any free port
    server.listen()
    port = server.getsockname()[1]
    try:
        assert is_listening("127.0.0.1", port) is True
    finally:
        server.close()
    assert is_listening("127.0.0.1", port) is False

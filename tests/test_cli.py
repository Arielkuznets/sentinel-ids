"""Unit tests for main.py's command line: live by default, --replay for a file."""
import pytest

from main import _parse_args


def test_no_arguments_means_live_capture():
    args = _parse_args([])

    assert args.replay is None
    assert args.speed == 1.0


def test_replay_takes_a_capture_file_and_a_pace(tmp_path):
    capture = tmp_path / "scan.pcap"
    capture.write_bytes(b"")

    args = _parse_args(["--replay", str(capture), "--speed", "10"])

    assert args.replay == str(capture)
    assert args.speed == 10.0


def test_a_missing_capture_file_is_refused_before_anything_starts(tmp_path):
    with pytest.raises(SystemExit):
        _parse_args(["--replay", str(tmp_path / "nope.pcap")])


def test_a_negative_speed_is_refused():
    with pytest.raises(SystemExit):
        _parse_args(["--speed", "-1"])

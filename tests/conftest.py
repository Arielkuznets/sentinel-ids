"""Shared pytest fixtures, auto-loaded for every test in this directory."""
from pathlib import Path

import pytest
import yaml

from core.alerts.scoring import ThreatScorer
from db.database import init_db

_CONFIG = Path(__file__).resolve().parent.parent / "config" / "config.yaml"


@pytest.fixture
def session_factory(tmp_path):
    """A fresh, isolated SQLite database (its own file) for each test."""
    return init_db((tmp_path / "test.db").as_posix())


@pytest.fixture
def scorer():
    """A ThreatScorer built from the numbers the app actually ships.

    Reading the real config, rather than restating the weights here, means a
    scoring key renamed or dropped from config.yaml fails these tests instead of
    only failing at startup.
    """
    config = yaml.safe_load(_CONFIG.read_text())
    return ThreatScorer(**config["alerts"]["scoring"])


@pytest.fixture
def no_baseline():
    """A deviation source that has never measured anything."""
    return lambda src_ip, now: None


@pytest.fixture
def no_geo():
    """A geo source with no GeoLite2 database behind it."""
    return lambda ip: None

"""Unit tests for the database initialization in db/database."""
from sqlalchemy import text


def test_connections_use_write_ahead_logging(session_factory):
    # The dashboard reads this file from another process while the core writes
    # it; WAL is what keeps those reads from waiting out every commit.
    with session_factory() as session:
        assert session.execute(text("PRAGMA journal_mode")).scalar() == "wal"


def test_wal_runs_with_normal_sync(session_factory):
    # NORMAL (1) is safe from corruption under WAL and skips an fsync per commit.
    with session_factory() as session:
        assert session.execute(text("PRAGMA synchronous")).scalar() == 1

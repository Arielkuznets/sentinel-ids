"""Database operations – the read/write functions the app calls.

Keeping these here (instead of inline in main.py) means the persistence
logic has one home and main.py stays a thin assembly layer.
"""
import time

from sqlalchemy import select

from core.alerts.alert import Alert
from db.models import AlertRecord, Baseline, BlockedIp


def save_alert(session_factory, alert: Alert) -> int:
    """Persists a single Alert as a row and returns its new id.

    The id lets the dedup layer address this row later to bump its count.
    A fresh session per alert is fine: alerts are rare events, not per-packet,
    so the open/commit/close overhead is negligible.
    """
    with session_factory() as session:
        record = AlertRecord(
            timestamp = alert.timestamp,
            type      = alert.type,
            severity  = alert.severity,
            src_ip    = alert.src_ip,
            details   = alert.details,
            last_seen = alert.timestamp,
            score     = alert.score,
        )
        session.add(record)
        session.commit()
        return record.id


def update_alert_repeat(session_factory, alert_id: int, count: int, score: int,
                        deviation: float | None, now: float) -> None:
    """Persist an episode's state after a repeat: count, score, deviation, last_seen.

    Everything feeding the score is rewritten, or the row ends up showing a score
    of 100 beside the stale deviation that plainly did not produce it. The
    detector's own details stay as the episode opened. A missing row is a no-op.
    """
    with session_factory() as session:
        record = session.get(AlertRecord, alert_id)
        if record is None:
            return
        record.count     = count
        record.score     = score
        record.details   = {**record.details, "deviation": deviation}
        record.last_seen = now
        session.commit()


def alerts_since(session_factory, seconds: int = 3600, now: float | None = None) -> list[AlertRecord]:
    """Returns alerts from the last `seconds` (default: the past hour), newest first.

    `now` is injectable so the query can be tested against a fixed clock
    instead of depending on the real wall-clock time. The timestamp filter
    rides the index on AlertRecord.timestamp.
    """
    if now is None:
        now = time.time()
    cutoff = now - seconds
    with session_factory() as session:
        stmt = (
            select(AlertRecord)
            .where(AlertRecord.timestamp >= cutoff)
            .order_by(AlertRecord.timestamp.desc())
        )
        return list(session.scalars(stmt).all())


def record_block(session_factory, ip: str, reason: str, blocked_by: str,
                 now: float | None = None) -> None:
    """Persist a block action as a new row in blocked_ips."""
    if now is None:
        now = time.time()
    with session_factory() as session:
        session.add(BlockedIp(ip=ip, blocked_at=now, reason=reason, blocked_by=blocked_by))
        session.commit()


def record_unblock(session_factory, ip: str, now: float | None = None) -> bool:
    """Stamp the active block for `ip` as lifted. Returns True if one was active.

    We match only the row with unblocked_at still NULL – the currently-active
    block – so an old, already-lifted entry for the same IP is left untouched.
    """
    if now is None:
        now = time.time()
    with session_factory() as session:
        stmt = select(BlockedIp).where(
            BlockedIp.ip == ip, BlockedIp.unblocked_at.is_(None)
        )
        record = session.scalars(stmt).first()
        if record is None:
            return False
        record.unblocked_at = now
        session.commit()
        return True


def is_blocked(session_factory, ip: str) -> bool:
    """True if `ip` has an active block (a row with unblocked_at still NULL)."""
    with session_factory() as session:
        stmt = select(BlockedIp).where(
            BlockedIp.ip == ip, BlockedIp.unblocked_at.is_(None)
        )
        return session.scalars(stmt).first() is not None


def active_blocks(session_factory) -> list[BlockedIp]:
    """Every currently-blocked IP (unblocked_at NULL), newest block first."""
    with session_factory() as session:
        stmt = (
            select(BlockedIp)
            .where(BlockedIp.unblocked_at.is_(None))
            .order_by(BlockedIp.blocked_at.desc())
        )
        return list(session.scalars(stmt).all())


def save_baselines(session_factory, items: dict[str, tuple[int, float, float]],
                   now: float | None = None) -> None:
    """Upsert each source's Welford state (n, mean, m2), keyed by ip."""
    if now is None:
        now = time.time()
    with session_factory() as session:
        for ip, (n, mean, m2) in items.items():
            record = session.get(Baseline, ip)
            if record is None:
                session.add(Baseline(ip=ip, n=n, mean=mean, m2=m2, updated_at=now))
            else:
                record.n, record.mean, record.m2, record.updated_at = n, mean, m2, now
        session.commit()


def load_baselines(session_factory) -> dict[str, tuple[int, float, float]]:
    """Return every persisted baseline as ip -> (n, mean, m2)."""
    with session_factory() as session:
        rows = session.scalars(select(Baseline)).all()
        return {r.ip: (r.n, r.mean, r.m2) for r in rows}

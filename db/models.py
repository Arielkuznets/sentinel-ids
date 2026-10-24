"""ORM models – the persistence shape of the data.

AlertRecord is the stored counterpart of the in-memory Alert dataclass
(core/alerts/alert.py). The dataclass is the message passed on the queue;
this is the row written to disk.
"""
from typing import Any

from sqlalchemy import JSON, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db.database import Base


class AlertRecord(Base):
    """One persisted detection event. Maps to the `alerts` table."""
    __tablename__ = "alerts"

    id:        Mapped[int]            = mapped_column(primary_key=True)
    timestamp: Mapped[float]          = mapped_column(Float, index=True)
    type:      Mapped[str]            = mapped_column(String, index=True)
    severity:  Mapped[str]            = mapped_column(String)
    # Nullable on purpose: a SYN flood carries no real src_ip (the source is
    # spoofed), so its alert is stored with src_ip = None. The index still
    # covers the rows that do have a source.
    src_ip:    Mapped[str | None]     = mapped_column(String, index=True)
    details:   Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    count:     Mapped[int]            = mapped_column(Integer, default=1)
    last_seen: Mapped[float]          = mapped_column(Float)
    score:     Mapped[int]            = mapped_column(Integer, default=0)


class BlockedIp(Base):
    """One block action. A row whose unblocked_at IS NULL is blocked right now;
    once it is unblocked we stamp the time instead of deleting the row, so the
    table doubles as an audit log of every block/unblock that ever happened.
    """
    __tablename__ = "blocked_ips"

    id:           Mapped[int]          = mapped_column(primary_key=True)
    ip:           Mapped[str]          = mapped_column(String, index=True)
    blocked_at:   Mapped[float]        = mapped_column(Float)
    reason:       Mapped[str]          = mapped_column(String)
    blocked_by:   Mapped[str]          = mapped_column(String)
    unblocked_at: Mapped[float | None] = mapped_column(Float, nullable=True, default=None)


class Baseline(Base):
    """Persisted Welford state (n, mean, M2) per source IP, so a learned
    packet-rate baseline survives a restart instead of relearning from scratch."""
    __tablename__ = "baselines"

    ip:         Mapped[str]   = mapped_column(String, primary_key=True)
    n:          Mapped[int]   = mapped_column(Integer)
    mean:       Mapped[float] = mapped_column(Float)
    m2:         Mapped[float] = mapped_column(Float)
    updated_at: Mapped[float] = mapped_column(Float)

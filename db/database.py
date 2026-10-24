"""SQLAlchemy foundation: the declarative Base and the DB initialization.

The engine is the entry point to the SQLite file and manages connections.
The Base collects every model's table metadata so create_all() can build them.
A Session is a single unit of work (one transaction) against the DB.
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """All ORM models inherit from this so their tables register here."""
    pass


def init_db(db_path: str):
    """Builds the engine, creates any missing tables, returns a Session factory.

    Models must be imported before this runs so they are registered on
    Base.metadata – otherwise create_all() sees no tables to build.
    """
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    event.listen(engine, "connect", _use_wal)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _use_wal(dbapi_connection, _connection_record) -> None:
    """Run every connection in write-ahead-log mode.

    The dashboard is a second process reading this file while the core writes
    to it. In SQLite's default rollback-journal mode readers are locked out while
    a write commits; with WAL they keep reading the last committed state while
    new writes are appended to the log. synchronous=NORMAL is the pairing WAL is
    built for: a power cut can lose the newest commits, never corrupt the file.
    """
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()

# ADR 0004 – SQLite, in WAL mode, shared by two processes

**Status:** accepted (Phase 5; WAL since v0.12.0)

## Context

SENTINEL persists alerts, blocks, learned baselines and a log of every packet's
header fields. The terminal UI's process writes all of them; the web dashboard
is a second, read-only process that polls the same data every second. Everything
runs on one machine with no administrator to look after a database server.

## Decision

SQLite through SQLAlchemy, one file (`sentinel.db`), with every connection in
write-ahead-log mode and `synchronous=NORMAL`. Each table arrived with its first
consumer rather than being created empty up front: `alerts` with the TUI,
`blocked_ips` with the response engine, `baselines` with baseline learning,
`packets` with the dashboard's statistics.

## Alternatives considered

- **PostgreSQL** – real concurrency and a real server to install, run and secure;
  nothing here needs it at lab scale. The ORM keeps the switch to a connection
  string.
- **SQLite in its default rollback-journal mode** – adequate while the core wrote
  once per alert. Once the packet log began committing every second, each commit
  would lock the dashboard's reads out for its duration.
- **An in-memory store shared by the two processes** – the dashboard is a separate
  process precisely so it can come and go; a file both can open is the simplest
  contract between them.

## Consequences

- In WAL mode a reader keeps reading the last committed state while a writer
  appends to the log, so the dashboard and the packet log never wait on each
  other. `synchronous=NORMAL` drops the fsync per commit – a power cut can lose
  the newest commits but cannot corrupt the file – and took the test suite from
  about 3.5 to under 2 seconds.
- WAL leaves `-wal` and `-shm` files beside the database; both are gitignored.
- Writes are batched where volume demands it: packets go in at 500 per
  transaction (about 50,000 rows a second on the development laptop), alerts one
  per episode, which the deduplicator keeps rare.
- `create_all` creates missing tables but never alters existing ones, so a schema
  change means deleting the lab database – acceptable for a lab tool, and the
  first thing a migration tool would replace.

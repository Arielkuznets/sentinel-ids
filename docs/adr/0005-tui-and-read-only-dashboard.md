# ADR 0005 – A terminal UI that acts, a web dashboard that only reads

**Status:** accepted (Phases 3, 9 and 10)

## Context

An operator needs two things: a fast console to watch traffic and act on an alert,
and a visual overview – charts, history, filters – to understand what happened.
Acting means changing the Windows Firewall, which takes administrator rights.

## Decision

Two interfaces with different powers. The Textual TUI is the primary one and the
only place that can block: `b` and `u` go through the response engine's checks
(a source exists, it is not whitelisted, it is not already blocked) before
`netsh` runs. The FastAPI dashboard is a separate process that only reads
`sentinel.db`: alerts are pushed to the browser over a WebSocket as they land, and
the aggregates behind the charts are polled from `/api/stats` every five seconds.
The TUI's `d` key starts the dashboard if nothing is listening on its port.

## Alternatives considered

- **Block buttons on the dashboard** – the original plan. An unauthenticated
  endpoint on `localhost` that adds firewall rules could be triggered by any web
  page the operator opens: a cross-site request needs no access to the machine,
  only to the operator's browser. Adding authentication, CSRF tokens and an admin
  process behind the web server would cost more than one keystroke in a terminal
  that is already open.
- **Pushing the aggregates over the WebSocket too** – events and aggregates have
  different rhythms. An alert matters the moment it happens; a packets-per-second
  chart redrawn every few seconds loses nothing by being polled, and polling
  keeps the socket's message format a single kind.
- **One process for both** – the dashboard would die with the TUI and share its
  event loop; as a separate reader it can be opened, closed and restarted freely.

## Consequences

- The response path stays behind one door with one set of checks, run by the user
  who can see the alert that motivated it.
- The dashboard can be shown to anyone without handing them the firewall; it lists
  the blocked IPs but cannot change them.
- The two processes share nothing but the database file, which is why SQLite runs
  in WAL mode ([ADR 0004](0004-sqlite-in-wal-mode.md)).
- The server resolves each score's colour band from `config.yaml` and sends it, so
  the browser never hard-codes a threshold that could drift from the TUI's.

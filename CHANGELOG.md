# Changelog

Every release of SENTINEL IDS, newest first. Versions follow the plan's phases
(`v0.N.0` closes phase N), so the early tags are not in numeric order: the five
detectors were built before the terminal UI (Phase 3) and the database (Phase 5),
which is why `v0.5.0` and `v0.3.0` were released after `v0.8.0`.

## [1.0.0] – 2026-10-24 – Phase 13: Portfolio Polish

### Added
- `docs/adr/`: eight architecture decision records – Python and Scapy, the fan-out
  queue, packet time, SQLite in WAL mode, the acting TUI and the read-only
  dashboard, central deduplication, the threat score, the replay lab.
- `docs/THREAT_MODEL.md`: what the sensor can see, what it detects and what it
  does not, threats against SENTINEL itself, assumptions.
- `scripts/benchmark.py` and `docs/BENCHMARKS.md`: per-stage timings and memory
  bounds – about 3,650 packets per second per core, bounded by Scapy's dissection.
- `CONTRIBUTING.md`, this changelog, and README screenshots and diagram.

### Fixed
- One packet the parser could not read ended live capture silently, since Scapy's
  sniffer closes its socket when the callback raises; it is now skipped and counted.
- A SYN flood judged early in its ramp read MEDIUM and was then held there for a
  minute by a per-target cooldown; the cooldown now keys on target and severity,
  so the flood escalates to HIGH.
- Chart.js is pinned to an exact version, and the dashboard no longer requests a
  missing favicon.

## [0.12.0] – 2026-10-24 – Phase 12: Demo Scenarios

### Added
- `main.py --replay FILE [--speed X]`: a capture file played through the full
  system, streamed with `PcapReader`, at its recorded pace by default.
- `scripts/make_samples.py`: a deterministic reference capture for every attack
  plus `all_attacks.pcap`; `tests/test_samples.py` replays each one through the
  detectors.
- `DEMO.md`: every scenario with its command, expected alerts and talking points.
- The packet log: a `packets` table written in batches by a seventh queue
  consumer, trimmed to `packet_retention_hours`; SQLite now runs in WAL mode.
- Dashboard statistics from `/api/stats` – packets per second, top talkers,
  alerts per hour, the attack mix, blocked IPs – and an incident log filtered by
  type, severity and time through `/api/alerts`.
- The `d` key opens the dashboard, starting its server if nothing is listening.

### Fixed
- IPv6 was not parsed – 99% of a live capture on the development machine – so no
  detector saw it.
- A replayed packet's `EDecimal` timestamp crashed the TUI's alert line and lost
  the alert at its pcap filename.
- The TUI's packet counter showed what the log drained, not what was captured.
- `sim_arp_spoof.py` broadcast fake gateway replies that could poison real ARP
  caches; it now sends unicast to a MAC no device owns.
- Quitting with `q` skipped every component's stop, so the baseline's final flush
  never ran; components now stop in parallel on every exit.

## [0.11.0] – 2026-10-24 – Phase 11: Advanced Features

### Added
- Alert deduplication: `(src_ip, type, severity)` episodes with a live repeat
  counter in both interfaces – closes the DNS and ARP alert storms found in the
  v0.10.2 audit.
- Baseline learning: a sixth detector learning each host's packet rate with an
  online Welford mean and variance, persisted across restarts.
- Threat scoring: `(severity + frequency + deviation) × type weight`, 0–100.
- GeoIP: country and city from a local MaxMind database, once per episode.
- PCAP export: the last 30 seconds of raw packets kept in a bounded ring, and the
  source's traffic written to `captures/` when an episode opens.
- Runnable demos for scoring, the baseline, GeoIP and evidence capture.

### Fixed
- Alert lines wrapped past the panel's edge, hiding the deviation, the pcap marker
  and the repeat count.

## [0.10.2] – 2026-07-08 – Audit fixes

### Fixed
- SYN-flood alerts with no source IP crashed persistence.
- SYN-flood detection evaluated on the wall clock and never fired under replay.
- Detector window dictionaries grew without bound under spoofed sources.
- Unblock was not symmetric with block; `netsh` calls had no timeout.

## [0.10.1] – 2026-07-06 – Test suite

### Added
- A pytest suite across utils, the parser, all five detectors, the DB layer, the
  firewall and the response engine – time is injected, nothing sleeps.

## [0.10.0] – 2026-07-01 – Phase 10: Response Engine

### Added
- Block and unblock from the TUI (`b`, `u`) through a response engine that refuses
  spoofed sources, whitelisted IPs and repeats, and records every action.
- `FirewallManager` adding and removing Windows Firewall rules with `netsh`.

## [0.9.0] – 2026-07-01 – Phase 9: Web Dashboard

### Added
- A FastAPI dashboard, run as its own read-only process, pushing alerts to the
  browser over a WebSocket, with an alerts-by-type chart.

### Fixed
- Port-scan alert storms, with a per-source cooldown.

## [0.3.0] – 2026-06-23 – Phase 3: Basic TUI

### Added
- The Textual terminal UI: live packet log, alert panel, stats bar, pause and
  protocol filter.

## [0.5.0] – 2026-06-22 – Phase 5: Database & persistence

### Added
- SQLite persistence for alerts through SQLAlchemy, and the `alerts_since` query.

## [0.8.0] – 2026-06-18 – Phase 8: SYN Flood Detector

### Added
- SYN/ACK ratio per destination, keyed on the target because sources are spoofed,
  and `sim_syn_flood.py`.

### Fixed
- The SYN flood never escalated past MEDIUM.

## [0.7.0] – 2026-06-16 – Phase 7: DNS Anomaly Detector

### Added
- Long-label, Shannon-entropy and query-flood detection, and `sim_dns_tunnel.py`.
- `SlidingWindow` and `CooldownTracker`, shared by every detector.

## [0.6.0] – 2026-06-14 – Phase 6: Brute Force Detector

### Added
- SSH, HTTP and HTTPS login-attempt detection, and `sim_brute_force.py`.

## [0.4.0] – 2026-06-09 – Phase 4: ARP Spoof Detector

### Added
- MAC-conflict and gratuitous-ARP-flood detection, and `sim_arp_spoof.py`.

## [0.2.0] – 2026-06-08 – Phase 2: Port Scan Detector

### Added
- SYN, NULL, FIN and XMAS scan detection, and the `Alert` dataclass.

## [0.1.0] – 2026-06-02 – Phase 1: Packet Capture Engine

### Added
- `PacketCapture` (live sniff and PCAP replay), `PacketParser` and the
  fan-out `PacketQueue`.

## [0.0.1] – 2026-05-21 – Phase 0: Scaffold

### Added
- The project structure, configuration and dependencies.

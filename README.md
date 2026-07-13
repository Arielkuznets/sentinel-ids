# SENTINEL IDS

A real-time network intrusion detection system (IDS) that runs on Windows, listens to live network traffic, detects 5 types of cyber attacks, learns each host's normal traffic to flag statistical anomalies, and presents everything through a dual tactical interface — a terminal UI and a web dashboard.

---

## What It Does

SENTINEL captures every packet that travels through the network and analyzes it in real time. When it detects suspicious behavior, it raises an alert with the attacker's IP, the attack type, and a severity level (HIGH / MEDIUM / LOW). From the terminal UI the user can block the attacker with a single keystroke: the response engine adds a Windows Firewall rule on command — never automatically — and lifts it just as easily.

**The 5 attacks SENTINEL detects:**

| # | Attack Type | Network Layer | What It Looks For |
|---|-------------|---------------|-------------------|
| 1 | Port Scan | L4 – Transport | Unusual SYN bursts across many ports |
| 2 | ARP Spoofing | L2 – Data Link | MAC/IP mapping conflicts |
| 3 | Brute Force | L7 – Application | Repeated SSH/HTTP login attempts |
| 4 | DNS Anomaly | L7 – Application | DNS tunneling, high-frequency queries |
| 5 | SYN Flood | L4 – Transport | Flood of half-open TCP connections |

**Beyond fixed patterns (Phase 11):**

- **Baseline anomaly detection** — a sixth detector learns each source IP's normal packet rate and flags a statistical spike (a z-score far past its *own* learned baseline), catching abnormal behaviour no fixed rule was written for. The learned baseline persists across restarts.
- **Alert deduplication** — a storm of identical alerts collapses into a single entry with a live repeat counter, in both the terminal UI and the web dashboard.
- **Threat scoring** — every alert carries a 0–100 score, so a HIGH from one detector can be ranked against a HIGH from another. It composes what the two features above already produce: how severe the detector called it, how often it has repeated (the dedup counter), and how far the source strays from its own learned baseline — then multiplies by a weight for the attack type, because an ARP spoof and a DNS oddity are not equally dangerous. The score **climbs while an attack is live**, since each repeat re-scores it.
- **GeoIP** — an alert from a public address carries the country and city its source resolves to, shown in both interfaces. The lookup is local: a MaxMind GeoLite2 file, memory-mapped, so no query ever leaves the machine and an alert costs no network round-trip. It runs once per alert episode, not per packet — the source IP is part of the deduplication key, so an episode cannot change country.

---

## Architecture Overview

```
[Network Interface / PCAP File]
            ↓
    [Packet Capture Engine]        core/capture/engine.py
            ↓
       [Packet Parser]             core/capture/parser.py
            ↓
    [Thread-Safe Fan-Out Queue]    core/capture/queue.py
     ↓    ↓    ↓    ↓    ↓    ↓
 [Port][ARP][BF][DNS][SYN][Base]  core/detectors/   (Base = baseline anomaly)
     ↓    ↓    ↓    ↓    ↓    ↓
  [Alert Loop: Dedup + Scoring]   core/alerts/ + main.py
         ↓           ↓
   [Terminal UI]  [Web Dashboard]  ui/tui/  ui/web/
         ↓
  [Response Engine]                core/response/
         ↓
   [SQLite Database]               db/
```

Each component has one responsibility and does not know about the others. The capture engine does not know detectors exist. The detectors do not know about the UI. This design is called **Separation of Concerns** and makes each part independently testable and replaceable.

---

## Folder Structure

```
sentinel/
├── core/                        # All network and security logic
│   ├── capture/                 # Packet ingestion pipeline
│   │   ├── engine.py            # Listens to a NIC (live) or replays a PCAP file
│   │   ├── parser.py            # Breaks a raw Scapy packet into clean, flat fields
│   │   └── queue.py             # Fan-out queue – sends each packet to all detectors
│   ├── detectors/               # One file per attack type
│   │   ├── port_scan.py
│   │   ├── arp_spoof.py
│   │   ├── brute_force.py
│   │   ├── dns_anomaly.py
│   │   ├── syn_flood.py
│   │   └── baseline.py          # (Phase 11) per-IP statistical anomaly detector
│   ├── utils/                   # Shared detection primitives
│   │   ├── sliding_window.py    # Time-bounded O(1) event counter + idle-window sweep
│   │   ├── cooldown.py          # Per-key alert suppression (anti-storm)
│   │   └── welford.py           # (Phase 11) online mean/variance for baselines
│   ├── alerts/                  # Alert data + deduplication + scoring + geo
│   │   ├── alert.py             # The Alert dataclass passed on the queue
│   │   ├── deduplicator.py      # (Phase 11) collapses repeat alerts into one + counter
│   │   ├── scoring.py           # (Phase 11) ThreatScorer – ranks an alert 0–100
│   │   └── geoip.py             # (Phase 11) GeoIPResolver – public IP → country/city
│   └── response/                # Block/unblock actions (Phase 10)
│       ├── engine.py            # Policy brain – confirm, whitelist, record to DB
│       └── firewall.py          # Adds/removes Windows Firewall rules via netsh
│
├── db/                          # Data persistence layer
│   ├── database.py              # SQLAlchemy engine + Base + init_db()
│   ├── models.py                # Tables: alerts, blocked_ips, baselines
│   └── queries.py               # save_alert, update_alert_repeat, alerts_since, save/load_baselines, block/unblock
│
├── ui/
│   ├── tui/                     # Terminal UI (Textual framework) – primary interface
│   │   ├── app.py               # Main Textual application + queue bridge
│   │   ├── sentinel.tcss        # Dark tactical stylesheet
│   │   └── widgets/             # stats_bar.py, packet_log.py, alert_panel.py
│   └── web/                     # Web dashboard (FastAPI + WebSocket) – read-only process
│       ├── server.py            # create_app(): WebSocket push, serves the page, polls DB
│       ├── __main__.py          # `python -m ui.web` entry point (binds the port)
│       └── static/              # index.html, dashboard.js, dashboard.css (Chart.js)
│
├── config/
│   └── config.yaml              # All tunable thresholds – no hardcoded values in code
│
├── data/                        # GeoLite2 database – downloaded by hand, not in the repo
│
├── scripts/                     # Runnable demos (Scapy attack sims are Phase 12)
│   ├── demo_baseline.py         # (Phase 11) watch the baseline fire in the TUI, no capture
│   ├── demo_scoring.py          # (Phase 11) watch a threat score climb live, no capture
│   └── demo_geoip.py            # (Phase 11) five sources, five different geo answers
│
├── pcap_samples/                # Pre-recorded attack traffic for offline replay
│
├── tests/                       # 178 pytest tests – utils, parser, detectors, dedup, baseline, scoring, geoip, db, response
│   └── conftest.py              # Shared fixtures (fresh per-test file DB, scorer from config)
├── docs/                        # (planned, Phase 13) ADRs, THREAT_MODEL.md, BENCHMARKS.md
│
├── main.py                      # Entry point – starts the full system
├── requirements.txt             # Runtime dependencies
├── requirements-dev.txt         # Test-only dependencies (pytest)
├── pytest.ini                   # Test config (pythonpath + testpaths)
└── DEMO.md                      # (planned, Phase 12) Step-by-step demo scenarios
```

---

## Tech Stack

| Component | Technology | Why |
|-----------|------------|-----|
| Language | Python 3.11+ | Balance of control and productivity; best ecosystem for network tools |
| Packet capture | Scapy + Npcap | Full byte-level control; not a wrapper – we parse every field ourselves |
| Terminal UI | Textual | The most advanced Python TUI framework; looks like a real application |
| Web API | FastAPI | Fast, modern, async-native Python web framework |
| Real-time push | WebSockets | Server pushes alerts to browser – no polling delay |
| Frontend | Vanilla JS + Chart.js | No framework overhead; enough for the use case |
| Database | SQLite + SQLAlchemy | Zero configuration; sufficient for lab scale |
| Packet driver | Npcap | Kernel-mode Windows driver that enables Promiscuous Mode on the NIC |

---

## Key Design Decisions

**Why Scapy and not PyShark or a simpler library?**
Scapy gives direct access to every byte of every packet. We parse IP headers, TCP flags, and DNS payloads ourselves.

**Why a fan-out queue?**
The capture engine runs in one thread. Each of the 6 detectors runs in its own thread. A fan-out queue lets every detector see every packet in parallel without blocking each other. If a detector is slow, it drops packets from its own queue — the other detectors are unaffected.

**Why configuration in YAML and not hardcoded?**
Every detection threshold (e.g., "more than 15 ports in 5 seconds = port scan") lives in `config/config.yaml`. Changing sensitivity requires editing one file, not hunting through code. This is a production pattern from The Twelve-Factor App methodology.

**Why SQLite and not PostgreSQL?**
This system runs in a lab environment on a single machine. SQLite requires zero setup, zero server process, and handles the packet/alert volume comfortably. Switching to PostgreSQL later would only require changing the connection string in `config.yaml`.

**Why PCAP files for development instead of live VMs?**
Running three virtual machines (Kali, Ubuntu, Windows) simultaneously is too resource-intensive on a laptop. Scapy reads `.pcap` files exactly like live traffic, so all five detectors can be developed and tested against real recorded attack traffic — with zero VM overhead.

---

## Testing Strategy

| Layer | Method |
|-------|--------|
| Unit tests | 178 `pytest` tests across the utils (including Welford), parser, all 6 detectors, alert deduplication, threat scoring, geo resolution, the DB layer, the firewall, and the response engine. Time is injected (no `sleep`s), so they are deterministic and run in ~3s: `python -m pytest`. The GeoIP tests drive a fake reader, so the suite is green on a clone that never downloaded the 63MB database |
| Development | Replay pre-recorded PCAP files with `rdpcap()` – exact repeatability for debugging |
| Demo & live | `scripts/demo_scoring.py`, `scripts/demo_baseline.py` and `scripts/demo_geoip.py` feed synthetic traffic through the real pipeline into the TUI – watch a score climb, the baseline fire, or five sources resolve to five different places, with no VMs and no Npcap. Scapy loopback attack scripts are planned for Phase 12 |

---

## Getting Started

```bash
# Install runtime dependencies
pip install -r requirements.txt

# Run the system (terminal UI – the primary interface)
python main.py

# Open the web dashboard in a second process (read-only)
python -m ui.web

# Run the test suite
pip install -r requirements-dev.txt
python -m pytest
```

> Npcap must be installed for live capture. Download from https://npcap.com

**Optional – GeoIP.** The GeoLite2 database is a 63MB binary and is not committed. Without it the system runs exactly as before, and alerts simply carry no location. To enable it, take the free `GeoLite2-City.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and drop it in `data/`; the path is `alerts.geoip.database_path` in `config/config.yaml`.

---

## Project Status

| Phase | Description | Status |
|-------|-------------|--------|
| 0 | Environment setup, project scaffold | ✅ Done – v0.0.1 |
| 1 | Packet capture engine | ✅ Done – v0.1.0 |
| 2 | Port scan detector | ✅ Done – v0.2.0 |
| 3 | Terminal UI | ✅ Done – v0.3.0 |
| 4 | ARP spoof detector | ✅ Done – v0.4.0 |
| 5 | Database & logging | 🟡 Partial – v0.5.0 |
| 6 | Brute force detector | ✅ Done – v0.6.0 |
| 7 | DNS anomaly detector | ✅ Done – v0.7.0 |
| 8 | SYN flood detector | ✅ Done – v0.8.0 |
| 9 | Web dashboard | ✅ Done – v0.9.0 |
| 10 | Response engine | ✅ Done – v0.10.0 |
| 11 | Advanced features | 🟡 In progress |
| 12 | Demo scenarios | ⬜ Pending |
| 13 | Portfolio polish | ⬜ Pending |

> ✅ **Test suite (v0.10.1) and audit round (v0.10.2):** after Phase 10 the project gained a committed suite of **88 `pytest` tests**, then a hardening round that fixed a SYN-flood alert-persistence crash, bounded detector memory against spoofed-source floods, made SYN-flood detection work under PCAP replay, and hardened the response layer (unblock symmetry, netsh timeout). Both shipped between Phase 10 and Phase 11.

> 🟡 **Phase 11 in progress:** four of the advanced features are done and merged. **Alert deduplication** collapses a storm of identical alerts into one entry with a live repeat counter (closing two alert-storm bugs deferred from the audit). **Baseline learning** adds a sixth detector that learns each host's normal packet rate with an online Welford mean/variance and flags a z-score spike past its *own* baseline, with the learned state persisted across restarts. **Threat scoring** composes both into a 0–100 rank per alert — severity, repeat count and baseline deviation are summed as evidence, then multiplied by a weight for the attack type — so alerts of different types can be compared and a live attack's score climbs as it repeats. **GeoIP** resolves a public source to a country and city from a local MaxMind database, once per alert episode, and shows it in both interfaces. PCAP export remains.

> 🟡 **Phase 5 is partial:** the `alerts` table is live (write + read), `blocked_ips` arrived with the Response Engine (Phase 10), and `baselines` arrived with Phase 11 baseline learning. The `packets` table, retention cleanup, and built-in stat queries are still deferred — each consumer pulls in what it needs, when it needs it, rather than creating empty tables up front.

> 📌 **Build order vs. phase numbers:** the table follows the *plan's* phase numbers, not the order the work actually happened. The detection engine was the priority, so all five detectors (Phases 4, 6, 7, 8) were built and validated first — before the terminal UI (Phase 3) and the persistence layer (Phase 5). This is why the **early** Git tags are not chronological: `v0.3.0` (TUI) and `v0.5.0` (DB) sit later in history than the detector tags around them. From `v0.9.0` onward the tags are chronological. Each early tag is numbered after its **plan phase**, not its release date.

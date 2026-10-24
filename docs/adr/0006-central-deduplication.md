# ADR 0006 – One deduplicator, downstream of every detector

**Status:** accepted (Phase 11)

## Context

The v0.10.2 audit found two alert storms: DNS tunnelling raised a HIGH alert per
query, because each query carries a unique name and the per-name cooldown never
matched twice; and an active ARP poisoning raised one per packet, because the
real and the spoofed MAC keep interleaving. Each detector had its own cooldown
idea, and none of them could see the storm as one event.

## Decision

A single `Deduplicator` in the alert loop, after all six detectors, keyed on
`(src_ip, type, severity)` with a fixed 60-second window measured in packet time.
The first alert of a key opens an episode – one row, one line on screen – and
every repeat inside the window only bumps the episode's counter and re-scores it.
The deduplicator is pure: it decides NEW or REPEAT, and the alert loop does the
database and UI work.

## Alternatives considered

- **Fixing each detector's cooldown** – two point fixes for two storms, and the
  next detector would bring the next storm.
- **Sub-type in the key** (scan type, DNS reason) – would split the three stealth
  probes of one scan into three rows. Severity already separates the meaningful
  sub-threats.
- **A sliding window** – a fixed one re-opens the episode every minute while an
  attack continues, which reads as a "still happening" heartbeat; a sliding one
  could hold a long attack in one row forever.

## Consequences

- Both storms collapse to one row with a count: 100 alerts in, one row with
  count 100 out, proven in `tests/test_alert_dedup_regression.py` without touching
  either detector.
- Severity is part of the key, so an escalation from MEDIUM to HIGH surfaces as a
  new episode instead of hiding inside an old one – and it is why the threat score
  is a separate field rather than a replacement for severity
  ([ADR 0007](0007-threat-score.md)).
- Work that should happen once per attack runs on the NEW branch only: the GeoIP
  lookup and the PCAP export. A storm writes one evidence file, not thousands.

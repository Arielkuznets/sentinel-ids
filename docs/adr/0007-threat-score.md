# ADR 0007 – The threat score adds evidence and multiplies by type

**Status:** accepted (Phase 11)

## Context

Five detectors say HIGH about very different things. An analyst needs one number
to rank them, and the plan proposed `frequency × deviation × attack_type_weight`.

## Decision

`score = (severity + frequency + deviation) × type_weight`, clamped to 0–100.

- **Severity** gives a fixed number of points per label (LOW 15, MEDIUM 25, HIGH 35).
- **Frequency** comes from the deduplicator's repeat count, log-scaled and
  saturating: the first ten repeats matter far more than the difference between
  200 and 210.
- **Deviation** is the source's z-score against its own learned baseline, taken
  linearly up to a cap – a z-score is already normalised, so compressing it again
  would throw resolution away. With no usable baseline it earns nothing, and the
  alert records `deviation: null`, which reads differently from a measured 0.0.
- **The type weight** amplifies: ARP spoof 1.8, SYN flood 1.5, port scan 1.2,
  brute force and baseline 1.0, DNS 0.9.

All weights and caps live in `config.yaml`.

## Alternatives considered

- **The planned product** – a first-sighting ARP spoof has no repeats and barely
  moves a packet rate, so a pure product scores the most dangerous attack in the
  system zero; the product also has no ceiling. Evidence should accumulate, with
  no single weak signal able to cancel the strong ones.
- **Replacing severity with the score** – severity is part of the dedup key; a
  label derived from a climbing score would change the key mid-attack, split one
  episode into two rows and reset the counter.

## Consequences

- Scoring runs after deduplication, because the repeat count is an input: a live
  attack's score climbs as it repeats, and the stored row is re-scored on every
  repeat.
- A lone HIGH from the DNS detector scores 32 – green – while a lone ARP spoof
  scores 63: the ranking reflects how much a type of attack hurts, not only how
  sure its detector is.
- Each UI paints the score's band, never a hard-coded threshold: the band comes
  from `ui.score_high` and `ui.score_medium`.

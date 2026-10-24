# ADR 0003 – Every window runs on packet time

**Status:** accepted (v0.10.2 audit, completed in Phase 11)

## Context

Every detector counts events inside a time window: 15 ports in 5 seconds, 5 SSH
attempts in 30, a SYN/ACK ratio per 5-second window. The deduplicator, the
baseline's buckets and the packet log's retention all have windows too. The
question is which clock measures them: the wall clock when the packet is
processed, or the timestamp the driver stamped on the packet when it was captured.

## Decision

Packet time, everywhere. Detectors read `packet["timestamp"]`, alerts carry the
time of the packet that triggered them, and the deduplicator, the baseline and
the recorder's retention all key on that same clock. The parser hands the
timestamp on as a float whatever Scapy produced.

## Alternatives considered

- **Wall clock** – correct live, wrong everywhere else: a replayed capture's
  packets arrive far faster than they were recorded (or, at `--speed 0`, all at
  once), so every rate would be wildly inflated and a SYN-flood window would never
  close. Tests would need real sleeps and still be flaky.

## Consequences

- A replay at its recorded pace raises the alerts the live run did, which is what
  makes `pcap_samples/` a regression suite and the demo reproducible. Tests inject
  timestamps and never sleep.
- A window only advances when packets arrive. A detector that judges once per
  window – the SYN-flood ratio – needs a later packet to close the window, which is
  why the SYN-flood sample lasts six seconds.
- Scapy stamps a packet read from a file with an `EDecimal`, not a float. Arithmetic
  on it works, but `datetime.fromtimestamp` refuses it; the first replayed alert
  crashed the TUI until the parser began converting at the edge.
- Retention by packet time means a capture replayed from last year is not deleted
  the moment it is written.

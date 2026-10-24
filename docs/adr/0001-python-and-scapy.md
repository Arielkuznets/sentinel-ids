# ADR 0001 – Python and Scapy for capture and parsing

**Status:** accepted (Phase 0–1)

## Context

An IDS lives or dies by how well its author understands what is in each packet.
The project is also a learning vehicle: every header field a detector relies on
has to be explainable, so the capture layer must expose packets field by field
rather than hand back a summary. It runs on one Windows laptop, against a lab
segment, not on a backbone link.

## Decision

Python 3.11 with Scapy on top of the Npcap driver. Scapy dissects each frame into
layers (Ether, IP/IPv6, TCP/UDP, DNS, ARP); `PacketParser` reads the fields the
detectors need out of those layers into one flat dict, and nothing downstream of
the parser imports Scapy.

## Alternatives considered

- **PyShark / tshark** – Wireshark's dissectors are excellent, but the parsing
  happens in another process and arrives as text fields: the byte-level work this
  project exists to show would be hidden inside a black box.
- **C or Rust over libpcap** – an order of magnitude faster, at the cost of the
  iteration speed that let six detectors, a TUI and a dashboard get built and tested.
- **dpkt** – faster than Scapy at dissection, but read-only and with no packet
  crafting, so the attack simulations and reference captures would need a second
  library.

## Consequences

- Scapy dissection is the throughput ceiling: about 118 µs per frame, which with
  the parser and fan-out puts one core at roughly 3,600 packets per second
  ([BENCHMARKS.md](../BENCHMARKS.md)). The detectors themselves cost under 1% of
  that. Plenty for a lab segment; a busy production link would need native
  dissection or several processes.
- One library both reads and forges packets, so the simulations
  (`scripts/sim_*.py`), the reference captures (`scripts/make_samples.py`) and the
  tests all speak the same language as the capture engine.
- The parser is the single place that knows Scapy's layout – where an address
  lives for ARP versus IP, that IPv6 calls its TTL a hop limit, that a packet read
  from a file carries an `EDecimal` timestamp. Each of those was a bug or a
  near-miss, and each was fixed once, there.

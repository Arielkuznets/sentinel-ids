# ADR 0002 – A fan-out queue with one thread per consumer

**Status:** accepted (Phase 1)

## Context

One capture thread produces packets; six detectors, the packet recorder and the
terminal UI each need to see every one of them. A consumer can stall – a database
write, a UI redraw – and the capture must never stall with it, or the NIC's
buffer overflows and packets are lost for everyone.

## Decision

`PacketQueue` gives every consumer its own bounded queue (1,000 packets) and its
own thread. The producer hands each parsed packet to every queue with
`put_nowait`; when one consumer's queue is full, that consumer misses the packet
and nobody else notices.

## Alternatives considered

- **One loop calling every detector in turn** – simplest, but the slowest
  consumer sets the pace for all, and one exception stops detection entirely.
- **A single shared queue** – consumers would compete for packets instead of
  each receiving all of them.
- **Processes instead of threads** – escapes the GIL, at the cost of pickling
  every packet across a process boundary; not worth it while the detectors cost
  under 1% of the per-packet time.

## Consequences

- A slow consumer degrades only itself. The packet recorder is the clearest case:
  a slow disk costs rows in the packet log, never packets in detection.
- The drop is silent by design. A replay at `--speed 0` pushes packets faster
  than any consumer can drain, so long files are replayed at their recorded pace
  by default.
- Threads share the GIL, so this is concurrency, not parallelism. It is enough
  because the work per packet is dominated by Scapy in the capture thread, not by
  the consumers.
- Every consumer polls its queue with a one-second timeout, so a stop takes up to
  a second per consumer; `main.py` stops them all in parallel to keep shutdown to
  one second.

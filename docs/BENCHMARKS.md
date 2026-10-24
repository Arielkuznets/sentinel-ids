# SENTINEL IDS – Benchmarks

Where the time goes, per packet, measured stage by stage. Reproduce with:

```bash
python scripts/benchmark.py
```

The script times each stage in isolation, on one core, over about 11,000 packets
built from the reference scenarios (`scripts/make_samples.py`) plus a slice of
IPv6 – no NIC and no Npcap, so the numbers do not depend on what the network
happens to carry. The database is a throwaway file.

## Machine

| | |
|---|---|
| CPU | 13th Gen Intel Core i7-1355U (10 cores, 12 threads) – a 15 W laptop part |
| RAM | 16 GB |
| OS | Windows 11 (build 26300) |
| Software | Python 3.11.9, Scapy 2.7.0, SQLite 3.45.1 |

## Results

Representative of three consecutive runs; the spread between runs was within ±10%,
except the two disk-bound rows (packet log, alerts), which varied by ±20%.

| Stage | Throughput | Per item |
|-------|-----------:|---------:|
| Dissect – Scapy turning raw bytes into layered packets (what `sniff` does per frame) | 8,600 /s | 116 µs |
| Parse – `PacketParser` flattening a packet into the detectors' dict | 29,000 /s | 34 µs |
| Detector: port scan | 1,200,000 /s | 0.8 µs |
| Detector: ARP spoof | 9,000,000 /s | 0.1 µs |
| Detector: brute force | 2,500,000 /s | 0.4 µs |
| Detector: DNS anomaly | 5,300,000 /s | 0.2 µs |
| Detector: SYN flood | 2,300,000 /s | 0.4 µs |
| Detector: baseline | 2,700,000 /s | 0.4 µs |
| Packet ring – add | 1,800,000 /s | 0.6 µs |
| Packet ring – select one source out of 11,040 packets | | 1.1 ms |
| Packet log – insert, 500 rows per transaction | 55,000 rows/s | 18 µs |
| Alert, new episode – dedup, score, one database row | 2,700 /s | 370 µs |
| Replay end to end – read, dissect, parse, ring, fan out to 8 consumers | 3,700 /s | 270 µs |

**One core, the capture side plus all six detectors: about 3,650 packets per
second.** Of each packet's ~274 µs, Scapy's dissection takes about 43%, the parser
13%, the six detectors together 1%, the ring well under 1% – and the rest is
reading the file and the fan-out's queue operations.

## What the numbers say

- **The detectors are not the bottleneck.** Each one is a few dictionary operations
  on an O(1) sliding window, so all six together cost about 2 µs per packet.
  Detection logic could grow tenfold before it showed up in this table.
- **Scapy is.** Building a Python object for every layer of every frame costs more
  than everything SENTINEL does with the result. Going faster means native
  dissection (a C extension, or dpkt for the parts that only read) or several
  capture processes – not a cleverer detector.
- **Headroom on a real network.** The packet log measured the development machine's
  own traffic at 700–1,100 packets per second, against a capacity of a few thousand
  on one core: enough for a lab segment or a workstation, not for a backbone link.
  Past that rate the fan-out queue drops per consumer, by design – the capture never
  stalls ([ADR 0002](adr/0002-fan-out-queue.md)).
- **The packet log never limits.** At 55,000 rows a second in batches of 500, it
  outruns the capture more than tenfold. One transaction per packet would have
  paid ~18 µs of transaction overhead *per row* on top of that.
- **Alerts are expensive and rare.** A new episode costs about 370 µs, almost all of
  it one SQLite commit. Deduplication is what keeps that affordable: a storm of a
  thousand identical alerts costs one insert and a stream of cheap updates.

## Memory

| Structure | Bound | Cost at the bound |
|-----------|-------|-------------------|
| Packet ring | 30 s and 20,000 packets | ~79 MiB – 4.1 KiB per dissected packet |
| Per-consumer queues | 1,000 parsed packets × 8 consumers | up to ~8 MiB, with every queue full |
| Detector windows, cooldowns, baselines | swept when idle, per source | grows with *active* sources only |
| Evidence files | 50 files, each at most the ring's 20,000 packets | disk, usually kilobytes per file |
| Packet log | `packet_retention_hours` (48 h) | disk, not RAM |

The ring is the largest consumer, and for a reason worth knowing: live, it holds
the only reference to each dissected packet, so its cost is Scapy's object graph,
not the bytes on the wire – even a bare SYN costs kilobytes as a layered Python
object. The next optimisation would keep each frame's raw bytes and timestamp
instead, and dissect only the few packets an alert actually exports – roughly a
tenth of the memory, paid for with a re-dissection on the rare export.

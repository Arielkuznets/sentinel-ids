# ADR 0008 – A replay lab instead of virtual machines

**Status:** accepted (Phase 0, revised in Phase 12)

## Context

The original plan was three VirtualBox machines – Kali to attack, Ubuntu and
Windows as victims – on a NAT network, with SENTINEL on the host. Each detector's
success criterion named a real tool: Nmap, arpspoof, Hydra.

## Decision

No VMs. Attacks are crafted with Scapy, in two forms:

- **Live simulations** (`scripts/sim_*.py`) send each attack on the real
  interface beside a running `main.py`.
- **Reference captures** (`scripts/make_samples.py`) write each attack to a
  `.pcap` with fixed timestamps and a seeded random source, so every build is byte
  for byte identical. `main.py --replay` plays any capture through the full
  system, and `tests/test_samples.py` replays every sample through the detectors
  on each test run.

## Alternatives considered

- **The VM lab** – realistic tools and real victims, but three VMs exhaust a
  laptop, the setup is hard to reproduce on another machine, and a demo depends on
  all of it booting.
- **Committing captured `.pcap` files** – binaries in the repo, and a capture of
  a real network can carry other people's traffic. The recipe is smaller,
  reviewable, diffable and always regenerable.

## Consequences

- Every demo runs on one laptop with no Npcap and no administrator rights, and
  produces the same alerts every time; DEMO.md lists them.
- A threshold change that would silence a scenario fails the test suite before it
  can fail a demo.
- The attacks are protocol-accurate but not tool-accurate: no Nmap timing
  heuristics, no Hydra retries. The live simulations exist to show the same
  detections on a real interface, with its background traffic and false positives.
- Simulations send spoofed packets on a real network, so they stay low-volume, and
  the ARP one sends unicast to a MAC no device owns – broadcast, it would poison
  the ARP caches of real hosts.

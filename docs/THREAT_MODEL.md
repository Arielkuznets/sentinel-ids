# SENTINEL IDS – Threat Model

What SENTINEL protects, what it can and cannot see, what it deliberately does not
detect, and how it defends itself. Every limit named here is a known one – most
were found by testing, and the ones that could be closed were.

---

## 1. Scope: what the sensor can see

SENTINEL is a **host-based network IDS**: one Windows machine reading its own NIC
through Npcap in promiscuous mode. On a modern switched network that NIC receives:

- every packet to or from the host itself;
- every broadcast and multicast frame on the segment – ARP above all;
- unicast between *other* hosts **only** if the switch floods it (unknown
  destination) or a mirror/SPAN port copies it there.

So it protects the host it runs on and watches the shared layer-2 segment, which is
exactly where ARP spoofing lives. Watching a whole network's traffic would need the
sensor on a mirror port – a deployment change, not a code change.

## 2. Assets

| Asset | Why it matters |
|-------|----------------|
| The host's connectivity | ARP spoofing silently reroutes it through an attacker |
| The services the host exposes (SSH, HTTP) | Targets of scanning and brute force |
| The host's DNS channel | A covert path for data leaving the network |
| The operator's attention | An alert storm or a stream of false positives hides the real alert |
| The firewall | The response engine can change it; misused, it can cut the host off |
| The evidence | `captures/*.pcap` and `sentinel.db` are what an investigation starts from |

## 3. Threats in scope – detected

| Threat | Signal | Detector | Known limits |
|--------|--------|----------|--------------|
| Port scan | > 15 distinct ports from one source in 5s; NULL, FIN, XMAS probes | `port_scan` | A scan slower than the window, or spread across sources, stays under the threshold |
| ARP spoofing / MITM | A known IP answering from a second MAC; > 3 gratuitous replies per minute | `arp_spoof` | The first MAC seen for an IP is trusted – a spoof already in place when SENTINEL starts looks normal |
| SSH / HTTP brute force | ≥ 5 SYNs to :22 in 30s; ≥ 20 `POST /login` to :80 in 60s; HTTPS by connection rate only | `brute_force` | HTTPS content is encrypted – only the connection rate is visible |
| DNS tunnelling | A label over 50 characters; Shannon entropy over 3.5; ≥ 50 queries for one name per minute | `dns_anomaly` | CDN and telemetry names can be random-looking: a real false positive seen live (it scores 32, green) |
| SYN flood | SYN/ACK ratio per destination over 10 (MEDIUM) or 50 (HIGH), ≥ 20 SYNs | `syn_flood` | Keyed on the target, because sources are spoofed – so there is no one to block |
| Anything unusual for a host | A packet-rate z-score past the host's *own* learned baseline | `baseline` | Needs five minutes of history per host; a slow, sub-threshold ramp can still be learned as normal |

IPv4 and IPv6 are both parsed. Until v0.12.0 the parser read IPv4 only – on the
development machine that left 99% of live traffic invisible to every detector.

## 4. Out of scope – not detected

- **Encrypted payloads.** HTTPS, SSH after the handshake, DNS over HTTPS or TLS:
  SENTINEL sees rates and endpoints, never content.
- **Application attacks.** No payload signatures – SQL injection, XSS, exploit
  shellcode. SENTINEL is anomaly- and threshold-based, not a Snort or Suricata
  replacement.
- **IPv6 neighbour-discovery spoofing.** NDP is IPv6's ARP, and an NDP spoof is the
  same MITM; there is no NDP detector.
- **Fragmented packets.** There is no reassembly, so a scan or a query split across
  fragments is seen piecewise.
- **IPv6 extension headers.** A packet carrying them reads as protocol OTHER, since
  its next header names the extension, not the transport, and the transport
  detectors skip it.
- **Low-and-slow and distributed attacks.** Fixed thresholds per source and window
  are evaded by going slower than the window or by spreading over many sources.
- **Traffic the sensor never receives** – see §1.

## 5. Threats against SENTINEL itself

| Threat | Defence |
|--------|---------|
| **Memory exhaustion by spoofed sources** – every new source IP creates state | Every per-source structure is bounded: detector windows are swept when idle, cooldowns prune themselves, the baseline evicts idle hosts, the deduplicator drops closed episodes, the packet ring is capped by time *and* count, evidence files are capped at 50, and the packet log is trimmed to `packet_retention_hours` |
| **A crafted packet that crashes the parser** | Scapy's sniffer closes its socket when the callback raises, so one unreadable packet used to end live capture silently. Since v1.0.0 such a packet is skipped and counted (`packets_unreadable`) and the capture continues |
| **Overload** | The fan-out queue drops per consumer: a slow consumer misses packets, the capture never stalls. One core handles about 3,600 packets/s ([BENCHMARKS.md](BENCHMARKS.md)); beyond that, consumers drop, by design |
| **Alert flooding to hide a real attack** | Central deduplication folds a storm into one row with a counter; the threat score ranks what remains |
| **Command injection through an attacker-controlled IP** | `netsh` runs from an argument list, never a shell string, so an "IP" cannot carry a command |
| **XSS through attacker-controlled fields** | The dashboard writes every value with `textContent`, never `innerHTML` |
| **SQL injection through dashboard filters** | Every filter is a bound parameter, and FastAPI rejects malformed ones with a 422 before any query runs |
| **Cross-site requests against the dashboard** | It has no state-changing endpoint at all: blocking exists only in the terminal UI ([ADR 0005](adr/0005-tui-and-read-only-dashboard.md)) |
| **Tricking the operator into blocking an innocent host** – e.g. a scan spoofed from a real server's address | Blocking is never automatic. The response engine refuses alerts with no real source (SYN flood) and anything on `response.whitelist` – the gateway by default. The operator decides, with the alert in front of them |
| **Misleading attribution** | GeoIP names where an *address* is registered: a Tor exit or a VPN resolves to the exit node, never the attacker. Shown as context, never used to decide |

## 6. Assumptions

- The machine running SENTINEL, its operator and its administrator account are
  trusted. Blocking needs administrator rights; nothing else does.
- The dashboard binds to `127.0.0.1` (`web.host`). Binding it to a LAN address
  would expose the alert history to the network without authentication.
- The evidence on disk – the pcaps and the database – is not integrity-protected:
  anyone with access to the machine can alter it. Hashing or signing evidence is
  out of scope.
- The monitored segment carries lab-scale traffic, within a few thousand packets
  per second.
- Detection never depends on the host's clock: every window runs on packet time
  ([ADR 0003](adr/0003-packet-time.md)).

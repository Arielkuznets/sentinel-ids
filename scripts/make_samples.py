"""Write a reference capture for every attack SENTINEL detects - no Npcap, no admin.

Each sample is built packet by packet with fixed timestamps and a fixed random
seed, so the same bytes come out on every machine: a scenario that replays the
same way each time and opens in Wireshark exactly as DEMO.md describes it.

Run from the sentinel/ folder:
    python scripts/make_samples.py
    python main.py --replay pcap_samples/all_attacks.pcap

The files are gitignored - the repo carries this recipe, not the binaries.
tests/test_samples.py builds the same captures and replays each one through the
detectors, so a sample that stopped firing its alert would fail the suite.
"""
import base64
import random
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

OUT_DIR = Path(__file__).resolve().parent.parent / "pcap_samples"

START = 1767225600.0             # 2026-01-01 00:00:00 UTC - fixed, so every build is identical

# Locally administered MACs (second hex digit 2): no real NIC owns them.
SENSOR_MAC   = "02:00:00:00:00:01"
VICTIM_MAC   = "02:00:00:00:00:02"
GATEWAY_MAC  = "02:00:00:00:00:fe"
ATTACKER_MAC = "02:00:00:00:00:66"

GATEWAY = "192.168.1.1"
VICTIM  = "192.168.1.20"


def _at(packet, seconds: float):
    """Stamp a packet `seconds` after START - its capture time in the file."""
    packet.time = START + seconds
    return packet


def _tcp(src: str, dst: str, dport: int, flags: str, seconds: float, sport: int = 40000):
    return _at(Ether(src=SENSOR_MAC, dst=VICTIM_MAC) / IP(src=src, dst=dst)
               / TCP(sport=sport, dport=dport, flags=flags), seconds)


def port_scan() -> list:
    """A SYN scan of 20 ports in one second (past 15 distinct ports in 5s: HIGH),
    then a NULL, a FIN and an XMAS probe from a second scanner (LOW each)."""
    syn = [_tcp("10.0.0.99", VICTIM, port, "S", i * 0.05) for i, port in enumerate(range(20, 40))]
    stealth = [_tcp("10.0.0.98", VICTIM, 80, flags, 2.0 + i * 0.5)
               for i, flags in enumerate(["", "F", "FPU"])]
    return syn + stealth


def arp_spoof() -> list:
    """A reply teaches the gateway's real MAC, a second MAC then claims the same IP
    (HIGH), and that MAC follows with five gratuitous replies (MEDIUM past three)."""
    def reply(mac: str, psrc: str, pdst: str, seconds: float):
        # Unicast to the sensor, never broadcast: a capture replayed by tcpreplay
        # onto a real LAN must not poison anyone's cache.
        return _at(Ether(src=mac, dst=SENSOR_MAC)
                   / ARP(op=2, hwsrc=mac, psrc=psrc, hwdst=SENSOR_MAC, pdst=pdst), seconds)

    packets = [reply(GATEWAY_MAC, GATEWAY, VICTIM, 0.0),
               reply(ATTACKER_MAC, GATEWAY, VICTIM, 1.0)]
    packets += [reply(ATTACKER_MAC, "192.168.1.200", "192.168.1.200", 2.0 + i * 0.3)
                for i in range(5)]
    return packets


def brute_force() -> list:
    """Seven SSH connection attempts in 3.5s (HIGH at five), then 22 POST /login
    requests in 4.4s (HIGH at twenty), each from its own attacker."""
    ssh = [_tcp("10.0.0.77", VICTIM, 22, "S", i * 0.5, sport=41000 + i) for i in range(7)]
    login = b"POST /login HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\n\r\n"
    http = [_at(Ether(src=SENSOR_MAC, dst=VICTIM_MAC) / IP(src="10.0.0.78", dst=VICTIM)
                / TCP(sport=42000 + i, dport=80, flags="PA") / Raw(load=login), 5.0 + i * 0.2)
            for i in range(22)]
    return ssh + http


def dns_tunnel() -> list:
    """A 62-character label (HIGH), a Base32 payload label (HIGH), then 55 queries
    for one name in under three seconds (MEDIUM at fifty)."""
    def query(qname: str, seconds: float):
        return _at(Ether(src=SENSOR_MAC, dst=GATEWAY_MAC) / IP(src="10.0.0.88", dst=GATEWAY)
                   / UDP(sport=54321, dport=53) / DNS(rd=1, qd=DNSQR(qname=qname)), seconds)

    payload = base64.b32encode(b"secret-exfil-data-12345").decode().lower().rstrip("=")
    packets = [query("a" * 62 + ".evil-c2.com", 0.0), query(f"{payload}.evil-c2.com", 0.5)]
    packets += [query("flood-target.evil-c2.com", 1.0 + i * 0.05) for i in range(55)]
    return packets


def syn_flood() -> list:
    """120 SYNs from spoofed sources to one target, spread over six seconds.

    The detector judges once per 5-second window of packet time, so the flood has
    to outlast one window - a burst that ends before the next judgement, at the end
    of a file, is never judged at all.
    """
    rng = random.Random(7)

    def spoofed() -> str:
        return (f"{rng.randint(11, 250)}.{rng.randint(0, 255)}."
                f"{rng.randint(0, 255)}.{rng.randint(1, 254)}")

    return [_tcp(spoofed(), "192.168.1.10", 80, "S", i * 0.05, sport=rng.randint(1024, 65535))
            for i in range(120)]


SCENARIOS = {
    "port_scan":   port_scan,
    "arp_spoof":   arp_spoof,
    "brute_force": brute_force,
    "dns_tunnel":  dns_tunnel,
    "syn_flood":   syn_flood,
}

# all_attacks.pcap plays the five back to back, this far apart in packet time -
# longer than any detector window, so no scenario leaks into the next one's count.
_GAP_SECONDS = 15.0


def all_attacks() -> list:
    packets = []
    for slot, build in enumerate(SCENARIOS.values()):
        for packet in build():
            packet.time += slot * _GAP_SECONDS
            packets.append(packet)
    return packets


def write_samples(out_dir: Path = OUT_DIR) -> list[Path]:
    """Write every sample into out_dir and return their paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, build in [*SCENARIOS.items(), ("all_attacks", all_attacks)]:
        path = out_dir / f"{name}.pcap"
        wrpcap(str(path), build())
        written.append(path)
    return written


if __name__ == "__main__":
    for path in write_samples():
        print(f"wrote {path}")

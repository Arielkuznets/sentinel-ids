"""
Simulates two ARP-based attack patterns on the interface SENTINEL listens on.

Run SENTINEL first, then execute this script from a second terminal:
    python scripts/sim_arp_spoof.py

Scenario A – MAC Conflict:
    Sends a legitimate ARP Reply to populate SENTINEL's ARP table,
    then sends a second Reply for the same IP with a different MAC.
    Expected: one ARP_SPOOF HIGH alert.

Scenario B – Gratuitous ARP Flood:
    Sends repeated unsolicited ARP Replies (src_ip == dst_ip)
    from the same MAC above the configured threshold.
    Expected: one ARP_SPOOF MEDIUM alert.
"""

import time

from scapy.all import conf
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp

IFACE        = conf.iface          # same interface SENTINEL listens on
VICTIM_IP    = "192.168.1.200"     # unused IP in the local subnet
GATEWAY_IP   = "192.168.1.1"
REAL_MAC     = "aa:bb:cc:11:22:33"
ATTACKER_MAC = "dd:ee:ff:44:55:66"

# Every frame is unicast to a locally administered MAC that no device owns. The
# frames still leave this NIC, so SENTINEL's capture sees them, but every other
# host's NIC drops them on the destination address. Broadcast, "the gateway is
# at <fake MAC>" would rewrite real ARP caches and cut a live LAN off its router.
SINK_MAC     = "02:00:00:00:00:99"


def _send(pkt):
    sendp(pkt, iface=IFACE, verbose=False)


def scenario_a_mac_conflict():
    print("[A] Sending legitimate ARP Reply – populating SENTINEL's table...")
    legit = Ether(src=REAL_MAC, dst=SINK_MAC) / ARP(
        op=2,
        hwsrc=REAL_MAC,
        psrc=GATEWAY_IP,
        hwdst="00:00:00:00:00:00",
        pdst=VICTIM_IP,
    )
    _send(legit)
    time.sleep(1)

    print("[A] Sending spoofed ARP Reply – same IP, different MAC...")
    spoofed = Ether(src=ATTACKER_MAC, dst=SINK_MAC) / ARP(
        op=2,
        hwsrc=ATTACKER_MAC,
        psrc=GATEWAY_IP,
        hwdst="00:00:00:00:00:00",
        pdst=VICTIM_IP,
    )
    _send(spoofed)
    print("[A] Done – expect ARP_SPOOF HIGH alert.\n")


def scenario_b_gratuitous_flood():
    print("[B] Sending Gratuitous ARP flood (src_ip == dst_ip)...")
    for i in range(5):
        pkt = Ether(src=ATTACKER_MAC, dst=SINK_MAC) / ARP(
            op=2,
            hwsrc=ATTACKER_MAC,
            psrc=VICTIM_IP,
            hwdst="00:00:00:00:00:00",
            pdst=VICTIM_IP,        # src_ip == dst_ip → Gratuitous ARP
        )
        _send(pkt)
        print(f"  sent gratuitous #{i + 1}")
        time.sleep(0.3)

    print("[B] Done – expect ARP_SPOOF MEDIUM alert.\n")


if __name__ == "__main__":
    print("=== ARP Spoof Simulation ===\n")
    scenario_a_mac_conflict()
    time.sleep(2)
    scenario_b_gratuitous_flood()
    print("=== Simulation complete ===")

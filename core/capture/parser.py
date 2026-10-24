import time

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP


class PacketParser:
    """
    Converts raw Scapy packets into standardized, flat dictionaries.
    Decouples downstream detectors from Scapy's complex internal objects.
    """

    def parse(self, packet) -> dict:
        """
        Extracts relevant fields across L2-L4 layers into a flat dict.
        Always returns a dict; fields for layers the packet lacks stay None
        (and `protocol` is "OTHER" for unsupported protocols), so downstream
        detectors filter on `protocol` rather than on a None return.
        """
        result = self._base(packet)
        self._extract_ethernet(packet, result)
        self._extract_ip(packet, result)
        self._extract_transport(packet, result)
        self._extract_arp(packet, result)
        self._extract_dns(packet, result)

        return result

    def _base(self, packet) -> dict:
        return {
            "timestamp": getattr(packet, "time", time.time()),
            "size":      len(packet),
            "src_mac":   None,
            "dst_mac":   None,
            "src_ip":    None,
            "dst_ip":    None,
            "ttl":       None,
            "protocol":  None,
            "src_port":  None,
            "dst_port":  None,
            "flags":     None,
            "seq":       None,
            "payload":   b"",
            "arp_op":    None,
            "dns_qname": None,
            "dns_qtype": None,
        }

    def _extract_ethernet(self, packet, result: dict) -> None:
        if not packet.haslayer(Ether):
            return
        eth = packet[Ether]
        result["src_mac"] = eth.src
        result["dst_mac"] = eth.dst

    def _extract_ip(self, packet, result: dict) -> None:
        if packet.haslayer(IP):
            ip = packet[IP]
            result["src_ip"]   = ip.src
            result["dst_ip"]   = ip.dst
            result["ttl"]      = ip.ttl
            result["protocol"] = self._protocol_name(ip.proto)
        elif packet.haslayer(IPv6):
            # The same fields under IPv6's names: the hop limit is the TTL, and the
            # next header names the transport the way IPv4's proto field does.
            ip6 = packet[IPv6]
            result["src_ip"]   = ip6.src
            result["dst_ip"]   = ip6.dst
            result["ttl"]      = ip6.hlim
            result["protocol"] = self._protocol_name(ip6.nh)

    def _extract_transport(self, packet, result: dict) -> None:
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            result["src_port"] = tcp.sport
            result["dst_port"] = tcp.dport
            result["flags"]    = str(tcp.flags)
            result["seq"]      = tcp.seq
            result["payload"]  = bytes(tcp.payload)

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            result["src_port"] = udp.sport
            result["dst_port"] = udp.dport
            result["payload"]  = bytes(udp.payload)

        elif packet.haslayer(ICMP):
            result["protocol"] = "ICMP"

    def _extract_dns(self, packet, result: dict) -> None:
        if not packet.haslayer(DNS):
            return
        dns = packet[DNS]
        # QR=0 means this is a Query (not a Response)
        if dns.qr != 0 or not packet.haslayer(DNSQR):
            return
        qr = packet[DNSQR]
        raw = qr.qname
        if raw:
            result["dns_qname"] = raw.decode("utf-8", errors="replace").rstrip(".")
            result["dns_qtype"] = qr.qtype

    def _extract_arp(self, packet, result: dict) -> None:
        if not packet.haslayer(ARP):
            return
        arp = packet[ARP]
        result["protocol"] = "ARP"
        result["src_ip"]   = arp.psrc
        result["dst_ip"]   = arp.pdst
        result["src_mac"]  = arp.hwsrc
        result["dst_mac"]  = arp.hwdst
        result["arp_op"]   = arp.op   # 1=Request, 2=Reply

    @staticmethod
    def _protocol_name(proto_number: int) -> str:
        mapping = {
            6:   "TCP",
            17:  "UDP",
            1:   "ICMP",
            58:  "ICMPv6",
        }
        return mapping.get(proto_number, "OTHER")
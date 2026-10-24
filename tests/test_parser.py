"""Unit tests for PacketParser.

Each test builds a real Scapy packet, round-trips it through bytes (`_wire`) so
its fields are in wire form - exactly as a sniffed packet arrives - and then
checks the flat dict the parser produces.
"""
from scapy.layers.dns import DNS, DNSQR
import queue

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import rdpcap, wrpcap

from core.capture.parser import PacketParser
from core.detectors.port_scan import PortScanDetector


def _wire(pkt):
    """Serialize then re-parse, so fields hold their on-the-wire values."""
    return pkt.__class__(bytes(pkt))


def test_parse_tcp_packet():
    parser = PacketParser()
    pkt = IP(src="10.0.0.5", dst="10.0.0.1", ttl=64) / TCP(
        sport=1234, dport=80, flags="S", seq=1000)

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "TCP"
    assert result["src_ip"] == "10.0.0.5"
    assert result["dst_ip"] == "10.0.0.1"
    assert result["ttl"] == 64
    assert result["src_port"] == 1234
    assert result["dst_port"] == 80
    assert result["flags"] == "S"
    assert result["seq"] == 1000


def test_parse_tcp_payload():
    parser = PacketParser()
    pkt = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80, flags="PA") / b"POST /login HTTP/1.1"

    result = parser.parse(_wire(pkt))

    assert result["payload"] == b"POST /login HTTP/1.1"


def test_parse_dns_query():
    parser = PacketParser()
    pkt = (IP(src="10.0.0.5", dst="8.8.8.8")
           / UDP(sport=5000, dport=53)
           / DNS(qr=0, rd=1, qd=DNSQR(qname="tunnel.evil.com", qtype="A")))

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "UDP"
    assert result["dst_port"] == 53
    assert result["dns_qname"] == "tunnel.evil.com"   # trailing dot stripped
    assert result["dns_qtype"] == 1                   # A record


def test_parse_arp_packet():
    parser = PacketParser()
    pkt = Ether(src="aa:aa:aa:aa:aa:aa") / ARP(
        op=2, psrc="10.0.0.5", pdst="10.0.0.1",
        hwsrc="aa:aa:aa:aa:aa:aa", hwdst="bb:bb:bb:bb:bb:bb")

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "ARP"
    assert result["src_ip"] == "10.0.0.5"
    assert result["dst_ip"] == "10.0.0.1"
    assert result["src_mac"] == "aa:aa:aa:aa:aa:aa"
    assert result["arp_op"] == 2


def test_parse_extracts_ethernet_macs():
    parser = PacketParser()
    pkt = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP() / TCP()

    result = parser.parse(_wire(pkt))

    assert result["src_mac"] == "aa:bb:cc:dd:ee:ff"
    assert result["dst_mac"] == "11:22:33:44:55:66"


def test_unsupported_packet_returns_dict_not_none():
    parser = PacketParser()
    pkt = IP(proto=99) / b"unknown-l4"

    result = parser.parse(_wire(pkt))

    # parse() always returns a dict, even for protocols it does not decode.
    assert result is not None
    assert result["protocol"] == "OTHER"


def test_parse_ipv6_tcp_packet():
    # Most of a modern LAN's traffic is IPv6. Unparsed, it reached every detector
    # with no address and no protocol, so all six were blind to it.
    parser = PacketParser()
    pkt = IPv6(src="2001:db8::5", dst="2001:db8::1", hlim=64) / TCP(
        sport=1234, dport=22, flags="S")

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "TCP"
    assert result["src_ip"] == "2001:db8::5"
    assert result["dst_ip"] == "2001:db8::1"
    assert result["ttl"] == 64              # the hop limit, IPv6's TTL
    assert result["dst_port"] == 22
    assert result["flags"] == "S"


def test_parse_ipv6_dns_query():
    parser = PacketParser()
    pkt = IPv6(src="2001:db8::5", dst="2001:db8::53") / UDP(sport=5353, dport=53) / DNS(
        rd=1, qd=DNSQR(qname="example.com"))

    result = parser.parse(_wire(pkt))

    assert result["protocol"] == "UDP"
    assert result["dns_qname"] == "example.com"


def test_parse_icmpv6_names_its_own_protocol():
    result = PacketParser().parse(_wire(IPv6(src="fe80::1", dst="ff02::1") / ICMPv6EchoRequest()))

    assert result["protocol"] == "ICMPv6"
    assert result["src_ip"] == "fe80::1"


def test_an_ipv6_scan_reaches_the_port_scan_detector():
    # The detectors key on address strings and never cared about the IP version;
    # all they needed was a parser that hands IPv6 over.
    parser, alerts = PacketParser(), queue.Queue()
    detector = PortScanDetector(queue.Queue(), alerts, threshold_ports=3, window_seconds=5)

    for port in (20, 21, 22, 23):
        packet = parser.parse(_wire(IPv6(src="2001:db8::bad", dst="2001:db8::1") / TCP(dport=port, flags="S")))
        packet["timestamp"] = 1000.0
        detector._process(packet)

    alert = alerts.get_nowait()
    assert alert.type == "PORT_SCAN"
    assert alert.src_ip == "2001:db8::bad"


def test_a_packet_read_from_a_capture_file_gets_a_float_timestamp(tmp_path):
    # Scapy times a file's packets with an EDecimal, not a float. Arithmetic on it
    # works, but datetime.fromtimestamp refuses it - the first replayed alert
    # crashed the TUI's alert line and lost the alert at its pcap filename.
    path = (tmp_path / "one.pcap").as_posix()
    wrpcap(path, [IP(src="10.0.0.5", dst="10.0.0.1") / TCP()])

    result = PacketParser().parse(rdpcap(path)[0])

    assert type(result["timestamp"]) is float

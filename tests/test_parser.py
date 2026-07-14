"""
tests/test_parser.py

Unit tests for parser.packet_parser.PacketParser.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from parser.packet_parser import PacketParser, ParsedPacket


def test_parser_raises_on_missing_file() -> None:
    """PacketParser should raise FileNotFoundError for a missing path."""
    with pytest.raises(FileNotFoundError):
        PacketParser("this_file_does_not_exist.pcap")


def test_parser_raises_on_directory_path(tmp_path: Path) -> None:
    """PacketParser should raise ValueError if given a directory."""
    with pytest.raises(ValueError):
        PacketParser(tmp_path)


def test_parser_loads_all_packets(sample_pcap_path: Path) -> None:
    """load() should return one ParsedPacket per packet in the file."""
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()

    assert len(packets) > 0
    assert all(isinstance(pkt, ParsedPacket) for pkt in packets)
    assert engine.malformed_count == 0


def test_parser_identifies_arp_packets(sample_pcap_path: Path) -> None:
    """The sample capture contains ARP packets that should be labeled 'ARP'."""
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()

    arp_packets = [pkt for pkt in packets if pkt.protocol == "ARP"]
    assert len(arp_packets) > 0
    for pkt in arp_packets:
        assert pkt.arp_sender_ip is not None
        assert pkt.arp_sender_mac is not None


def test_parser_identifies_tcp_udp_icmp(sample_pcap_path: Path) -> None:
    """The sample capture should contain TCP, UDP, and ICMP packets."""
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()
    protocols_found = {pkt.protocol for pkt in packets}

    assert "TCP" in protocols_found
    assert "UDP" in protocols_found
    assert "ICMP" in protocols_found


def test_get_protocol_counts_matches_packet_total(sample_pcap_path: Path) -> None:
    """The sum of protocol counts should equal the total packet count."""
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()
    counts = engine.get_protocol_counts()

    assert sum(counts.values()) == len(packets)

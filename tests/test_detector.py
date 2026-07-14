"""
tests/test_detector.py

Unit tests for detector.arp_detector.ARPSpoofDetector.
"""

from __future__ import annotations

from pathlib import Path

from detector.arp_detector import ARPSpoofDetector
from parser.packet_parser import PacketParser


def test_detector_finds_spoofing_indicator_in_sample(sample_pcap_path: Path) -> None:
    """
    The sample capture deliberately contains a forged ARP reply where
    the gateway IP is claimed by a second MAC address. The detector
    must flag at least one ARPEvent for this.
    """
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()

    detector = ARPSpoofDetector(packets)
    events = detector.analyze()

    assert len(events) > 0
    spoofed_ips = {event.ip_address for event in events}
    assert "192.168.1.1" in spoofed_ips


def test_detector_summary_reports_flapping_ip(sample_pcap_path: Path) -> None:
    """get_summary() should report the gateway IP as having multiple MACs."""
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()

    detector = ARPSpoofDetector(packets)
    detector.analyze()
    summary = detector.get_summary()

    assert summary["ips_with_multiple_macs"] >= 1
    assert "192.168.1.1" in summary["flapping_ip_list"]


def test_detector_no_false_positive_on_stable_ip(sample_pcap_path: Path) -> None:
    """Hosts that never change MAC should not appear in the flapping list."""
    engine = PacketParser(sample_pcap_path)
    packets = engine.load()

    detector = ARPSpoofDetector(packets)
    detector.analyze()
    summary = detector.get_summary()

    # host_a (192.168.1.10) never changes its MAC in the sample capture.
    assert "192.168.1.10" not in summary["flapping_ip_list"]


def test_detector_handles_empty_packet_list() -> None:
    """The detector should not crash on an empty packet list."""
    detector = ARPSpoofDetector([])
    events = detector.analyze()
    summary = detector.get_summary()

    assert events == []
    assert summary["total_ips_tracked"] == 0

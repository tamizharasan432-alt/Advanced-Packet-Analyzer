"""
tests/test_reports.py

Unit tests for reports.report_generator.ReportGenerator.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from detector.arp_detector import ARPSpoofDetector
from parser.packet_parser import PacketParser
from reports.report_generator import ReportGenerator


def _run_full_pipeline(pcap_path: Path, output_dir: Path) -> ReportGenerator:
    """Helper: run parser + detector and build a ReportGenerator."""
    engine = PacketParser(pcap_path)
    packets = engine.load()
    protocol_counts = engine.get_protocol_counts()

    detector = ARPSpoofDetector(packets)
    arp_events = detector.analyze()
    arp_summary = detector.get_summary()

    return ReportGenerator(
        pcap_path=pcap_path,
        packets=packets,
        protocol_counts=protocol_counts,
        malformed_count=engine.malformed_count,
        arp_events=arp_events,
        ip_mac_table=detector.ip_mac_table,
        arp_summary=arp_summary,
        output_dir=output_dir,
    )


def test_generate_csv_creates_valid_file(sample_pcap_path: Path, tmp_path: Path) -> None:
    """generate_csv() should write a CSV readable by pandas with the right row count."""
    output_dir = tmp_path / "out"
    generator = _run_full_pipeline(sample_pcap_path, output_dir)

    csv_path = generator.generate_csv()
    assert csv_path.exists()

    dataframe = pd.read_csv(csv_path)
    assert len(dataframe) == len(generator.packets)


def test_generate_json_creates_valid_file(sample_pcap_path: Path, tmp_path: Path) -> None:
    """generate_json() should write valid JSON with expected top-level keys."""
    output_dir = tmp_path / "out"
    generator = _run_full_pipeline(sample_pcap_path, output_dir)

    json_path = generator.generate_json()
    assert json_path.exists()

    with open(json_path, "r", encoding="utf-8") as json_file:
        data = json.load(json_file)

    assert "protocol_counts" in data
    assert "arp_summary" in data
    assert "packets" in data
    assert data["total_packets"] == len(generator.packets)


def test_generate_html_creates_file_with_dashboard(sample_pcap_path: Path, tmp_path: Path) -> None:
    """generate_html() should write an HTML file containing the dashboard title."""
    output_dir = tmp_path / "out"
    generator = _run_full_pipeline(sample_pcap_path, output_dir)

    html_path = generator.generate_html()
    assert html_path.exists()

    content = html_path.read_text(encoding="utf-8")
    assert "Security Summary Dashboard" in content
    assert "plotly" in content.lower()


def test_generate_all_creates_all_three_reports(sample_pcap_path: Path, tmp_path: Path) -> None:
    """generate_all() should return paths for csv, json, and html reports, all existing."""
    output_dir = tmp_path / "out"
    generator = _run_full_pipeline(sample_pcap_path, output_dir)

    results = generator.generate_all()
    assert set(results.keys()) == {"csv", "json", "html"}
    for path in results.values():
        assert path.exists()

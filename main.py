#!/usr/bin/env python3
"""
main.py

Advanced Packet Analyzer with ARP Spoofing Detection
------------------------------------------------------
A defensive, educational command-line tool for analyzing OFFLINE PCAP
files. It parses Ethernet/ARP/IPv4/TCP/UDP/ICMP traffic, builds an
IP-to-MAC mapping table, flags possible ARP spoofing indicators, and
generates CSV/JSON/HTML reports.

This tool performs NO live packet capture, NO packet injection, and NO
offensive network activity of any kind. It is strictly a read-only
analysis utility intended for authorized network analysis, security
research, and educational use.

Usage:
    python main.py <path-to-pcap-file> [options]

Example:
    python main.py sample_data/sample.pcap
    python main.py sample_data/sample.pcap --output-dir reports_out --verbose
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from detector.arp_detector import ARPSpoofDetector
from parser.packet_parser import PacketParser
from reports.report_generator import ReportGenerator
from utils.logger_config import setup_logging


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse command-line arguments.

    Args:
        argv: Optional list of argument strings (used for testing).
            Defaults to sys.argv when None.

    Returns:
        The parsed argparse.Namespace.
    """
    parser = argparse.ArgumentParser(
        prog="Advanced Packet Analyzer",
        description=(
            "Analyze an offline PCAP file and detect possible ARP "
            "spoofing indicators. Educational / defensive use only."
        ),
    )
    parser.add_argument(
        "pcap_file",
        type=str,
        help="Path to the offline .pcap / .pcapng file to analyze.",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Directory where CSV/JSON/HTML reports will be written (default: current directory).",
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="logs",
        help="Directory where analyzer.log will be written (default: ./logs).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging output.",
    )
    return parser.parse_args(argv)


def run_analysis(pcap_file: str, output_dir: str, log_dir: str, verbose: bool = False) -> int:
    """
    Execute the full analysis pipeline: parse -> detect -> report.

    Args:
        pcap_file: Path to the offline PCAP file to analyze.
        output_dir: Directory to write report files into.
        log_dir: Directory to write the log file into.
        verbose: If True, sets logging level to DEBUG.

    Returns:
        Process exit code: 0 on success, 1 on failure.
    """
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = setup_logging(log_dir=log_dir, level=log_level)

    logger.info("=" * 60)
    logger.info("Advanced Packet Analyzer with ARP Spoofing Detection")
    logger.info("Educational / defensive use only - offline analysis mode")
    logger.info("=" * 60)

    try:
        # --- Step 1: Parse the PCAP file ---
        parser_engine = PacketParser(pcap_file)
        packets = parser_engine.load()
        protocol_counts = parser_engine.get_protocol_counts()

        if not packets:
            logger.warning("No packets were successfully parsed from the file.")

        # --- Step 2: Run ARP spoofing indicator detection ---
        detector = ARPSpoofDetector(packets)
        arp_events = detector.analyze()
        arp_summary = detector.get_summary()

        # --- Step 3: Print a console summary ---
        _print_console_summary(protocol_counts, arp_summary, arp_events, parser_engine.malformed_count)

        # --- Step 4: Generate CSV / JSON / HTML reports ---
        report_generator = ReportGenerator(
            pcap_path=pcap_file,
            packets=packets,
            protocol_counts=protocol_counts,
            malformed_count=parser_engine.malformed_count,
            arp_events=arp_events,
            ip_mac_table=detector.ip_mac_table,
            arp_summary=arp_summary,
            output_dir=output_dir,
        )
        written_files = report_generator.generate_all()

        logger.info("Reports generated successfully:")
        for report_type, path in written_files.items():
            logger.info("  - %s: %s", report_type.upper(), path)

        return 0

    except FileNotFoundError as exc:
        logger.error("File error: %s", exc)
        return 1
    except ValueError as exc:
        logger.error("Input error: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001 - top-level safety net
        logger.exception("Unexpected error during analysis: %s", exc)
        return 1


def _print_console_summary(
    protocol_counts: dict,
    arp_summary: dict,
    arp_events: list,
    malformed_count: int,
) -> None:
    """Print a human-friendly summary of the analysis to the console."""
    print("\n" + "=" * 60)
    print(" ANALYSIS SUMMARY")
    print("=" * 60)
    print(f" Malformed/skipped packets : {malformed_count}")
    print(" Protocol distribution:")
    for protocol, count in sorted(protocol_counts.items(), key=lambda item: -item[1]):
        print(f"   - {protocol:<12}: {count}")

    print("\n ARP Spoofing Indicator Summary:")
    print(f"   - Unique IPs tracked        : {arp_summary['total_ips_tracked']}")
    print(f"   - IPs with multiple MACs    : {arp_summary['ips_with_multiple_macs']}")
    print(f"   - Suspicious events flagged : {arp_summary['total_suspicious_events']}")

    if arp_events:
        print("\n   Suspicious events:")
        for event in arp_events:
            print(
                f"     [!] Packet #{event.packet_index}: {event.ip_address} "
                f"changed MAC {event.previous_mac} -> {event.new_mac}"
            )
    else:
        print("\n   No ARP spoofing indicators detected.")
    print("=" * 60 + "\n")


def main() -> None:
    """Entry point for command-line execution."""
    args = parse_arguments()
    exit_code = run_analysis(
        pcap_file=args.pcap_file,
        output_dir=args.output_dir,
        log_dir=args.log_dir,
        verbose=args.verbose,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

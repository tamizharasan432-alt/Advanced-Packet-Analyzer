"""
reports/report_generator.py

Generates CSV, JSON, and interactive HTML reports from packet analysis
results. The HTML report includes a Plotly bar chart of protocol
distribution and a styled table of suspicious ARP events, rendered
through a Jinja2 template.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import pandas as pd
import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader, select_autoescape

from detector.arp_detector import ARPEvent, IPMacMapping
from parser.packet_parser import ParsedPacket

logger = logging.getLogger("packet_analyzer.reports")

TEMPLATE_DIR = Path(__file__).parent / "templates"


class ReportGenerator:
    """
    Builds CSV, JSON, and HTML reports from the results of the parser
    and detector stages.
    """

    def __init__(
        self,
        pcap_path: str | Path,
        packets: List[ParsedPacket],
        protocol_counts: Dict[str, int],
        malformed_count: int,
        arp_events: List[ARPEvent],
        ip_mac_table: Dict[str, IPMacMapping],
        arp_summary: Dict,
        output_dir: str | Path = ".",
    ) -> None:
        """
        Args:
            pcap_path: Path to the source PCAP file (for display only).
            packets: All parsed packets.
            protocol_counts: Mapping of protocol name -> count.
            malformed_count: Number of packets that failed to parse.
            arp_events: List of detected ARPEvent objects.
            ip_mac_table: The detector's full IP-to-MAC mapping table.
            arp_summary: Summary dictionary from ARPSpoofDetector.get_summary().
            output_dir: Directory in which report files will be written.
        """
        self.pcap_path = Path(pcap_path)
        self.packets = packets
        self.protocol_counts = protocol_counts
        self.malformed_count = malformed_count
        self.arp_events = arp_events
        self.ip_mac_table = ip_mac_table
        self.arp_summary = arp_summary
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def generate_csv(self, filename: str = "analysis_report.csv") -> Path:
        """
        Write a flat CSV report of every parsed packet.

        Args:
            filename: Name of the CSV file to create in the output dir.

        Returns:
            The path to the written CSV file.
        """
        output_path = self.output_dir / filename
        try:
            rows = [pkt.to_dict() for pkt in self.packets]
            dataframe = pd.DataFrame(rows)
            dataframe.to_csv(output_path, index=False)
            logger.info("CSV report written to %s", output_path)
        except Exception as exc:
            logger.error("Failed to write CSV report: %s", exc)
            raise
        return output_path

    def generate_json(self, filename: str = "analysis_report.json") -> Path:
        """
        Write a structured JSON report combining packet data, protocol
        statistics, and ARP spoofing findings.

        Args:
            filename: Name of the JSON file to create in the output dir.

        Returns:
            The path to the written JSON file.
        """
        output_path = self.output_dir / filename
        try:
            report_data = {
                "source_file": str(self.pcap_path),
                "generated_at": datetime.now().isoformat(),
                "total_packets": len(self.packets),
                "malformed_count": self.malformed_count,
                "protocol_counts": self.protocol_counts,
                "arp_summary": self.arp_summary,
                "arp_events": [event.to_dict() for event in self.arp_events],
                "packets": [pkt.to_dict() for pkt in self.packets],
            }
            with open(output_path, "w", encoding="utf-8") as json_file:
                json.dump(report_data, json_file, indent=2, default=str)
            logger.info("JSON report written to %s", output_path)
        except Exception as exc:
            logger.error("Failed to write JSON report: %s", exc)
            raise
        return output_path

    def generate_html(self, filename: str = "analysis_report.html") -> Path:
        """
        Render the interactive HTML security dashboard.

        Args:
            filename: Name of the HTML file to create in the output dir.

        Returns:
            The path to the written HTML file.
        """
        output_path = self.output_dir / filename
        try:
            protocol_chart_html = self._build_protocol_chart()

            ip_mac_rows = [
                {
                    "ip_address": ip,
                    "current_mac": mapping.current_mac,
                    "mac_count": len(mapping.macs_seen),
                }
                for ip, mapping in sorted(self.ip_mac_table.items())
            ]

            template = self._jinja_env.get_template("report_template.html")
            html_content = template.render(
                pcap_filename=self.pcap_path.name,
                generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_packets=len(self.packets),
                malformed_count=self.malformed_count,
                protocol_counts=self.protocol_counts,
                arp_summary=self.arp_summary,
                arp_events=[event.to_dict() for event in self.arp_events],
                ip_mac_rows=ip_mac_rows,
                protocol_chart_html=protocol_chart_html,
            )

            with open(output_path, "w", encoding="utf-8") as html_file:
                html_file.write(html_content)
            logger.info("HTML report written to %s", output_path)
        except Exception as exc:
            logger.error("Failed to write HTML report: %s", exc)
            raise
        return output_path

    def _build_protocol_chart(self) -> str:
        """
        Build an interactive Plotly bar chart of protocol distribution
        and return it as an embeddable HTML <div> snippet.

        Returns:
            HTML string containing the Plotly chart (no full page).
        """
        protocols = list(self.protocol_counts.keys())
        counts = list(self.protocol_counts.values())

        figure = go.Figure(
            data=[
                go.Bar(
                    x=protocols,
                    y=counts,
                    marker_color="#39ff88",
                    text=counts,
                    textposition="auto",
                )
            ]
        )
        figure.update_layout(
            title="Packet Count by Protocol",
            xaxis_title="Protocol",
            yaxis_title="Packet Count",
            template="plotly_dark",
            paper_bgcolor="#131a22",
            plot_bgcolor="#131a22",
            font=dict(family="Consolas, monospace", color="#d7e2ea"),
            height=420,
        )
        return figure.to_html(full_html=False, include_plotlyjs="cdn")

    def generate_all(self) -> Dict[str, Path]:
        """
        Convenience method to generate CSV, JSON, and HTML reports in
        one call.

        Returns:
            A dictionary mapping report type -> written file path.
        """
        return {
            "csv": self.generate_csv(),
            "json": self.generate_json(),
            "html": self.generate_html(),
        }

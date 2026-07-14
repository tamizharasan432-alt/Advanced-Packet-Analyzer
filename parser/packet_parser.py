"""
parser/packet_parser.py

Defensive, read-only PCAP parsing module.

This module ONLY reads pre-captured (offline) .pcap / .pcapng files from
disk using Scapy's `rdpcap`. It never opens a live network interface,
never sends packets, and never performs any injection or spoofing.

Each packet is converted into a `ParsedPacket` dataclass so the rest of
the application (detector, reports) works with clean, typed data instead
of raw Scapy objects.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet

logger = logging.getLogger("packet_analyzer.parser")


@dataclass
class ParsedPacket:
    """
    A flattened, human-readable representation of a single network packet.

    Only the fields relevant to this project's analysis are extracted.
    Fields that do not apply to a given packet (e.g. TCP ports on a UDP
    packet) are left as `None`.
    """

    index: int
    timestamp: float
    protocol: str  # highest-level protocol identified for this packet
    length: int

    # Ethernet / Layer 2
    eth_src: Optional[str] = None
    eth_dst: Optional[str] = None

    # ARP
    arp_op: Optional[str] = None  # "who-has" or "is-at"
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    arp_target_mac: Optional[str] = None

    # IPv4
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    ip_ttl: Optional[int] = None

    # TCP
    tcp_sport: Optional[int] = None
    tcp_dport: Optional[int] = None
    tcp_flags: Optional[str] = None

    # UDP
    udp_sport: Optional[int] = None
    udp_dport: Optional[int] = None

    # ICMP
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    summary: str = field(default="")

    def to_dict(self) -> dict:
        """Return a plain dictionary representation, used for reports."""
        return self.__dict__.copy()


class PacketParser:
    """
    Reads an offline PCAP file and extracts structured packet information.

    This class is strictly read-only / passive. It performs no network
    I/O of its own: Scapy's `rdpcap` loads packets that were already
    captured and stored on disk by another authorized tool (e.g.
    tcpdump, Wireshark) or generated for testing purposes.
    """

    def __init__(self, pcap_path: str | Path) -> None:
        """
        Initialize the parser with the path to a PCAP file.

        Args:
            pcap_path: Path to a .pcap or .pcapng file on disk.

        Raises:
            FileNotFoundError: If the given path does not exist.
            ValueError: If the path does not point to a file.
        """
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_path}")
        if not self.pcap_path.is_file():
            raise ValueError(f"Path is not a file: {self.pcap_path}")

        self.parsed_packets: List[ParsedPacket] = []
        self.malformed_count: int = 0

    def load(self) -> List[ParsedPacket]:
        """
        Load and parse every packet in the PCAP file.

        Returns:
            A list of ParsedPacket objects, one per successfully parsed
            packet. Malformed or unreadable packets are skipped and
            logged, not raised, so a single bad packet cannot crash the
            whole analysis run.
        """
        logger.info("Loading PCAP file: %s", self.pcap_path)
        try:
            raw_packets = rdpcap(str(self.pcap_path))
        except Exception as exc:  # Scapy can raise several exception types
            logger.error("Failed to read PCAP file '%s': %s", self.pcap_path, exc)
            raise

        logger.info("Loaded %d raw packets from file", len(raw_packets))

        for index, raw_packet in enumerate(raw_packets):
            try:
                parsed = self._parse_single_packet(index, raw_packet)
                self.parsed_packets.append(parsed)
            except Exception as exc:  # noqa: BLE001 - intentional broad catch
                self.malformed_count += 1
                logger.warning(
                    "Skipping malformed packet at index %d: %s", index, exc
                )

        logger.info(
            "Parsing complete: %d parsed, %d malformed/skipped",
            len(self.parsed_packets),
            self.malformed_count,
        )
        return self.parsed_packets

    def _parse_single_packet(self, index: int, packet: Packet) -> ParsedPacket:
        """
        Convert a single Scapy packet object into a ParsedPacket.

        Args:
            index: The packet's position in the capture file.
            packet: The raw Scapy packet object.

        Returns:
            A populated ParsedPacket instance.
        """
        timestamp = float(getattr(packet, "time", 0.0))
        length = len(packet)
        protocol = "OTHER"

        parsed = ParsedPacket(
            index=index,
            timestamp=timestamp,
            protocol=protocol,
            length=length,
        )

        # --- Layer 2: Ethernet ---
        if packet.haslayer(Ether):
            eth = packet[Ether]
            parsed.eth_src = eth.src
            parsed.eth_dst = eth.dst

        # --- ARP ---
        if packet.haslayer(ARP):
            arp = packet[ARP]
            parsed.protocol = "ARP"
            parsed.arp_op = "who-has" if arp.op == 1 else "is-at" if arp.op == 2 else str(arp.op)
            parsed.arp_sender_ip = arp.psrc
            parsed.arp_sender_mac = arp.hwsrc
            parsed.arp_target_ip = arp.pdst
            parsed.arp_target_mac = arp.hwdst

        # --- IPv4 ---
        elif packet.haslayer(IP):
            ip_layer = packet[IP]
            parsed.ip_src = ip_layer.src
            parsed.ip_dst = ip_layer.dst
            parsed.ip_ttl = ip_layer.ttl

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                parsed.protocol = "TCP"
                parsed.tcp_sport = int(tcp.sport)
                parsed.tcp_dport = int(tcp.dport)
                parsed.tcp_flags = str(tcp.flags)
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                parsed.protocol = "UDP"
                parsed.udp_sport = int(udp.sport)
                parsed.udp_dport = int(udp.dport)
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                parsed.protocol = "ICMP"
                parsed.icmp_type = int(icmp.type)
                parsed.icmp_code = int(icmp.code)
            else:
                parsed.protocol = "IPv4-OTHER"

        parsed.summary = packet.summary()
        return parsed

    def get_protocol_counts(self) -> dict[str, int]:
        """
        Count how many parsed packets fall under each protocol label.

        Returns:
            A dictionary mapping protocol name -> packet count.
        """
        counts: dict[str, int] = {}
        for pkt in self.parsed_packets:
            counts[pkt.protocol] = counts.get(pkt.protocol, 0) + 1
        return counts

"""
detector/arp_detector.py

Defensive ARP spoofing indicator detection.

This module builds an IP-to-MAC mapping table from parsed ARP traffic
and flags any IP address that is observed with more than one distinct
MAC address over the course of the capture. This "MAC flapping" pattern
is one of the most common indicators of ARP spoofing / ARP cache
poisoning attacks, where an attacker sends forged ARP replies to
associate their own MAC address with the IP address of another host
(commonly the default gateway).

This module is purely analytical: it reads already-captured packet data
and reports on it. It never generates or sends ARP packets.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set

from parser.packet_parser import ParsedPacket

logger = logging.getLogger("packet_analyzer.detector")


@dataclass
class ARPEvent:
    """Represents a single suspicious ARP mapping-change event."""

    packet_index: int
    timestamp: float
    ip_address: str
    previous_mac: str
    new_mac: str
    severity: str = "HIGH"
    description: str = ""

    def to_dict(self) -> dict:
        """Return a plain dictionary representation, used for reports."""
        return self.__dict__.copy()


@dataclass
class IPMacMapping:
    """Tracks every MAC address ever seen for a given IP address."""

    ip_address: str
    macs_seen: Set[str] = field(default_factory=set)
    first_mac: str = ""
    current_mac: str = ""


class ARPSpoofDetector:
    """
    Builds an IP-to-MAC mapping table from ARP traffic and detects
    changes that may indicate ARP spoofing.

    Detection logic:
        For every ARP packet (request or reply), the (sender_ip,
        sender_mac) pair is recorded. If an IP address is later seen
        associated with a *different* MAC address than the one it was
        first observed with, an ARPEvent is raised.
    """

    def __init__(self, packets: List[ParsedPacket]) -> None:
        """
        Args:
            packets: The list of ParsedPacket objects produced by
                PacketParser.load().
        """
        self.packets = packets
        self.ip_mac_table: Dict[str, IPMacMapping] = {}
        self.events: List[ARPEvent] = []

    def analyze(self) -> List[ARPEvent]:
        """
        Run ARP spoofing indicator detection over all parsed packets.

        Returns:
            A list of ARPEvent objects describing every detected
            IP-to-MAC mapping change, in the order they occurred.
        """
        logger.info("Starting ARP spoofing analysis")
        arp_packets = [p for p in self.packets if p.protocol == "ARP" and p.arp_sender_ip]

        for packet in arp_packets:
            self._process_arp_packet(packet)

        logger.info(
            "ARP analysis complete: %d ARP packets examined, %d suspicious events found",
            len(arp_packets),
            len(self.events),
        )
        return self.events

    def _process_arp_packet(self, packet: ParsedPacket) -> None:
        """
        Update the IP-to-MAC table for a single ARP packet and record
        an ARPEvent if a mapping conflict is detected.
        """
        ip_address = packet.arp_sender_ip
        mac_address = packet.arp_sender_mac

        if not ip_address or not mac_address:
            return

        # Ignore broadcast / unset placeholder MACs which are not
        # meaningful for spoofing detection.
        if mac_address.lower() in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            return

        if ip_address not in self.ip_mac_table:
            self.ip_mac_table[ip_address] = IPMacMapping(
                ip_address=ip_address,
                macs_seen={mac_address},
                first_mac=mac_address,
                current_mac=mac_address,
            )
            return

        mapping = self.ip_mac_table[ip_address]

        if mac_address != mapping.current_mac:
            event = ARPEvent(
                packet_index=packet.index,
                timestamp=packet.timestamp,
                ip_address=ip_address,
                previous_mac=mapping.current_mac,
                new_mac=mac_address,
                severity="HIGH",
                description=(
                    f"IP {ip_address} changed MAC address from "
                    f"{mapping.current_mac} to {mac_address}. This may "
                    f"indicate ARP spoofing / cache poisoning."
                ),
            )
            self.events.append(event)
            logger.warning(
                "Possible ARP spoofing detected: %s (packet #%d)",
                event.description,
                packet.index,
            )

        mapping.macs_seen.add(mac_address)
        mapping.current_mac = mac_address

    def get_summary(self) -> dict:
        """
        Build a summary dictionary of the ARP analysis results.

        Returns:
            A dictionary with the total unique IPs tracked, how many
            IPs had more than one MAC address, and the total number of
            suspicious events.
        """
        flapping_ips = [
            ip for ip, mapping in self.ip_mac_table.items() if len(mapping.macs_seen) > 1
        ]
        return {
            "total_ips_tracked": len(self.ip_mac_table),
            "ips_with_multiple_macs": len(flapping_ips),
            "flapping_ip_list": flapping_ips,
            "total_suspicious_events": len(self.events),
        }

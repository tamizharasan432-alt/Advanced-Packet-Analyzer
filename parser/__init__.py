"""
Parser package.

Contains the PacketParser class responsible for reading offline PCAP
files with Scapy and extracting structured, protocol-aware information
from each packet (Ethernet, ARP, IPv4, TCP, UDP, ICMP).
"""

from .packet_parser import PacketParser, ParsedPacket

__all__ = ["PacketParser", "ParsedPacket"]

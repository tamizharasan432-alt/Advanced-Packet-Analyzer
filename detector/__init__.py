"""
Detector package.

Contains the ARPSpoofDetector class, which analyzes already-parsed
packet data (produced by the parser package) to flag IP-to-MAC mapping
changes that are indicative of possible ARP spoofing activity.

This package performs analysis only. It does not send, forge, or
inject any network traffic.
"""

from .arp_detector import ARPSpoofDetector, ARPEvent

__all__ = ["ARPSpoofDetector", "ARPEvent"]

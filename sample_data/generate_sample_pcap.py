"""
sample_data/generate_sample_pcap.py

Generates a small, synthetic offline PCAP file (sample.pcap) for testing
and demonstrating the Advanced Packet Analyzer.

This script builds packets IN MEMORY using Scapy's packet-crafting
objects and writes them straight to a file with `wrpcap`. It never
opens a network interface and never sends a single packet onto a real
network - it only serializes packet objects to disk, the same way a
unit test would construct test fixtures.

The generated capture includes:
    - Normal ARP requests/replies for a handful of hosts
    - Normal TCP, UDP, and ICMP traffic
    - One deliberate ARP spoofing indicator: the "gateway" IP address
      (192.168.1.1) is later seen advertised from a second, different
      MAC address, simulating a forged ARP reply.

Run this script directly to (re)generate sample_data/sample.pcap:

    python sample_data/generate_sample_pcap.py
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP


def build_sample_packets() -> list:
    """
    Construct the full list of synthetic packets for the sample capture.

    Returns:
        A list of Scapy packet objects in chronological order.
    """
    packets = []

    gateway_ip = "192.168.1.1"
    gateway_mac_legit = "aa:bb:cc:00:00:01"
    attacker_mac = "de:ad:be:ef:00:66"
    host_a_ip, host_a_mac = "192.168.1.10", "aa:bb:cc:00:00:10"
    host_b_ip, host_b_mac = "192.168.1.20", "aa:bb:cc:00:00:20"

    # --- Normal ARP traffic ---
    packets.append(
        Ether(src=host_a_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc=host_a_ip, hwsrc=host_a_mac, pdst=gateway_ip)
    )
    packets.append(
        Ether(src=gateway_mac_legit, dst=host_a_mac)
        / ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac_legit, pdst=host_a_ip)
    )
    packets.append(
        Ether(src=host_b_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc=host_b_ip, hwsrc=host_b_mac, pdst=gateway_ip)
    )
    packets.append(
        Ether(src=gateway_mac_legit, dst=host_b_mac)
        / ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac_legit, pdst=host_b_ip)
    )

    # --- Normal TCP traffic (host A -> external web server via gateway) ---
    packets.append(
        Ether(src=host_a_mac, dst=gateway_mac_legit)
        / IP(src=host_a_ip, dst="93.184.216.34", ttl=64)
        / TCP(sport=51000, dport=443, flags="S")
    )
    packets.append(
        Ether(src=host_a_mac, dst=gateway_mac_legit)
        / IP(src=host_a_ip, dst="93.184.216.34", ttl=64)
        / TCP(sport=51000, dport=443, flags="PA")
    )

    # --- Normal UDP traffic (DNS lookup) ---
    packets.append(
        Ether(src=host_b_mac, dst=gateway_mac_legit)
        / IP(src=host_b_ip, dst="8.8.8.8", ttl=64)
        / UDP(sport=53412, dport=53)
    )

    # --- Normal ICMP traffic (ping) ---
    packets.append(
        Ether(src=host_a_mac, dst=gateway_mac_legit)
        / IP(src=host_a_ip, dst=gateway_ip, ttl=64)
        / ICMP(type=8, code=0)
    )
    packets.append(
        Ether(src=gateway_mac_legit, dst=host_a_mac)
        / IP(src=gateway_ip, dst=host_a_ip, ttl=64)
        / ICMP(type=0, code=0)
    )

    # --- Malicious/forged ARP reply: attacker claims to BE the gateway ---
    # This is the injected ARP spoofing indicator the detector should catch:
    # the gateway_ip is now associated with a second, different MAC address.
    packets.append(
        Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac, pdst=host_a_ip)
    )
    packets.append(
        Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, psrc=gateway_ip, hwsrc=attacker_mac, pdst=host_b_ip)
    )

    # --- More normal traffic after the spoofed packets, for realism ---
    packets.append(
        Ether(src=host_b_mac, dst=gateway_mac_legit)
        / IP(src=host_b_ip, dst="93.184.216.34", ttl=64)
        / TCP(sport=51001, dport=80, flags="S")
    )

    return packets


def main() -> None:
    """Generate sample.pcap in the sample_data directory."""
    output_path = Path(__file__).parent / "sample.pcap"
    packets = build_sample_packets()
    wrpcap(str(output_path), packets)
    print(f"Sample PCAP with {len(packets)} packets written to: {output_path}")


if __name__ == "__main__":
    main()

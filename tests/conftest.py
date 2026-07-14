"""
tests/conftest.py

Shared pytest fixtures. Generates a temporary sample PCAP file (via the
same builder used by sample_data/generate_sample_pcap.py) so tests do
not depend on a pre-existing file on disk.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from scapy.all import wrpcap

# Ensure the project root is importable when running `pytest` from the
# project root directory.
sys.path.insert(0, str(Path(__file__).parent.parent))

from sample_data.generate_sample_pcap import build_sample_packets  # noqa: E402


@pytest.fixture()
def sample_pcap_path(tmp_path: Path) -> Path:
    """
    Create a temporary sample PCAP file for use in tests.

    Args:
        tmp_path: Built-in pytest fixture providing a temporary directory.

    Returns:
        Path to the generated .pcap file.
    """
    pcap_path = tmp_path / "test_sample.pcap"
    packets = build_sample_packets()
    wrpcap(str(pcap_path), packets)
    return pcap_path

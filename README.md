# Advanced Packet Analyzer with ARP Spoofing Detection

A defensive, educational Python tool that analyzes **offline PCAP files**
and flags possible **ARP spoofing indicators**, generating professional
CSV, JSON, and interactive HTML security reports.

> **Scope note:** This project performs read-only analysis of PCAP files
> that were already captured by another authorized tool (e.g. tcpdump,
> Wireshark). It does **not** implement live packet sniffing, packet
> injection, MITM attacks, ARP poisoning, or credential capture. It is
> built strictly for education and authorized network analysis.

---

## Table of Contents

- [Project Features](#project-features)
- [Project Structure](#project-structure)
- [Installation Guide](#installation-guide)
- [Usage Guide](#usage-guide)
- [Sample Output](#sample-output)
- [Screenshots](#screenshots)
- [Running Tests](#running-tests)
- [How ARP Spoofing Detection Works](#how-arp-spoofing-detection-works)
- [Future Improvements](#future-improvements)
- [GitHub Project Description](#github-project-description)
- [Resume Project Description](#resume-project-description)
- [LinkedIn Project Description](#linkedin-project-description)
- [License](#license)

---

## Project Features

- **Offline PCAP analysis** using Scapy's `rdpcap` (no live capture)
- Protocol-aware parsing of **Ethernet, ARP, IPv4, TCP, UDP, and ICMP**
- Per-packet summaries and full packet-level export
- **Protocol distribution statistics** (counts by protocol)
- **IP-to-MAC mapping table** built from observed ARP traffic
- **ARP spoofing indicator detection** — flags any IP address seen with
  more than one MAC address during the capture (classic MAC-flapping /
  cache-poisoning signature)
- **Security Summary Dashboard** — interactive HTML report with a
  Plotly protocol-distribution chart and a table of suspicious events
- **CSV, JSON, and HTML report generation** via Pandas and Jinja2
- Centralized **logging** (console + rotating file handler), no `print()`
  used for application logging
- **Graceful error handling** for malformed/corrupt packets — a single
  bad packet never crashes the whole run
- Full **command-line interface** built with `argparse`
- **Pytest test suite** covering the parser, detector, and report layers
- Type-hinted, PEP 8-compliant, fully documented modular codebase

---

## Project Structure

```
advanced-packet-analyzer/
├── main.py                        # CLI entry point / pipeline orchestrator
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── parser/
│   ├── __init__.py
│   └── packet_parser.py           # PacketParser: reads PCAP, extracts fields
│
├── detector/
│   ├── __init__.py
│   └── arp_detector.py            # ARPSpoofDetector: IP-MAC table + event detection
│
├── reports/
│   ├── __init__.py
│   ├── report_generator.py        # ReportGenerator: CSV/JSON/HTML output
│   └── templates/
│       └── report_template.html   # Jinja2 dashboard template
│
├── utils/
│   ├── __init__.py
│   └── logger_config.py           # Centralized logging setup
│
├── logs/                          # analyzer.log written here at runtime
│
├── sample_data/
│   ├── generate_sample_pcap.py    # Builds a synthetic demo capture
│   └── sample.pcap                # Generated sample capture (includes 1 spoof event)
│
├── screenshots/                   # Dashboard / console screenshots for the README
│
└── tests/
    ├── __init__.py
    ├── conftest.py                # Shared pytest fixtures
    ├── test_parser.py
    ├── test_detector.py
    └── test_reports.py
```

---

## Installation Guide

**Requirements:** Python 3.12+

1. Clone or copy the project folder:
   ```bash
   git clone https://github.com/<your-username>/advanced-packet-analyzer.git
   cd advanced-packet-analyzer
   ```

2. (Recommended) create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate        # Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Generate the sample PCAP file (only needed if `sample_data/sample.pcap`
   is not already present):
   ```bash
   python sample_data/generate_sample_pcap.py
   ```

---

## Usage Guide

Run the analyzer against any offline `.pcap` / `.pcapng` file:

```bash
python main.py sample_data/sample.pcap
```

This produces:
- Console summary output (protocol counts + ARP findings)
- `logs/analyzer.log` — full run log
- `analysis_report.csv` — flat packet-level CSV
- `analysis_report.json` — structured JSON report
- `analysis_report.html` — interactive security dashboard

### Command-line options

```bash
python main.py <pcap_file> [--output-dir DIR] [--log-dir DIR] [--verbose]
```

| Argument        | Description                                              | Default   |
|-----------------|------------------------------------------------------------|-----------|
| `pcap_file`     | Path to the offline `.pcap` / `.pcapng` file to analyze    | required  |
| `--output-dir`  | Directory to write CSV/JSON/HTML reports into              | `.`       |
| `--log-dir`     | Directory to write `analyzer.log` into                     | `logs`    |
| `--verbose`     | Enable DEBUG-level logging                                 | off       |

### Example with custom output directory

```bash
python main.py sample_data/sample.pcap --output-dir reports_out --verbose
```

---

## Sample Output

```
============================================================
 ANALYSIS SUMMARY
============================================================
 Malformed/skipped packets : 0
 Protocol distribution:
   - ARP         : 6
   - TCP         : 3
   - ICMP        : 2
   - UDP         : 1

 ARP Spoofing Indicator Summary:
   - Unique IPs tracked        : 3
   - IPs with multiple MACs    : 1
   - Suspicious events flagged : 1

   Suspicious events:
     [!] Packet #9: 192.168.1.1 changed MAC aa:bb:cc:00:00:01 -> de:ad:be:ef:00:66
============================================================
```

---

## Screenshots


| Console Summary | HTML Security Dashboard |
|---|---|<img width="1918" height="1078" alt="console_summary png" src="https://github.com/user-attachments/assets/8547c542-9765-4461-9980-9b4a85f82567" />
` | ` |<img width="1918" height="1078" alt="html_dashboard png" src="https://github.com/user-attachments/assets/85c6bcb4-19ce-4e5b-8f54-74c1954c8d51" />


---

## Running Tests

The project includes a Pytest suite covering the parser, detector, and
report generator:

```bash
pytest -v
```

Tests generate their own temporary sample PCAP via a shared fixture in
`tests/conftest.py`, so they do not depend on any file already existing
on disk.

---

## How ARP Spoofing Detection Works

ARP has no built-in authentication: any host on a local network segment
can send an ARP reply claiming to own any IP address. ARP spoofing
(a.k.a. ARP cache poisoning) exploits this by sending forged ARP replies
that associate the attacker's MAC address with a legitimate IP address
(commonly the default gateway), allowing traffic interception.

This tool's `ARPSpoofDetector`:

1. Walks every ARP packet in chronological order.
2. Builds an **IP → MAC** table from each `(sender_ip, sender_mac)` pair.
3. If an IP address is later observed with a **different** MAC address
   than previously recorded, it raises a suspicious `ARPEvent`.
4. Aggregates results into a summary: how many IPs "flapped" between
   multiple MACs, and how many total suspicious events occurred.

This is a well-established, lightweight heuristic for surfacing
possible ARP spoofing activity in a capture, and is the same underlying
signal used by many production ARP-monitoring tools (though real-world
deployments often add allow-lists for legitimate DHCP/failover MAC
changes to reduce false positives).

---



## License

This project is licensed under the [MIT License](LICENSE), with an
added educational-use disclaimer — see the LICENSE file for details.

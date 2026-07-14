"""
Reports package.

Contains the ReportGenerator class, which turns analysis results
(parsed packets, protocol counts, ARP events) into CSV, JSON, and HTML
reports, including an interactive Plotly-powered security dashboard.
"""

from .report_generator import ReportGenerator

__all__ = ["ReportGenerator"]

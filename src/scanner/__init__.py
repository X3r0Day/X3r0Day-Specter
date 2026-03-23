"""
scanner package - port scanning and service detection
"""

from .port_scan import run_cli as run_port_scan

__all__ = ["run_port_scan"]

"""
CCTV ML - Automated Vulnerability Assessment and Penetration Testing tool for CCTV cameras & DVRs

This package provides specialized AI-powered security testing for CCTV systems,
replacing manual audits with continuous automated monitoring.

Main Features:
- AI-powered vulnerability prediction and exploitation
- Automated CCTV device discovery and fingerprinting
- Zero-day vulnerability detection
- Cloud dashboard for global vulnerability visualization
- Comprehensive penetration testing suite
"""

__version__ = "1.0.0"
__author__ = "CCTV ML Security Team"
__email__ = "security@cctvml.com"

from .core.engine import VulnerabilityAssessmentEngine
from .scanner.device_scanner import CCTVScanner
from .ai.predictor import VulnerabilityPredictor
from .dashboard.app import create_dashboard_app

__all__ = [
    "VulnerabilityAssessmentEngine",
    "CCTVScanner", 
    "VulnerabilityPredictor",
    "create_dashboard_app",
]
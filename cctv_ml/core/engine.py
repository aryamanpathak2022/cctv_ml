"""
Core Vulnerability Assessment Engine for CCTV cameras and DVRs

This engine coordinates all scanning, analysis, and exploitation activities
using AI-powered vulnerability prediction and automated exploitation.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import json

from ..scanner.device_scanner import CCTVScanner
from ..ai.predictor import VulnerabilityPredictor
from ..exploits.exploit_engine import ExploitEngine
from ..utils.logger import setup_logger
from .database import VulnerabilityDatabase
from .config import Config


class VulnerabilityAssessmentEngine:
    """
    Main engine that orchestrates CCTV vulnerability assessment and penetration testing.
    
    Features:
    - Automated device discovery and fingerprinting
    - AI-powered vulnerability prediction including zero-day detection
    - Automated exploitation and validation
    - Continuous monitoring and threat intelligence integration
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the vulnerability assessment engine."""
        self.config = Config(config_path)
        self.logger = setup_logger("VulnAssessmentEngine", self.config.log_level)
        
        # Initialize core components
        self.scanner = CCTVScanner(self.config)
        self.ai_predictor = VulnerabilityPredictor(self.config)
        self.exploit_engine = ExploitEngine(self.config)
        self.db = VulnerabilityDatabase(self.config.database_path)
        
        # Assessment state
        self.current_scan_id = None
        self.discovered_devices = []
        self.vulnerabilities = []
        self.exploited_targets = []
        
    async def run_full_assessment(self, targets: List[str]) -> Dict[str, Any]:
        """
        Run complete vulnerability assessment on specified targets.
        
        Args:
            targets: List of IP ranges, hostnames, or CIDR blocks to scan
            
        Returns:
            Assessment results including discovered devices, vulnerabilities, and exploitation results
        """
        self.logger.info(f"Starting full vulnerability assessment on {len(targets)} targets")
        
        assessment_id = self._generate_assessment_id()
        start_time = datetime.utcnow()
        
        try:
            # Phase 1: Device Discovery and Fingerprinting
            self.logger.info("Phase 1: Device Discovery and Fingerprinting")
            discovered_devices = await self._discover_devices(targets)
            
            # Phase 2: Vulnerability Scanning
            self.logger.info("Phase 2: Vulnerability Scanning")
            vulnerabilities = await self._scan_vulnerabilities(discovered_devices)
            
            # Phase 3: AI-Powered Vulnerability Prediction
            self.logger.info("Phase 3: AI-Powered Vulnerability Prediction")
            predicted_vulns = await self._predict_vulnerabilities(discovered_devices, vulnerabilities)
            
            # Phase 4: Automated Exploitation
            self.logger.info("Phase 4: Automated Exploitation")
            exploitation_results = await self._exploit_vulnerabilities(vulnerabilities + predicted_vulns)
            
            # Phase 5: Generate Report
            self.logger.info("Phase 5: Generating Assessment Report")
            report = self._generate_report(
                assessment_id, discovered_devices, vulnerabilities, 
                predicted_vulns, exploitation_results, start_time
            )
            
            # Store results in database
            await self.db.store_assessment_results(report)
            
            self.logger.info(f"Assessment {assessment_id} completed successfully")
            return report
            
        except Exception as e:
            self.logger.error(f"Assessment {assessment_id} failed: {str(e)}")
            raise
    
    async def _discover_devices(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Discover CCTV devices and DVRs on the network."""
        discovered = []
        
        for target in targets:
            self.logger.info(f"Scanning target: {target}")
            devices = await self.scanner.scan_network(target)
            discovered.extend(devices)
            
        self.logger.info(f"Discovered {len(discovered)} CCTV devices")
        return discovered
    
    async def _scan_vulnerabilities(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan discovered devices for known vulnerabilities."""
        vulnerabilities = []
        
        for device in devices:
            self.logger.info(f"Scanning vulnerabilities for {device['ip']}:{device['port']}")
            device_vulns = await self.scanner.scan_device_vulnerabilities(device)
            vulnerabilities.extend(device_vulns)
            
        self.logger.info(f"Found {len(vulnerabilities)} known vulnerabilities")
        return vulnerabilities
    
    async def _predict_vulnerabilities(self, devices: List[Dict[str, Any]], 
                                     known_vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use AI to predict potential zero-day vulnerabilities."""
        predicted_vulns = []
        
        for device in devices:
            predictions = await self.ai_predictor.predict_vulnerabilities(device, known_vulns)
            predicted_vulns.extend(predictions)
            
        self.logger.info(f"AI predicted {len(predicted_vulns)} potential vulnerabilities")
        return predicted_vulns
    
    async def _exploit_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Attempt automated exploitation of discovered vulnerabilities."""
        exploitation_results = []
        
        for vuln in vulnerabilities:
            if vuln.get('exploitable', False):
                result = await self.exploit_engine.exploit_vulnerability(vuln)
                exploitation_results.append(result)
                
        self.logger.info(f"Successfully exploited {len(exploitation_results)} vulnerabilities")
        return exploitation_results
    
    def _generate_assessment_id(self) -> str:
        """Generate unique assessment ID."""
        return f"CCTV_ASSESS_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    
    def _generate_report(self, assessment_id: str, devices: List, vulns: List, 
                        predicted: List, exploited: List, start_time: datetime) -> Dict[str, Any]:
        """Generate comprehensive assessment report."""
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        return {
            'assessment_id': assessment_id,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': duration,
            'summary': {
                'devices_discovered': len(devices),
                'vulnerabilities_found': len(vulns),
                'vulnerabilities_predicted': len(predicted),
                'successful_exploits': len(exploited),
                'critical_vulns': len([v for v in vulns + predicted if v.get('severity') == 'critical']),
                'high_vulns': len([v for v in vulns + predicted if v.get('severity') == 'high'])
            },
            'discovered_devices': devices,
            'vulnerabilities': vulns,
            'predicted_vulnerabilities': predicted,
            'exploitation_results': exploited,
            'recommendations': self._generate_recommendations(vulns + predicted)
        }
    
    def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable security recommendations."""
        recommendations = [
            "Immediately patch all critical and high severity vulnerabilities",
            "Change default credentials on all discovered CCTV devices",
            "Implement network segmentation to isolate CCTV systems",
            "Enable encryption for video streams and management interfaces",
            "Regularly update firmware and security patches",
            "Implement strong authentication and access controls",
            "Monitor network traffic for suspicious activities",
            "Conduct regular security assessments"
        ]
        
        # Add specific recommendations based on found vulnerabilities
        vuln_types = set(v.get('type', 'unknown') for v in vulnerabilities)
        
        if 'authentication_bypass' in vuln_types:
            recommendations.append("Review and strengthen authentication mechanisms")
        if 'default_credentials' in vuln_types:
            recommendations.append("Audit and change all default passwords immediately")
        if 'buffer_overflow' in vuln_types:
            recommendations.append("Apply buffer overflow protection mechanisms")
        if 'remote_code_execution' in vuln_types:
            recommendations.append("Isolate affected devices and apply emergency patches")
            
        return recommendations

    async def continuous_monitoring(self, targets: List[str], interval_hours: int = 24):
        """Run continuous vulnerability monitoring."""
        self.logger.info(f"Starting continuous monitoring with {interval_hours}h intervals")
        
        while True:
            try:
                await self.run_full_assessment(targets)
                await asyncio.sleep(interval_hours * 3600)
            except Exception as e:
                self.logger.error(f"Continuous monitoring error: {str(e)}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry
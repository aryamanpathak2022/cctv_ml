"""
AI Models for Zero-Day Vulnerability Prediction and Threat Intelligence.
"""

import asyncio
import logging
import requests
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import hashlib
import re

from ..utils.logger import setup_logger


class ZeroDayPredictor:
    """
    Zero-day vulnerability prediction engine using AI and pattern analysis.
    
    This engine analyzes device characteristics, known vulnerability patterns,
    and behavioral indicators to predict potential zero-day vulnerabilities.
    """
    
    def __init__(self, config):
        """Initialize the zero-day predictor."""
        self.config = config
        self.logger = setup_logger("ZeroDayPredictor", config.log_level)
        
        # Zero-day prediction patterns
        self.vulnerability_patterns = self._load_vulnerability_patterns()
        
        # Historical data for pattern matching
        self.historical_patterns = []
        
    async def predict(self, device: Dict[str, Any], features: Dict[str, float]) -> List[Dict[str, Any]]:
        """
        Predict potential zero-day vulnerabilities for a device.
        
        Args:
            device: Device information
            features: Extracted device features
            
        Returns:
            List of predicted zero-day vulnerabilities
        """
        predictions = []
        
        try:
            # Pattern-based prediction
            pattern_predictions = await self._pattern_based_prediction(device, features)
            predictions.extend(pattern_predictions)
            
            # Behavioral analysis prediction
            behavioral_predictions = await self._behavioral_analysis(device, features)
            predictions.extend(behavioral_predictions)
            
            # Firmware analysis prediction
            firmware_predictions = await self._firmware_analysis(device)
            predictions.extend(firmware_predictions)
            
            # Protocol analysis prediction
            protocol_predictions = await self._protocol_analysis(device)
            predictions.extend(protocol_predictions)
            
            self.logger.info(f"Generated {len(predictions)} zero-day predictions for {device.get('ip')}")
            
        except Exception as e:
            self.logger.error(f"Zero-day prediction failed: {str(e)}")
        
        return predictions
    
    async def _pattern_based_prediction(self, device: Dict[str, Any], 
                                      features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Predict vulnerabilities based on known patterns."""
        predictions = []
        
        manufacturer = device.get('manufacturer', '').lower()
        device_type = device.get('device_type', '')
        
        # Check each vulnerability pattern
        for pattern in self.vulnerability_patterns:
            if self._device_matches_pattern(device, features, pattern):
                prediction = {
                    'id': f"zeroday_pattern_{pattern['id']}_{device['ip']}",
                    'type': pattern['vuln_type'],
                    'severity': pattern['severity'],
                    'title': f"Potential {pattern['vuln_type'].replace('_', ' ').title()}",
                    'description': pattern['description'],
                    'confidence_score': pattern['confidence'] * self._calculate_match_strength(device, pattern),
                    'exploitable': pattern.get('likely_exploitable', False),
                    'prediction_method': 'pattern_analysis',
                    'pattern_id': pattern['id'],
                    'remediation': pattern.get('remediation', 'Monitor for security updates')
                }
                
                predictions.append(prediction)
        
        return predictions
    
    def _device_matches_pattern(self, device: Dict[str, Any], 
                               features: Dict[str, float], pattern: Dict[str, Any]) -> bool:
        """Check if device matches a vulnerability pattern."""
        # Check manufacturer match
        if pattern.get('manufacturers'):
            device_manufacturer = device.get('manufacturer', '').lower()
            if device_manufacturer not in [m.lower() for m in pattern['manufacturers']]:
                return False
        
        # Check device type match
        if pattern.get('device_types'):
            device_type = device.get('device_type', '')
            if device_type not in pattern['device_types']:
                return False
        
        # Check feature thresholds
        if pattern.get('feature_thresholds'):
            for feature, threshold in pattern['feature_thresholds'].items():
                if features.get(feature, 0) < threshold:
                    return False
        
        # Check exclusion criteria
        if pattern.get('exclusions'):
            for exclusion in pattern['exclusions']:
                if self._check_exclusion(device, exclusion):
                    return False
        
        return True
    
    def _calculate_match_strength(self, device: Dict[str, Any], pattern: Dict[str, Any]) -> float:
        """Calculate how strongly a device matches a pattern (0.0 to 1.0)."""
        match_strength = 1.0
        
        # Reduce confidence for generic patterns
        if len(pattern.get('manufacturers', [])) > 5:
            match_strength *= 0.8
        
        # Increase confidence for specific model matches
        if pattern.get('models') and device.get('model') in pattern['models']:
            match_strength *= 1.2
        
        # Adjust based on firmware version specificity
        if pattern.get('firmware_patterns'):
            firmware = device.get('firmware_version', '')
            for fw_pattern in pattern['firmware_patterns']:
                if re.search(fw_pattern, firmware, re.IGNORECASE):
                    match_strength *= 1.1
                    break
        
        return min(1.0, match_strength)
    
    def _check_exclusion(self, device: Dict[str, Any], exclusion: Dict[str, Any]) -> bool:
        """Check if device matches an exclusion criteria."""
        if exclusion.get('manufacturer'):
            if device.get('manufacturer', '').lower() == exclusion['manufacturer'].lower():
                return True
        
        if exclusion.get('firmware_min_version'):
            # Would need version comparison logic here
            pass
        
        return False
    
    async def _behavioral_analysis(self, device: Dict[str, Any], 
                                 features: Dict[str, float]) -> List[Dict[str, Any]]:
        """Analyze device behavior for vulnerability indicators."""
        predictions = []
        
        # High complexity + weak auth = potential privilege escalation
        if (features.get('web_interface_complexity', 0) > 0.8 and 
            features.get('authentication_methods', 1) < 0.3):
            predictions.append({
                'id': f"zeroday_behavior_privesc_{device['ip']}",
                'type': 'privilege_escalation',
                'severity': 'high',
                'title': 'Potential Privilege Escalation via Complex Interface',
                'description': 'Complex web interface with weak authentication may allow privilege escalation',
                'confidence_score': 0.65,
                'exploitable': True,
                'prediction_method': 'behavioral_analysis',
                'remediation': 'Strengthen authentication and reduce interface complexity'
            })
        
        # High exposure + old firmware = potential RCE
        if (features.get('network_exposure_score', 0) > 0.7 and 
            features.get('firmware_age_days', 0) > 545):  # ~1.5 years
            predictions.append({
                'id': f"zeroday_behavior_rce_{device['ip']}",
                'type': 'remote_code_execution',
                'severity': 'critical',
                'title': 'Potential RCE via Outdated Network-Exposed Device',
                'description': 'Old firmware on network-exposed device increases RCE risk',
                'confidence_score': 0.7,
                'exploitable': True,
                'prediction_method': 'behavioral_analysis',
                'remediation': 'Update firmware immediately and restrict network access'
            })
        
        return predictions
    
    async def _firmware_analysis(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze firmware for potential vulnerabilities."""
        predictions = []
        
        firmware_version = device.get('firmware_version', '')
        if not firmware_version:
            return predictions
        
        # Check for known vulnerable firmware patterns
        vulnerable_patterns = [
            r'v[12]\.[0-4]\.\d+',  # Very old version patterns
            r'beta|alpha|rc',      # Pre-release versions
            r'debug|test|dev',     # Development versions
        ]
        
        for pattern in vulnerable_patterns:
            if re.search(pattern, firmware_version, re.IGNORECASE):
                predictions.append({
                    'id': f"zeroday_firmware_{hashlib.md5(firmware_version.encode()).hexdigest()[:8]}",
                    'type': 'firmware_vulnerability',
                    'severity': 'medium',
                    'title': 'Potential Firmware Vulnerability',
                    'description': f'Firmware version {firmware_version} may contain vulnerabilities',
                    'confidence_score': 0.6,
                    'exploitable': False,
                    'prediction_method': 'firmware_analysis',
                    'remediation': 'Update to latest stable firmware version'
                })
                break
        
        return predictions
    
    async def _protocol_analysis(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze network protocols for potential vulnerabilities."""
        predictions = []
        
        # RTSP protocol vulnerabilities
        if device.get('protocol') == 'RTSP' or 'rtsp' in str(device.get('fingerprint', {})).lower():
            predictions.append({
                'id': f"zeroday_protocol_rtsp_{device['ip']}",
                'type': 'protocol_vulnerability',
                'severity': 'medium',
                'title': 'Potential RTSP Protocol Vulnerability',
                'description': 'RTSP implementations often contain buffer overflow vulnerabilities',
                'confidence_score': 0.55,
                'exploitable': True,
                'prediction_method': 'protocol_analysis',
                'remediation': 'Restrict RTSP access and monitor for protocol updates'
            })
        
        # Unencrypted HTTP on cameras
        if device.get('protocol') == 'HTTP' and device.get('device_type') == 'ip_camera':
            predictions.append({
                'id': f"zeroday_protocol_http_{device['ip']}",
                'type': 'information_disclosure',
                'severity': 'medium',
                'title': 'Unencrypted Communication Vulnerability',
                'description': 'Unencrypted HTTP communication may expose sensitive data',
                'confidence_score': 0.8,
                'exploitable': True,
                'prediction_method': 'protocol_analysis',
                'remediation': 'Enable HTTPS encryption'
            })
        
        return predictions
    
    def _load_vulnerability_patterns(self) -> List[Dict[str, Any]]:
        """Load vulnerability prediction patterns."""
        return [
            {
                'id': 'hikvision_auth_bypass',
                'vuln_type': 'authentication_bypass',
                'severity': 'critical',
                'confidence': 0.8,
                'description': 'Hikvision devices historically prone to auth bypass vulnerabilities',
                'manufacturers': ['hikvision'],
                'device_types': ['ip_camera', 'dvr', 'nvr'],
                'feature_thresholds': {
                    'manufacturer_risk_score': 0.7,
                    'authentication_methods': 0.6
                },
                'likely_exploitable': True,
                'remediation': 'Enable strong authentication and monitor for firmware updates'
            },
            {
                'id': 'dahua_rce_pattern',
                'vuln_type': 'remote_code_execution',
                'severity': 'critical',
                'confidence': 0.75,
                'description': 'Dahua devices show patterns consistent with RCE vulnerabilities',
                'manufacturers': ['dahua'],
                'feature_thresholds': {
                    'manufacturer_risk_score': 0.6,
                    'network_exposure_score': 0.5
                },
                'likely_exploitable': True
            },
            {
                'id': 'foscam_default_creds',
                'vuln_type': 'default_credentials',
                'severity': 'high',
                'confidence': 0.9,
                'description': 'Foscam devices frequently ship with default credentials',
                'manufacturers': ['foscam'],
                'feature_thresholds': {
                    'default_credentials': 0.5
                },
                'likely_exploitable': True
            },
            {
                'id': 'generic_old_firmware',
                'vuln_type': 'firmware_vulnerability',
                'severity': 'medium',
                'confidence': 0.6,
                'description': 'Old firmware versions likely contain unpatched vulnerabilities',
                'feature_thresholds': {
                    'firmware_age_days': 730
                },
                'likely_exploitable': False
            },
            {
                'id': 'exposed_admin_interface',
                'vuln_type': 'unauthorized_access',
                'severity': 'high',
                'confidence': 0.7,
                'description': 'Internet-exposed admin interfaces increase attack surface',
                'feature_thresholds': {
                    'network_exposure_score': 0.8,
                    'web_interface_complexity': 0.6
                },
                'likely_exploitable': True
            }
        ]


class ThreatIntelligenceEngine:
    """
    Threat intelligence engine for correlating CCTV threats with global intelligence.
    """
    
    def __init__(self, config):
        """Initialize the threat intelligence engine."""
        self.config = config
        self.logger = setup_logger("ThreatIntel", config.log_level)
        
        # Threat intelligence sources
        self.intel_sources = self._configure_intel_sources()
        
        # Cache for threat data
        self.threat_data_cache = {}
        self.last_update = None
        
    async def correlate_threats(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Correlate device information with threat intelligence data.
        
        Args:
            device: Device information
            
        Returns:
            List of threat-correlated vulnerability predictions
        """
        predictions = []
        
        try:
            # Update threat intelligence if needed
            await self._update_threat_intelligence()
            
            # Correlate with IoC database
            ioc_predictions = await self._correlate_with_iocs(device)
            predictions.extend(ioc_predictions)
            
            # Correlate with threat campaigns
            campaign_predictions = await self._correlate_with_campaigns(device)
            predictions.extend(campaign_predictions)
            
            # Correlate with vulnerability feeds
            vuln_feed_predictions = await self._correlate_with_vuln_feeds(device)
            predictions.extend(vuln_feed_predictions)
            
            self.logger.info(f"Generated {len(predictions)} threat intelligence predictions")
            
        except Exception as e:
            self.logger.error(f"Threat intelligence correlation failed: {str(e)}")
        
        return predictions
    
    async def _update_threat_intelligence(self):
        """Update threat intelligence data from various sources."""
        if (self.last_update and 
            datetime.utcnow() - self.last_update < timedelta(hours=6)):
            return  # Data is fresh enough
        
        try:
            # Update from configured sources
            for source in self.intel_sources:
                await self._fetch_from_source(source)
            
            self.last_update = datetime.utcnow()
            self.logger.info("Threat intelligence updated successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to update threat intelligence: {str(e)}")
    
    async def _fetch_from_source(self, source: Dict[str, Any]):
        """Fetch threat data from a specific source."""
        # This would integrate with real threat intelligence APIs
        # For demo purposes, we'll simulate with static data
        pass
    
    async def _correlate_with_iocs(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate device with Indicators of Compromise (IoCs).""" 
        predictions = []
        
        # Check if device IP is in known IoC lists
        device_ip = device.get('ip')
        
        # Simulate IoC correlation (in production, this would query real IoC feeds)
        malicious_ips = ['192.168.1.100', '10.0.0.50']  # Example malicious IPs
        
        if device_ip in malicious_ips:
            predictions.append({
                'id': f"threat_intel_ioc_{device_ip}",
                'type': 'malicious_activity',
                'severity': 'critical',
                'title': 'Device IP Matches Known IoC',
                'description': f'Device IP {device_ip} appears in threat intelligence as malicious',
                'confidence_score': 0.95,
                'exploitable': True,
                'prediction_method': 'threat_intelligence',
                'remediation': 'Isolate device immediately and investigate'
            })
        
        return predictions
    
    async def _correlate_with_campaigns(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate device with known threat campaigns."""
        predictions = []
        
        manufacturer = device.get('manufacturer', '').lower()
        
        # Known threat campaigns targeting specific manufacturers
        campaigns = {
            'hikvision': {
                'name': 'Mirai-based Botnet Campaign',
                'description': 'Ongoing campaign targeting Hikvision cameras for botnet inclusion',
                'severity': 'high',
                'confidence': 0.7
            },
            'dahua': {
                'name': 'APT Campaign against Dahua DVRs',
                'description': 'Advanced threat actors targeting Dahua DVR systems',
                'severity': 'critical',
                'confidence': 0.8
            }
        }
        
        if manufacturer in campaigns:
            campaign = campaigns[manufacturer]
            predictions.append({
                'id': f"threat_campaign_{manufacturer}_{device['ip']}",
                'type': 'targeted_campaign',
                'severity': campaign['severity'],
                'title': f'Device Targeted by {campaign["name"]}',
                'description': campaign['description'],
                'confidence_score': campaign['confidence'],
                'exploitable': True,
                'prediction_method': 'threat_intelligence',
                'remediation': 'Apply security patches and monitor for suspicious activity'
            })
        
        return predictions
    
    async def _correlate_with_vuln_feeds(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Correlate with vulnerability feeds and advisories."""
        predictions = []
        
        # This would integrate with CVE feeds, vendor advisories, etc.
        # For now, we'll provide a basic implementation
        
        manufacturer = device.get('manufacturer', '').lower()
        model = device.get('model', '').lower()
        
        # Recent vulnerabilities by manufacturer (simulated)
        recent_vulns = {
            'hikvision': {
                'cve': 'CVE-2023-XXXX',
                'description': 'Recent authentication bypass discovered in Hikvision cameras',
                'severity': 'critical'
            },
            'dahua': {
                'cve': 'CVE-2023-YYYY',
                'description': 'Remote code execution vulnerability in Dahua DVR systems',
                'severity': 'critical'
            }
        }
        
        if manufacturer in recent_vulns:
            vuln = recent_vulns[manufacturer]
            predictions.append({
                'id': f"vuln_feed_{vuln['cve']}_{device['ip']}",
                'type': 'emerging_threat',
                'severity': vuln['severity'],
                'title': f'Device May Be Affected by {vuln["cve"]}',
                'description': vuln['description'],
                'confidence_score': 0.8,
                'exploitable': True,
                'prediction_method': 'vulnerability_feed',
                'cve_id': vuln['cve'],
                'remediation': 'Check vendor advisories and apply patches immediately'
            })
        
        return predictions
    
    def _configure_intel_sources(self) -> List[Dict[str, Any]]:
        """Configure threat intelligence sources."""
        sources = []
        
        # MISP (Malware Information Sharing Platform) integration
        if self.config.get('threat_intel.misp_url'):
            sources.append({
                'name': 'MISP',
                'type': 'misp',
                'url': self.config.get('threat_intel.misp_url'),
                'api_key': self.config.get('threat_intel.misp_api_key')
            })
        
        # OpenCTI integration
        if self.config.get('threat_intel.opencti_url'):
            sources.append({
                'name': 'OpenCTI',
                'type': 'opencti',
                'url': self.config.get('threat_intel.opencti_url'),
                'api_key': self.config.get('threat_intel.opencti_api_key')
            })
        
        # Commercial threat intelligence feeds
        if self.config.get('threat_intel.commercial_feeds'):
            for feed in self.config.get('threat_intel.commercial_feeds'):
                sources.append(feed)
        
        return sources
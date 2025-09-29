"""
Device Fingerprinting for CCTV ML - Identify CCTV devices and extract metadata.
"""

import re
import logging
from typing import Dict, Any, Optional, List
import base64
import hashlib
from urllib.parse import urlparse, urljoin

from ..utils.logger import setup_logger


class DeviceFingerprinter:
    """Device fingerprinting engine for CCTV cameras and DVRs."""
    
    def __init__(self, config):
        """Initialize the device fingerprinter."""
        self.config = config
        self.logger = setup_logger("DeviceFingerprinter", config.log_level)
        
        # Load fingerprinting signatures
        self.signatures = self._load_signatures()
    
    async def fingerprint_http_service(self, response, content: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """
        Fingerprint HTTP/HTTPS service to identify CCTV device.
        
        Args:
            response: HTTP response object
            content: Response content text
            headers: HTTP response headers
            
        Returns:
            Fingerprint information if CCTV device detected, None otherwise
        """
        fingerprint = {
            'is_cctv_device': False,
            'confidence': 0.0,
            'device_type': None,
            'manufacturer': None,
            'model': None,
            'firmware_version': None,
            'auth_required': True,
            'default_creds': False,
            'signatures_matched': [],
            'title': None,
            'login_page': None
        }
        
        # Check for CCTV signatures in content
        content_lower = content.lower()
        
        # Extract page title
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
        if title_match:
            fingerprint['title'] = title_match.group(1).strip()
        
        # Check each signature against the response
        for signature in self.signatures:
            if self._matches_signature(content, headers, signature):
                fingerprint['is_cctv_device'] = True
                fingerprint['confidence'] = max(fingerprint['confidence'], signature.get('confidence', 0.5))
                fingerprint['signatures_matched'].append(signature['name'])
                
                # Update device information
                if signature.get('manufacturer'):
                    fingerprint['manufacturer'] = signature['manufacturer']
                if signature.get('device_type'):
                    fingerprint['device_type'] = signature['device_type']
                if signature.get('model'):
                    fingerprint['model'] = signature['model']
                
                # Extract firmware version if pattern provided
                if signature.get('firmware_pattern'):
                    fw_match = re.search(signature['firmware_pattern'], content, re.IGNORECASE)
                    if fw_match:
                        fingerprint['firmware_version'] = fw_match.group(1)
        
        # Additional heuristic checks
        if not fingerprint['is_cctv_device']:
            fingerprint.update(self._heuristic_detection(content, headers))
        
        # Check for authentication requirements
        fingerprint['auth_required'] = self._check_auth_required(content, headers, response.status)
        
        # Check for default credentials hints
        fingerprint['default_creds'] = self._check_default_creds_hints(content)
        
        # Find login page
        fingerprint['login_page'] = self._find_login_page(content)
        
        return fingerprint if fingerprint['is_cctv_device'] else None
    
    def _matches_signature(self, content: str, headers: Dict[str, str], signature: Dict[str, Any]) -> bool:
        """Check if content matches a specific signature."""
        content_lower = content.lower()
        
        # Check content patterns
        if signature.get('content_patterns'):
            for pattern in signature['content_patterns']:
                if re.search(pattern, content_lower):
                    return True
        
        # Check header patterns
        if signature.get('header_patterns'):
            for header_name, pattern in signature['header_patterns'].items():
                header_value = headers.get(header_name, '').lower()
                if re.search(pattern, header_value):
                    return True
        
        # Check title patterns
        if signature.get('title_patterns'):
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
            if title_match:
                title = title_match.group(1).lower()
                for pattern in signature['title_patterns']:
                    if re.search(pattern, title):
                        return True
        
        # Check URL patterns (would need to be passed in)
        # For now, we'll skip URL pattern matching
        
        return False
    
    def _heuristic_detection(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Use heuristics to detect CCTV devices."""
        result = {
            'is_cctv_device': False,
            'confidence': 0.0,
            'device_type': 'unknown_cctv'
        }
        
        content_lower = content.lower()
        
        # Common CCTV keywords
        cctv_keywords = [
            'ip camera', 'network camera', 'surveillance', 'dvr', 'nvr',
            'video recorder', 'cctv', 'security camera', 'webcam',
            'live view', 'channel', 'ptz', 'motion detection',
            'record', 'playback', 'alarm', 'preset'
        ]
        
        keyword_matches = sum(1 for keyword in cctv_keywords if keyword in content_lower)
        
        if keyword_matches >= 2:
            result['is_cctv_device'] = True
            result['confidence'] = min(0.3 + (keyword_matches * 0.1), 0.9)
        
        # Check for common CCTV UI elements
        ui_elements = [
            'login', 'username', 'password', 'live', 'record',
            'setup', 'configuration', 'device info', 'network',
            'video', 'audio', 'motion', 'alarm'
        ]
        
        form_fields = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', content, re.IGNORECASE)
        ui_matches = sum(1 for field in form_fields if field.lower() in ui_elements)
        
        if ui_matches >= 3:
            result['is_cctv_device'] = True
            result['confidence'] = max(result['confidence'], 0.4)
        
        # Check server headers for CCTV indicators
        server_header = headers.get('Server', '').lower()
        if any(indicator in server_header for indicator in ['camera', 'dvr', 'nvr', 'cctv']):
            result['is_cctv_device'] = True
            result['confidence'] = max(result['confidence'], 0.6)
        
        return result
    
    def _check_auth_required(self, content: str, headers: Dict[str, str], status_code: int) -> bool:
        """Check if authentication is required."""
        # HTTP 401 Unauthorized
        if status_code == 401:
            return True
        
        # Look for login forms
        if re.search(r'<form[^>]*login', content, re.IGNORECASE):
            return True
        
        # Look for username/password fields
        if re.search(r'<input[^>]*(?:name=["\'](?:user|pass|login)|type=["\']password)', content, re.IGNORECASE):
            return True
        
        # Check for authentication challenges
        auth_header = headers.get('WWW-Authenticate', '')
        if auth_header:
            return True
        
        # Look for common auth-required keywords
        auth_keywords = ['login required', 'please login', 'authentication', 'unauthorized']
        content_lower = content.lower()
        
        if any(keyword in content_lower for keyword in auth_keywords):
            return True
        
        return False
    
    def _check_default_creds_hints(self, content: str) -> bool:
        """Check for hints that default credentials might work."""
        content_lower = content.lower()
        
        # Look for setup/initialization pages
        setup_indicators = [
            'initial setup', 'first time setup', 'quick setup',
            'default password', 'change password', 'admin/admin'
        ]
        
        return any(indicator in content_lower for indicator in setup_indicators)
    
    def _find_login_page(self, content: str) -> Optional[str]:
        """Find login page URL from content."""
        # Look for common login page references
        login_patterns = [
            r'action=["\']([^"\']*login[^"\']*)["\']',
            r'href=["\']([^"\']*login[^"\']*)["\']',
            r'location\.href\s*=\s*["\']([^"\']*login[^"\']*)["\']'
        ]
        
        for pattern in login_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _load_signatures(self) -> List[Dict[str, Any]]:
        """Load device fingerprinting signatures."""
        return [
            # Hikvision signatures
            {
                'name': 'Hikvision IP Camera',
                'manufacturer': 'hikvision',
                'device_type': 'ip_camera',
                'confidence': 0.9,
                'content_patterns': [
                    r'hikvision',
                    r'ds-\d+',
                    r'web components',
                    r'hikfinder'
                ],
                'title_patterns': [
                    r'web components',
                    r'ds-\d+',
                    r'hikvision'
                ],
                'header_patterns': {
                    'Server': r'hikvision'
                },
                'firmware_pattern': r'version[:\s]+v?(\d+\.\d+\.\d+)'
            },
            
            # Dahua signatures
            {
                'name': 'Dahua IP Camera/DVR',
                'manufacturer': 'dahua',
                'device_type': 'ip_camera',
                'confidence': 0.9,
                'content_patterns': [
                    r'dahua',
                    r'dh-\w+',
                    r'configmanager\.cgi',
                    r'webservice\.js'
                ],
                'title_patterns': [
                    r'web service',
                    r'dahua',
                    r'ipc-\w+'
                ],
                'firmware_pattern': r'version[:\s]+(\d+\.\d+\.\d+)'
            },
            
            # Axis signatures
            {
                'name': 'Axis Network Camera',
                'manufacturer': 'axis',
                'device_type': 'ip_camera',
                'confidence': 0.9,
                'content_patterns': [
                    r'axis communications',
                    r'axis camera',
                    r'vapix'
                ],
                'title_patterns': [
                    r'axis \d+',
                    r'axis camera'
                ],
                'header_patterns': {
                    'Server': r'axis'
                }
            },
            
            # Foscam signatures
            {
                'name': 'Foscam IP Camera',
                'manufacturer': 'foscam',
                'device_type': 'ip_camera',
                'confidence': 0.8,
                'content_patterns': [
                    r'foscam',
                    r'fi\d+\w*',
                    r'camera\.js'
                ],
                'title_patterns': [
                    r'foscam',
                    r'fi\d+\w*'
                ]
            },
            
            # TP-Link/Tapo signatures
            {
                'name': 'TP-Link Tapo Camera',
                'manufacturer': 'tp-link',
                'device_type': 'ip_camera',
                'confidence': 0.8,
                'content_patterns': [
                    r'tp-link',
                    r'tapo',
                    r'tplinkcloud'
                ],
                'title_patterns': [
                    r'tapo',
                    r'tp-link'
                ]
            },
            
            # Ubiquiti UniFi signatures
            {
                'name': 'Ubiquiti UniFi Camera',
                'manufacturer': 'ubiquiti',
                'device_type': 'ip_camera',
                'confidence': 0.8,
                'content_patterns': [
                    r'ubiquiti',
                    r'unifi',
                    r'uvc-\w+'
                ],
                'title_patterns': [
                    r'unifi',
                    r'ubiquiti'
                ]
            },
            
            # Generic DVR signatures
            {
                'name': 'Generic DVR System',
                'device_type': 'dvr',
                'confidence': 0.6,
                'content_patterns': [
                    r'digital video recorder',
                    r'dvr system',
                    r'channel \d+',
                    r'video recorder'
                ],
                'title_patterns': [
                    r'dvr',
                    r'video recorder',
                    r'surveillance system'
                ]
            },
            
            # Generic NVR signatures
            {
                'name': 'Generic NVR System',
                'device_type': 'nvr',
                'confidence': 0.6,
                'content_patterns': [
                    r'network video recorder',
                    r'nvr system',
                    r'ip camera recorder'
                ],
                'title_patterns': [
                    r'nvr',
                    r'network video'
                ]
            },
            
            # Generic IP Camera signatures
            {
                'name': 'Generic IP Camera',
                'device_type': 'ip_camera',
                'confidence': 0.5,
                'content_patterns': [
                    r'ip camera',
                    r'network camera',
                    r'live view',
                    r'ptz control',
                    r'motion detection'
                ],
                'title_patterns': [
                    r'ip camera',
                    r'network camera',
                    r'webcam'
                ]
            }
        ]
    
    def calculate_fingerprint_hash(self, fingerprint: Dict[str, Any]) -> str:
        """Calculate a hash of the fingerprint for deduplication."""
        # Create a string representation of key fingerprint elements
        key_elements = [
            fingerprint.get('manufacturer', ''),
            fingerprint.get('model', ''),
            fingerprint.get('device_type', ''),
            fingerprint.get('firmware_version', ''),
            str(fingerprint.get('signatures_matched', []))
        ]
        
        fingerprint_string = '|'.join(key_elements)
        return hashlib.md5(fingerprint_string.encode()).hexdigest()
    
    def extract_device_info_from_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Extract additional device information from HTTP headers."""
        info = {}
        
        # Server header analysis
        server = headers.get('Server', '')
        if server:
            info['server'] = server
            
            # Extract version information
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', server)
            if version_match:
                info['server_version'] = version_match.group(1)
        
        # PoweredBy header
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            info['powered_by'] = powered_by
        
        # Custom headers that might indicate CCTV devices
        custom_headers = [
            'X-CCTV-Device', 'X-Camera-Model', 'X-DVR-Version',
            'X-Surveillance-System', 'X-Security-Device'
        ]
        
        for header in custom_headers:
            value = headers.get(header)
            if value:
                info[header.lower().replace('-', '_')] = value
        
        return info
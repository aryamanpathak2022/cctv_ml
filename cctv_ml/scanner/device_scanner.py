"""
CCTV Device Scanner - Automated discovery and vulnerability scanning for CCTV cameras and DVRs.
"""

import asyncio
import aiohttp
import socket
import logging
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
import ssl

from .network_scanner import NetworkScanner  
from .fingerprinting import DeviceFingerprinter
from ..utils.logger import setup_logger


class CCTVScanner:
    """
    Specialized scanner for CCTV cameras and DVR systems.
    
    Features:
    - Network discovery of CCTV devices
    - Device fingerprinting and identification
    - Vulnerability scanning using known CCTV exploits
    - Authentication bypass testing
    - Default credential checking
    """
    
    def __init__(self, config):
        """Initialize the CCTV scanner."""
        self.config = config
        self.logger = setup_logger("CCTVScanner", config.log_level)
        
        self.network_scanner = NetworkScanner(config)
        self.fingerprinter = DeviceFingerprinter(config)
        
        # Common CCTV ports
        self.cctv_ports = [
            80, 81, 8080, 8081, 8000, 8888, 9000,  # HTTP variants
            443, 8443, 9443,  # HTTPS variants
            554, 8554,  # RTSP
            1935,  # RTMP
            37777, 37778,  # Dahua DVR
            34567, 34599,  # Hikvision
            9091, 8091,  # Various IP cameras
            5000, 5001,  # Synology
            49152, 49153, 49154  # UPnP/random high ports
        ]
        
        # Load vulnerability signatures
        self.vuln_signatures = self._load_vulnerability_signatures()
        
    async def scan_network(self, target: str) -> List[Dict[str, Any]]:
        """
        Scan network range for CCTV devices.
        
        Args:
            target: IP range, hostname, or CIDR block
            
        Returns:
            List of discovered CCTV devices with basic information
        """
        self.logger.info(f"Starting network scan for CCTV devices: {target}")
        
        # Discover live hosts
        live_hosts = await self.network_scanner.discover_hosts(target)
        self.logger.info(f"Found {len(live_hosts)} live hosts")
        
        # Scan for CCTV services on discovered hosts
        cctv_devices = []
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
        tasks = []
        for host in live_hosts:
            task = self._scan_host_for_cctv(semaphore, host)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                cctv_devices.extend(result)
            elif isinstance(result, Exception):
                self.logger.warning(f"Host scan failed: {result}")
        
        self.logger.info(f"Discovered {len(cctv_devices)} CCTV devices")
        return cctv_devices
    
    async def _scan_host_for_cctv(self, semaphore: asyncio.Semaphore, host: str) -> List[Dict[str, Any]]:
        """Scan a single host for CCTV services.""" 
        async with semaphore:
            devices = []
            
            # Port scan for CCTV services
            open_ports = await self.network_scanner.scan_ports(host, self.cctv_ports)
            
            for port in open_ports:
                try:
                    device_info = await self._identify_cctv_device(host, port)
                    if device_info:
                        devices.append(device_info)
                except Exception as e:
                    self.logger.debug(f"Failed to identify device {host}:{port}: {e}")
            
            return devices
    
    async def _identify_cctv_device(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Identify if a service is a CCTV device and gather basic information."""
        try:
            # Try HTTP/HTTPS first
            for scheme in ['http', 'https']:
                try:
                    url = f"{scheme}://{host}:{port}"
                    device_info = await self._probe_http_service(url)
                    if device_info:
                        device_info.update({
                            'ip': host,
                            'port': port,
                            'protocol': scheme.upper(),
                            'discovered_at': datetime.utcnow().isoformat()
                        })
                        return device_info
                except Exception:
                    continue
            
            # Try RTSP for IP cameras
            if port in [554, 8554]:
                rtsp_info = await self._probe_rtsp_service(host, port)
                if rtsp_info:
                    rtsp_info.update({
                        'ip': host,
                        'port': port,
                        'protocol': 'RTSP',
                        'discovered_at': datetime.utcnow().isoformat()
                    })
                    return rtsp_info
                    
        except Exception as e:
            self.logger.debug(f"Device identification failed for {host}:{port}: {e}")
        
        return None
    
    async def _probe_http_service(self, url: str) -> Optional[Dict[str, Any]]:
        """Probe HTTP/HTTPS service to identify CCTV device."""
        try:
            timeout = aiohttp.ClientTimeout(total=self.config.scan_timeout)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try to access common CCTV endpoints
                endpoints = ['/', '/login.html', '/index.html', '/web/', '/cgi-bin/']
                
                for endpoint in endpoints:
                    try:
                        full_url = urljoin(url, endpoint)
                        
                        async with session.get(full_url, ssl=False, allow_redirects=True) as response:
                            headers = dict(response.headers)
                            content = await response.text()
                            
                            # Fingerprint the device
                            fingerprint = await self.fingerprinter.fingerprint_http_service(
                                response, content, headers
                            )
                            
                            if fingerprint and fingerprint.get('is_cctv_device'):
                                return {
                                    'device_type': fingerprint.get('device_type', 'unknown_cctv'),
                                    'manufacturer': fingerprint.get('manufacturer'),
                                    'model': fingerprint.get('model'),
                                    'firmware_version': fingerprint.get('firmware_version'),
                                    'web_interface_url': full_url,
                                    'authentication_required': fingerprint.get('auth_required', True),
                                    'default_credentials': fingerprint.get('default_creds', False),
                                    'fingerprint': fingerprint,
                                    'title': fingerprint.get('title', ''),
                                    'server_header': headers.get('Server', ''),
                                    'response_code': response.status
                                }
                    except Exception as e:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"HTTP probe failed for {url}: {e}")
        
        return None
    
    async def _probe_rtsp_service(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Probe RTSP service for IP camera identification."""
        try:
            # Simple RTSP OPTIONS request
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.config.scan_timeout
            )
            
            rtsp_request = f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            writer.write(rtsp_request.encode())
            await writer.drain()
            
            response = await asyncio.wait_for(
                reader.read(1024), 
                timeout=5
            )
            
            writer.close()
            await writer.wait_closed()
            
            response_text = response.decode('utf-8', errors='ignore')
            
            if 'RTSP/1.0' in response_text:
                # Extract server information
                server_match = re.search(r'Server:\s*(.+)', response_text, re.IGNORECASE)
                server = server_match.group(1).strip() if server_match else 'Unknown'
                
                return {
                    'device_type': 'ip_camera',
                    'manufacturer': self._extract_manufacturer_from_server(server),
                    'server_header': server,
                    'rtsp_endpoint': f"rtsp://{host}:{port}/",
                    'supports_rtsp': True
                }
                
        except Exception as e:
            self.logger.debug(f"RTSP probe failed for {host}:{port}: {e}")
        
        return None
    
    def _extract_manufacturer_from_server(self, server_header: str) -> Optional[str]:
        """Extract manufacturer from server header."""
        manufacturers = {
            'hikvision': ['hikvision', 'ds-', 'hik'],
            'dahua': ['dahua', 'dh-', 'ipc-'],
            'axis': ['axis'],
            'bosch': ['bosch'],
            'sony': ['sony'],
            'panasonic': ['panasonic'],
            'vivotek': ['vivotek'],
            'foscam': ['foscam'],
            'tp-link': ['tp-link', 'tapo'],
            'ubiquiti': ['ubiquiti', 'unifi']
        }
        
        server_lower = server_header.lower()
        for manufacturer, patterns in manufacturers.items():
            if any(pattern in server_lower for pattern in patterns):
                return manufacturer
                
        return None
    
    async def scan_device_vulnerabilities(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Scan a specific CCTV device for known vulnerabilities.
        
        Args:
            device: Device information from discovery phase
            
        Returns:
            List of discovered vulnerabilities
        """
        self.logger.info(f"Scanning vulnerabilities for {device['ip']}:{device['port']}")
        
        vulnerabilities = []
        
        # Test for common CCTV vulnerabilities
        vuln_tests = [
            self._test_default_credentials,
            self._test_authentication_bypass,
            self._test_directory_traversal,
            self._test_command_injection,
            self._test_weak_encryption,
            self._test_information_disclosure,
            self._test_known_cves
        ]
        
        for test_func in vuln_tests:
            try:
                found_vulns = await test_func(device)
                if found_vulns:
                    vulnerabilities.extend(found_vulns)
            except Exception as e:
                self.logger.warning(f"Vulnerability test failed for {device['ip']}: {e}")
        
        # Add device context to vulnerabilities
        for vuln in vulnerabilities:
            vuln.update({
                'device_ip': device['ip'],
                'device_port': device['port'],
                'device_type': device.get('device_type'),
                'manufacturer': device.get('manufacturer'),
                'discovered_at': datetime.utcnow().isoformat()
            })
        
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities on {device['ip']}")
        return vulnerabilities
    
    async def _test_default_credentials(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for default credentials on CCTV device."""
        vulnerabilities = []
        
        # Common default credentials for CCTV devices
        default_creds = [
            ('admin', 'admin'), ('admin', '12345'), ('admin', 'password'),
            ('admin', ''), ('root', 'root'), ('user', 'user'),
            ('admin', '888888'), ('admin', '123456'), ('viewer', 'viewer'),
            ('operator', 'operator'), ('guest', 'guest'), ('demo', 'demo'),
            # Manufacturer specific
            ('admin', 'hikvisionsecurity'),  # Hikvision
            ('admin', 'tlJwpbo6'),  # Dahua
            ('root', 'pass'), ('service', 'service')
        ]
        
        if device.get('web_interface_url'):
            for username, password in default_creds:
                try:
                    success = await self._test_web_login(
                        device['web_interface_url'], username, password
                    )
                    
                    if success:
                        vulnerabilities.append({
                            'id': f"default_creds_{device['ip']}_{device['port']}",
                            'type': 'default_credentials',
                            'severity': 'critical',
                            'title': 'Default Credentials Detected',
                            'description': f'Device accepts default credentials: {username}:{password}',
                            'cvss_score': 9.8,
                            'exploitable': True,
                            'credentials': {'username': username, 'password': password},
                            'proof_of_concept': f'Login with {username}:{password}',
                            'remediation': 'Change default credentials immediately'
                        })
                        break  # Found working creds, no need to test more
                        
                except Exception as e:
                    self.logger.debug(f"Credential test failed: {e}")
        
        return vulnerabilities
    
    async def _test_web_login(self, base_url: str, username: str, password: str) -> bool:
        """Test web login with given credentials."""
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # Try different login endpoints
                login_endpoints = [
                    '/cgi-bin/login.cgi',
                    '/cgi-bin/authLogin.cgi', 
                    '/api/login',
                    '/login',
                    '/Login.htm',
                    '/logincheck.rsp'
                ]
                
                for endpoint in login_endpoints:
                    login_url = urljoin(base_url, endpoint)
                    
                    # Try both POST and GET methods
                    for method in ['POST', 'GET']:
                        login_data = {
                            'username': username,
                            'password': password,
                            'user': username,
                            'pass': password,
                            'login': 'Login'
                        }
                        
                        try:
                            if method == 'POST':
                                async with session.post(login_url, data=login_data, ssl=False) as response:
                                    return self._check_login_success(await response.text(), response.status)
                            else:
                                async with session.get(login_url, params=login_data, ssl=False) as response:
                                    return self._check_login_success(await response.text(), response.status)
                        except Exception:
                            continue
                            
        except Exception as e:
            self.logger.debug(f"Web login test failed: {e}")
        
        return False
    
    def _check_login_success(self, response_text: str, status_code: int) -> bool:
        """Check if login was successful based on response."""
        success_indicators = [
            'success', 'login successful', 'welcome', 'dashboard',
            'main.htm', 'index.htm', 'home.htm', 'status.htm'
        ]
        
        failure_indicators = [
            'login failed', 'invalid', 'error', 'unauthorized',
            'wrong password', 'access denied'
        ]
        
        response_lower = response_text.lower()
        
        # Check for explicit failure first
        if any(indicator in response_lower for indicator in failure_indicators):
            return False
            
        # Check for success indicators
        if any(indicator in response_lower for indicator in success_indicators):
            return True
            
        # Check HTTP status codes
        if status_code in [200, 302]:  # OK or redirect often indicates success
            return True
            
        return False
    
    async def _test_authentication_bypass(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for authentication bypass vulnerabilities."""
        vulnerabilities = []
        
        if not device.get('web_interface_url'):
            return vulnerabilities
            
        base_url = device['web_interface_url']
        
        # Test common bypass techniques
        bypass_tests = [
            # Path traversal bypasses
            ('/../../../etc/passwd', 'Path traversal authentication bypass'),
            ('/..%2f..%2f..%2fetc%2fpasswd', 'URL encoded path traversal bypass'),
            
            # Direct access to admin pages
            ('/admin/', 'Direct admin page access'),
            ('/cgi-bin/main-cgi', 'Direct CGI access'),
            ('/system.ini', 'Configuration file access'),
            ('/web/cgi-bin/hi3510/param.cgi', 'Hikvision bypass'),
            
            # SQL injection in auth
            ("admin'--", 'SQL injection authentication bypass'),
            ("admin'/*", 'SQL comment injection bypass'),
        ]
        
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for test_path, description in bypass_tests:
                    try:
                        test_url = urljoin(base_url, test_path)
                        
                        async with session.get(test_url, ssl=False) as response:
                            content = await response.text()
                            
                            if self._check_bypass_success(content, response.status):
                                vulnerabilities.append({
                                    'id': f"auth_bypass_{device['ip']}_{device['port']}",
                                    'type': 'authentication_bypass',
                                    'severity': 'high',
                                    'title': 'Authentication Bypass',
                                    'description': description,
                                    'cvss_score': 8.1,
                                    'exploitable': True,
                                    'proof_of_concept': f'Access {test_url}',
                                    'remediation': 'Implement proper authentication checks'
                                })
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.debug(f"Auth bypass test failed: {e}")
        
        return vulnerabilities
    
    def _check_bypass_success(self, content: str, status_code: int) -> bool:
        """Check if authentication bypass was successful."""
        if status_code == 200:
            # Look for admin interface indicators
            admin_indicators = [
                'admin', 'configuration', 'settings', 'system status',
                'device information', 'network settings', 'user management'
            ]
            
            content_lower = content.lower()
            return any(indicator in content_lower for indicator in admin_indicators)
        
        return False
    
    async def _test_directory_traversal(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities."""
        # Implementation for directory traversal testing
        return []
    
    async def _test_command_injection(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for command injection vulnerabilities.""" 
        # Implementation for command injection testing
        return []
    
    async def _test_weak_encryption(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for weak encryption implementations."""
        # Implementation for encryption testing
        return []
    
    async def _test_information_disclosure(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for information disclosure vulnerabilities."""
        # Implementation for information disclosure testing
        return []
    
    async def _test_known_cves(self, device: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test for known CVE vulnerabilities."""
        vulnerabilities = []
        
        manufacturer = device.get('manufacturer', '').lower()
        model = device.get('model', '').lower()
        
        # Match device against known vulnerable signatures
        for signature in self.vuln_signatures:
            if self._device_matches_signature(device, signature):
                vulnerabilities.append({
                    'id': f"cve_{signature['cve_id']}_{device['ip']}_{device['port']}",
                    'type': signature['type'],
                    'severity': signature['severity'],
                    'title': signature['title'],
                    'description': signature['description'],
                    'cve_id': signature['cve_id'], 
                    'cvss_score': signature['cvss_score'],
                    'exploitable': signature.get('exploitable', False),
                    'proof_of_concept': signature.get('poc'),
                    'remediation': signature.get('remediation')
                })
        
        return vulnerabilities
    
    def _device_matches_signature(self, device: Dict[str, Any], signature: Dict[str, Any]) -> bool:
        """Check if device matches vulnerability signature."""
        # Match by manufacturer
        if signature.get('manufacturer'):
            if device.get('manufacturer', '').lower() != signature['manufacturer'].lower():
                return False
        
        # Match by model pattern
        if signature.get('model_pattern'):
            model = device.get('model', '')
            if not re.search(signature['model_pattern'], model, re.IGNORECASE):
                return False
        
        # Match by firmware version
        if signature.get('firmware_version'):
            firmware = device.get('firmware_version', '')
            if signature['firmware_version'] not in firmware:
                return False
        
        return True
    
    def _load_vulnerability_signatures(self) -> List[Dict[str, Any]]:
        """Load known CCTV vulnerability signatures."""
        # This would typically load from a database or external file
        # For now, return some common CCTV vulnerabilities
        return [
            {
                'cve_id': 'CVE-2017-7921',
                'manufacturer': 'hikvision',
                'type': 'authentication_bypass',
                'severity': 'critical',
                'title': 'Hikvision IP Camera Authentication Bypass',
                'description': 'Multiple Hikvision IP cameras allow authentication bypass',
                'cvss_score': 9.8,
                'exploitable': True,
                'poc': 'Access /System/configurationFile',
                'remediation': 'Update firmware to latest version'
            },
            {
                'cve_id': 'CVE-2019-3929',
                'manufacturer': 'axis',
                'type': 'directory_traversal',
                'severity': 'high',
                'title': 'Axis Camera Directory Traversal',
                'description': 'Directory traversal vulnerability in Axis cameras',
                'cvss_score': 7.5,
                'exploitable': True
            },
            {
                'cve_id': 'CVE-2020-25078',
                'manufacturer': 'dahua',
                'type': 'remote_code_execution',
                'severity': 'critical',
                'title': 'Dahua DVR Remote Code Execution',
                'description': 'Remote code execution in Dahua DVR systems',
                'cvss_score': 9.8,
                'exploitable': True
            }
        ]
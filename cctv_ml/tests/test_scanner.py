"""
Tests for CCTV device scanner functionality.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from cctv_ml.scanner.device_scanner import CCTVScanner
from cctv_ml.scanner.fingerprinting import DeviceFingerprinter
from cctv_ml.scanner.network_scanner import NetworkScanner


class TestNetworkScanner:
    """Test network scanning functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        config = Mock()
        config.max_concurrent_scans = 10
        config.scan_timeout = 30
        config.log_level = 'INFO'
        return config
    
    def test_target_parsing(self, mock_config):
        """Test target specification parsing."""
        scanner = NetworkScanner(mock_config)
        
        # Test CIDR parsing
        ips = scanner._parse_target('192.168.1.0/30')
        assert '192.168.1.1' in ips
        assert '192.168.1.2' in ips
        
        # Test single IP
        ips = scanner._parse_target('192.168.1.100')
        assert ips == ['192.168.1.100']
        
        # Test IP range
        ips = scanner._parse_target('192.168.1.1-3')
        expected = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        assert ips == expected
    
    def test_os_detection(self, mock_config):
        """Test OS detection from TTL values."""
        scanner = NetworkScanner(mock_config)
        
        assert 'Linux' in scanner._guess_os_from_ttl(64)
        assert 'Windows' in scanner._guess_os_from_ttl(128)
        assert 'Network Device' in scanner._guess_os_from_ttl(255)


class TestDeviceFingerprinter:
    """Test device fingerprinting functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        config = Mock()
        config.log_level = 'INFO'
        return config
    
    @pytest.fixture
    def fingerprinter(self, mock_config):
        """Create fingerprinter instance."""
        return DeviceFingerprinter(mock_config)
    
    @pytest.mark.asyncio
    async def test_hikvision_detection(self, fingerprinter):
        """Test Hikvision device detection."""
        mock_response = Mock()
        mock_response.status = 200
        
        content = "<title>Web Components</title><h1>Hikvision DS-2CD2142FWD-I</h1>"
        headers = {'Server': 'Hikvision-Webs'}
        
        fingerprint = await fingerprinter.fingerprint_http_service(
            mock_response, content, headers
        )
        
        assert fingerprint is not None
        assert fingerprint['is_cctv_device'] is True
        assert fingerprint['manufacturer'] == 'hikvision'
        assert fingerprint['device_type'] == 'ip_camera'
    
    @pytest.mark.asyncio
    async def test_dahua_detection(self, fingerprinter):
        """Test Dahua device detection."""
        mock_response = Mock()
        mock_response.status = 200
        
        content = "<title>Web Service</title>Dahua IPC-HFW1230S"
        headers = {'Server': 'DahuaWebServer'}
        
        fingerprint = await fingerprinter.fingerprint_http_service(
            mock_response, content, headers
        )
        
        assert fingerprint is not None
        assert fingerprint['is_cctv_device'] is True
        assert fingerprint['manufacturer'] == 'dahua'
    
    def test_manufacturer_extraction(self, fingerprinter):
        """Test manufacturer extraction from server headers."""
        assert fingerprinter._extract_manufacturer_from_server('Hikvision-Webs') == 'hikvision'
        assert fingerprinter._extract_manufacturer_from_server('DahuaWebServer') == 'dahua'
        assert fingerprinter._extract_manufacturer_from_server('Axis') == 'axis'
        assert fingerprinter._extract_manufacturer_from_server('Unknown-Server') is None
    
    def test_signature_matching(self, fingerprinter):
        """Test signature matching logic."""
        content = "hikvision ip camera web components"
        headers = {'Server': 'Hikvision-Webs'}
        
        signature = {
            'content_patterns': [r'hikvision', r'web components'],
            'header_patterns': {'Server': r'hikvision'}
        }
        
        assert fingerprinter._matches_signature(content, headers, signature) is True


class TestCCTVScanner:
    """Test CCTV device scanner."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        config = Mock()
        config.max_concurrent_scans = 10
        config.scan_timeout = 30
        config.log_level = 'INFO'
        config.safe_mode = True
        return config
    
    @pytest.fixture
    def scanner(self, mock_config):
        """Create scanner instance."""
        return CCTVScanner(mock_config)
    
    def test_cctv_ports(self, scanner):
        """Test CCTV port list."""
        assert 80 in scanner.cctv_ports
        assert 8080 in scanner.cctv_ports
        assert 554 in scanner.cctv_ports  # RTSP
        assert 37777 in scanner.cctv_ports  # Dahua
        assert 34567 in scanner.cctv_ports  # Hikvision
    
    @pytest.mark.asyncio
    async def test_device_identification(self, scanner):
        """Test device identification."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {'Server': 'Hikvision-Webs'}
            mock_response.text = AsyncMock(return_value="<title>Web Components</title>")
            
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            # Mock fingerprinter
            mock_fingerprint = {
                'is_cctv_device': True,
                'manufacturer': 'hikvision',
                'device_type': 'ip_camera'
            }
            
            with patch.object(scanner.fingerprinter, 'fingerprint_http_service', return_value=mock_fingerprint):
                device_info = await scanner._identify_cctv_device('192.168.1.100', 80)
                
                assert device_info is not None
                assert device_info['ip'] == '192.168.1.100'
                assert device_info['port'] == 80
                assert device_info['manufacturer'] == 'hikvision'
    
    def test_device_signature_matching(self, scanner):
        """Test device signature matching."""
        device = {
            'manufacturer': 'hikvision',
            'model': 'DS-2CD2142FWD-I',
            'firmware_version': 'V5.5.3'
        }
        
        signature = {
            'manufacturer': 'hikvision',
            'model_pattern': r'DS-2CD\d+',
            'firmware_version': 'V5.5'
        }
        
        assert scanner._device_matches_signature(device, signature) is True
    
    def test_login_success_detection(self, scanner):
        """Test login success detection."""
        success_content = "<html><body>Welcome to admin panel</body></html>"
        failure_content = "<html><body>Login failed</body></html>"
        
        assert scanner._check_login_success(success_content, 200) is True
        assert scanner._check_login_success(failure_content, 200) is False
    
    @pytest.mark.asyncio
    async def test_default_credentials_testing(self, scanner):
        """Test default credentials vulnerability testing."""
        device = {
            'ip': '192.168.1.100',
            'port': 80,
            'web_interface_url': 'http://192.168.1.100'
        }
        
        with patch.object(scanner, '_test_web_login', return_value=(True, 'success')):
            vulns = await scanner._test_default_credentials(device)
            
            assert len(vulns) > 0
            assert vulns[0]['type'] == 'default_credentials'
            assert vulns[0]['severity'] == 'critical'


if __name__ == '__main__':
    pytest.main([__file__])
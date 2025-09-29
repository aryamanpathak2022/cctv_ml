"""
Tests for core CCTV ML functionality.
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, patch

from cctv_ml.core.config import Config
from cctv_ml.core.database import VulnerabilityDatabase
from cctv_ml.core.engine import VulnerabilityAssessmentEngine


class TestConfig:
    """Test configuration management."""
    
    def test_default_config(self):
        """Test default configuration loading."""
        config = Config()
        
        assert config.log_level == 'INFO'
        assert config.max_concurrent_scans == 50
        assert config.scan_timeout == 30
        assert config.ai_prediction_threshold == 0.7
    
    def test_environment_override(self):
        """Test environment variable overrides."""
        with patch.dict(os.environ, {'CCTV_LOG_LEVEL': 'DEBUG', 'CCTV_MAX_SCANS': '100'}):
            config = Config()
            
            assert config.log_level == 'DEBUG'
            assert config.max_concurrent_scans == 100
    
    def test_custom_config_file(self):
        """Test custom configuration file loading."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("""
            logging:
              level: WARNING
            scanning:
              max_concurrent_scans: 75
            """)
            config_path = f.name
        
        try:
            config = Config(config_path)
            assert config.log_level == 'WARNING'
            assert config.max_concurrent_scans == 75
        finally:
            os.unlink(config_path)


class TestDatabase:
    """Test database functionality."""
    
    @pytest.fixture
    def temp_db(self):
        """Create temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        
        db = VulnerabilityDatabase(db_path)
        yield db
        
        # Cleanup
        try:
            os.unlink(db_path)
        except:
            pass
    
    @pytest.mark.asyncio
    async def test_database_initialization(self, temp_db):
        """Test database initialization."""
        # Database should be initialized without errors
        assert os.path.exists(temp_db.db_path)
    
    @pytest.mark.asyncio
    async def test_assessment_storage(self, temp_db):
        """Test storing assessment results."""
        mock_report = {
            'assessment_id': 'test_001',
            'start_time': '2024-01-15T10:00:00Z',
            'end_time': '2024-01-15T11:00:00Z',
            'duration_seconds': 3600,
            'summary': {
                'devices_discovered': 5,
                'vulnerabilities_found': 10,
                'vulnerabilities_predicted': 3,
                'successful_exploits': 2
            },
            'discovered_devices': [
                {
                    'ip': '192.168.1.100',
                    'port': 80,
                    'device_type': 'ip_camera',
                    'manufacturer': 'test_vendor'
                }
            ],
            'vulnerabilities': [
                {
                    'id': 'vuln_001',
                    'device_ip': '192.168.1.100',
                    'device_port': 80,
                    'type': 'default_credentials',
                    'severity': 'critical',
                    'title': 'Test Vulnerability'
                }
            ],
            'predicted_vulnerabilities': [],
            'exploitation_results': []
        }
        
        result = await temp_db.store_assessment_results(mock_report)
        assert result is True
    
    @pytest.mark.asyncio
    async def test_summary_retrieval(self, temp_db):
        """Test assessment summary retrieval."""
        summary = await temp_db.get_assessment_summary()
        
        assert 'total_assessments' in summary
        assert 'total_devices_scanned' in summary
        assert 'severity_breakdown' in summary


class TestEngine:
    """Test vulnerability assessment engine."""
    
    @pytest.fixture
    def mock_config(self):
        """Create mock configuration."""
        config = Mock()
        config.log_level = 'INFO'
        config.max_concurrent_scans = 10
        config.scan_timeout = 30
        config.ai_prediction_threshold = 0.7
        config.exploitation_enabled = True
        config.safe_mode = True
        config.database_path = ':memory:'
        return config
    
    def test_engine_initialization(self, mock_config):
        """Test engine initialization."""
        with patch('cctv_ml.core.engine.Config', return_value=mock_config):
            engine = VulnerabilityAssessmentEngine()
            assert engine.config == mock_config
    
    @pytest.mark.asyncio
    async def test_device_discovery(self, mock_config):
        """Test device discovery phase."""
        with patch('cctv_ml.core.engine.Config', return_value=mock_config):
            engine = VulnerabilityAssessmentEngine()
            
            # Mock the scanner
            mock_devices = [
                {
                    'ip': '192.168.1.100',
                    'port': 80,
                    'device_type': 'ip_camera',
                    'manufacturer': 'test_vendor'
                }
            ]
            
            with patch.object(engine.scanner, 'scan_network', return_value=mock_devices):
                devices = await engine._discover_devices(['192.168.1.0/24'])
                
                assert len(devices) == 1
                assert devices[0]['ip'] == '192.168.1.100'
    
    def test_assessment_id_generation(self, mock_config):
        """Test assessment ID generation."""
        with patch('cctv_ml.core.engine.Config', return_value=mock_config):
            engine = VulnerabilityAssessmentEngine()
            
            assessment_id = engine._generate_assessment_id()
            assert assessment_id.startswith('CCTV_ASSESS_')
            assert len(assessment_id) > 15
    
    def test_recommendations_generation(self, mock_config):
        """Test security recommendations generation."""
        with patch('cctv_ml.core.engine.Config', return_value=mock_config):
            engine = VulnerabilityAssessmentEngine()
            
            mock_vulns = [
                {'type': 'default_credentials', 'severity': 'critical'},
                {'type': 'authentication_bypass', 'severity': 'high'}
            ]
            
            recommendations = engine._generate_recommendations(mock_vulns)
            
            assert len(recommendations) > 0
            assert any('default credentials' in rec.lower() for rec in recommendations)


if __name__ == '__main__':
    pytest.main([__file__])
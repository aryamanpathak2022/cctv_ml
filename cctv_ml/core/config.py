"""
Configuration management for CCTV ML vulnerability assessment tool.
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path


class Config:
    """Configuration manager for the CCTV vulnerability assessment tool."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration from file or environment variables."""
        self.config_path = config_path or os.getenv('CCTV_CONFIG_PATH', 'config/default.yaml')
        self.config_data = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file with environment variable overrides."""
        # Default configuration
        default_config = {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'logs/cctv_ml.log'
            },
            'database': {
                'path': 'vulnerability_db/cctv_vulns.db',
                'backup_enabled': True,
                'backup_interval_hours': 24
            },
            'scanning': {
                'max_concurrent_scans': 50,
                'timeout_seconds': 30,
                'retry_attempts': 3,
                'user_agents': [
                    'CCTV-Security-Scanner/1.0',
                    'Mozilla/5.0 (compatible; CCTVBot/1.0)',
                    'SecurityScanner/1.0'
                ]
            },
            'ai': {
                'model_path': 'models/',
                'prediction_threshold': 0.7,
                'max_predictions_per_device': 10,
                'retrain_interval_days': 7
            },
            'exploitation': {
                'enabled': True,
                'max_concurrent_exploits': 10,
                'timeout_seconds': 60,
                'safe_mode': True  # Prevents destructive actions
            },
            'dashboard': {
                'host': '0.0.0.0',
                'port': 5000,
                'debug': False,
                'secret_key': 'change-this-in-production'
            },
            'external_apis': {
                'shodan_api_key': None,
                'censys_api_id': None,
                'censys_api_secret': None,
                'nvd_api_key': None
            },
            'threat_intelligence': {
                'update_interval_hours': 6,
                'sources': [
                    'https://cve.mitre.org/data/downloads/allitems.xml',
                    'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz'
                ]
            }
        }
        
        # Load from file if exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    file_config = yaml.safe_load(f)
                    if file_config:
                        default_config.update(file_config)
            except Exception as e:
                logging.warning(f"Could not load config file {self.config_path}: {e}")
        
        # Override with environment variables
        self._apply_env_overrides(default_config)
        
        return default_config
    
    def _apply_env_overrides(self, config: Dict[str, Any]):
        """Apply environment variable overrides to configuration."""
        env_mappings = {
            'CCTV_LOG_LEVEL': ['logging', 'level'],
            'CCTV_DB_PATH': ['database', 'path'],
            'CCTV_MAX_SCANS': ['scanning', 'max_concurrent_scans'],
            'CCTV_SCAN_TIMEOUT': ['scanning', 'timeout_seconds'],
            'CCTV_AI_THRESHOLD': ['ai', 'prediction_threshold'],
            'CCTV_EXPLOIT_ENABLED': ['exploitation', 'enabled'],
            'CCTV_SAFE_MODE': ['exploitation', 'safe_mode'],
            'CCTV_DASHBOARD_HOST': ['dashboard', 'host'],
            'CCTV_DASHBOARD_PORT': ['dashboard', 'port'],
            'CCTV_SECRET_KEY': ['dashboard', 'secret_key'],
            'SHODAN_API_KEY': ['external_apis', 'shodan_api_key'],
            'CENSYS_API_ID': ['external_apis', 'censys_api_id'],
            'CENSYS_API_SECRET': ['external_apis', 'censys_api_secret'],
            'NVD_API_KEY': ['external_apis', 'nvd_api_key']
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert string values to appropriate types
                if value.lower() in ('true', 'false'):
                    value = value.lower() == 'true'
                elif value.isdigit():
                    value = int(value)
                elif '.' in value and value.replace('.', '').isdigit():
                    value = float(value)
                
                # Set nested configuration value
                current = config
                for key in config_path[:-1]:
                    current = current.setdefault(key, {})
                current[config_path[-1]] = value
    
    @property
    def log_level(self) -> str:
        """Get logging level."""
        return self.config_data['logging']['level']
    
    @property
    def log_format(self) -> str:  
        """Get logging format."""
        return self.config_data['logging']['format']
    
    @property
    def log_file(self) -> str:
        """Get log file path."""
        return self.config_data['logging']['file']
    
    @property
    def database_path(self) -> str:
        """Get database path."""
        return self.config_data['database']['path']
    
    @property
    def max_concurrent_scans(self) -> int:
        """Get maximum concurrent scans."""
        return self.config_data['scanning']['max_concurrent_scans']
    
    @property
    def scan_timeout(self) -> int:
        """Get scan timeout in seconds."""
        return self.config_data['scanning']['timeout_seconds']
    
    @property
    def ai_prediction_threshold(self) -> float:
        """Get AI prediction threshold."""
        return self.config_data['ai']['prediction_threshold']
    
    @property
    def exploitation_enabled(self) -> bool:
        """Check if exploitation is enabled."""
        return self.config_data['exploitation']['enabled']
    
    @property
    def safe_mode(self) -> bool:
        """Check if safe mode is enabled."""
        return self.config_data['exploitation']['safe_mode']
    
    @property
    def dashboard_host(self) -> str:
        """Get dashboard host."""
        return self.config_data['dashboard']['host']
    
    @property
    def dashboard_port(self) -> int:
        """Get dashboard port."""
        return self.config_data['dashboard']['port']
    
    @property
    def secret_key(self) -> str:
        """Get Flask secret key."""
        return self.config_data['dashboard']['secret_key']
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key path (e.g., 'logging.level')."""
        keys = key.split('.')
        current = self.config_data
        
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default
                
        return current
    
    def ensure_directories(self):
        """Ensure all required directories exist."""
        directories = [
            os.path.dirname(self.log_file),
            os.path.dirname(self.database_path),
            self.get('ai.model_path', 'models/'),
            'reports/',
            'scan_results/'
        ]
        
        for directory in directories:
            if directory:
                Path(directory).mkdir(parents=True, exist_ok=True)
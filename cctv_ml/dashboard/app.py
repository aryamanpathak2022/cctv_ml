"""
Web Dashboard for CCTV ML Vulnerability Assessment Tool

This module provides a web-based dashboard for visualizing vulnerability
assessment results, managing scans, and monitoring CCTV security globally.
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import os

from ..core.engine import VulnerabilityAssessmentEngine
from ..core.database import VulnerabilityDatabase
from ..utils.logger import setup_logger
from .views import dashboard_blueprint


def create_dashboard_app(config=None) -> Flask:
    """
    Create and configure Flask dashboard application.
    
    Args:
        config: Configuration object
        
    Returns:
        Configured Flask application
    """
    app = Flask(__name__)
    
    # Configuration
    if config:
        app.config['SECRET_KEY'] = config.secret_key
        app.config['DEBUG'] = config.get('dashboard.debug', False)
        app.config['CCTV_CONFIG'] = config
    else:
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
        app.config['DEBUG'] = True
    
    # Enable CORS for API endpoints
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Set up logging
    logger = setup_logger("Dashboard", config.log_level if config else "INFO")
    app.logger.handlers = logger.handlers
    app.logger.setLevel(logger.level)
    
    # Initialize components
    if config:
        app.vuln_engine = VulnerabilityAssessmentEngine(config)
        app.database = VulnerabilityDatabase(config.database_path)
    
    # Register blueprints
    app.register_blueprint(dashboard_blueprint)
    
    # Main dashboard routes
    @app.route('/')
    def index():
        """Main dashboard page."""
        return render_template('dashboard.html')
    
    @app.route('/api/summary')
    def api_summary():
        """Get vulnerability assessment summary."""
        try:
            if hasattr(app, 'database'):
                # Run async method in event loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                summary = loop.run_until_complete(app.database.get_assessment_summary())
                loop.close()
            else:
                # Mock data for development
                summary = _get_mock_summary()
            
            return jsonify(summary)
        except Exception as e:
            app.logger.error(f"Failed to get summary: {str(e)}")
            return jsonify({'error': 'Failed to retrieve summary'}), 500
    
    @app.route('/api/vulnerable-devices')
    def api_vulnerable_devices():
        """Get list of vulnerable devices."""
        try:
            severity = request.args.get('severity')
            
            if hasattr(app, 'database'):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                devices = loop.run_until_complete(
                    app.database.get_vulnerable_devices(severity)
                )
                loop.close()
            else:
                devices = _get_mock_vulnerable_devices()
            
            return jsonify(devices)
        except Exception as e:
            app.logger.error(f"Failed to get vulnerable devices: {str(e)}")
            return jsonify({'error': 'Failed to retrieve devices'}), 500
    
    @app.route('/api/scan', methods=['POST'])
    def api_start_scan():
        """Start a new vulnerability assessment scan."""
        try:
            data = request.get_json()
            targets = data.get('targets', [])
            
            if not targets:
                return jsonify({'error': 'No targets specified'}), 400
            
            if hasattr(app, 'vuln_engine'):
                # Start scan asynchronously
                scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                
                # In production, this would be handled by a task queue
                app.logger.info(f"Starting scan {scan_id} for targets: {targets}")
                
                return jsonify({
                    'scan_id': scan_id,
                    'status': 'started',
                    'targets': targets,
                    'estimated_duration': len(targets) * 5  # 5 minutes per target estimate
                })
            else:
                return jsonify({'error': 'Scan engine not available'}), 503
                
        except Exception as e:
            app.logger.error(f"Failed to start scan: {str(e)}")
            return jsonify({'error': 'Failed to start scan'}), 500
    
    @app.route('/api/scan/<scan_id>/status')
    def api_scan_status(scan_id: str):
        """Get status of a running scan."""
        try:
            # Mock scan status for development
            status = {
                'scan_id': scan_id,
                'status': 'running',
                'progress': 65,
                'devices_scanned': 15,
                'vulnerabilities_found': 23,
                'estimated_remaining': '2m 30s'
            }
            
            return jsonify(status)
        except Exception as e:
            app.logger.error(f"Failed to get scan status: {str(e)}")
            return jsonify({'error': 'Failed to retrieve scan status'}), 500
    
    @app.route('/api/map-data')
    def api_map_data():
        """Get vulnerability map data for global visualization."""
        try:
            # Mock geographic vulnerability data
            map_data = _get_mock_map_data()
            return jsonify(map_data)
        except Exception as e:
            app.logger.error(f"Failed to get map data: {str(e)}")
            return jsonify({'error': 'Failed to retrieve map data'}), 500
    
    @app.route('/api/trends')
    def api_trends():
        """Get vulnerability trends over time."""
        try:
            days = int(request.args.get('days', 30))
            trends = _get_mock_trends(days)
            return jsonify(trends)
        except Exception as e:
            app.logger.error(f"Failed to get trends: {str(e)}")
            return jsonify({'error': 'Failed to retrieve trends'}), 500
    
    @app.route('/api/threat-intel')
    def api_threat_intelligence():
        """Get latest threat intelligence updates."""
        try:
            threat_intel = _get_mock_threat_intel()
            return jsonify(threat_intel)
        except Exception as e:
            app.logger.error(f"Failed to get threat intelligence: {str(e)}")
            return jsonify({'error': 'Failed to retrieve threat intelligence'}), 500
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('error.html', error_code=404, error_message="Page not found"), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('error.html', error_code=500, error_message="Internal server error"), 500
    
    return app


def _get_mock_summary() -> Dict[str, Any]:
    """Generate mock summary data for development."""
    return {
        'period_days': 30,
        'total_assessments': 45,
        'total_devices_scanned': 1247,
        'total_vulnerabilities': 892,
        'predicted_vulnerabilities': 156,
        'successful_exploits': 234,
        'average_scan_duration': 1847.5,
        'severity_breakdown': {
            'critical': 67,
            'high': 189,
            'medium': 445,
            'low': 191
        },
        'top_device_types': {
            'ip_camera': 678,
            'dvr': 234,
            'nvr': 189,
            'unknown_cctv': 146
        }
    }


def _get_mock_vulnerable_devices() -> List[Dict[str, Any]]:
    """Generate mock vulnerable devices data."""
    return [
        {
            'ip_address': '192.168.1.100',
            'port': 80,
            'device_type': 'ip_camera',
            'manufacturer': 'hikvision',
            'model': 'DS-2CD2142FWD-I',
            'vulnerability_count': 5,
            'has_critical': True,
            'has_high': True
        },
        {
            'ip_address': '192.168.1.101',
            'port': 8080,
            'device_type': 'dvr',
            'manufacturer': 'dahua',
            'model': 'DH-XVR5108HS-X',
            'vulnerability_count': 3,
            'has_critical': False,
            'has_high': True
        },
        {
            'ip_address': '10.0.0.50',
            'port': 80,
            'device_type': 'ip_camera',
            'manufacturer': 'foscam',
            'model': 'FI9821W',
            'vulnerability_count': 8,
            'has_critical': True,
            'has_high': True
        }
    ]


def _get_mock_map_data() -> Dict[str, Any]:
    """Generate mock map data for global vulnerability visualization."""
    return {
        'regions': [
            {
                'country': 'United States',
                'coordinates': [39.8283, -98.5795],
                'vulnerable_devices': 15432,
                'critical_vulns': 2341,
                'risk_level': 'high'
            },
            {
                'country': 'China',
                'coordinates': [35.8617, 104.1954],
                'vulnerable_devices': 23451,
                'critical_vulns': 4567,
                'risk_level': 'critical'
            },
            {
                'country': 'Germany',
                'coordinates': [51.1657, 10.4515],
                'vulnerable_devices': 8934,
                'critical_vulns': 1234,
                'risk_level': 'medium'
            },
            {
                'country': 'Japan',
                'coordinates': [36.2048, 138.2529],
                'vulnerable_devices': 12456,
                'critical_vulns': 1890,
                'risk_level': 'high'
            },
            {
                'country': 'United Kingdom',
                'coordinates': [55.3781, -3.4360],
                'vulnerable_devices': 6789,
                'critical_vulns': 987,
                'risk_level': 'medium'
            }
        ],
        'total_devices': 67062,
        'total_critical': 11019,
        'last_updated': datetime.utcnow().isoformat()
    }


def _get_mock_trends(days: int) -> Dict[str, Any]:
    """Generate mock vulnerability trends data."""
    import random
    
    dates = []
    vulnerabilities = []
    exploits = []
    
    base_date = datetime.utcnow() - timedelta(days=days)
    
    for i in range(days):
        current_date = base_date + timedelta(days=i)
        dates.append(current_date.strftime('%Y-%m-%d'))
        vulnerabilities.append(random.randint(50, 150))
        exploits.append(random.randint(5, 25))
    
    return {
        'dates': dates,
        'vulnerabilities_discovered': vulnerabilities,
        'successful_exploits': exploits,
        'total_period': {
            'vulnerabilities': sum(vulnerabilities),
            'exploits': sum(exploits),
            'average_per_day': sum(vulnerabilities) / len(vulnerabilities)
        }
    }


def _get_mock_threat_intel() -> Dict[str, Any]:
    """Generate mock threat intelligence data."""
    return {
        'alerts': [
            {
                'id': 'TI-001',
                'title': 'New Hikvision Zero-Day Exploited in Wild',
                'severity': 'critical',
                'description': 'A new zero-day vulnerability in Hikvision cameras is being actively exploited',
                'published': '2024-01-15T10:30:00Z',
                'source': 'CISA',
                'affected_devices': ['hikvision'],
                'cve_id': 'CVE-2024-0001'
            },
            {
                'id': 'TI-002', 
                'title': 'Botnet Campaign Targeting Dahua DVRs',
                'severity': 'high',
                'description': 'Large-scale botnet campaign observed targeting Dahua DVR systems',
                'published': '2024-01-14T15:45:00Z',
                'source': 'Threat Intelligence',
                'affected_devices': ['dahua'],
                'indicators': ['malicious_ips', 'suspicious_traffic']
            },
            {
                'id': 'TI-003',
                'title': 'Default Credential Abuse Surge',
                'severity': 'medium',
                'description': 'Significant increase in attacks exploiting default credentials',
                'published': '2024-01-13T09:15:00Z',
                'source': 'Security Research',
                'affected_devices': ['foscam', 'tp-link'],
                'remediation': 'Change default passwords immediately'
            }
        ],
        'statistics': {
            'total_alerts': 156,
            'critical_alerts': 23,
            'high_alerts': 67,
            'active_campaigns': 12,
            'compromised_devices': 45231
        },
        'last_updated': datetime.utcnow().isoformat()
    }


def main():
    """Main entry point for running the dashboard."""
    from ..core.config import Config
    
    # Load configuration
    config = Config()
    config.ensure_directories()
    
    # Create Flask app
    app = create_dashboard_app(config)
    
    # Run development server
    app.run(
        host=config.dashboard_host,
        port=config.dashboard_port,
        debug=config.get('dashboard.debug', False)
    )


if __name__ == '__main__':
    main()
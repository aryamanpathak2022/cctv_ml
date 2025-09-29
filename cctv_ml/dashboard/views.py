"""
Dashboard views and API endpoints for CCTV ML vulnerability assessment.
"""

from flask import Blueprint, render_template, request, jsonify, current_app
import asyncio
from typing import Dict, List, Any
from datetime import datetime
import json

dashboard_blueprint = Blueprint('dashboard', __name__, template_folder='templates')


@dashboard_blueprint.route('/devices')
def devices():
    """Devices management page."""
    return render_template('devices.html')


@dashboard_blueprint.route('/scans')
def scans():
    """Scan management and history page."""
    return render_template('scans.html')


@dashboard_blueprint.route('/vulnerabilities')
def vulnerabilities():
    """Vulnerability details and management page."""
    return render_template('vulnerabilities.html')


@dashboard_blueprint.route('/reports')
def reports():
    """Reports and analytics page.""" 
    return render_template('reports.html')


@dashboard_blueprint.route('/settings')
def settings():
    """Configuration and settings page."""
    return render_template('settings.html')


@dashboard_blueprint.route('/api/devices/search')
def api_devices_search():
    """Search devices by various criteria."""
    try:
        query = request.args.get('q', '')
        device_type = request.args.get('type')
        manufacturer = request.args.get('manufacturer')
        severity = request.args.get('severity')
        
        # Mock search results for development
        devices = _mock_device_search(query, device_type, manufacturer, severity)
        
        return jsonify({
            'devices': devices,
            'total': len(devices),
            'query': {
                'q': query,
                'type': device_type,
                'manufacturer': manufacturer,
                'severity': severity
            }
        })
    except Exception as e:
        current_app.logger.error(f"Device search failed: {str(e)}")
        return jsonify({'error': 'Search failed'}), 500


@dashboard_blueprint.route('/api/scans/history')
def api_scans_history():
    """Get scan history."""
    try:
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        
        scans = _mock_scan_history(limit, offset)
        
        return jsonify({
            'scans': scans,
            'total': 127,  # Mock total
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        current_app.logger.error(f"Failed to get scan history: {str(e)}")
        return jsonify({'error': 'Failed to retrieve scan history'}), 500


@dashboard_blueprint.route('/api/vulnerabilities/details/<vuln_id>')
def api_vulnerability_details(vuln_id: str):
    """Get detailed vulnerability information."""
    try:
        vulnerability = _mock_vulnerability_details(vuln_id)
        
        if not vulnerability:
            return jsonify({'error': 'Vulnerability not found'}), 404
        
        return jsonify(vulnerability)
    except Exception as e:
        current_app.logger.error(f"Failed to get vulnerability details: {str(e)}")
        return jsonify({'error': 'Failed to retrieve vulnerability details'}), 500


@dashboard_blueprint.route('/api/reports/generate', methods=['POST'])
def api_generate_report():
    """Generate a custom report."""
    try:
        data = request.get_json()
        report_type = data.get('type', 'summary')
        date_range = data.get('date_range', '30d')
        filters = data.get('filters', {})
        
        # Mock report generation
        report = _mock_generate_report(report_type, date_range, filters)
        
        return jsonify({
            'report_id': f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            'status': 'generated',
            'download_url': f"/api/reports/download/{report['report_id']}",
            'report': report
        })
    except Exception as e:
        current_app.logger.error(f"Report generation failed: {str(e)}")
        return jsonify({'error': 'Report generation failed'}), 500


@dashboard_blueprint.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update configuration."""
    if request.method == 'GET':
        try:
            config = _mock_get_config()
            return jsonify(config)
        except Exception as e:
            current_app.logger.error(f"Failed to get config: {str(e)}")
            return jsonify({'error': 'Failed to retrieve configuration'}), 500
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            success = _mock_update_config(data)
            
            if success:
                return jsonify({'status': 'updated', 'message': 'Configuration updated successfully'})
            else:
                return jsonify({'error': 'Failed to update configuration'}), 400
        except Exception as e:
            current_app.logger.error(f"Config update failed: {str(e)}")
            return jsonify({'error': 'Configuration update failed'}), 500


def _mock_device_search(query: str, device_type: str, manufacturer: str, severity: str) -> List[Dict[str, Any]]:
    """Mock device search results."""
    devices = [
        {
            'id': 'dev_001',
            'ip_address': '192.168.1.100',
            'port': 80,
            'device_type': 'ip_camera',
            'manufacturer': 'hikvision',
            'model': 'DS-2CD2142FWD-I',
            'firmware_version': 'V5.5.3',
            'status': 'online',
            'last_seen': '2024-01-15T14:30:00Z',
            'vulnerability_count': 5,
            'risk_score': 85,
            'risk_level': 'critical'
        },
        {
            'id': 'dev_002',
            'ip_address': '192.168.1.101',
            'port': 8080,
            'device_type': 'dvr',
            'manufacturer': 'dahua',
            'model': 'DH-XVR5108HS-X',
            'firmware_version': 'V4.001.0000000.0',
            'status': 'online',
            'last_seen': '2024-01-15T14:25:00Z',
            'vulnerability_count': 3,
            'risk_score': 65,
            'risk_level': 'high'
        }
    ]
    
    # Apply filters
    if device_type:
        devices = [d for d in devices if d['device_type'] == device_type]
    if manufacturer:
        devices = [d for d in devices if d['manufacturer'] == manufacturer]
    if severity:
        devices = [d for d in devices if d['risk_level'] == severity]
    if query:
        devices = [d for d in devices if query.lower() in str(d).lower()]
    
    return devices


def _mock_scan_history(limit: int, offset: int) -> List[Dict[str, Any]]:
    """Mock scan history data."""
    scans = [
        {
            'scan_id': 'scan_20240115_143000',
            'start_time': '2024-01-15T14:30:00Z',
            'end_time': '2024-01-15T15:45:00Z',
            'duration': 4500,
            'status': 'completed',
            'targets': ['192.168.1.0/24'],
            'devices_discovered': 23,
            'vulnerabilities_found': 67,
            'critical_vulns': 12,
            'high_vulns': 25,
            'exploits_successful': 8
        },
        {
            'scan_id': 'scan_20240114_093000',
            'start_time': '2024-01-14T09:30:00Z', 
            'end_time': '2024-01-14T11:15:00Z',
            'duration': 6300,
            'status': 'completed',
            'targets': ['10.0.0.0/24', '172.16.1.0/24'],
            'devices_discovered': 45,
            'vulnerabilities_found': 123,
            'critical_vulns': 18,
            'high_vulns': 42,
            'exploits_successful': 15
        },
        {
            'scan_id': 'scan_20240113_163000',
            'start_time': '2024-01-13T16:30:00Z',
            'end_time': None,
            'duration': None,
            'status': 'failed',
            'targets': ['203.0.113.0/24'],
            'error': 'Network unreachable',
            'devices_discovered': 0,
            'vulnerabilities_found': 0,
            'critical_vulns': 0,
            'high_vulns': 0,
            'exploits_successful': 0
        }
    ]
    
    return scans[offset:offset+limit]


def _mock_vulnerability_details(vuln_id: str) -> Dict[str, Any]:
    """Mock detailed vulnerability information."""
    return {
        'id': vuln_id,
        'cve_id': 'CVE-2023-1234',
        'title': 'Authentication Bypass in CCTV Camera',
        'description': 'A vulnerability in the web interface allows authentication bypass through path traversal',
        'severity': 'critical',
        'cvss_score': 9.8,
        'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'type': 'authentication_bypass',
        'exploitable': True,
        'affected_device': {
            'ip_address': '192.168.1.100',
            'port': 80,
            'manufacturer': 'hikvision',
            'model': 'DS-2CD2142FWD-I',
            'firmware_version': 'V5.5.3'
        },
        'discovery_method': 'automated_scan',
        'discovered_at': '2024-01-15T14:35:22Z',
        'proof_of_concept': 'GET /../../admin/ bypasses authentication',
        'remediation': 'Update firmware to version V5.6.1 or later',
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1234',
            'https://www.hikvision.com/security-advisory'
        ],
        'exploitation_status': 'exploited',
        'exploitation_details': {
            'method': 'path_traversal',
            'success': True,
            'timestamp': '2024-01-15T14:36:15Z',
            'access_gained': 'administrative',
            'impact': 'Full device compromise'
        }
    }


def _mock_generate_report(report_type: str, date_range: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Mock report generation."""
    return {
        'report_id': f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        'type': report_type,
        'date_range': date_range,
        'filters': filters,
        'generated_at': datetime.utcnow().isoformat(),
        'summary': {
            'total_devices': 156,
            'vulnerable_devices': 89,
            'critical_vulnerabilities': 23,
            'high_vulnerabilities': 67,
            'successful_exploits': 34
        },
        'sections': [
            {
                'title': 'Executive Summary',
                'content': 'Assessment of 156 CCTV devices revealed 89 vulnerable systems...'
            },
            {
                'title': 'Risk Assessment',
                'content': 'Overall risk score: 78/100 (High Risk)'
            },
            {
                'title': 'Recommendations',
                'content': '1. Update firmware on all critical devices\n2. Change default passwords...'
            }
        ]
    }


def _mock_get_config() -> Dict[str, Any]:
    """Mock configuration data."""
    return {
        'scanning': {
            'max_concurrent_scans': 50,
            'timeout_seconds': 30,
            'retry_attempts': 3
        },
        'ai': {
            'prediction_threshold': 0.7,
            'max_predictions_per_device': 10
        },
        'exploitation': {
            'enabled': True,
            'safe_mode': True,
            'max_concurrent_exploits': 10
        },
        'notifications': {
            'email_enabled': False,
            'email_recipients': [],
            'slack_webhook': '',
            'critical_only': False
        },
        'api_keys': {
            'shodan': '***hidden***',
            'censys': '***hidden***',
            'nvd': '***hidden***'
        }
    }


def _mock_update_config(data: Dict[str, Any]) -> bool:
    """Mock configuration update."""
    # In real implementation, this would validate and save the configuration
    return True
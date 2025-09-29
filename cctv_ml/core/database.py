"""
Database management for CCTV vulnerability assessment results.
"""

import sqlite3
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import aiosqlite


class VulnerabilityDatabase:
    """Database manager for storing and retrieving vulnerability assessment results."""
    
    def __init__(self, db_path: str = "vulnerability_db/cctv_vulns.db"):
        """Initialize the vulnerability database."""
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        
        # Ensure database directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database schema
        asyncio.create_task(self._init_database())
    
    async def _init_database(self):
        """Initialize database schema if not exists."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                -- Assessments table
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    start_time TEXT NOT NULL,
                    end_time TEXT NOT NULL,
                    duration_seconds REAL NOT NULL,
                    devices_discovered INTEGER NOT NULL,
                    vulnerabilities_found INTEGER NOT NULL,
                    vulnerabilities_predicted INTEGER NOT NULL,
                    successful_exploits INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'completed',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Discovered devices table
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT,
                    device_type TEXT,
                    manufacturer TEXT,
                    model TEXT,
                    firmware_version TEXT,
                    web_interface_url TEXT,
                    authentication_required BOOLEAN,
                    default_credentials BOOLEAN,
                    fingerprint TEXT,
                    discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (id)
                );
                
                -- Vulnerabilities table
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    device_id INTEGER,
                    cve_id TEXT,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    cvss_score REAL,
                    exploitable BOOLEAN DEFAULT FALSE,
                    proof_of_concept TEXT,
                    remediation TEXT,
                    discovered_method TEXT, -- 'scan' or 'ai_prediction'
                    confidence_score REAL,
                    discovered_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (id),
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                );
                
                -- Exploitation results table  
                CREATE TABLE IF NOT EXISTS exploits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    vulnerability_id INTEGER NOT NULL,
                    exploit_type TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    payload TEXT,
                    response TEXT,
                    access_gained TEXT,
                    impact_assessment TEXT,
                    exploited_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (assessment_id) REFERENCES assessments (id),
                    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
                );
                
                -- Threat intelligence table
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    indicators TEXT, -- JSON array of IOCs
                    description TEXT,
                    severity TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Create indexes for performance
                CREATE INDEX IF NOT EXISTS idx_assessments_created_at ON assessments(created_at);
                CREATE INDEX IF NOT EXISTS idx_devices_assessment_id ON devices(assessment_id);
                CREATE INDEX IF NOT EXISTS idx_devices_ip_port ON devices(ip_address, port);
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_assessment_id ON vulnerabilities(assessment_id);
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
                CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve ON vulnerabilities(cve_id);
                CREATE INDEX IF NOT EXISTS idx_exploits_assessment_id ON exploits(assessment_id);
                CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intelligence(threat_type);
            """)
            await db.commit()
    
    async def store_assessment_results(self, report: Dict[str, Any]) -> bool:
        """Store complete assessment results in the database."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Store assessment summary
                await db.execute("""
                    INSERT INTO assessments (
                        id, start_time, end_time, duration_seconds,
                        devices_discovered, vulnerabilities_found, 
                        vulnerabilities_predicted, successful_exploits
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    report['assessment_id'],
                    report['start_time'],
                    report['end_time'],
                    report['duration_seconds'],
                    report['summary']['devices_discovered'],
                    report['summary']['vulnerabilities_found'],
                    report['summary']['vulnerabilities_predicted'],
                    report['summary']['successful_exploits']
                ))
                
                # Store discovered devices
                device_id_map = {}
                for device in report.get('discovered_devices', []):
                    cursor = await db.execute("""
                        INSERT INTO devices (
                            assessment_id, ip_address, port, protocol, device_type,
                            manufacturer, model, firmware_version, web_interface_url,
                            authentication_required, default_credentials, fingerprint
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        report['assessment_id'],
                        device['ip'],
                        device['port'],
                        device.get('protocol'),
                        device.get('device_type'),
                        device.get('manufacturer'),
                        device.get('model'),
                        device.get('firmware_version'),
                        device.get('web_interface_url'),
                        device.get('authentication_required'),
                        device.get('default_credentials'),
                        json.dumps(device.get('fingerprint', {}))
                    ))
                    device_id_map[f"{device['ip']}:{device['port']}"] = cursor.lastrowid
                
                # Store vulnerabilities  
                vuln_id_map = {}
                for vuln in report.get('vulnerabilities', []):
                    device_key = f"{vuln['device_ip']}:{vuln['device_port']}"
                    device_id = device_id_map.get(device_key)
                    
                    cursor = await db.execute("""
                        INSERT INTO vulnerabilities (
                            assessment_id, device_id, cve_id, vuln_type, severity,
                            title, description, cvss_score, exploitable, 
                            proof_of_concept, remediation, discovered_method, confidence_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        report['assessment_id'],
                        device_id,
                        vuln.get('cve_id'),
                        vuln['type'],
                        vuln['severity'],
                        vuln['title'],
                        vuln.get('description'),
                        vuln.get('cvss_score'),
                        vuln.get('exploitable', False),
                        vuln.get('proof_of_concept'),
                        vuln.get('remediation'),
                        'scan',
                        vuln.get('confidence_score', 1.0)
                    ))
                    vuln_id_map[vuln['id']] = cursor.lastrowid
                
                # Store predicted vulnerabilities
                for vuln in report.get('predicted_vulnerabilities', []):
                    device_key = f"{vuln['device_ip']}:{vuln['device_port']}"
                    device_id = device_id_map.get(device_key)
                    
                    cursor = await db.execute("""
                        INSERT INTO vulnerabilities (
                            assessment_id, device_id, vuln_type, severity,
                            title, description, exploitable, discovered_method, confidence_score
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        report['assessment_id'],
                        device_id,
                        vuln['type'],
                        vuln['severity'],
                        vuln['title'],
                        vuln.get('description'),
                        vuln.get('exploitable', False),
                        'ai_prediction',
                        vuln.get('confidence_score', 0.5)
                    ))
                    vuln_id_map[vuln['id']] = cursor.lastrowid
                
                # Store exploitation results
                for exploit in report.get('exploitation_results', []):
                    vuln_id = vuln_id_map.get(exploit['vulnerability_id'])
                    
                    await db.execute("""
                        INSERT INTO exploits (
                            assessment_id, vulnerability_id, exploit_type, success,
                            payload, response, access_gained, impact_assessment
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        report['assessment_id'],
                        vuln_id,
                        exploit['type'],
                        exploit['success'],
                        exploit.get('payload'),
                        exploit.get('response'),
                        exploit.get('access_gained'),
                        exploit.get('impact_assessment')
                    ))
                
                await db.commit()
                self.logger.info(f"Stored assessment results for {report['assessment_id']}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to store assessment results: {str(e)}")
            return False
    
    async def get_assessment_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get assessment summary for the last N days."""
        cutoff_date = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        async with aiosqlite.connect(self.db_path) as db:
            # Get basic statistics
            cursor = await db.execute("""
                SELECT 
                    COUNT(*) as total_assessments,
                    SUM(devices_discovered) as total_devices,
                    SUM(vulnerabilities_found) as total_vulns,
                    SUM(vulnerabilities_predicted) as total_predicted,
                    SUM(successful_exploits) as total_exploits,
                    AVG(duration_seconds) as avg_duration
                FROM assessments 
                WHERE created_at >= ?
            """, (cutoff_date,))
            
            stats = await cursor.fetchone()
            
            # Get severity breakdown
            cursor = await db.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities v
                JOIN assessments a ON v.assessment_id = a.id
                WHERE a.created_at >= ?
                GROUP BY severity
            """, (cutoff_date,))
            
            severity_breakdown = dict(await cursor.fetchall())
            
            # Get top device types
            cursor = await db.execute("""
                SELECT device_type, COUNT(*) as count
                FROM devices d
                JOIN assessments a ON d.assessment_id = a.id
                WHERE a.created_at >= ? AND device_type IS NOT NULL
                GROUP BY device_type
                ORDER BY count DESC
                LIMIT 10
            """, (cutoff_date,))
            
            device_types = dict(await cursor.fetchall())
            
            return {
                'period_days': days,
                'total_assessments': stats[0] or 0,
                'total_devices_scanned': stats[1] or 0,
                'total_vulnerabilities': stats[2] or 0,
                'predicted_vulnerabilities': stats[3] or 0,
                'successful_exploits': stats[4] or 0,
                'average_scan_duration': stats[5] or 0,
                'severity_breakdown': severity_breakdown,
                'top_device_types': device_types
            }
    
    async def get_vulnerable_devices(self, severity: str = None) -> List[Dict[str, Any]]:
        """Get list of devices with vulnerabilities."""
        query = """
            SELECT DISTINCT
                d.ip_address,
                d.port,
                d.device_type,
                d.manufacturer,
                d.model,
                COUNT(v.id) as vuln_count,
                MAX(CASE WHEN v.severity = 'critical' THEN 1 ELSE 0 END) as has_critical,
                MAX(CASE WHEN v.severity = 'high' THEN 1 ELSE 0 END) as has_high
            FROM devices d
            JOIN vulnerabilities v ON d.id = v.device_id
        """
        
        params = []
        if severity:
            query += " WHERE v.severity = ?"
            params.append(severity)
            
        query += """
            GROUP BY d.ip_address, d.port, d.device_type, d.manufacturer, d.model
            ORDER BY has_critical DESC, has_high DESC, vuln_count DESC
        """
        
        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(query, params)
            rows = await cursor.fetchall()
            
            return [
                {
                    'ip_address': row[0],
                    'port': row[1], 
                    'device_type': row[2],
                    'manufacturer': row[3],
                    'model': row[4],
                    'vulnerability_count': row[5],
                    'has_critical': bool(row[6]),
                    'has_high': bool(row[7])
                }
                for row in rows
            ]
    
    async def cleanup_old_data(self, days_to_keep: int = 90) -> int:
        """Clean up old assessment data older than specified days."""
        cutoff_date = (datetime.utcnow() - timedelta(days=days_to_keep)).isoformat()
        
        async with aiosqlite.connect(self.db_path) as db:
            # Delete old records (cascading will handle related tables)
            cursor = await db.execute(
                "DELETE FROM assessments WHERE created_at < ?", 
                (cutoff_date,)
            )
            deleted_count = cursor.rowcount
            await db.commit()
            
            # Vacuum to reclaim space
            await db.execute("VACUUM")
            
            self.logger.info(f"Cleaned up {deleted_count} old assessment records")
            return deleted_count
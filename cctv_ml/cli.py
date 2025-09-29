#!/usr/bin/env python3
"""
Command Line Interface for CCTV ML Vulnerability Assessment Tool

This module provides a comprehensive CLI for running vulnerability assessments,
managing configurations, and interacting with the CCTV security testing platform.
"""

import argparse
import asyncio
import sys
import os
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

# Add the package to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cctv_ml.core.engine import VulnerabilityAssessmentEngine
from cctv_ml.core.config import Config
from cctv_ml.core.database import VulnerabilityDatabase
from cctv_ml.scanner.device_scanner import CCTVScanner
from cctv_ml.ai.predictor import VulnerabilityPredictor
from cctv_ml.utils.logger import setup_logger, SecurityLogger
from cctv_ml.utils.helpers import format_duration, calculate_risk_score


class CCTVCLIRunner:
    """Main CLI application runner."""
    
    def __init__(self):
        """Initialize the CLI runner."""
        self.config = None
        self.logger = None
        self.security_logger = None
        self.engine = None
        
    def setup(self, config_path: Optional[str] = None, verbose: bool = False):
        """Set up the CLI environment."""
        # Load configuration
        self.config = Config(config_path)
        self.config.ensure_directories()
        
        # Set up logging
        log_level = "DEBUG" if verbose else self.config.log_level
        self.logger = setup_logger("CCTV-CLI", log_level, self.config.log_file)
        self.security_logger = SecurityLogger()
        
        # Initialize core engine
        self.engine = VulnerabilityAssessmentEngine(config_path)
        
        self.logger.info("CCTV ML CLI initialized successfully")
    
    async def run_scan(self, targets: List[str], output_file: Optional[str] = None,
                      scan_type: str = 'full') -> Dict[str, Any]:
        """Run vulnerability assessment scan."""
        self.logger.info(f"Starting {scan_type} scan on {len(targets)} targets")
        
        try:
            if scan_type == 'discovery':
                results = await self._run_discovery_scan(targets)
            elif scan_type == 'vulnerability':
                results = await self._run_vulnerability_scan(targets)
            elif scan_type == 'exploit':
                results = await self._run_exploit_scan(targets)
            else:  # full scan
                results = await self.engine.run_full_assessment(targets)
            
            # Output results
            if output_file:
                await self._save_results(results, output_file)
                self.logger.info(f"Results saved to {output_file}")
            else:
                self._print_results_summary(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise
    
    async def _run_discovery_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Run device discovery scan only."""
        scanner = CCTVScanner(self.config)
        discovered_devices = []
        
        for target in targets:
            devices = await scanner.scan_network(target)
            discovered_devices.extend(devices)
        
        return {
            'scan_type': 'discovery',
            'targets': targets,
            'discovered_devices': discovered_devices,
            'summary': {
                'devices_discovered': len(discovered_devices),
                'scan_completed': True
            }
        }
    
    async def _run_vulnerability_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Run vulnerability scan without exploitation."""
        scanner = CCTVScanner(self.config)
        predictor = VulnerabilityPredictor(self.config)
        
        # Discovery
        discovered_devices = []
        for target in targets:
            devices = await scanner.scan_network(target)
            discovered_devices.extend(devices)
        
        # Vulnerability scanning
        vulnerabilities = []
        predicted_vulns = []
        
        for device in discovered_devices:
            # Known vulnerabilities
            device_vulns = await scanner.scan_device_vulnerabilities(device)
            vulnerabilities.extend(device_vulns)
            
            # AI predictions
            predictions = await predictor.predict_vulnerabilities(device, device_vulns)
            predicted_vulns.extend(predictions)
        
        return {
            'scan_type': 'vulnerability',
            'targets': targets,
            'discovered_devices': discovered_devices,
            'vulnerabilities': vulnerabilities,
            'predicted_vulnerabilities': predicted_vulns,
            'summary': {
                'devices_discovered': len(discovered_devices),
                'vulnerabilities_found': len(vulnerabilities),
                'vulnerabilities_predicted': len(predicted_vulns),
                'scan_completed': True
            }
        }
    
    async def _run_exploit_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Run exploitation scan for validation."""
        # First run vulnerability scan
        vuln_results = await self._run_vulnerability_scan(targets)
        
        # Then attempt exploitation
        from cctv_ml.exploits.exploit_engine import ExploitEngine
        exploit_engine = ExploitEngine(self.config)
        
        exploitation_results = []
        all_vulns = vuln_results['vulnerabilities'] + vuln_results['predicted_vulnerabilities']
        
        for vuln in all_vulns:
            if vuln.get('exploitable', False):
                result = await exploit_engine.exploit_vulnerability(vuln)
                exploitation_results.append(result)
        
        vuln_results.update({
            'scan_type': 'exploit',
            'exploitation_results': exploitation_results,
            'summary': {
                **vuln_results['summary'],
                'successful_exploits': len([r for r in exploitation_results if r.get('success')])
            }
        })
        
        return vuln_results
    
    async def _save_results(self, results: Dict[str, Any], output_file: str):
        """Save scan results to file."""
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    
    def _print_results_summary(self, results: Dict[str, Any]):
        """Print scan results summary to console."""
        print("\n" + "="*60)
        print("CCTV VULNERABILITY ASSESSMENT RESULTS")
        print("="*60)
        
        summary = results.get('summary', {})
        
        print(f"Scan Type: {results.get('scan_type', 'unknown').title()}")
        print(f"Targets: {', '.join(results.get('targets', []))}")
        
        if 'duration_seconds' in results:
            print(f"Duration: {format_duration(results['duration_seconds'])}")
        
        print(f"\nDevices Discovered: {summary.get('devices_discovered', 0)}")
        
        if 'vulnerabilities_found' in summary:
            print(f"Vulnerabilities Found: {summary['vulnerabilities_found']}")
        
        if 'vulnerabilities_predicted' in summary:
            print(f"Vulnerabilities Predicted: {summary['vulnerabilities_predicted']}")
        
        if 'successful_exploits' in summary:
            print(f"Successful Exploits: {summary['successful_exploits']}")
        
        # Risk assessment
        all_vulns = results.get('vulnerabilities', []) + results.get('predicted_vulnerabilities', [])
        if all_vulns:
            risk_score = calculate_risk_score(all_vulns)
            print(f"Overall Risk Score: {risk_score}/100")
        
        # Top vulnerabilities
        if all_vulns:
            critical_vulns = [v for v in all_vulns if v.get('severity') == 'critical']
            if critical_vulns:
                print(f"\nCRITICAL VULNERABILITIES ({len(critical_vulns)}):")
                for vuln in critical_vulns[:5]:  # Show top 5
                    print(f"  - {vuln.get('title', 'Unknown')} on {vuln.get('device_ip', 'unknown')}")
        
        print("\n" + "="*60)
    
    async def list_devices(self, filters: Optional[Dict[str, str]] = None):
        """List discovered devices."""
        db = VulnerabilityDatabase(self.config.database_path)
        
        severity = filters.get('severity') if filters else None
        devices = await db.get_vulnerable_devices(severity)
        
        if not devices:
            print("No devices found matching criteria.")
            return
        
        print(f"\nFound {len(devices)} devices:")
        print("-" * 80)
        print(f"{'IP Address':<15} {'Port':<6} {'Type':<12} {'Manufacturer':<12} {'Vulns':<6} {'Risk'}")
        print("-" * 80)
        
        for device in devices:
            risk_level = "Critical" if device['has_critical'] else "High" if device['has_high'] else "Medium"
            print(f"{device['ip_address']:<15} {device['port']:<6} {device['device_type']:<12} "
                  f"{device['manufacturer'] or 'Unknown':<12} {device['vulnerability_count']:<6} {risk_level}")
    
    async def show_summary(self, days: int = 30):
        """Show assessment summary."""
        db = VulnerabilityDatabase(self.config.database_path)
        summary = await db.get_assessment_summary(days)
        
        print(f"\nVULNERABILITY ASSESSMENT SUMMARY (Last {days} days)")
        print("=" * 60)
        print(f"Total Assessments: {summary['total_assessments']}")
        print(f"Devices Scanned: {summary['total_devices_scanned']}")
        print(f"Vulnerabilities Found: {summary['total_vulnerabilities']}")
        print(f"Predicted Vulnerabilities: {summary['predicted_vulnerabilities']}")
        print(f"Successful Exploits: {summary['successful_exploits']}")
        
        if summary['average_scan_duration']:
            print(f"Average Scan Duration: {format_duration(summary['average_scan_duration'])}")
        
        print("\nVulnerability Breakdown:")
        for severity, count in summary['severity_breakdown'].items():
            print(f"  {severity.title()}: {count}")
        
        if summary['top_device_types']:
            print("\nTop Device Types:")
            for device_type, count in summary['top_device_types'].items():
                print(f"  {device_type.replace('_', ' ').title()}: {count}")
    
    def start_dashboard(self):
        """Start the web dashboard."""
        from cctv_ml.dashboard.app import create_dashboard_app
        
        app = create_dashboard_app(self.config)
        
        print(f"Starting CCTV ML Dashboard on http://{self.config.dashboard_host}:{self.config.dashboard_port}")
        
        app.run(
            host=self.config.dashboard_host,
            port=self.config.dashboard_port,
            debug=self.config.get('dashboard.debug', False)
        )


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="CCTV ML - Automated Vulnerability Assessment and Penetration Testing tool",
        epilog="Examples:\n"
               "  cctv-scanner scan -t 192.168.1.0/24\n"
               "  cctv-scanner scan -t 192.168.1.100 192.168.1.101 --type vulnerability\n"
               "  cctv-scanner dashboard\n"
               "  cctv-scanner summary --days 7",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run vulnerability assessment scan')
    scan_parser.add_argument('-t', '--targets', nargs='+', required=True,
                           help='Target IP addresses, ranges, or hostnames')
    scan_parser.add_argument('--type', choices=['discovery', 'vulnerability', 'exploit', 'full'],
                           default='full', help='Type of scan to perform')
    scan_parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    # Devices command
    devices_parser = subparsers.add_parser('devices', help='List discovered devices')
    devices_parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'],
                              help='Filter by vulnerability severity')
    
    # Summary command
    summary_parser = subparsers.add_parser('summary', help='Show assessment summary')
    summary_parser.add_argument('--days', type=int, default=30,
                               help='Number of days to include in summary')
    
    # Dashboard command
    subparsers.add_parser('dashboard', help='Start web dashboard')
    
    return parser


async def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        runner = CCTVCLIRunner()
        runner.setup(args.config, args.verbose)
        
        if args.command == 'scan':
            await runner.run_scan(args.targets, args.output, args.type)
        
        elif args.command == 'devices':
            filters = {'severity': args.severity} if args.severity else None
            await runner.list_devices(filters)
        
        elif args.command == 'summary':
            await runner.show_summary(args.days)
        
        elif args.command == 'dashboard':
            runner.start_dashboard()
        
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cli_main():
    """Entry point for console script."""
    return asyncio.run(main())


if __name__ == '__main__':
    sys.exit(cli_main())
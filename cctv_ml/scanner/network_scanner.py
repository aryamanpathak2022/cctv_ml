"""
Network Scanner for CCTV ML - Host discovery and port scanning functionality.
"""

import asyncio
import socket
import struct
import logging
import ipaddress
from typing import List, Set, Dict, Any, Optional
import subprocess
import concurrent.futures
import time

from ..utils.logger import setup_logger


class NetworkScanner:
    """Network scanner for discovering live hosts and open ports."""
    
    def __init__(self, config):
        """Initialize the network scanner."""
        self.config = config
        self.logger = setup_logger("NetworkScanner", config.log_level)
        
    async def discover_hosts(self, target: str) -> List[str]:
        """
        Discover live hosts in the given target range.
        
        Args:
            target: IP address, hostname, or CIDR block
            
        Returns:
            List of live IP addresses
        """
        self.logger.info(f"Discovering hosts in target: {target}")
        
        # Parse target to get IP list
        ip_list = self._parse_target(target)
        self.logger.info(f"Scanning {len(ip_list)} IP addresses")
        
        # Ping sweep to find live hosts
        live_hosts = await self._ping_sweep(ip_list)
        
        self.logger.info(f"Found {len(live_hosts)} live hosts")
        return live_hosts
    
    def _parse_target(self, target: str) -> List[str]:
        """Parse target specification into list of IP addresses."""
        try:
            # Try to parse as CIDR network
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return [str(ip) for ip in network.hosts()]
            
            # Try to parse as IP range (e.g., 192.168.1.1-254)
            elif '-' in target and '.' in target:
                return self._parse_ip_range(target)
            
            # Single IP or hostname
            else:
                try:
                    # Resolve hostname to IP
                    ip = socket.gethostbyname(target)
                    return [ip]
                except socket.gaierror:
                    # Try as IP address
                    ipaddress.ip_address(target)
                    return [target]
                    
        except Exception as e:
            self.logger.error(f"Failed to parse target '{target}': {e}")
            return []
    
    def _parse_ip_range(self, target: str) -> List[str]:
        """Parse IP range like 192.168.1.1-254 into list of IPs."""
        try:
            if target.count('-') == 1:
                base_part, range_part = target.rsplit('.', 1)
                
                if '-' in range_part:
                    start_str, end_str = range_part.split('-')
                    start_ip = int(start_str)
                    end_ip = int(end_str)
                    
                    ips = []
                    for i in range(start_ip, end_ip + 1):
                        ips.append(f"{base_part}.{i}")
                    
                    return ips
        except Exception as e:
            self.logger.error(f"Failed to parse IP range '{target}': {e}")
        
        return [target]  # Return as-is if parsing fails
    
    async def _ping_sweep(self, ip_list: List[str]) -> List[str]:
        """Perform ping sweep to identify live hosts."""
        live_hosts = []
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
        # Create ping tasks
        tasks = []
        for ip in ip_list:
            task = self._ping_host(semaphore, ip)
            tasks.append(task)
        
        # Execute ping sweep
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for ip, result in zip(ip_list, results):
            if isinstance(result, bool) and result:
                live_hosts.append(ip)
            elif isinstance(result, Exception):
                self.logger.debug(f"Ping failed for {ip}: {result}")
        
        return live_hosts
    
    async def _ping_host(self, semaphore: asyncio.Semaphore, ip: str) -> bool:
        """Ping a single host to check if it's alive.""" 
        async with semaphore:
            try:
                # Use system ping command for better compatibility
                process = await asyncio.create_subprocess_exec(
                    'ping', '-c', '1', '-W', '2', ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=5
                )
                
                return process.returncode == 0
                
            except Exception as e:
                self.logger.debug(f"Ping failed for {ip}: {e}")
                return False
    
    async def scan_ports(self, host: str, ports: List[int]) -> List[int]:
        """
        Scan specific ports on a host.
        
        Args:
            host: Target host IP address 
            ports: List of ports to scan
            
        Returns:
            List of open ports
        """
        self.logger.debug(f"Scanning {len(ports)} ports on {host}")
        
        open_ports = []
        semaphore = asyncio.Semaphore(50)  # Limit concurrent port scans
        
        # Create port scan tasks
        tasks = []
        for port in ports:
            task = self._scan_port(semaphore, host, port)
            tasks.append(task)
        
        # Execute port scans
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for port, result in zip(ports, results):
            if isinstance(result, bool) and result:
                open_ports.append(port)
            elif isinstance(result, Exception):
                self.logger.debug(f"Port scan failed for {host}:{port}: {result}")
        
        self.logger.debug(f"Found {len(open_ports)} open ports on {host}")
        return open_ports
    
    async def _scan_port(self, semaphore: asyncio.Semaphore, host: str, port: int) -> bool:
        """Scan a single port on a host."""
        async with semaphore:
            try:
                # TCP connect scan
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(
                    future, timeout=self.config.scan_timeout
                )
                
                writer.close()
                await writer.wait_closed()
                return True
                
            except Exception:
                return False
    
    async def service_detection(self, host: str, port: int) -> Dict[str, Any]:
        """
        Detect service running on a specific port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Service information dictionary
        """
        service_info = {
            'host': host,
            'port': port,
            'protocol': 'tcp',
            'service': 'unknown',
            'version': None,
            'banner': None
        }
        
        try:
            # Try to grab banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5
            )
            
            # Send HTTP request to check for web service
            if port in [80, 8080, 8081, 8000, 8888, 9000]:
                writer.write(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner = response.decode('utf-8', errors='ignore')
                
                if 'HTTP/' in banner:
                    service_info['service'] = 'http'
                    service_info['banner'] = banner[:200]  # Truncate banner
                    
                    # Extract server header
                    if 'Server:' in banner:
                        server_line = [line for line in banner.split('\n') if 'Server:' in line]
                        if server_line:
                            service_info['version'] = server_line[0].split('Server:')[-1].strip()
            
            elif port in [443, 8443, 9443]:
                service_info['service'] = 'https'
            
            elif port in [554, 8554]:
                # RTSP service detection
                writer.write(f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=3)
                banner = response.decode('utf-8', errors='ignore')
                
                if 'RTSP/' in banner:
                    service_info['service'] = 'rtsp'
                    service_info['banner'] = banner[:200]
            
            elif port == 22:
                service_info['service'] = 'ssh'
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')[:200]
            
            elif port == 23:
                service_info['service'] = 'telnet'
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')[:200]
            
            elif port == 21:
                service_info['service'] = 'ftp'
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                service_info['banner'] = banner.decode('utf-8', errors='ignore')[:200]
            
            else:
                # Generic banner grab
                try:
                    banner = await asyncio.wait_for(reader.read(512), timeout=2)
                    if banner:
                        service_info['banner'] = banner.decode('utf-8', errors='ignore')[:200]
                except:
                    pass
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            self.logger.debug(f"Service detection failed for {host}:{port}: {e}")
        
        return service_info
    
    async def advanced_host_discovery(self, target: str) -> List[Dict[str, Any]]:
        """
        Advanced host discovery using multiple techniques.
        
        Args:
            target: Target specification
            
        Returns:
            List of discovered hosts with additional information
        """
        self.logger.info(f"Advanced host discovery for: {target}")
        
        discovered_hosts = []
        
        # Standard ping discovery
        live_hosts = await self.discover_hosts(target)
        
        for host in live_hosts:
            host_info = {
                'ip': host,
                'hostname': None,
                'mac_address': None,
                'os_guess': None,
                'discovery_method': 'ping'
            }
            
            # Try reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(host)[0]
                host_info['hostname'] = hostname
            except:
                pass
            
            # Basic OS fingerprinting based on TTL
            ttl = await self._get_ttl(host)
            if ttl:
                host_info['os_guess'] = self._guess_os_from_ttl(ttl)
            
            discovered_hosts.append(host_info)
        
        return discovered_hosts
    
    async def _get_ttl(self, host: str) -> Optional[int]:
        """Get TTL value from ping response for OS fingerprinting."""
        try:
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            output = stdout.decode()
            
            # Parse TTL from ping output
            import re
            ttl_match = re.search(r'ttl=(\d+)', output, re.IGNORECASE)
            if ttl_match:
                return int(ttl_match.group(1))
                
        except Exception:
            pass
        
        return None
    
    def _guess_os_from_ttl(self, ttl: int) -> str:
        """Guess operating system based on TTL value."""
        if ttl <= 64:
            if ttl > 60:
                return "Linux/Unix"
            else:
                return "Linux/Unix (distant)"
        elif ttl <= 128:
            if ttl > 120:
                return "Windows"
            else:
                return "Windows (distant)"
        elif ttl <= 255:
            return "Network Device/Router"
        else:
            return "Unknown"
    
    async def port_range_scan(self, host: str, start_port: int = 1, end_port: int = 1024) -> List[int]:
        """
        Scan a range of ports on a host.
        
        Args:
            host: Target host
            start_port: Starting port number
            end_port: Ending port number
            
        Returns:
            List of open ports
        """
        ports = list(range(start_port, end_port + 1))
        return await self.scan_ports(host, ports)
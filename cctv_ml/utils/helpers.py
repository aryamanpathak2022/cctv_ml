"""
Helper utilities for CCTV ML vulnerability assessment tool.
"""

import hashlib
import ipaddress
import socket
import re
import json
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import asyncio
import aiohttp


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Check if IP address is in private range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_public_ip(ip: str) -> bool:
    """Check if IP address is public/internet-routable."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    """Normalize URL by ensuring it has a scheme."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    return url


def extract_domain_from_url(url: str) -> Optional[str]:
    """Extract domain from URL."""
    try:
        parsed = urlparse(normalize_url(url))
        return parsed.netloc
    except:
        return None


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def calculate_hash(data: Union[str, bytes], algorithm: str = 'md5') -> str:
    """Calculate hash of data."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    hash_func = getattr(hashlib, algorithm, hashlib.md5)
    return hash_func(data).hexdigest()


def generate_device_id(ip: str, port: int, device_type: str = '') -> str:
    """Generate unique device identifier."""
    data = f"{ip}:{port}:{device_type}"
    return calculate_hash(data, 'sha256')[:16]


def parse_version_string(version: str) -> Optional[Dict[str, int]]:
    """Parse version string into components."""
    if not version:
        return None
    
    # Remove common prefixes
    version = re.sub(r'^[vV]', '', version.strip())
    
    # Extract version numbers
    match = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?', version)
    
    if match:
        return {
            'major': int(match.group(1)),
            'minor': int(match.group(2)),
            'patch': int(match.group(3) or 0),
            'build': int(match.group(4) or 0)
        }
    
    return None


def compare_versions(version1: str, version2: str) -> int:
    """
    Compare two version strings.
    
    Returns:
        -1 if version1 < version2
         0 if version1 == version2
         1 if version1 > version2
    """
    v1 = parse_version_string(version1)
    v2 = parse_version_string(version2)
    
    if not v1 or not v2:
        return 0  # Can't compare
    
    for key in ['major', 'minor', 'patch', 'build']:
        if v1[key] < v2[key]:
            return -1
        elif v1[key] > v2[key]:
            return 1
    
    return 0


def is_version_vulnerable(current_version: str, fixed_version: str) -> bool:
    """Check if current version is vulnerable (older than fixed version)."""
    return compare_versions(current_version, fixed_version) < 0


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file operations."""
    # Remove or replace dangerous characters
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    filename = re.sub(r'\.+', '.', filename)  # Multiple dots to single
    filename = filename.strip('. ')  # Remove leading/trailing dots and spaces
    
    # Limit length
    if len(filename) > 200:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:200-len(ext)-1] + ('.' + ext if ext else '')
    
    return filename


def format_bytes(bytes_value: int) -> str:
    """Format bytes into human-readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in seconds to human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    else:
        hours = seconds / 3600
        return f"{hours:.1f}h"


def calculate_risk_score(vulnerabilities: List[Dict[str, Any]]) -> float:
    """Calculate overall risk score based on vulnerabilities."""
    if not vulnerabilities:
        return 0.0
    
    severity_weights = {
        'critical': 10.0,
        'high': 7.0,
        'medium': 4.0,
        'low': 1.0
    }
    
    total_score = 0.0
    max_possible = 0.0
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'low').lower()
        weight = severity_weights.get(severity, 1.0)
        confidence = vuln.get('confidence_score', 1.0)
        exploitable = vuln.get('exploitable', False)
        
        # Boost score for exploitable vulnerabilities
        if exploitable:
            weight *= 1.5
        
        total_score += weight * confidence
        max_possible += severity_weights['critical']
    
    # Normalize to 0-100 scale
    risk_score = min(100.0, (total_score / max_possible) * 100) if max_possible > 0 else 0.0
    
    return round(risk_score, 2)


def categorize_risk_score(score: float) -> str:
    """Categorize numeric risk score into text categories."""
    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 40:
        return "Medium"
    elif score >= 20:
        return "Low"
    else:
        return "Minimal"


def extract_cve_info(text: str) -> List[str]:
    """Extract CVE identifiers from text."""
    cve_pattern = r'CVE-\d{4}-\d{4,7}'
    return re.findall(cve_pattern, text, re.IGNORECASE)


def validate_cve_format(cve_id: str) -> bool:
    """Validate CVE identifier format."""
    pattern = r'^CVE-\d{4}-\d{4,7}$'
    return bool(re.match(pattern, cve_id, re.IGNORECASE))


def parse_user_agent(user_agent: str) -> Dict[str, str]:
    """Parse User-Agent string to extract browser/device information."""
    info = {
        'browser': 'Unknown',
        'version': 'Unknown',
        'os': 'Unknown',
        'device': 'Unknown'
    }
    
    if not user_agent:
        return info
    
    ua_lower = user_agent.lower()
    
    # Browser detection
    if 'chrome' in ua_lower:
        info['browser'] = 'Chrome'
    elif 'firefox' in ua_lower:
        info['browser'] = 'Firefox'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        info['browser'] = 'Safari'
    elif 'edge' in ua_lower:
        info['browser'] = 'Edge'
    
    # OS detection
    if 'windows' in ua_lower:
        info['os'] = 'Windows'
    elif 'mac os' in ua_lower or 'macos' in ua_lower:
        info['os'] = 'macOS'
    elif 'linux' in ua_lower:
        info['os'] = 'Linux'
    elif 'android' in ua_lower:
        info['os'] = 'Android'
    elif 'ios' in ua_lower:
        info['os'] = 'iOS'
    
    return info


def clean_html(html: str) -> str:
    """Remove HTML tags from string."""
    import html
    
    # Decode HTML entities
    text = html.unescape(html)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', '', text)
    
    # Clean up whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    return text


def truncate_text(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """Truncate text to specified length."""
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def generate_report_filename(report_type: str, timestamp: Optional[datetime] = None) -> str:
    """Generate filename for reports."""
    if timestamp is None:
        timestamp = datetime.utcnow()
    
    date_str = timestamp.strftime('%Y%m%d_%H%M%S')
    filename = f"cctv_{report_type}_report_{date_str}.json"
    
    return sanitize_filename(filename)


async def make_http_request(url: str, method: str = 'GET', **kwargs) -> Optional[Dict[str, Any]]:
    """Make HTTP request with error handling."""
    try:
        timeout = aiohttp.ClientTimeout(total=kwargs.pop('timeout', 30))
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(method, url, **kwargs) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'content': await response.text(),
                    'url': str(response.url)
                }
    except Exception as e:
        return {
            'error': str(e),
            'status': 0,
            'headers': {},
            'content': '',
            'url': url
        }


def merge_dictionaries(*dicts: Dict[str, Any]) -> Dict[str, Any]:
    """Merge multiple dictionaries, with later ones taking precedence."""
    result = {}
    for d in dicts:
        if d:
            result.update(d)
    return result


def deep_merge_dictionaries(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Deep merge two dictionaries."""
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dictionaries(result[key], value)
        else:
            result[key] = value
    
    return result


def flatten_dictionary(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """Flatten nested dictionary."""
    items = []
    
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dictionary(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    
    return dict(items)


def safe_json_loads(json_str: str, default: Any = None) -> Any:
    """Safely load JSON string with fallback."""
    try:
        return json.loads(json_str)
    except (json.JSONDecodeError, TypeError):
        return default


def safe_json_dumps(obj: Any, default: Any = None, **kwargs) -> str:
    """Safely dump object to JSON string."""
    try:
        return json.dumps(obj, **kwargs)
    except (TypeError, ValueError):
        return json.dumps(default or {})


def batch_items(items: List[Any], batch_size: int) -> List[List[Any]]:
    """Split list into batches of specified size."""
    batches = []
    for i in range(0, len(items), batch_size):
        batches.append(items[i:i + batch_size])
    return batches


def retry_async(max_attempts: int = 3, delay: float = 1.0):
    """Decorator for retrying async functions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(delay * (2 ** attempt))  # Exponential backoff
                    
            raise last_exception
        return wrapper
    return decorator
"""
Utility Functions for VulnScanner
Common helper functions used across all services
"""

import re
import socket
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Tuple, Optional, Dict, List, Any
import ipaddress
from datetime import datetime
import hashlib
import json
import os


# ============ Constants ============
DEFAULT_USER_AGENT = 'VulnScanner/1.0 (Security Research Tool)'
DEFAULT_TIMEOUT = 10
MAX_RETRIES = 3

COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    111: 'RPC',
    135: 'MSRPC',
    139: 'NetBIOS',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MSSQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB'
}


# ============ Validation Functions ============

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address (IPv4 or IPv6)"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is a valid IPv4 address"""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is a valid IPv6 address"""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain name"""
    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(domain_pattern.match(domain))


def is_valid_url(url: str) -> bool:
    """Check if string is a valid URL"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_target(target: str) -> Tuple[bool, str, str]:
    """
    Validate and identify target type
    
    Returns:
        Tuple[bool, str, str]: (is_valid, target_type, normalized_target)
    """
    target = target.strip()
    
    # Check if it's an IP address
    if is_valid_ip(target):
        return True, 'ip', target
    
    # Check if it's a URL
    if target.startswith(('http://', 'https://')):
        if is_valid_url(target):
            parsed = urlparse(target)
            return True, 'url', target
        return False, 'invalid', target
    
    # Check if it's a domain
    if is_valid_domain(target):
        return True, 'domain', target
    
    # Try adding http:// and check again
    test_url = f'http://{target}'
    if is_valid_url(test_url):
        parsed = urlparse(test_url)
        if is_valid_domain(parsed.netloc) or is_valid_ip(parsed.netloc):
            return True, 'domain', parsed.netloc
    
    return False, 'invalid', target


# ============ URL Functions ============

def normalize_url(url: str) -> str:
    """Normalize URL to standard format"""
    url = url.strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    
    # Reconstruct URL
    normalized = f"{parsed.scheme}://{parsed.netloc}"
    
    if parsed.path:
        normalized += parsed.path
    else:
        normalized += '/'
    
    if parsed.query:
        normalized += f'?{parsed.query}'
    
    return normalized.rstrip('/')


def get_domain_from_url(url: str) -> str:
    """Extract domain from URL"""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc


def get_base_url(url: str) -> str:
    """Get base URL (scheme + netloc)"""
    parsed = urlparse(normalize_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def url_join(base: str, path: str) -> str:
    """Join base URL with path"""
    return urljoin(base, path)


def extract_params(url: str) -> Dict[str, List[str]]:
    """Extract query parameters from URL"""
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def build_url_with_params(base_url: str, params: Dict[str, str]) -> str:
    """Build URL with query parameters"""
    if not params:
        return base_url
    
    parsed = urlparse(base_url)
    query = urlencode(params)
    
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"


# ============ Network Functions ============

def get_ip_from_domain(domain: str) -> Optional[str]:
    """Resolve domain to IP address"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def get_all_ips_from_domain(domain: str) -> List[str]:
    """Get all IP addresses for a domain"""
    try:
        return list(set(socket.gethostbyname_ex(domain)[2]))
    except socket.gaierror:
        return []


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None


def check_port(host: str, port: int, timeout: float = 2) -> bool:
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_service_name(port: int) -> str:
    """Get common service name for port"""
    return COMMON_PORTS.get(port, 'Unknown')


# ============ HTTP Functions ============

def make_request(
    url: str,
    method: str = 'GET',
    headers: Optional[Dict] = None,
    data: Optional[Dict] = None,
    params: Optional[Dict] = None,
    timeout: int = DEFAULT_TIMEOUT,
    allow_redirects: bool = True,
    verify_ssl: bool = False,
    proxies: Optional[Dict] = None
) -> Optional[requests.Response]:
    """
    Make HTTP request with error handling
    
    Returns:
        Response object or None if request failed
    """
    default_headers = {
        'User-Agent': DEFAULT_USER_AGENT,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }
    
    if headers:
        default_headers.update(headers)
    
    try:
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=default_headers,
            data=data,
            params=params,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=verify_ssl,
            proxies=proxies
        )
        return response
    except requests.exceptions.RequestException as e:
        return None


def get_response_info(response: requests.Response) -> Dict[str, Any]:
    """Extract useful information from response"""
    return {
        'status_code': response.status_code,
        'headers': dict(response.headers),
        'content_type': response.headers.get('Content-Type', ''),
        'content_length': len(response.content),
        'response_time': response.elapsed.total_seconds(),
        'url': response.url,
        'redirects': [r.url for r in response.history]
    }


# ============ String Functions ============

def generate_scan_id() -> str:
    """Generate unique scan ID"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    random_hash = hashlib.md5(os.urandom(16)).hexdigest()[:8]
    return f"scan_{timestamp}_{random_hash}"


def sanitize_filename(filename: str) -> str:
    """Sanitize string for use as filename"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)


def truncate_string(s: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + '...'


# ============ File Functions ============

def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file"""
    words = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.append(word)
    except FileNotFoundError:
        pass
    return words


def save_json_report(data: Dict, filepath: str) -> bool:
    """Save data as JSON report"""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False


def load_json_report(filepath: str) -> Optional[Dict]:
    """Load JSON report from file"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


# ============ Parsing Functions ============

def parse_ports(port_string: str) -> List[int]:
    """
    Parse port string into list of ports
    Supports: single (80), range (80-100), comma-separated (80,443,8080)
    """
    ports = set()
    
    for part in port_string.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-')
                for port in range(int(start), int(end) + 1):
                    if 1 <= port <= 65535:
                        ports.add(port)
            except ValueError:
                continue
        else:
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.add(port)
            except ValueError:
                continue
    
    return sorted(list(ports))


def parse_cookie_string(cookie_string: str) -> Dict[str, str]:
    """Parse cookie string into dictionary"""
    cookies = {}
    for item in cookie_string.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    return cookies


# ============ Security Functions ============

def detect_waf(response: requests.Response) -> Optional[str]:
    """Detect Web Application Firewall from response"""
    waf_signatures = {
        'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
        'Akamai': ['akamai', 'x-akamai'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Imperva': ['incapsula', 'x-iinfo'],
        'F5 BIG-IP': ['x-wa-info', 'f5'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'Barracuda': ['barra_counter_session'],
        'Fortinet': ['fortigate', 'fortiwaf']
    }
    
    headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
    body_lower = response.text.lower() if response.text else ''
    
    for waf_name, signatures in waf_signatures.items():
        for sig in signatures:
            if sig in str(headers_lower) or sig in body_lower:
                return waf_name
    
    return None


def calculate_risk_score(vulnerabilities: List[Dict]) -> int:
    """Calculate overall risk score from vulnerabilities"""
    severity_scores = {
        'critical': 40,
        'high': 25,
        'medium': 10,
        'low': 5,
        'info': 1
    }
    
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()
        total_score += severity_scores.get(severity, 0)
    
    # Normalize to 0-100 scale
    return min(100, total_score)


def get_severity_color(severity: str) -> str:
    """Get color code for severity level"""
    colors = {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#f59e0b',
        'low': '#22c55e',
        'info': '#3b82f6'
    }
    return colors.get(severity.lower(), '#94a3b8')
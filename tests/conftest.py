"""
Pytest Configuration and Fixtures
Shared fixtures for all test modules
"""

import pytest
import os
import sys
import json
import tempfile
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)


# ============================================================
# CONFIGURATION
# ============================================================

def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "live: marks tests that require live network access"
    )
    config.addinivalue_line(
        "markers", "unit: marks unit tests"
    )
    config.addinivalue_line(
        "markers", "integration: marks integration tests"
    )


# ============================================================
# FIXTURES - BASIC
# ============================================================

@pytest.fixture
def test_domain():
    """Test domain fixture"""
    return "example.com"


@pytest.fixture
def test_ip():
    """Test IP address fixture"""
    return "93.184.216.34"


@pytest.fixture
def test_url():
    """Test URL fixture"""
    return "https://example.com"


@pytest.fixture
def test_url_with_params():
    """Test URL with parameters fixture"""
    return "https://example.com/search?q=test&page=1"


@pytest.fixture
def invalid_domain():
    """Invalid domain fixture"""
    return "this-domain-does-not-exist-12345.com"


@pytest.fixture
def invalid_ip():
    """Invalid IP address fixture"""
    return "999.999.999.999"


@pytest.fixture
def localhost():
    """Localhost fixture"""
    return "127.0.0.1"


# ============================================================
# FIXTURES - TEMPORARY FILES/DIRECTORIES
# ============================================================

@pytest.fixture
def temp_dir():
    """Temporary directory fixture"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_wordlist(temp_dir):
    """Temporary wordlist file fixture"""
    wordlist_path = os.path.join(temp_dir, "wordlist.txt")
    words = ["admin", "login", "test", "backup", "config", "api", "dev"]
    
    with open(wordlist_path, 'w') as f:
        f.write('\n'.join(words))
    
    return wordlist_path


@pytest.fixture
def temp_report_dir(temp_dir):
    """Temporary reports directory fixture"""
    reports_dir = os.path.join(temp_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir


# ============================================================
# FIXTURES - MOCK RESPONSES
# ============================================================

@pytest.fixture
def mock_html_response():
    """Mock HTML response fixture"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Test Page</title>
    </head>
    <body>
        <h1>Welcome</h1>
        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>
        <a href="/admin">Admin</a>
        <a href="/about">About</a>
        <script src="/js/main.js"></script>
        <!-- TODO: Remove this comment -->
    </body>
    </html>
    """


@pytest.fixture
def mock_response(mock_html_response):
    """Mock requests.Response fixture"""
    response = Mock()
    response.status_code = 200
    response.text = mock_html_response
    response.content = mock_html_response.encode()
    response.headers = {
        'Content-Type': 'text/html; charset=utf-8',
        'Server': 'Apache/2.4.41',
        'X-Powered-By': 'PHP/7.4.3',
        'Content-Length': str(len(mock_html_response))
    }
    response.url = "https://example.com"
    response.elapsed = Mock()
    response.elapsed.total_seconds = Mock(return_value=0.5)
    response.history = []
    response.cookies = {}
    return response


@pytest.fixture
def mock_response_with_xss():
    """Mock response that reflects XSS payload"""
    html = """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Search Results for: <script>alert(1)</script></h1>
    </body>
    </html>
    """
    response = Mock()
    response.status_code = 200
    response.text = html
    response.content = html.encode()
    response.headers = {'Content-Type': 'text/html'}
    response.url = "https://example.com/search?q=<script>alert(1)</script>"
    return response


@pytest.fixture
def mock_response_with_sql_error():
    """Mock response with SQL error"""
    html = """
    <!DOCTYPE html>
    <html>
    <body>
        <h1>Error</h1>
        <p>You have an error in your SQL syntax; check the manual</p>
    </body>
    </html>
    """
    response = Mock()
    response.status_code = 500
    response.text = html
    response.content = html.encode()
    response.headers = {'Content-Type': 'text/html'}
    return response


@pytest.fixture
def mock_404_response():
    """Mock 404 response fixture"""
    html = "<html><body><h1>404 Not Found</h1></body></html>"
    response = Mock()
    response.status_code = 404
    response.text = html
    response.content = html.encode()
    response.headers = {'Content-Type': 'text/html'}
    return response


@pytest.fixture
def mock_ssl_certificate():
    """Mock SSL certificate fixture"""
    return {
        'subject': ((('commonName', 'example.com'),),),
        'issuer': ((('commonName', 'DigiCert'),),),
        'version': 3,
        'serialNumber': 'ABC123',
        'notBefore': 'Jan  1 00:00:00 2024 GMT',
        'notAfter': 'Dec 31 23:59:59 2024 GMT',
        'subjectAltName': (('DNS', 'example.com'), ('DNS', 'www.example.com'))
    }


# ============================================================
# FIXTURES - MOCK DNS RESPONSES
# ============================================================

@pytest.fixture
def mock_dns_a_record():
    """Mock DNS A record"""
    record = Mock()
    record.__str__ = Mock(return_value="93.184.216.34")
    return record


@pytest.fixture
def mock_dns_mx_record():
    """Mock DNS MX record"""
    record = Mock()
    record.preference = 10
    record.exchange = Mock()
    record.exchange.__str__ = Mock(return_value="mail.example.com.")
    return record


@pytest.fixture
def mock_dns_resolver(mock_dns_a_record, mock_dns_mx_record):
    """Mock DNS resolver"""
    resolver = Mock()
    
    # Mock A record response
    a_response = Mock()
    a_response.__iter__ = Mock(return_value=iter([mock_dns_a_record]))
    a_response.rrset = Mock()
    a_response.rrset.ttl = 3600
    
    # Mock MX record response
    mx_response = Mock()
    mx_response.__iter__ = Mock(return_value=iter([mock_dns_mx_record]))
    mx_response.rrset = Mock()
    mx_response.rrset.ttl = 3600
    
    def resolve_side_effect(domain, record_type):
        if record_type == 'A':
            return a_response
        elif record_type == 'MX':
            return mx_response
        else:
            raise Exception("No record")
    
    resolver.resolve = Mock(side_effect=resolve_side_effect)
    return resolver


# ============================================================
# FIXTURES - SAMPLE DATA
# ============================================================

@pytest.fixture
def sample_vulnerability():
    """Sample vulnerability data"""
    return {
        'id': 'vuln_001',
        'name': 'Test XSS Vulnerability',
        'type': 'XSS',
        'url': 'https://example.com/search',
        'parameter': 'q',
        'method': 'GET',
        'severity': 'high',
        'confidence': 'high',
        'payload': '<script>alert(1)</script>',
        'evidence': 'Payload reflected in response',
        'description': 'Cross-Site Scripting vulnerability detected',
        'remediation': 'Implement proper output encoding'
    }


@pytest.fixture
def sample_port_scan_result():
    """Sample port scan result"""
    return {
        'scan_id': 'port_20240115120000',
        'target': 'example.com',
        'target_ip': '93.184.216.34',
        'open_ports': [
            {'port': 80, 'state': 'open', 'service': 'HTTP'},
            {'port': 443, 'state': 'open', 'service': 'HTTPS'},
            {'port': 22, 'state': 'open', 'service': 'SSH'}
        ],
        'ports_scanned': 1000,
        'open_count': 3,
        'duration': 15.5,
        'success': True
    }


@pytest.fixture
def sample_subdomain_result():
    """Sample subdomain enumeration result"""
    return {
        'scan_id': 'subdomain_20240115120000',
        'domain': 'example.com',
        'subdomains': [
            {'subdomain': 'www', 'full_domain': 'www.example.com', 'alive': True},
            {'subdomain': 'mail', 'full_domain': 'mail.example.com', 'alive': True},
            {'subdomain': 'api', 'full_domain': 'api.example.com', 'alive': True}
        ],
        'total_found': 3,
        'success': True
    }


# ============================================================
# FIXTURES - XSS PAYLOADS
# ============================================================

@pytest.fixture
def xss_payloads():
    """Sample XSS payloads"""
    return [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'"
    ]


# ============================================================
# FIXTURES - SQLI PAYLOADS
# ============================================================

@pytest.fixture
def sqli_payloads():
    """Sample SQL injection payloads"""
    return [
        "'",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--"
    ]


# ============================================================
# FIXTURES - MOCK SESSIONS
# ============================================================

@pytest.fixture
def mock_session(mock_response):
    """Mock requests.Session fixture"""
    session = Mock()
    session.get = Mock(return_value=mock_response)
    session.post = Mock(return_value=mock_response)
    session.head = Mock(return_value=mock_response)
    session.request = Mock(return_value=mock_response)
    session.headers = {}
    session.cookies = Mock()
    session.cookies.update = Mock()
    session.proxies = {}
    session.verify = True
    return session


# ============================================================
# HELPER FUNCTIONS
# ============================================================

@pytest.fixture
def assert_valid_scan_result():
    """Fixture that returns a validation function for scan results"""
    def _validate(result):
        """Validate common scan result structure"""
        assert isinstance(result, dict)
        assert 'success' in result
        assert 'scan_id' in result or 'error' in result
        return True
    return _validate
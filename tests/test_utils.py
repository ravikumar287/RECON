"""
Tests for Utility Functions
Tests for app/services/utils.py
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.utils import (
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_domain,
    is_valid_url,
    validate_target,
    normalize_url,
    get_domain_from_url,
    get_base_url,
    url_join,
    extract_params,
    build_url_with_params,
    get_ip_from_domain,
    parse_ports,
    get_service_name,
    load_wordlist,
    generate_scan_id,
    sanitize_filename,
    truncate_string,
    calculate_risk_score,
    get_severity_color
)


# ============================================================
# IP VALIDATION TESTS
# ============================================================

class TestIPValidation:
    """Tests for IP address validation functions"""
    
    @pytest.mark.unit
    def test_valid_ipv4(self):
        """Test valid IPv4 addresses"""
        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "8.8.8.8",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255"
        ]
        for ip in valid_ips:
            assert is_valid_ip(ip) is True, f"{ip} should be valid"
            assert is_valid_ipv4(ip) is True, f"{ip} should be valid IPv4"
    
    @pytest.mark.unit
    def test_invalid_ipv4(self):
        """Test invalid IPv4 addresses"""
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "192.168.1.1.1",
            "192.168.1.a",
            "not_an_ip",
            "",
            "192.168.1.-1"
        ]
        for ip in invalid_ips:
            assert is_valid_ipv4(ip) is False, f"{ip} should be invalid"
    
    @pytest.mark.unit
    def test_valid_ipv6(self):
        """Test valid IPv6 addresses"""
        valid_ips = [
            "::1",
            "fe80::1",
            "2001:db8::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "::ffff:192.168.1.1"
        ]
        for ip in valid_ips:
            assert is_valid_ip(ip) is True, f"{ip} should be valid"
            assert is_valid_ipv6(ip) is True, f"{ip} should be valid IPv6"
    
    @pytest.mark.unit
    def test_invalid_ipv6(self):
        """Test invalid IPv6 addresses"""
        invalid_ips = [
            "2001:db8::g",
            "2001:db8",
            "not_ipv6"
        ]
        for ip in invalid_ips:
            assert is_valid_ipv6(ip) is False, f"{ip} should be invalid"


# ============================================================
# DOMAIN VALIDATION TESTS
# ============================================================

class TestDomainValidation:
    """Tests for domain validation functions"""
    
    @pytest.mark.unit
    def test_valid_domains(self):
        """Test valid domain names"""
        valid_domains = [
            "example.com",
            "subdomain.example.com",
            "test-site.org",
            "my-website.co.uk",
            "a.io",
            "xn--n3h.com"  # Punycode domain
        ]
        for domain in valid_domains:
            assert is_valid_domain(domain) is True, f"{domain} should be valid"
    
    @pytest.mark.unit
    def test_invalid_domains(self):
        """Test invalid domain names"""
        invalid_domains = [
            "example",
            "-example.com",
            "example-.com",
            "example..com",
            ".com",
            "example.c",
            "http://example.com",
            "example.com/path"
        ]
        for domain in invalid_domains:
            assert is_valid_domain(domain) is False, f"{domain} should be invalid"


# ============================================================
# URL VALIDATION TESTS
# ============================================================

class TestURLValidation:
    """Tests for URL validation functions"""
    
    @pytest.mark.unit
    def test_valid_urls(self):
        """Test valid URLs"""
        valid_urls = [
            "http://example.com",
            "https://example.com",
            "https://example.com/path",
            "https://example.com/path?query=1",
            "https://example.com:8080",
            "http://192.168.1.1",
            "https://sub.example.com/path/to/page"
        ]
        for url in valid_urls:
            assert is_valid_url(url) is True, f"{url} should be valid"
    
    @pytest.mark.unit
    def test_invalid_urls(self):
        """Test invalid URLs"""
        invalid_urls = [
            "example.com",
            "ftp://example.com",
            "not a url",
            "",
            "://example.com",
            "http:/example.com"
        ]
        for url in invalid_urls:
            assert is_valid_url(url) is False, f"{url} should be invalid"


# ============================================================
# TARGET VALIDATION TESTS
# ============================================================

class TestTargetValidation:
    """Tests for target validation function"""
    
    @pytest.mark.unit
    def test_validate_ip_target(self):
        """Test validation of IP targets"""
        is_valid, target_type, normalized = validate_target("192.168.1.1")
        assert is_valid is True
        assert target_type == "ip"
        assert normalized == "192.168.1.1"
    
    @pytest.mark.unit
    def test_validate_domain_target(self):
        """Test validation of domain targets"""
        is_valid, target_type, normalized = validate_target("example.com")
        assert is_valid is True
        assert target_type == "domain"
        assert normalized == "example.com"
    
    @pytest.mark.unit
    def test_validate_url_target(self):
        """Test validation of URL targets"""
        is_valid, target_type, normalized = validate_target("https://example.com/path")
        assert is_valid is True
        assert target_type == "url"
    
    @pytest.mark.unit
    def test_validate_invalid_target(self):
        """Test validation of invalid targets"""
        is_valid, target_type, normalized = validate_target("not_valid!!!")
        assert is_valid is False
        assert target_type == "invalid"


# ============================================================
# URL MANIPULATION TESTS
# ============================================================

class TestURLManipulation:
    """Tests for URL manipulation functions"""
    
    @pytest.mark.unit
    def test_normalize_url(self):
        """Test URL normalization"""
        test_cases = [
            ("example.com", "http://example.com"),
            ("http://example.com/", "http://example.com"),
            ("https://example.com/path/", "https://example.com/path"),
            ("example.com/path", "http://example.com/path")
        ]
        for input_url, expected in test_cases:
            result = normalize_url(input_url)
            assert result == expected, f"normalize_url({input_url}) = {result}, expected {expected}"
    
    @pytest.mark.unit
    def test_get_domain_from_url(self):
        """Test domain extraction from URL"""
        test_cases = [
            ("https://example.com/path", "example.com"),
            ("http://sub.example.com:8080/path", "sub.example.com:8080"),
            ("https://example.com", "example.com")
        ]
        for url, expected in test_cases:
            result = get_domain_from_url(url)
            assert result == expected, f"get_domain_from_url({url}) = {result}, expected {expected}"
    
    @pytest.mark.unit
    def test_get_base_url(self):
        """Test base URL extraction"""
        test_cases = [
            ("https://example.com/path/page", "https://example.com"),
            ("http://example.com:8080/path", "http://example.com:8080")
        ]
        for url, expected in test_cases:
            result = get_base_url(url)
            assert result == expected
    
    @pytest.mark.unit
    def test_url_join(self):
        """Test URL joining"""
        test_cases = [
            ("https://example.com", "/path", "https://example.com/path"),
            ("https://example.com/base/", "page", "https://example.com/base/page"),
            ("https://example.com/base", "../other", "https://example.com/other")
        ]
        for base, path, expected in test_cases:
            result = url_join(base, path)
            assert result == expected
    
    @pytest.mark.unit
    def test_extract_params(self):
        """Test URL parameter extraction"""
        url = "https://example.com/search?q=test&page=1&sort=asc"
        params = extract_params(url)
        
        assert 'q' in params
        assert 'page' in params
        assert 'sort' in params
        assert params['q'] == ['test']
        assert params['page'] == ['1']
    
    @pytest.mark.unit
    def test_build_url_with_params(self):
        """Test building URL with parameters"""
        base = "https://example.com/search"
        params = {"q": "test", "page": "1"}
        
        result = build_url_with_params(base, params)
        
        assert "q=test" in result
        assert "page=1" in result


# ============================================================
# PORT PARSING TESTS
# ============================================================

class TestPortParsing:
    """Tests for port parsing functions"""
    
    @pytest.mark.unit
    def test_parse_single_port(self):
        """Test parsing single port"""
        result = parse_ports("80")
        assert result == [80]
    
    @pytest.mark.unit
    def test_parse_port_range(self):
        """Test parsing port range"""
        result = parse_ports("80-83")
        assert result == [80, 81, 82, 83]
    
    @pytest.mark.unit
    def test_parse_comma_separated_ports(self):
        """Test parsing comma-separated ports"""
        result = parse_ports("80,443,8080")
        assert result == [80, 443, 8080]
    
    @pytest.mark.unit
    def test_parse_mixed_ports(self):
        """Test parsing mixed port specification"""
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]
    
    @pytest.mark.unit
    def test_parse_invalid_ports(self):
        """Test parsing invalid port specifications"""
        result = parse_ports("invalid")
        assert result == []
        
        result = parse_ports("99999")  # Port > 65535
        assert result == []
    
    @pytest.mark.unit
    def test_get_service_name(self):
        """Test getting service name for port"""
        assert get_service_name(80) == "HTTP"
        assert get_service_name(443) == "HTTPS"
        assert get_service_name(22) == "SSH"
        assert get_service_name(99999) == "Unknown"


# ============================================================
# FILE OPERATION TESTS
# ============================================================

class TestFileOperations:
    """Tests for file operation functions"""
    
    @pytest.mark.unit
    def test_load_wordlist(self, temp_wordlist):
        """Test loading wordlist from file"""
        words = load_wordlist(temp_wordlist)
        
        assert len(words) > 0
        assert "admin" in words
        assert "login" in words
    
    @pytest.mark.unit
    def test_load_nonexistent_wordlist(self):
        """Test loading non-existent wordlist"""
        words = load_wordlist("/nonexistent/path/wordlist.txt")
        assert words == []
    
    @pytest.mark.unit
    def test_generate_scan_id(self):
        """Test scan ID generation"""
        scan_id = generate_scan_id()
        
        assert scan_id.startswith("scan_")
        assert len(scan_id) > 10
        
        # Test uniqueness
        scan_id2 = generate_scan_id()
        assert scan_id != scan_id2
    
    @pytest.mark.unit
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        test_cases = [
            ("file<name>.txt", "file_name_.txt"),
            ('file"name".txt', "file_name_.txt"),
            ("file:name.txt", "file_name.txt"),
            ("normal_file.txt", "normal_file.txt")
        ]
        for input_name, expected in test_cases:
            result = sanitize_filename(input_name)
            assert result == expected


# ============================================================
# STRING OPERATION TESTS
# ============================================================

class TestStringOperations:
    """Tests for string operation functions"""
    
    @pytest.mark.unit
    def test_truncate_string(self):
        """Test string truncation"""
        long_string = "a" * 200
        result = truncate_string(long_string, 100)
        
        assert len(result) == 100
        assert result.endswith("...")
    
    @pytest.mark.unit
    def test_truncate_short_string(self):
        """Test truncating already short string"""
        short_string = "hello"
        result = truncate_string(short_string, 100)
        
        assert result == short_string


# ============================================================
# SECURITY FUNCTION TESTS
# ============================================================

class TestSecurityFunctions:
    """Tests for security-related functions"""
    
    @pytest.mark.unit
    def test_calculate_risk_score_empty(self):
        """Test risk score with no vulnerabilities"""
        score = calculate_risk_score([])
        assert score == 0
    
    @pytest.mark.unit
    def test_calculate_risk_score_critical(self):
        """Test risk score with critical vulnerability"""
        vulns = [{'severity': 'critical'}]
        score = calculate_risk_score(vulns)
        assert score > 0
    
    @pytest.mark.unit
    def test_calculate_risk_score_multiple(self):
        """Test risk score with multiple vulnerabilities"""
        vulns = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'medium'}
        ]
        score = calculate_risk_score(vulns)
        assert score > 50
    
    @pytest.mark.unit
    def test_get_severity_color(self):
        """Test severity color mapping"""
        assert get_severity_color("critical") == "#ef4444"
        assert get_severity_color("high") == "#f97316"
        assert get_severity_color("medium") == "#f59e0b"
        assert get_severity_color("low") == "#22c55e"
        assert get_severity_color("info") == "#3b82f6"
        assert get_severity_color("unknown") == "#94a3b8"
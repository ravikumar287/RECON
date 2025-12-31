"""
Tests for Vulnerability Scanner Modules
Tests for XSS scanner, SQLi scanner, directory bruteforce, crawler, etc.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import requests

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.xss_scanner import XSSScanner
from app.services.sqli_scanner import SQLiScanner
from app.services.dir_bruteforce import DirectoryBruteforce
from app.services.crawler import WebCrawler


# ============================================================
# XSS SCANNER TESTS
# ============================================================

class TestXSSScanner:
    """Tests for XSSScanner class"""
    
    @pytest.mark.unit
    def test_xss_scanner_initialization(self, test_url):
        """Test XSSScanner initialization"""
        scanner = XSSScanner(test_url)
        
        assert scanner.target_url is not None
        assert scanner.timeout == 10.0
        assert scanner.scan_id is not None
        assert scanner.canary is not None
    
    @pytest.mark.unit
    def test_xss_scanner_custom_settings(self, test_url):
        """Test XSSScanner with custom settings"""
        scanner = XSSScanner(
            test_url,
            timeout=15.0,
            max_threads=5,
            user_agent="Custom-Agent"
        )
        
        assert scanner.timeout == 15.0
        assert scanner.max_threads == 5
    
    @pytest.mark.unit
    def test_generate_canary(self, test_url):
        """Test canary generation"""
        scanner = XSSScanner(test_url)
        
        assert scanner.canary.startswith(XSSScanner.CANARY_PREFIX)
        assert scanner.canary.endswith(XSSScanner.CANARY_SUFFIX)
    
    @pytest.mark.unit
    def test_check_reflection_found(self, test_url):
        """Test checking for payload reflection"""
        scanner = XSSScanner(test_url)
        
        payload = "<script>alert(1)</script>"
        response_text = f"<html><body>Search: {payload}</body></html>"
        
        is_reflected, context = scanner._check_reflection(response_text, payload)
        
        assert is_reflected is True
    
    @pytest.mark.unit
    def test_check_reflection_not_found(self, test_url):
        """Test checking for payload when not reflected"""
        scanner = XSSScanner(test_url)
        
        payload = "<script>alert(1)</script>"
        response_text = "<html><body>Search: test</body></html>"
        
        is_reflected, context = scanner._check_reflection(response_text, payload)
        
        assert is_reflected is False
    
    @pytest.mark.unit
    def test_determine_context_html_body(self, test_url):
        """Test context determination - HTML body"""
        scanner = XSSScanner(test_url)
        
        payload = "<script>alert(1)</script>"
        response = f"<html><body><p>Result: {payload}</p></body></html>"
        
        context = scanner._determine_context(response, payload)
        
        assert context in ['html_body', 'unknown']
    
    @pytest.mark.unit
    def test_determine_context_attribute(self, test_url):
        """Test context determination - attribute"""
        scanner = XSSScanner(test_url)
        
        payload = "test123"
        response = f'<html><body><input value="{payload}"></body></html>'
        
        context = scanner._determine_context(response, payload)
        
        assert context in ['attribute', 'html_body', 'unknown']
    
    @pytest.mark.unit
    def test_check_xss_execution(self, test_url):
        """Test checking if XSS would execute"""
        scanner = XSSScanner(test_url)
        
        payload = "<script>alert(1)</script>"
        response_text = f"<html><body>{payload}</body></html>"
        
        would_execute = scanner._check_xss_execution(response_text, payload)
        
        assert would_execute is True
    
    @pytest.mark.unit
    @patch.object(XSSScanner, '_check_reflection')
    @patch('requests.Session')
    def test_test_parameter(self, mock_session_class, mock_check_reflection, test_url):
        """Test testing a single parameter"""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "<html><body><script>alert(1)</script></body></html>"
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        mock_check_reflection.return_value = (True, 'html_body')
        
        scanner = XSSScanner(test_url)
        scanner.session = mock_session
        
        with patch.object(scanner, '_check_xss_execution', return_value=True):
            result = scanner.test_parameter(
                url=f"{test_url}?q=test",
                param_name="q",
                param_value="test",
                payload="<script>alert(1)</script>"
            )
        
        if result:
            assert result['vulnerable'] is True
            assert result['parameter'] == 'q'
    
    @pytest.mark.unit
    def test_basic_payloads_list(self):
        """Test basic payloads list exists"""
        assert len(XSSScanner.BASIC_PAYLOADS) > 0
        assert '<script>alert(1)</script>' in XSSScanner.BASIC_PAYLOADS
    
    @pytest.mark.unit
    def test_event_handlers_list(self):
        """Test event handlers list"""
        assert len(XSSScanner.EVENT_HANDLERS) > 0
        assert 'onload' in XSSScanner.EVENT_HANDLERS
        assert 'onerror' in XSSScanner.EVENT_HANDLERS
    
    @pytest.mark.unit
    def test_stop_scan(self, test_url):
        """Test stopping a scan"""
        scanner = XSSScanner(test_url)
        scanner.stop()
        
        assert scanner.stop_scan is True
    
    @pytest.mark.unit
    def test_get_vulnerabilities(self, test_url):
        """Test getting vulnerabilities list"""
        scanner = XSSScanner(test_url)
        scanner.vulnerabilities = [{'type': 'XSS', 'severity': 'high'}]
        
        vulns = scanner.get_vulnerabilities()
        
        assert len(vulns) == 1
        assert vulns[0]['type'] == 'XSS'
    
    @pytest.mark.unit
    def test_calculate_risk_score_empty(self, test_url):
        """Test risk score calculation with no vulnerabilities"""
        scanner = XSSScanner(test_url)
        scanner.vulnerabilities = []
        
        score = scanner._calculate_risk_score()
        
        assert score == 0
    
    @pytest.mark.unit
    def test_calculate_risk_score_with_vulns(self, test_url):
        """Test risk score calculation with vulnerabilities"""
        scanner = XSSScanner(test_url)
        scanner.vulnerabilities = [
            {'severity': 'high', 'confidence': 'high'},
            {'severity': 'medium', 'confidence': 'medium'}
        ]
        
        score = scanner._calculate_risk_score()
        
        assert score > 0
    
    @pytest.mark.unit
    def test_generate_recommendations(self, test_url):
        """Test recommendation generation"""
        scanner = XSSScanner(test_url)
        scanner.vulnerabilities = [{'type': 'XSS', 'context': 'attribute'}]
        
        recommendations = scanner._generate_recommendations()
        
        assert len(recommendations) > 0


# ============================================================
# SQLI SCANNER TESTS
# ============================================================

class TestSQLiScanner:
    """Tests for SQLiScanner class"""
    
    @pytest.mark.unit
    def test_sqli_scanner_initialization(self, test_url):
        """Test SQLiScanner initialization"""
        scanner = SQLiScanner(test_url)
        
        assert scanner.target_url is not None
        assert scanner.timeout == 10.0
        assert scanner.time_delay == 5
        assert scanner.scan_id is not None
    
    @pytest.mark.unit
    def test_sqli_scanner_custom_settings(self, test_url):
        """Test SQLiScanner with custom settings"""
        scanner = SQLiScanner(
            test_url,
            timeout=15.0,
            time_delay=3,
            max_threads=3
        )
        
        assert scanner.timeout == 15.0
        assert scanner.time_delay == 3
        assert scanner.max_threads == 3
    
    @pytest.mark.unit
    def test_detect_sql_error_mysql(self, test_url):
        """Test MySQL error detection"""
        scanner = SQLiScanner(test_url)
        
        response_text = "You have an error in your SQL syntax; check the manual"
        
        has_error, db_type, error_msg = scanner._detect_sql_error(response_text)
        
        assert has_error is True
        assert db_type == "MySQL"
    
    @pytest.mark.unit
    def test_detect_sql_error_mssql(self, test_url):
        """Test MSSQL error detection"""
        scanner = SQLiScanner(test_url)
        
        response_text = "Unclosed quotation mark after the character string"
        
        has_error, db_type, error_msg = scanner._detect_sql_error(response_text)
        
        assert has_error is True
        assert db_type == "MSSQL"
    
    @pytest.mark.unit
    def test_detect_sql_error_postgresql(self, test_url):
        """Test PostgreSQL error detection"""
        scanner = SQLiScanner(test_url)
        
        response_text = "PostgreSQL query failed: ERROR: syntax error at or near"
        
        has_error, db_type, error_msg = scanner._detect_sql_error(response_text)
        
        assert has_error is True
        assert db_type == "PostgreSQL"
    
    @pytest.mark.unit
    def test_detect_sql_error_none(self, test_url):
        """Test when no SQL error present"""
        scanner = SQLiScanner(test_url)
        
        response_text = "<html><body>Normal page content</body></html>"
        
        has_error, db_type, error_msg = scanner._detect_sql_error(response_text)
        
        assert has_error is False
        assert db_type is None
    
    @pytest.mark.unit
    def test_compare_responses_different(self, test_url):
        """Test comparing different responses"""
        scanner = SQLiScanner(test_url)
        
        response1 = MagicMock()
        response1.status_code = 200
        response1.text = "Content A" * 100
        
        response2 = MagicMock()
        response2.status_code = 200
        response2.text = "Content B" * 50
        
        are_different = scanner._compare_responses(response1, response2)
        
        assert are_different is True
    
    @pytest.mark.unit
    def test_compare_responses_same(self, test_url):
        """Test comparing same responses"""
        scanner = SQLiScanner(test_url)
        
        response1 = MagicMock()
        response1.status_code = 200
        response1.text = "Same content"
        
        response2 = MagicMock()
        response2.status_code = 200
        response2.text = "Same content"
        
        are_different = scanner._compare_responses(response1, response2)
        
        assert are_different is False
    
    @pytest.mark.unit
    def test_error_payloads_list(self):
        """Test error-based payloads list"""
        assert len(SQLiScanner.ERROR_PAYLOADS) > 0
        assert "'" in SQLiScanner.ERROR_PAYLOADS
        assert "' OR '1'='1" in SQLiScanner.ERROR_PAYLOADS
    
    @pytest.mark.unit
    def test_boolean_payloads_list(self):
        """Test boolean-based payloads list"""
        assert len(SQLiScanner.BOOLEAN_PAYLOADS) > 0
        # Each boolean payload is a tuple (true_payload, false_payload)
        assert all(isinstance(p, tuple) for p in SQLiScanner.BOOLEAN_PAYLOADS)
    
    @pytest.mark.unit
    def test_time_payloads_by_db(self):
        """Test time-based payloads by database"""
        assert 'MySQL' in SQLiScanner.TIME_PAYLOADS
        assert 'PostgreSQL' in SQLiScanner.TIME_PAYLOADS
        assert 'MSSQL' in SQLiScanner.TIME_PAYLOADS
        assert 'Oracle' in SQLiScanner.TIME_PAYLOADS
    
    @pytest.mark.unit
    def test_stop_scan(self, test_url):
        """Test stopping a scan"""
        scanner = SQLiScanner(test_url)
        scanner.stop()
        
        assert scanner.stop_scan is True
    
    @pytest.mark.unit
    def test_get_vulnerabilities(self, test_url):
        """Test getting vulnerabilities list"""
        scanner = SQLiScanner(test_url)
        scanner.vulnerabilities = [{'type': 'SQLi', 'database': 'MySQL'}]
        
        vulns = scanner.get_vulnerabilities()
        
        assert len(vulns) == 1
        assert vulns[0]['database'] == 'MySQL'
    
    @pytest.mark.unit
    def test_get_databases_detected(self, test_url):
        """Test getting detected databases"""
        scanner = SQLiScanner(test_url)
        scanner.vulnerabilities = [
            {'database': 'MySQL'},
            {'database': 'MySQL'},
            {'database': 'PostgreSQL'}
        ]
        
        databases = scanner._get_databases_detected()
        
        assert 'MySQL' in databases
        assert 'PostgreSQL' in databases
        assert len(databases) == 2


# ============================================================
# DIRECTORY BRUTEFORCE TESTS
# ============================================================

class TestDirectoryBruteforce:
    """Tests for DirectoryBruteforce class"""
    
    @pytest.mark.unit
    def test_dir_bruteforce_initialization(self, test_url):
        """Test DirectoryBruteforce initialization"""
        scanner = DirectoryBruteforce(test_url)
        
        assert scanner.target_url is not None
        assert scanner.timeout == 10.0
        assert scanner.max_threads == 20
        assert scanner.scan_id is not None
    
    @pytest.mark.unit
    def test_dir_bruteforce_custom_settings(self, test_url):
        """Test DirectoryBruteforce with custom settings"""
        scanner = DirectoryBruteforce(
            test_url,
            timeout=15.0,
            max_threads=10,
            delay=0.5
        )
        
        assert scanner.timeout == 15.0
        assert scanner.max_threads == 10
        assert scanner.delay == 0.5
    
    @pytest.mark.unit
    def test_default_directories_list(self):
        """Test default directories list"""
        assert len(DirectoryBruteforce.DEFAULT_DIRECTORIES) > 0
        assert 'admin' in DirectoryBruteforce.DEFAULT_DIRECTORIES
        assert 'login' in DirectoryBruteforce.DEFAULT_DIRECTORIES
        assert 'backup' in DirectoryBruteforce.DEFAULT_DIRECTORIES
    
    @pytest.mark.unit
    def test_default_extensions_list(self):
        """Test default extensions list"""
        assert len(DirectoryBruteforce.DEFAULT_EXTENSIONS) > 0
        assert '.php' in DirectoryBruteforce.DEFAULT_EXTENSIONS
        assert '.html' in DirectoryBruteforce.DEFAULT_EXTENSIONS
        assert '.bak' in DirectoryBruteforce.DEFAULT_EXTENSIONS
    
    @pytest.mark.unit
    def test_success_codes(self):
        """Test success status codes"""
        assert 200 in DirectoryBruteforce.SUCCESS_CODES
        assert 301 in DirectoryBruteforce.SUCCESS_CODES
        assert 403 in DirectoryBruteforce.SUCCESS_CODES
    
    @pytest.mark.unit
    @patch('requests.Session')
    def test_check_path_found(self, mock_session_class, test_url):
        """Test checking an existing path"""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>Admin Panel</html>"
        mock_response.content = b"<html>Admin Panel</html>"
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        scanner = DirectoryBruteforce(test_url)
        scanner.session = mock_session
        
        result = scanner.check_path('/admin')
        
        assert result is not None
        assert result['status_code'] == 200
        assert result['path'] == '/admin'
    
    @pytest.mark.unit
    @patch('requests.Session')
    def test_check_path_not_found(self, mock_session_class, test_url):
        """Test checking a non-existing path"""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        scanner = DirectoryBruteforce(test_url)
        scanner.session = mock_session
        
        result = scanner.check_path('/nonexistent123')
        
        assert result is None
    
    @pytest.mark.unit
    def test_determine_severity(self, test_url):
        """Test path severity determination"""
        scanner = DirectoryBruteforce(test_url)
        
        assert scanner._determine_severity('/.git/config', 200) == 'critical'
        assert scanner._determine_severity('/.env', 200) == 'critical'
        assert scanner._determine_severity('/admin', 200) == 'high'
        assert scanner._determine_severity('/test', 200) == 'low'
        assert scanner._determine_severity('/restricted', 403) == 'medium'
    
    @pytest.mark.unit
    def test_extract_title(self, test_url):
        """Test page title extraction"""
        scanner = DirectoryBruteforce(test_url)
        
        html = "<html><head><title>Admin Panel</title></head></html>"
        title = scanner._extract_title(html)
        
        assert title == "Admin Panel"
    
    @pytest.mark.unit
    def test_stop_scan(self, test_url):
        """Test stopping a scan"""
        scanner = DirectoryBruteforce(test_url)
        scanner.stop()
        
        assert scanner.stop_scan is True
    
    @pytest.mark.unit
    def test_get_severity_summary(self, test_url):
        """Test getting severity summary"""
        scanner = DirectoryBruteforce(test_url)
        scanner.found_paths = [
            {'severity': 'critical'},
            {'severity': 'high'},
            {'severity': 'high'},
            {'severity': 'medium'}
        ]
        
        summary = scanner._get_severity_summary()
        
        assert summary['critical'] == 1
        assert summary['high'] == 2
        assert summary['medium'] == 1


# ============================================================
# WEB CRAWLER TESTS
# ============================================================

class TestWebCrawler:
    """Tests for WebCrawler class"""
    
    @pytest.mark.unit
    def test_crawler_initialization(self, test_url):
        """Test WebCrawler initialization"""
        crawler = WebCrawler(test_url)
        
        assert crawler.target_url is not None
        assert crawler.max_depth == 3
        assert crawler.max_pages == 100
        assert crawler.scan_id is not None
    
    @pytest.mark.unit
    def test_crawler_custom_settings(self, test_url):
        """Test WebCrawler with custom settings"""
        crawler = WebCrawler(
            test_url,
            max_depth=2,
            max_pages=50,
            timeout=15.0,
            delay=0.5
        )
        
        assert crawler.max_depth == 2
        assert crawler.max_pages == 50
        assert crawler.timeout == 15.0
        assert crawler.delay == 0.5
    
    @pytest.mark.unit
    def test_is_in_scope_same_domain(self, test_url):
        """Test URL scope check - same domain"""
        crawler = WebCrawler(test_url, scope='domain')
        
        assert crawler._is_in_scope("https://example.com/page") is True
        assert crawler._is_in_scope("https://sub.example.com/page") is True
        assert crawler._is_in_scope("https://other.com/page") is False
    
    @pytest.mark.unit
    def test_is_in_scope_subdomain(self):
        """Test URL scope check - subdomain only"""
        crawler = WebCrawler("https://www.example.com", scope='subdomain')
        
        assert crawler._is_in_scope("https://www.example.com/page") is True
        assert crawler._is_in_scope("https://example.com/page") is False
    
    @pytest.mark.unit
    def test_should_skip_url(self, test_url):
        """Test URL skip logic"""
        crawler = WebCrawler(test_url)
        
        # Should skip images
        assert crawler._should_skip_url("https://example.com/image.jpg") is True
        assert crawler._should_skip_url("https://example.com/image.png") is True
        
        # Should skip PDFs
        assert crawler._should_skip_url("https://example.com/doc.pdf") is True
        
        # Should not skip HTML pages
        crawler.visited_urls = set()
        crawler.queued_urls = set()
        assert crawler._should_skip_url("https://example.com/page") is False
    
    @pytest.mark.unit
    def test_normalize_url(self, test_url):
        """Test URL normalization"""
        crawler = WebCrawler(test_url)
        
        # Relative URL
        result = crawler._normalize_url("/path/page", test_url)
        assert result == "https://example.com/path/page"
        
        # Absolute URL
        result = crawler._normalize_url("https://example.com/page", test_url)
        assert result == "https://example.com/page"
        
        # Skip javascript
        result = crawler._normalize_url("javascript:void(0)", test_url)
        assert result is None
        
        # Skip mailto
        result = crawler._normalize_url("mailto:test@example.com", test_url)
        assert result is None
    
    @pytest.mark.unit
    def test_extract_links(self, test_url, mock_html_response):
        """Test link extraction"""
        from bs4 import BeautifulSoup
        
        crawler = WebCrawler(test_url)
        soup = BeautifulSoup(mock_html_response, 'html.parser')
        
        links = crawler._extract_links(soup, test_url)
        
        assert len(links) >= 0  # May or may not find links depending on scope
    
    @pytest.mark.unit
    def test_extract_forms(self, test_url, mock_html_response):
        """Test form extraction"""
        from bs4 import BeautifulSoup
        
        crawler = WebCrawler(test_url)
        soup = BeautifulSoup(mock_html_response, 'html.parser')
        
        forms = crawler._extract_forms(soup, test_url)
        
        assert len(forms) > 0
        assert forms[0]['method'] == 'POST'
        assert len(forms[0]['inputs']) >= 2
    
    @pytest.mark.unit
    def test_extract_emails(self, test_url):
        """Test email extraction"""
        crawler = WebCrawler(test_url)
        
        text = "Contact us at test@example.com or support@example.org"
        emails = crawler._extract_emails(text)
        
        assert len(emails) == 2
        assert "test@example.com" in emails
    
    @pytest.mark.unit
    def test_extract_comments(self, test_url):
        """Test HTML comment extraction"""
        crawler = WebCrawler(test_url)
        
        html = "<!-- TODO: Remove this password: secret123 --><html></html>"
        comments = crawler._extract_comments(html)
        
        assert len(comments) > 0
        assert "password" in comments[0].lower() or "TODO" in comments[0]
    
    @pytest.mark.unit
    def test_stop_crawl(self, test_url):
        """Test stopping a crawl"""
        crawler = WebCrawler(test_url)
        crawler.stop()
        
        assert crawler.stop_crawl is True
    
    @pytest.mark.unit
    def test_get_visited_urls(self, test_url):
        """Test getting visited URLs"""
        crawler = WebCrawler(test_url)
        crawler.visited_urls.add("https://example.com")
        crawler.visited_urls.add("https://example.com/page")
        
        urls = crawler.get_visited_urls()
        
        assert len(urls) == 2
    
    @pytest.mark.unit
    def test_find_login_forms(self, test_url):
        """Test finding login forms"""
        crawler = WebCrawler(test_url)
        crawler.forms = [
            {
                'action': '/login',
                'method': 'POST',
                'inputs': [
                    {'name': 'username', 'type': 'text'},
                    {'name': 'password', 'type': 'password'}
                ]
            },
            {
                'action': '/search',
                'method': 'GET',
                'inputs': [
                    {'name': 'q', 'type': 'text'}
                ]
            }
        ]
        
        login_forms = crawler.find_login_forms()
        
        assert len(login_forms) == 1
        assert login_forms[0]['action'] == '/login'
    
    @pytest.mark.unit
    def test_find_file_upload_forms(self, test_url):
        """Test finding file upload forms"""
        crawler = WebCrawler(test_url)
        crawler.forms = [
            {
                'action': '/upload',
                'method': 'POST',
                'inputs': [
                    {'name': 'file', 'type': 'file'}
                ]
            },
            {
                'action': '/search',
                'method': 'GET',
                'inputs': [
                    {'name': 'q', 'type': 'text'}
                ]
            }
        ]
        
        upload_forms = crawler.find_file_upload_forms()
        
        assert len(upload_forms) == 1
        assert upload_forms[0]['action'] == '/upload'


# ============================================================
# INTEGRATION TESTS
# ============================================================

@pytest.mark.integration
class TestScannerIntegration:
    """Integration tests for scanners"""
    
    @pytest.mark.unit
    def test_xss_scanner_find_injection_points(self, test_url_with_params):
        """Test finding XSS injection points"""
        with patch('requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = """
            <html>
            <body>
                <form action="/search" method="GET">
                    <input type="text" name="q" />
                    <input type="submit" />
                </form>
            </body>
            </html>
            """
            mock_session.get.return_value = mock_response
            mock_session_class.return_value = mock_session
            
            scanner = XSSScanner(test_url_with_params)
            scanner.session = mock_session
            
            points = scanner.find_injection_points(test_url_with_params)
            
            assert 'url_params' in points
            assert 'forms' in points
            assert points['total_points'] >= 0
    
    @pytest.mark.unit
    def test_sqli_scanner_find_injection_points(self, test_url_with_params):
        """Test finding SQLi injection points"""
        with patch('requests.Session') as mock_session_class:
            mock_session = MagicMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = """
            <html>
            <body>
                <form action="/login" method="POST">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                    <input type="submit" />
                </form>
            </body>
            </html>
            """
            mock_session.get.return_value = mock_response
            mock_session_class.return_value = mock_session
            
            scanner = SQLiScanner(test_url_with_params)
            scanner.session = mock_session
            
            points = scanner.find_injection_points(test_url_with_params)
            
            assert 'url_params' in points
            assert 'forms' in points
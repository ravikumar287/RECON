"""
HTTP Header Analyzer Service
Analyzes HTTP headers for security issues and misconfigurations
"""

import requests
from typing import Dict, List, Optional, Any
from datetime import datetime
import re

from app.services.utils import (
    normalize_url,
    make_request,
    generate_scan_id,
    detect_waf
)


class HeaderAnalyzer:
    """
    HTTP Header Analyzer for security assessment
    
    Features:
    - Security header analysis
    - Missing header detection
    - Header misconfiguration detection
    - Cookie security analysis
    - CORS configuration check
    - Content Security Policy analysis
    """
    
    # Required security headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HTTP Strict Transport Security (HSTS)',
            'severity': 'high',
            'recommendation': 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"'
        },
        'Content-Security-Policy': {
            'description': 'Content Security Policy (CSP)',
            'severity': 'high',
            'recommendation': 'Implement a strict Content Security Policy'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME type sniffing',
            'severity': 'medium',
            'recommendation': 'Add "X-Content-Type-Options: nosniff"'
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'severity': 'medium',
            'recommendation': 'Add "X-Frame-Options: DENY" or "SAMEORIGIN"'
        },
        'X-XSS-Protection': {
            'description': 'XSS filter (deprecated but still useful)',
            'severity': 'low',
            'recommendation': 'Add "X-XSS-Protection: 1; mode=block"'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'severity': 'low',
            'recommendation': 'Add "Referrer-Policy: strict-origin-when-cross-origin"'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features',
            'severity': 'low',
            'recommendation': 'Implement Permissions-Policy to restrict browser features'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'description': 'Controls cross-domain policies for Flash/PDF',
            'severity': 'low',
            'recommendation': 'Add "X-Permitted-Cross-Domain-Policies: none"'
        }
    }
    
    # Headers that should not be present (information disclosure)
    INSECURE_HEADERS = {
        'Server': {
            'description': 'Reveals server software',
            'severity': 'info',
            'recommendation': 'Remove or obfuscate the Server header'
        },
        'X-Powered-By': {
            'description': 'Reveals technology stack',
            'severity': 'info',
            'recommendation': 'Remove the X-Powered-By header'
        },
        'X-AspNet-Version': {
            'description': 'Reveals ASP.NET version',
            'severity': 'low',
            'recommendation': 'Remove the X-AspNet-Version header'
        },
        'X-AspNetMvc-Version': {
            'description': 'Reveals ASP.NET MVC version',
            'severity': 'low',
            'recommendation': 'Remove the X-AspNetMvc-Version header'
        }
    }
    
    def __init__(self, url: str, timeout: int = 10):
        """
        Initialize Header Analyzer
        
        Args:
            url: Target URL
            timeout: Request timeout
        """
        self.url = normalize_url(url)
        self.timeout = timeout
        self.scan_id = generate_scan_id()
    
    def analyze(self) -> Dict[str, Any]:
        """
        Analyze HTTP headers
        
        Returns:
            Dict with analysis results
        """
        start_time = datetime.now()
        
        result = {
            'success': False,
            'scan_id': self.scan_id,
            'url': self.url,
            'headers': {},
            'security_headers': {
                'present': [],
                'missing': [],
                'misconfigured': []
            },
            'information_disclosure': [],
            'cookies': [],
            'cors': {},
            'csp_analysis': {},
            'score': 0,
            'grade': 'F',
            'issues': [],
            'recommendations': [],
            'error': None
        }
        
        try:
            response = make_request(self.url, timeout=self.timeout)
            
            if not response:
                result['error'] = 'Failed to connect to target'
                return result
            
            # Store all headers
            result['headers'] = dict(response.headers)
            result['status_code'] = response.status_code
            
            # Analyze security headers
            self._analyze_security_headers(response.headers, result)
            
            # Check for information disclosure
            self._analyze_disclosure_headers(response.headers, result)
            
            # Analyze cookies
            self._analyze_cookies(response, result)
            
            # Analyze CORS
            self._analyze_cors(response.headers, result)
            
            # Analyze CSP
            self._analyze_csp(response.headers, result)
            
            # Detect WAF
            result['waf'] = detect_waf(response)
            
            # Calculate score
            result['score'] = self._calculate_score(result)
            result['grade'] = self._calculate_grade(result['score'])
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        end_time = datetime.now()
        result['duration'] = (end_time - start_time).total_seconds()
        result['timestamp'] = datetime.now().isoformat()
        
        return result
    
    def _analyze_security_headers(self, headers: Dict, result: Dict) -> None:
        """Analyze security headers"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, info in self.SECURITY_HEADERS.items():
            header_lower = header.lower()
            
            if header_lower in headers_lower:
                value = headers_lower[header_lower]
                
                # Check for misconfiguration
                misconfigured = self._check_header_config(header, value)
                
                if misconfigured:
                    result['security_headers']['misconfigured'].append({
                        'header': header,
                        'value': value,
                        'issue': misconfigured,
                        'severity': info['severity']
                    })
                    result['issues'].append({
                        'type': 'misconfigured_header',
                        'header': header,
                        'issue': misconfigured,
                        'severity': info['severity']
                    })
                else:
                    result['security_headers']['present'].append({
                        'header': header,
                        'value': value,
                        'description': info['description']
                    })
            else:
                result['security_headers']['missing'].append({
                    'header': header,
                    'description': info['description'],
                    'severity': info['severity'],
                    'recommendation': info['recommendation']
                })
                result['recommendations'].append(info['recommendation'])
    
    def _check_header_config(self, header: str, value: str) -> Optional[str]:
        """Check header for misconfigurations"""
        header_lower = header.lower()
        value_lower = value.lower()
        
        if header_lower == 'strict-transport-security':
            # Check max-age
            match = re.search(r'max-age=(\d+)', value_lower)
            if match:
                max_age = int(match.group(1))
                if max_age < 31536000:  # Less than 1 year
                    return f'max-age too short ({max_age}s). Should be at least 31536000 (1 year)'
            else:
                return 'Missing max-age directive'
        
        elif header_lower == 'x-frame-options':
            if value_lower not in ['deny', 'sameorigin']:
                if not value_lower.startswith('allow-from'):
                    return f'Invalid value "{value}". Use DENY or SAMEORIGIN'
        
        elif header_lower == 'x-content-type-options':
            if value_lower != 'nosniff':
                return f'Invalid value "{value}". Should be "nosniff"'
        
        elif header_lower == 'x-xss-protection':
            if '0' in value_lower and 'mode=block' not in value_lower:
                return 'XSS protection is disabled'
        
        elif header_lower == 'referrer-policy':
            valid_values = [
                'no-referrer', 'no-referrer-when-downgrade', 'origin',
                'origin-when-cross-origin', 'same-origin', 'strict-origin',
                'strict-origin-when-cross-origin', 'unsafe-url'
            ]
            if value_lower not in valid_values:
                return f'Invalid value "{value}"'
        
        return None
    
    def _analyze_disclosure_headers(self, headers: Dict, result: Dict) -> None:
        """Analyze headers that may disclose information"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, info in self.INSECURE_HEADERS.items():
            header_lower = header.lower()
            
            if header_lower in headers_lower:
                value = headers_lower[header_lower]
                
                result['information_disclosure'].append({
                    'header': header,
                    'value': value,
                    'description': info['description'],
                    'severity': info['severity'],
                    'recommendation': info['recommendation']
                })
                
                result['issues'].append({
                    'type': 'information_disclosure',
                    'header': header,
                    'value': value,
                    'severity': info['severity']
                })
    
    def _analyze_cookies(self, response: requests.Response, result: Dict) -> None:
        """Analyze cookie security"""
        for cookie in response.cookies:
            cookie_info = {
                'name': cookie.name,
                'value': cookie.value[:50] + '...' if len(cookie.value) > 50 else cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('httponly') or 'httponly' in str(cookie).lower(),
                'samesite': self._get_samesite(cookie),
                'expires': cookie.expires,
                'issues': []
            }
            
            # Check for security issues
            is_https = self.url.startswith('https')
            
            if is_https and not cookie.secure:
                cookie_info['issues'].append({
                    'issue': 'Missing Secure flag',
                    'severity': 'medium',
                    'description': 'Cookie can be sent over unencrypted connections'
                })
            
            if not cookie_info['httponly']:
                # Check if cookie looks sensitive
                sensitive_patterns = ['session', 'auth', 'token', 'csrf', 'jwt']
                if any(p in cookie.name.lower() for p in sensitive_patterns):
                    cookie_info['issues'].append({
                        'issue': 'Missing HttpOnly flag',
                        'severity': 'medium',
                        'description': 'Sensitive cookie accessible via JavaScript'
                    })
            
            if not cookie_info['samesite']:
                cookie_info['issues'].append({
                    'issue': 'Missing SameSite attribute',
                    'severity': 'low',
                    'description': 'Cookie may be vulnerable to CSRF attacks'
                })
            
            result['cookies'].append(cookie_info)
    
    def _get_samesite(self, cookie) -> Optional[str]:
        """Extract SameSite attribute from cookie"""
        cookie_str = str(cookie).lower()
        
        if 'samesite=strict' in cookie_str:
            return 'Strict'
        elif 'samesite=lax' in cookie_str:
            return 'Lax'
        elif 'samesite=none' in cookie_str:
            return 'None'
        
        return None
    
    def _analyze_cors(self, headers: Dict, result: Dict) -> None:
        """Analyze CORS configuration"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        cors_info = {
            'enabled': False,
            'allow_origin': None,
            'allow_credentials': False,
            'allow_methods': [],
            'allow_headers': [],
            'expose_headers': [],
            'max_age': None,
            'issues': []
        }
        
        if 'access-control-allow-origin' in headers_lower:
            cors_info['enabled'] = True
            cors_info['allow_origin'] = headers_lower['access-control-allow-origin']
            
            # Check for wildcard
            if cors_info['allow_origin'] == '*':
                cors_info['issues'].append({
                    'issue': 'Wildcard CORS origin',
                    'severity': 'medium',
                    'description': 'Any origin can make requests to this resource'
                })
        
        if 'access-control-allow-credentials' in headers_lower:
            cors_info['allow_credentials'] = headers_lower['access-control-allow-credentials'].lower() == 'true'
            
            # Check for dangerous combination
            if cors_info['allow_credentials'] and cors_info['allow_origin'] == '*':
                cors_info['issues'].append({
                    'issue': 'Wildcard origin with credentials',
                    'severity': 'high',
                    'description': 'This configuration is invalid and dangerous'
                })
        
        if 'access-control-allow-methods' in headers_lower:
            cors_info['allow_methods'] = [
                m.strip() for m in headers_lower['access-control-allow-methods'].split(',')
            ]
        
        if 'access-control-allow-headers' in headers_lower:
            cors_info['allow_headers'] = [
                h.strip() for h in headers_lower['access-control-allow-headers'].split(',')
            ]
        
        if 'access-control-expose-headers' in headers_lower:
            cors_info['expose_headers'] = [
                h.strip() for h in headers_lower['access-control-expose-headers'].split(',')
            ]
        
        if 'access-control-max-age' in headers_lower:
            try:
                cors_info['max_age'] = int(headers_lower['access-control-max-age'])
            except ValueError:
                pass
        
        result['cors'] = cors_info
    
    def _analyze_csp(self, headers: Dict, result: Dict) -> None:
        """Analyze Content Security Policy"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        csp_info = {
            'present': False,
            'policy': None,
            'directives': {},
            'issues': [],
            'score': 0
        }
        
        csp_header = headers_lower.get('content-security-policy')
        if not csp_header:
            csp_header = headers_lower.get('content-security-policy-report-only')
            if csp_header:
                csp_info['report_only'] = True
        
        if csp_header:
            csp_info['present'] = True
            csp_info['policy'] = csp_header
            
            # Parse directives
            for directive in csp_header.split(';'):
                directive = directive.strip()
                if directive:
                    parts = directive.split(None, 1)
                    if len(parts) == 2:
                        csp_info['directives'][parts[0]] = parts[1]
                    elif len(parts) == 1:
                        csp_info['directives'][parts[0]] = ''
            
            # Check for issues
            directives = csp_info['directives']
            
            if 'default-src' not in directives:
                csp_info['issues'].append({
                    'issue': 'Missing default-src directive',
                    'severity': 'medium'
                })
            
            # Check for unsafe directives
            for directive, value in directives.items():
                if "'unsafe-inline'" in value:
                    csp_info['issues'].append({
                        'issue': f"'unsafe-inline' in {directive}",
                        'severity': 'medium',
                        'description': 'Allows inline scripts/styles, weakening CSP'
                    })
                
                if "'unsafe-eval'" in value:
                    csp_info['issues'].append({
                        'issue': f"'unsafe-eval' in {directive}",
                        'severity': 'high',
                        'description': 'Allows eval(), significantly weakening CSP'
                    })
                
                if '*' in value and value.strip() != "'*'":
                    csp_info['issues'].append({
                        'issue': f'Wildcard in {directive}',
                        'severity': 'medium',
                        'description': 'Wildcard allows loading from any source'
                    })
            
            # Calculate CSP score
            csp_info['score'] = self._calculate_csp_score(csp_info)
        
        result['csp_analysis'] = csp_info
    
    def _calculate_csp_score(self, csp_info: Dict) -> int:
        """Calculate CSP effectiveness score"""
        score = 100
        
        directives = csp_info.get('directives', {})
        
        # Deduct for missing important directives
        important_directives = ['default-src', 'script-src', 'style-src', 'img-src', 'object-src']
        for directive in important_directives:
            if directive not in directives:
                score -= 10
        
        # Deduct for issues
        for issue in csp_info.get('issues', []):
            if issue.get('severity') == 'high':
                score -= 20
            elif issue.get('severity') == 'medium':
                score -= 10
            else:
                score -= 5
        
        return max(0, score)
    
    def _calculate_score(self, result: Dict) -> int:
        """Calculate overall security score"""
        score = 100
        
        # Deduct for missing headers
        missing = result['security_headers']['missing']
        for header in missing:
            if header['severity'] == 'high':
                score -= 15
            elif header['severity'] == 'medium':
                score -= 10
            else:
                score -= 5
        
        # Deduct for misconfigured headers
        for header in result['security_headers']['misconfigured']:
            if header['severity'] == 'high':
                score -= 10
            else:
                score -= 5
        
        # Deduct for information disclosure
        for disclosure in result['information_disclosure']:
            score -= 3
        
        # Deduct for cookie issues
        for cookie in result['cookies']:
            for issue in cookie.get('issues', []):
                if issue['severity'] == 'high':
                    score -= 10
                elif issue['severity'] == 'medium':
                    score -= 5
                else:
                    score -= 2
        
        # Deduct for CORS issues
        for issue in result['cors'].get('issues', []):
            if issue['severity'] == 'high':
                score -= 15
            elif issue['severity'] == 'medium':
                score -= 10
        
        return max(0, score)
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate grade from score"""
        if score >= 90:
            return 'A+'
        elif score >= 80:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 60:
            return 'C'
        elif score >= 50:
            return 'D'
        else:
            return 'F'
    
    def check_security_headers(self) -> Dict[str, Any]:
        """Quick check for security headers only"""
        return self.analyze()
    
    def get_missing_headers(self) -> List[str]:
        """Get list of missing security headers"""
        result = self.analyze()
        if result['success']:
            return [h['header'] for h in result['security_headers']['missing']]
        return []
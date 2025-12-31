"""
Technology Detection Service
Identifies technologies, frameworks, CMS, and server software
"""

import re
import requests
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from urllib.parse import urlparse
import hashlib
import json

from app.services.utils import (
    normalize_url,
    make_request,
    generate_scan_id,
    get_base_url
)


class TechDetector:
    """
    Technology Detection Service
    
    Features:
    - Web server identification
    - CMS detection (WordPress, Joomla, Drupal, etc.)
    - Framework detection
    - JavaScript library detection
    - Programming language hints
    - CDN detection
    - Analytics and tracking detection
    """
    
    # Technology signatures
    SIGNATURES = {
        # CMS
        'wordpress': {
            'headers': {'x-powered-by': r'wordpress', 'link': r'wp-json'},
            'html': [r'/wp-content/', r'/wp-includes/', r'wp-embed\.min\.js', r'wordpress'],
            'meta': {'generator': r'wordpress'}
        },
        'joomla': {
            'headers': {},
            'html': [r'/media/jui/', r'/media/system/', r'joomla'],
            'meta': {'generator': r'joomla'}
        },
        'drupal': {
            'headers': {'x-drupal-cache': r'.*', 'x-generator': r'drupal'},
            'html': [r'drupal\.js', r'/sites/default/files/', r'drupal\.settings'],
            'meta': {'generator': r'drupal'}
        },
        'magento': {
            'headers': {},
            'html': [r'/skin/frontend/', r'mage/', r'magento', r'/js/mage/'],
            'cookies': ['frontend', 'adminhtml']
        },
        'shopify': {
            'headers': {'x-shopify-stage': r'.*'},
            'html': [r'cdn\.shopify\.com', r'shopify\.com', r'Shopify\.theme'],
            'meta': {}
        },
        'wix': {
            'headers': {'x-wix-request-id': r'.*'},
            'html': [r'wix\.com', r'wixstatic\.com', r'_wix_browser_sess'],
            'meta': {'generator': r'wix'}
        },
        'squarespace': {
            'headers': {},
            'html': [r'squarespace\.com', r'static\.squarespace', r'squarespace-cdn'],
            'meta': {'generator': r'squarespace'}
        },
        
        # Frameworks
        'laravel': {
            'headers': {},
            'html': [r'laravel', r'csrf-token'],
            'cookies': ['laravel_session', 'XSRF-TOKEN']
        },
        'django': {
            'headers': {},
            'html': [r'csrfmiddlewaretoken', r'__admin_media_prefix__'],
            'cookies': ['csrftoken', 'django_language']
        },
        'ruby_on_rails': {
            'headers': {'x-powered-by': r'phusion passenger', 'x-runtime': r'\d+'},
            'html': [r'csrf-token', r'csrf-param', r'authenticity_token'],
            'meta': {'csrf-token': r'.*'}
        },
        'express': {
            'headers': {'x-powered-by': r'express'},
            'html': [],
            'meta': {}
        },
        'asp_net': {
            'headers': {'x-powered-by': r'asp\.net', 'x-aspnet-version': r'.*'},
            'html': [r'__VIEWSTATE', r'__EVENTVALIDATION', r'aspnetForm'],
            'cookies': ['ASP.NET_SessionId', 'ASPSESSIONID']
        },
        'flask': {
            'headers': {},
            'html': [],
            'cookies': ['session']
        },
        'spring': {
            'headers': {},
            'html': [r'springframework', r'spring-security'],
            'cookies': ['JSESSIONID']
        },
        
        # JavaScript Frameworks
        'react': {
            'headers': {},
            'html': [r'react\.js', r'react\.min\.js', r'react-dom', r'_reactRoot', r'data-reactroot'],
            'meta': {}
        },
        'angular': {
            'headers': {},
            'html': [r'angular\.js', r'angular\.min\.js', r'ng-app', r'ng-controller', r'ng-version'],
            'meta': {}
        },
        'vue': {
            'headers': {},
            'html': [r'vue\.js', r'vue\.min\.js', r'v-cloak', r'vue-router', r'data-v-'],
            'meta': {}
        },
        'jquery': {
            'headers': {},
            'html': [r'jquery\.js', r'jquery\.min\.js', r'jquery-\d'],
            'meta': {}
        },
        'bootstrap': {
            'headers': {},
            'html': [r'bootstrap\.js', r'bootstrap\.min\.js', r'bootstrap\.css', r'bootstrap\.min\.css'],
            'meta': {}
        },
        'next_js': {
            'headers': {'x-powered-by': r'next\.js'},
            'html': [r'_next/', r'__NEXT_DATA__'],
            'meta': {}
        },
        'nuxt': {
            'headers': {},
            'html': [r'_nuxt/', r'__NUXT__'],
            'meta': {}
        },
        
        # Web Servers
        'nginx': {
            'headers': {'server': r'nginx'},
            'html': [],
            'meta': {}
        },
        'apache': {
            'headers': {'server': r'apache'},
            'html': [],
            'meta': {}
        },
        'iis': {
            'headers': {'server': r'microsoft-iis', 'x-powered-by': r'asp\.net'},
            'html': [],
            'meta': {}
        },
        'litespeed': {
            'headers': {'server': r'litespeed'},
            'html': [],
            'meta': {}
        },
        'cloudflare': {
            'headers': {'server': r'cloudflare', 'cf-ray': r'.*'},
            'html': [],
            'meta': {}
        },
        
        # Programming Languages
        'php': {
            'headers': {'x-powered-by': r'php', 'set-cookie': r'phpsessid'},
            'html': [r'\.php'],
            'cookies': ['PHPSESSID']
        },
        'java': {
            'headers': {'x-powered-by': r'servlet', 'set-cookie': r'jsessionid'},
            'html': [r'\.jsp', r'\.jsf'],
            'cookies': ['JSESSIONID']
        },
        'python': {
            'headers': {'x-powered-by': r'python', 'server': r'python|gunicorn|uwsgi'},
            'html': [],
            'meta': {}
        },
        'node_js': {
            'headers': {'x-powered-by': r'express'},
            'html': [],
            'meta': {}
        },
        
        # CDN
        'cloudfront': {
            'headers': {'x-amz-cf-id': r'.*', 'x-amz-cf-pop': r'.*', 'via': r'cloudfront'},
            'html': [r'cloudfront\.net'],
            'meta': {}
        },
        'akamai': {
            'headers': {'x-akamai': r'.*'},
            'html': [r'akamai'],
            'meta': {}
        },
        'fastly': {
            'headers': {'x-served-by': r'cache', 'x-fastly': r'.*'},
            'html': [],
            'meta': {}
        },
        
        # Analytics
        'google_analytics': {
            'headers': {},
            'html': [r'google-analytics\.com', r'googletagmanager\.com', r'gtag\(', r'UA-\d+'],
            'meta': {}
        },
        'google_tag_manager': {
            'headers': {},
            'html': [r'googletagmanager\.com', r'GTM-'],
            'meta': {}
        },
        'facebook_pixel': {
            'headers': {},
            'html': [r'connect\.facebook\.net', r'fbq\(', r'facebook\.com/tr'],
            'meta': {}
        },
        'hotjar': {
            'headers': {},
            'html': [r'hotjar\.com', r'hj\('],
            'meta': {}
        },
        
        # Security
        'recaptcha': {
            'headers': {},
            'html': [r'google\.com/recaptcha', r'grecaptcha'],
            'meta': {}
        },
        'hcaptcha': {
            'headers': {},
            'html': [r'hcaptcha\.com', r'h-captcha'],
            'meta': {}
        }
    }
    
    # Version detection patterns
    VERSION_PATTERNS = {
        'wordpress': r'WordPress\s*([\d.]+)',
        'jquery': r'jquery[.-]?([\d.]+)',
        'bootstrap': r'bootstrap[.-]?([\d.]+)',
        'angular': r'angular[.-]?([\d.]+)',
        'react': r'react[.-]?([\d.]+)',
        'vue': r'vue[.-]?([\d.]+)',
        'php': r'PHP/([\d.]+)',
        'nginx': r'nginx/([\d.]+)',
        'apache': r'Apache/([\d.]+)',
        'iis': r'IIS/([\d.]+)'
    }
    
    def __init__(self, url: str, timeout: int = 10):
        """
        Initialize Technology Detector
        
        Args:
            url: Target URL
            timeout: Request timeout
        """
        self.url = normalize_url(url)
        self.base_url = get_base_url(self.url)
        self.timeout = timeout
        self.scan_id = generate_scan_id()
        self.detected_technologies: Dict[str, Dict] = {}
    
    def detect(self) -> Dict[str, Any]:
        """
        Detect technologies on target
        
        Returns:
            Dict with detection results
        """
        start_time = datetime.now()
        
        result = {
            'success': False,
            'scan_id': self.scan_id,
            'url': self.url,
            'technologies': [],
            'categories': {},
            'headers': {},
            'error': None
        }
        
        try:
            # Make request to target
            response = make_request(self.url, timeout=self.timeout)
            
            if not response:
                result['error'] = 'Failed to connect to target'
                return result
            
            # Store headers
            result['headers'] = dict(response.headers)
            
            # Get response content
            html = response.text
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            cookies = [c.name for c in response.cookies]
            
            # Extract meta tags
            meta_tags = self._extract_meta_tags(html)
            
            # Detect technologies
            for tech_name, signatures in self.SIGNATURES.items():
                detected = self._check_technology(
                    tech_name, signatures, html, headers, cookies, meta_tags
                )
                
                if detected:
                    tech_info = {
                        'name': self._format_name(tech_name),
                        'slug': tech_name,
                        'confidence': detected['confidence'],
                        'version': detected.get('version'),
                        'category': self._get_category(tech_name),
                        'evidence': detected.get('evidence', [])
                    }
                    
                    result['technologies'].append(tech_info)
                    
                    # Group by category
                    category = tech_info['category']
                    if category not in result['categories']:
                        result['categories'][category] = []
                    result['categories'][category].append(tech_info)
            
            # Additional checks
            self._check_robots_txt(result)
            self._check_security_txt(result)
            self._check_favicon(result)
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        end_time = datetime.now()
        result['duration'] = (end_time - start_time).total_seconds()
        result['timestamp'] = datetime.now().isoformat()
        result['total_technologies'] = len(result['technologies'])
        
        return result
    
    def _check_technology(
        self,
        tech_name: str,
        signatures: Dict,
        html: str,
        headers: Dict,
        cookies: List[str],
        meta_tags: Dict
    ) -> Optional[Dict]:
        """Check if technology is present"""
        evidence = []
        confidence = 0
        version = None
        
        # Check headers
        for header_name, pattern in signatures.get('headers', {}).items():
            if header_name in headers:
                if re.search(pattern, headers[header_name], re.I):
                    evidence.append(f"Header: {header_name}")
                    confidence += 30
                    
                    # Try to extract version
                    if tech_name in self.VERSION_PATTERNS:
                        ver_match = re.search(
                            self.VERSION_PATTERNS[tech_name],
                            headers[header_name],
                            re.I
                        )
                        if ver_match:
                            version = ver_match.group(1)
        
        # Check HTML patterns
        for pattern in signatures.get('html', []):
            if re.search(pattern, html, re.I):
                evidence.append(f"HTML pattern: {pattern[:30]}")
                confidence += 25
                
                # Try to extract version
                if tech_name in self.VERSION_PATTERNS and not version:
                    ver_match = re.search(
                        self.VERSION_PATTERNS[tech_name],
                        html,
                        re.I
                    )
                    if ver_match:
                        version = ver_match.group(1)
        
        # Check meta tags
        for meta_name, pattern in signatures.get('meta', {}).items():
            if meta_name in meta_tags:
                if re.search(pattern, meta_tags[meta_name], re.I):
                    evidence.append(f"Meta tag: {meta_name}")
                    confidence += 40
                    
                    # Generator often contains version
                    if meta_name == 'generator' and not version:
                        ver_match = re.search(r'[\d.]+', meta_tags[meta_name])
                        if ver_match:
                            version = ver_match.group(0)
        
        # Check cookies
        for cookie_name in signatures.get('cookies', []):
            if cookie_name.lower() in [c.lower() for c in cookies]:
                evidence.append(f"Cookie: {cookie_name}")
                confidence += 20
        
        if confidence > 0:
            return {
                'confidence': min(100, confidence),
                'version': version,
                'evidence': evidence[:5]  # Limit evidence
            }
        
        return None
    
    def _extract_meta_tags(self, html: str) -> Dict[str, str]:
        """Extract meta tags from HTML"""
        meta_tags = {}
        
        # Pattern for meta tags
        patterns = [
            r'<meta\s+name=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']',
            r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']([^"\']+)["\']',
            r'<meta\s+property=["\']([^"\']+)["\']\s+content=["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html, re.I)
            for match in matches:
                if len(match) == 2:
                    key, value = match[0].lower(), match[1]
                    meta_tags[key] = value
        
        return meta_tags
    
    def _format_name(self, slug: str) -> str:
        """Format technology slug to display name"""
        name_map = {
            'wordpress': 'WordPress',
            'joomla': 'Joomla',
            'drupal': 'Drupal',
            'magento': 'Magento',
            'shopify': 'Shopify',
            'wix': 'Wix',
            'squarespace': 'Squarespace',
            'laravel': 'Laravel',
            'django': 'Django',
            'ruby_on_rails': 'Ruby on Rails',
            'express': 'Express.js',
            'asp_net': 'ASP.NET',
            'flask': 'Flask',
            'spring': 'Spring',
            'react': 'React',
            'angular': 'Angular',
            'vue': 'Vue.js',
            'jquery': 'jQuery',
            'bootstrap': 'Bootstrap',
            'next_js': 'Next.js',
            'nuxt': 'Nuxt.js',
            'nginx': 'Nginx',
            'apache': 'Apache',
            'iis': 'Microsoft IIS',
            'litespeed': 'LiteSpeed',
            'cloudflare': 'Cloudflare',
            'php': 'PHP',
            'java': 'Java',
            'python': 'Python',
            'node_js': 'Node.js',
            'cloudfront': 'Amazon CloudFront',
            'akamai': 'Akamai',
            'fastly': 'Fastly',
            'google_analytics': 'Google Analytics',
            'google_tag_manager': 'Google Tag Manager',
            'facebook_pixel': 'Facebook Pixel',
            'hotjar': 'Hotjar',
            'recaptcha': 'reCAPTCHA',
            'hcaptcha': 'hCaptcha'
        }
        
        return name_map.get(slug, slug.replace('_', ' ').title())
    
    def _get_category(self, tech_name: str) -> str:
        """Get category for technology"""
        categories = {
            'cms': ['wordpress', 'joomla', 'drupal', 'magento', 'shopify', 'wix', 'squarespace'],
            'framework': ['laravel', 'django', 'ruby_on_rails', 'express', 'asp_net', 'flask', 'spring'],
            'javascript_framework': ['react', 'angular', 'vue', 'next_js', 'nuxt'],
            'javascript_library': ['jquery', 'bootstrap'],
            'web_server': ['nginx', 'apache', 'iis', 'litespeed'],
            'programming_language': ['php', 'java', 'python', 'node_js'],
            'cdn': ['cloudflare', 'cloudfront', 'akamai', 'fastly'],
            'analytics': ['google_analytics', 'google_tag_manager', 'facebook_pixel', 'hotjar'],
            'security': ['recaptcha', 'hcaptcha']
        }
        
        for category, techs in categories.items():
            if tech_name in techs:
                return category
        
        return 'other'
    
    def _check_robots_txt(self, result: Dict) -> None:
        """Check robots.txt for additional hints"""
        try:
            response = make_request(f"{self.base_url}/robots.txt", timeout=5)
            if response and response.status_code == 200:
                content = response.text.lower()
                
                # Check for CMS hints
                if 'wp-admin' in content or 'wp-includes' in content:
                    self._add_evidence(result, 'wordpress', 'robots.txt')
                if 'administrator' in content and 'joomla' in content:
                    self._add_evidence(result, 'joomla', 'robots.txt')
                    
        except Exception:
            pass
    
    def _check_security_txt(self, result: Dict) -> None:
        """Check security.txt"""
        try:
            for path in ['/.well-known/security.txt', '/security.txt']:
                response = make_request(f"{self.base_url}{path}", timeout=5)
                if response and response.status_code == 200:
                    result['security_txt'] = True
                    result['security_txt_content'] = response.text[:500]
                    break
        except Exception:
            pass
    
    def _check_favicon(self, result: Dict) -> None:
        """Check favicon hash for identification"""
        try:
            response = make_request(f"{self.base_url}/favicon.ico", timeout=5)
            if response and response.status_code == 200:
                favicon_hash = hashlib.md5(response.content).hexdigest()
                result['favicon_hash'] = favicon_hash
                
                # Known favicon hashes
                known_favicons = {
                    'd41d8cd98f00b204e9800998ecf8427e': 'Empty',
                    '1b6d6674bbf5e5e6f1b6b3a8c6e7a3d1': 'WordPress Default'
                }
                
                if favicon_hash in known_favicons:
                    result['favicon_match'] = known_favicons[favicon_hash]
                    
        except Exception:
            pass
    
    def _add_evidence(self, result: Dict, tech_slug: str, evidence: str) -> None:
        """Add evidence to existing technology detection"""
        for tech in result['technologies']:
            if tech['slug'] == tech_slug:
                if evidence not in tech['evidence']:
                    tech['evidence'].append(evidence)
                    tech['confidence'] = min(100, tech['confidence'] + 10)
                return
    
    def get_cms(self) -> Optional[str]:
        """Get detected CMS"""
        result = self.detect()
        if result['success']:
            for tech in result['technologies']:
                if tech['category'] == 'cms':
                    return tech['name']
        return None
    
    def get_server(self) -> Optional[str]:
        """Get detected web server"""
        result = self.detect()
        if result['success']:
            for tech in result['technologies']:
                if tech['category'] == 'web_server':
                    return tech['name']
        return None
    
    def get_frameworks(self) -> List[str]:
        """Get all detected frameworks"""
        result = self.detect()
        frameworks = []
        if result['success']:
            for tech in result['technologies']:
                if 'framework' in tech['category']:
                    frameworks.append(tech['name'])
        return frameworks
"""
Web Crawler Service
Discovers links, forms, and content across a website
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urldefrag
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any, Set, Tuple
from datetime import datetime
import threading
import re
import time
from collections import deque

from app.services.utils import (
    normalize_url,
    make_request,
    generate_scan_id,
    get_base_url,
    is_valid_url
)


class WebCrawler:
    """
    Web Crawler for website reconnaissance
    
    Features:
    - Multi-threaded crawling
    - Depth-limited crawling
    - Domain scope enforcement
    - Form discovery
    - Link extraction
    - JavaScript file detection
    - Email extraction
    - Comment extraction
    - Robots.txt parsing
    - Sitemap parsing
    - Rate limiting
    - Progress callbacks
    """
    
    # File extensions to skip
    SKIP_EXTENSIONS = [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
        '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
        '.exe', '.msi', '.dmg', '.pkg',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.css', '.map'
    ]
    
    # Content types to process
    VALID_CONTENT_TYPES = [
        'text/html', 'application/xhtml+xml', 'text/xml', 'application/xml'
    ]
    
    def __init__(
        self,
        target_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        timeout: float = 10.0,
        max_threads: int = 10,
        delay: float = 0.1,
        respect_robots: bool = True,
        user_agent: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        scope: str = 'domain'
    ):
        """
        Initialize Web Crawler
        
        Args:
            target_url: Starting URL
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
            timeout: Request timeout
            max_threads: Maximum concurrent threads
            delay: Delay between requests
            respect_robots: Respect robots.txt
            user_agent: Custom User-Agent
            cookies: Cookies to include
            headers: Custom headers
            proxy: Proxy server URL
            scope: Crawl scope ('domain', 'subdomain', 'path')
        """
        self.target_url = normalize_url(target_url)
        self.base_url = get_base_url(self.target_url)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.max_threads = max_threads
        self.delay = delay
        self.respect_robots = respect_robots
        self.scope = scope
        self.scan_id = generate_scan_id()
        
        # Parse target URL
        parsed = urlparse(self.target_url)
        self.target_domain = parsed.netloc
        self.target_scheme = parsed.scheme
        self.target_path = parsed.path or '/'
        
        # Session configuration
        self.session = requests.Session()
        self.session.verify = False
        
        # Set headers
        self.user_agent = user_agent or 'VulnScanner-Crawler/1.0 (Security Research)'
        self.headers = {
            'User-Agent': self.user_agent,
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
        
        # Crawl state
        self.visited_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.found_urls: List[Dict] = []
        self.forms: List[Dict] = []
        self.emails: Set[str] = set()
        self.js_files: Set[str] = set()
        self.comments: List[Dict] = []
        self.external_links: Set[str] = set()
        self.subdomains: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}
        
        # Robots.txt
        self.robots_disallowed: Set[str] = set()
        self.robots_allowed: Set[str] = set()
        self.sitemaps: List[str] = []
        
        # State management
        self.is_crawling = False
        self.stop_crawl = False
        self._lock = threading.Lock()
        
        # Statistics
        self.stats = {
            'pages_crawled': 0,
            'pages_failed': 0,
            'forms_found': 0,
            'emails_found': 0,
            'js_files_found': 0,
            'external_links': 0
        }
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within crawl scope"""
        try:
            parsed = urlparse(url)
            
            # Must be HTTP(S)
            if parsed.scheme not in ['http', 'https']:
                return False
            
            if self.scope == 'domain':
                # Same domain (including subdomains)
                target_parts = self.target_domain.split('.')
                url_parts = parsed.netloc.split('.')
                
                # Check if main domain matches
                if len(target_parts) >= 2 and len(url_parts) >= 2:
                    return target_parts[-2:] == url_parts[-2:]
                return parsed.netloc == self.target_domain
            
            elif self.scope == 'subdomain':
                # Exact domain match only
                return parsed.netloc == self.target_domain
            
            elif self.scope == 'path':
                # Same domain and path prefix
                if parsed.netloc != self.target_domain:
                    return False
                return parsed.path.startswith(self.target_path)
            
            return False
            
        except Exception:
            return False
    
    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped"""
        # Skip if already visited or queued
        if url in self.visited_urls or url in self.queued_urls:
            return True
        
        # Skip file extensions
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in self.SKIP_EXTENSIONS:
            if path.endswith(ext):
                return True
        
        # Skip common non-content paths
        skip_patterns = [
            '/wp-json/', '/feed/', '/rss/', '/atom/',
            '/trackback/', '/xmlrpc.php', '/wp-cron.php',
            'javascript:', 'mailto:', 'tel:', 'data:',
            '#', 'void(0)'
        ]
        
        for pattern in skip_patterns:
            if pattern in url.lower():
                return True
        
        # Check robots.txt restrictions
        if self.respect_robots and self._is_disallowed(url):
            return True
        
        return False
    
    def _is_disallowed(self, url: str) -> bool:
        """Check if URL is disallowed by robots.txt"""
        parsed = urlparse(url)
        path = parsed.path
        
        for disallowed in self.robots_disallowed:
            if path.startswith(disallowed):
                return True
        
        return False
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize URL and resolve relative paths"""
        try:
            # Remove fragment
            url, _ = urldefrag(url)
            
            # Skip empty URLs
            if not url or url.isspace():
                return None
            
            # Skip special protocols
            if url.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
                return None
            
            # Resolve relative URLs
            if not url.startswith(('http://', 'https://')):
                url = urljoin(base_url, url)
            
            # Normalize
            parsed = urlparse(url)
            
            # Rebuild URL without fragment
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            
            return normalized
            
        except Exception:
            return None
    
    def parse_robots_txt(self) -> Dict[str, Any]:
        """Parse robots.txt file"""
        result = {
            'exists': False,
            'disallowed': [],
            'allowed': [],
            'sitemaps': [],
            'crawl_delay': None
        }
        
        try:
            robots_url = f"{self.base_url}/robots.txt"
            response = self.session.get(robots_url, timeout=self.timeout)
            
            if response.status_code == 200:
                result['exists'] = True
                content = response.text
                
                current_agent = None
                
                for line in content.split('\n'):
                    line = line.strip()
                    
                    if line.startswith('#') or not line:
                        continue
                    
                    if ':' in line:
                        directive, value = line.split(':', 1)
                        directive = directive.strip().lower()
                        value = value.strip()
                        
                        if directive == 'user-agent':
                            current_agent = value.lower()
                        
                        elif directive == 'disallow' and value:
                            if current_agent in ['*', 'vulnscanner', self.user_agent.lower()]:
                                self.robots_disallowed.add(value)
                                result['disallowed'].append(value)
                        
                        elif directive == 'allow' and value:
                            if current_agent in ['*', 'vulnscanner', self.user_agent.lower()]:
                                self.robots_allowed.add(value)
                                result['allowed'].append(value)
                        
                        elif directive == 'sitemap':
                            self.sitemaps.append(value)
                            result['sitemaps'].append(value)
                        
                        elif directive == 'crawl-delay':
                            try:
                                result['crawl_delay'] = float(value)
                            except ValueError:
                                pass
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def parse_sitemap(self, sitemap_url: Optional[str] = None) -> List[str]:
        """Parse sitemap.xml for URLs"""
        urls = []
        
        if sitemap_url is None:
            sitemap_url = f"{self.base_url}/sitemap.xml"
        
        try:
            response = self.session.get(sitemap_url, timeout=self.timeout)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'xml')
                
                # Check for sitemap index
                sitemap_tags = soup.find_all('sitemap')
                if sitemap_tags:
                    for sitemap in sitemap_tags:
                        loc = sitemap.find('loc')
                        if loc:
                            # Recursively parse nested sitemaps
                            urls.extend(self.parse_sitemap(loc.text))
                
                # Parse URL entries
                url_tags = soup.find_all('url')
                for url_tag in url_tags:
                    loc = url_tag.find('loc')
                    if loc:
                        urls.append(loc.text)
        
        except Exception:
            pass
        
        return urls
    
    def crawl_page(self, url: str, depth: int = 0) -> Optional[Dict[str, Any]]:
        """
        Crawl a single page
        
        Returns:
            Dict with page information
        """
        if self.stop_crawl:
            return None
        
        if depth > self.max_depth:
            return None
        
        with self._lock:
            if len(self.visited_urls) >= self.max_pages:
                return None
            self.visited_urls.add(url)
        
        result = {
            'url': url,
            'depth': depth,
            'status_code': None,
            'content_type': None,
            'title': None,
            'links': [],
            'forms': [],
            'emails': [],
            'js_files': [],
            'comments': [],
            'external_links': [],
            'parameters': {}
        }
        
        try:
            # Rate limiting
            if self.delay > 0:
                time.sleep(self.delay)
            
            # Make request
            response = self.session.get(url, timeout=self.timeout)
            
            result['status_code'] = response.status_code
            result['content_type'] = response.headers.get('Content-Type', '')
            result['content_length'] = len(response.content)
            
            # Check content type
            if not any(ct in result['content_type'].lower() for ct in self.VALID_CONTENT_TYPES):
                with self._lock:
                    self.stats['pages_crawled'] += 1
                return result
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract title
            title_tag = soup.find('title')
            if title_tag:
                result['title'] = title_tag.get_text().strip()[:200]
            
            # Extract links
            result['links'] = self._extract_links(soup, url)
            
            # Extract forms
            result['forms'] = self._extract_forms(soup, url)
            
            # Extract emails
            result['emails'] = self._extract_emails(response.text)
            
            # Extract JavaScript files
            result['js_files'] = self._extract_js_files(soup, url)
            
            # Extract comments
            result['comments'] = self._extract_comments(response.text)
            
            # Extract parameters from URLs
            result['parameters'] = self._extract_parameters(result['links'])
            
            # Categorize external links
            for link in result['links']:
                if not self._is_in_scope(link):
                    result['external_links'].append(link)
                    with self._lock:
                        self.external_links.add(link)
            
            # Store data globally
            with self._lock:
                self.forms.extend(result['forms'])
                self.emails.update(result['emails'])
                self.js_files.update(result['js_files'])
                
                for comment in result['comments']:
                    self.comments.append({'url': url, 'comment': comment})
                
                for param, values in result['parameters'].items():
                    if param not in self.parameters:
                        self.parameters[param] = set()
                    self.parameters[param].update(values)
                
                self.stats['pages_crawled'] += 1
                self.stats['forms_found'] = len(self.forms)
                self.stats['emails_found'] = len(self.emails)
                self.stats['js_files_found'] = len(self.js_files)
                self.stats['external_links'] = len(self.external_links)
        
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
            with self._lock:
                self.stats['pages_failed'] += 1
        except Exception as e:
            result['error'] = str(e)
            with self._lock:
                self.stats['pages_failed'] += 1
        
        return result
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from page"""
        links = set()
        
        # Find all anchor tags
        for tag in soup.find_all('a', href=True):
            href = tag.get('href', '')
            normalized = self._normalize_url(href, base_url)
            if normalized and self._is_in_scope(normalized):
                links.add(normalized)
        
        # Find links in other tags
        for tag in soup.find_all(['link', 'area'], href=True):
            href = tag.get('href', '')
            normalized = self._normalize_url(href, base_url)
            if normalized and self._is_in_scope(normalized):
                links.add(normalized)
        
        # Find links in meta refresh
        for meta in soup.find_all('meta', attrs={'http-equiv': 'refresh'}):
            content = meta.get('content', '')
            match = re.search(r'url=(.+)', content, re.IGNORECASE)
            if match:
                normalized = self._normalize_url(match.group(1).strip('"\''), base_url)
                if normalized and self._is_in_scope(normalized):
                    links.add(normalized)
        
        return list(links)
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract all forms from page"""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': '',
                'method': 'GET',
                'inputs': [],
                'url': base_url
            }
            
            # Get form action
            action = form.get('action', '')
            if action:
                form_data['action'] = self._normalize_url(action, base_url) or action
            else:
                form_data['action'] = base_url
            
            # Get form method
            form_data['method'] = form.get('method', 'GET').upper()
            
            # Get form enctype
            form_data['enctype'] = form.get('enctype', 'application/x-www-form-urlencoded')
            
            # Get all input fields
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required'),
                    'id': input_tag.get('id', '')
                }
                
                # Get placeholder
                if input_tag.name == 'input':
                    input_data['placeholder'] = input_tag.get('placeholder', '')
                
                # Get options for select
                if input_tag.name == 'select':
                    input_data['options'] = []
                    for option in input_tag.find_all('option'):
                        input_data['options'].append({
                            'value': option.get('value', ''),
                            'text': option.get_text().strip()
                        })
                
                if input_data['name']:
                    form_data['inputs'].append(input_data)
            
            if form_data['inputs']:
                forms.append(form_data)
        
        return forms
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        
        # Filter out common false positives
        filtered = []
        for email in emails:
            email_lower = email.lower()
            if not any(x in email_lower for x in ['example.com', 'test.com', 'localhost', '.png', '.jpg', '.gif']):
                filtered.append(email)
        
        return list(set(filtered))
    
    def _extract_js_files(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract JavaScript file URLs"""
        js_files = set()
        
        for script in soup.find_all('script', src=True):
            src = script.get('src', '')
            normalized = self._normalize_url(src, base_url)
            if normalized:
                js_files.add(normalized)
        
        return list(js_files)
    
    def _extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments"""
        comments = []
        
        # Find HTML comments
        comment_pattern = r'<!--(.*?)-->'
        matches = re.findall(comment_pattern, html, re.DOTALL)
        
        for comment in matches:
            comment = comment.strip()
            if comment and len(comment) > 3:  # Skip empty or tiny comments
                # Check for interesting content
                interesting_patterns = [
                    'todo', 'fixme', 'bug', 'hack', 'password', 'user',
                    'admin', 'debug', 'test', 'remove', 'delete', 'secret',
                    'key', 'token', 'api', 'config', 'database', 'sql'
                ]
                
                comment_lower = comment.lower()
                if any(pattern in comment_lower for pattern in interesting_patterns):
                    comments.append(comment[:500])  # Limit length
                elif len(comment) > 50:  # Include longer comments
                    comments.append(comment[:500])
        
        return comments
    
    def _extract_parameters(self, urls: List[str]) -> Dict[str, Set[str]]:
        """Extract URL parameters"""
        parameters = {}
        
        for url in urls:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                for param, values in params.items():
                    if param not in parameters:
                        parameters[param] = set()
                    parameters[param].update(values)
            except Exception:
                pass
        
        return parameters
    
    def crawl(
        self,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Perform web crawling
        
        Args:
            callback: Progress callback(url, depth, status)
            
        Returns:
            Dict with crawl results
        """
        start_time = datetime.now()
        self.is_crawling = True
        self.stop_crawl = False
        
        # Reset state
        self.visited_urls = set()
        self.queued_urls = set()
        self.found_urls = []
        self.forms = []
        self.emails = set()
        self.js_files = set()
        self.comments = []
        self.external_links = set()
        self.parameters = {}
        self.stats = {
            'pages_crawled': 0,
            'pages_failed': 0,
            'forms_found': 0,
            'emails_found': 0,
            'js_files_found': 0,
            'external_links': 0
        }
        
        # Parse robots.txt
        robots_info = {}
        if self.respect_robots:
            robots_info = self.parse_robots_txt()
        
        # Parse sitemap for additional URLs
        sitemap_urls = []
        if self.sitemaps:
            for sitemap in self.sitemaps:
                sitemap_urls.extend(self.parse_sitemap(sitemap))
        else:
            sitemap_urls = self.parse_sitemap()
        
        # Initialize queue with starting URL and sitemap URLs
        queue = deque([(self.target_url, 0)])
        self.queued_urls.add(self.target_url)
        
        for sitemap_url in sitemap_urls[:50]:  # Limit sitemap URLs
            if sitemap_url not in self.queued_urls:
                queue.append((sitemap_url, 0))
                self.queued_urls.add(sitemap_url)
        
        # BFS crawling
        while queue and not self.stop_crawl:
            if len(self.visited_urls) >= self.max_pages:
                break
            
            # Get batch of URLs to crawl
            batch = []
            while queue and len(batch) < self.max_threads:
                url, depth = queue.popleft()
                
                if url not in self.visited_urls and not self._should_skip_url(url):
                    batch.append((url, depth))
            
            if not batch:
                continue
            
            # Crawl batch concurrently
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_url = {
                    executor.submit(self.crawl_page, url, depth): (url, depth)
                    for url, depth in batch
                }
                
                for future in concurrent.futures.as_completed(future_to_url):
                    if self.stop_crawl:
                        break
                    
                    url, depth = future_to_url[future]
                    
                    try:
                        result = future.result()
                        
                        if result:
                            self.found_urls.append(result)
                            
                            # Add new links to queue
                            if depth < self.max_depth:
                                for link in result.get('links', []):
                                    if link not in self.visited_urls and link not in self.queued_urls:
                                        if not self._should_skip_url(link):
                                            queue.append((link, depth + 1))
                                            self.queued_urls.add(link)
                            
                            if callback:
                                try:
                                    callback(url, depth, result.get('status_code', 0))
                                except Exception:
                                    pass
                    
                    except Exception:
                        pass
        
        end_time = datetime.now()
        self.is_crawling = False
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'urls': list(self.visited_urls),
            'urls_found': len(self.visited_urls),
            'pages': self.found_urls,
            'forms': self.forms,
            'emails': list(self.emails),
            'js_files': list(self.js_files),
            'comments': self.comments,
            'external_links': list(self.external_links),
            'parameters': {k: list(v) for k, v in self.parameters.items()},
            'subdomains': list(self.subdomains),
            'robots': robots_info,
            'sitemap_urls': len(sitemap_urls),
            'statistics': self.stats,
            'max_depth': self.max_depth,
            'scope': self.scope,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def stop(self) -> None:
        """Stop ongoing crawl"""
        self.stop_crawl = True
    
    def get_visited_urls(self) -> List[str]:
        """Get list of visited URLs"""
        with self._lock:
            return list(self.visited_urls)
    
    def get_forms(self) -> List[Dict]:
        """Get list of discovered forms"""
        with self._lock:
            return list(self.forms)
    
    def get_emails(self) -> List[str]:
        """Get list of discovered emails"""
        with self._lock:
            return list(self.emails)
    
    def get_parameters(self) -> Dict[str, List[str]]:
        """Get discovered URL parameters"""
        with self._lock:
            return {k: list(v) for k, v in self.parameters.items()}
    
    def quick_crawl(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform quick crawl with limited depth and pages"""
        original_depth = self.max_depth
        original_pages = self.max_pages
        
        self.max_depth = 1
        self.max_pages = 20
        
        result = self.crawl(callback=callback)
        
        self.max_depth = original_depth
        self.max_pages = original_pages
        
        return result
    
    def find_login_forms(self) -> List[Dict]:
        """Find potential login forms"""
        login_forms = []
        
        login_indicators = [
            'login', 'signin', 'sign-in', 'log-in', 'logon', 'auth',
            'password', 'passwd', 'username', 'email', 'user'
        ]
        
        for form in self.forms:
            form_str = str(form).lower()
            
            # Check if form contains login indicators
            if any(indicator in form_str for indicator in login_indicators):
                # Check if has password field
                has_password = any(
                    inp.get('type') == 'password'
                    for inp in form.get('inputs', [])
                )
                
                if has_password:
                    login_forms.append(form)
        
        return login_forms
    
    def find_search_forms(self) -> List[Dict]:
        """Find potential search forms"""
        search_forms = []
        
        search_indicators = ['search', 'query', 'q', 's', 'keyword', 'find']
        
        for form in self.forms:
            for inp in form.get('inputs', []):
                name = inp.get('name', '').lower()
                if any(indicator in name for indicator in search_indicators):
                    search_forms.append(form)
                    break
        
        return search_forms
    
    def find_file_upload_forms(self) -> List[Dict]:
        """Find forms with file upload"""
        upload_forms = []
        
        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('type') == 'file':
                    upload_forms.append(form)
                    break
        
        return upload_forms
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate detailed crawl report"""
        return {
            'scan_id': self.scan_id,
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'pages_crawled': self.stats['pages_crawled'],
                'pages_failed': self.stats['pages_failed'],
                'forms_found': len(self.forms),
                'emails_found': len(self.emails),
                'js_files_found': len(self.js_files),
                'external_links': len(self.external_links),
                'parameters_found': len(self.parameters),
                'comments_found': len(self.comments)
            },
            'urls': list(self.visited_urls),
            'forms': self.forms,
            'login_forms': self.find_login_forms(),
            'search_forms': self.find_search_forms(),
            'upload_forms': self.find_file_upload_forms(),
            'emails': list(self.emails),
            'js_files': list(self.js_files),
            'parameters': {k: list(v) for k, v in self.parameters.items()},
            'interesting_comments': [c for c in self.comments if len(c.get('comment', '')) > 20],
            'external_links': list(self.external_links)[:50],  # Limit
            'security_observations': self._generate_observations()
        }
    
    def _generate_observations(self) -> List[str]:
        """Generate security observations from crawl data"""
        observations = []
        
        # Check for forms without CSRF protection
        forms_without_csrf = 0
        for form in self.forms:
            has_csrf = any(
                'csrf' in inp.get('name', '').lower() or 'token' in inp.get('name', '').lower()
                for inp in form.get('inputs', [])
            )
            if not has_csrf and form.get('method', 'GET').upper() == 'POST':
                forms_without_csrf += 1
        
        if forms_without_csrf > 0:
            observations.append(f"Found {forms_without_csrf} POST form(s) potentially without CSRF protection")
        
        # Check for login forms
        login_forms = self.find_login_forms()
        if login_forms:
            observations.append(f"Found {len(login_forms)} potential login form(s)")
        
        # Check for file upload
        upload_forms = self.find_file_upload_forms()
        if upload_forms:
            observations.append(f"Found {len(upload_forms)} file upload form(s) - potential for file upload vulnerabilities")
        
        # Check for sensitive parameters
        sensitive_params = ['password', 'passwd', 'token', 'key', 'secret', 'api', 'auth']
        found_sensitive = [p for p in self.parameters.keys() if any(s in p.lower() for s in sensitive_params)]
        if found_sensitive:
            observations.append(f"Found sensitive parameter names: {', '.join(found_sensitive)}")
        
        # Check for emails
        if self.emails:
            observations.append(f"Found {len(self.emails)} email address(es) - potential for social engineering")
        
        # Check for interesting comments
        interesting_comments = len([c for c in self.comments if len(c.get('comment', '')) > 20])
        if interesting_comments > 0:
            observations.append(f"Found {interesting_comments} potentially interesting HTML comment(s)")
        
        # Check for JavaScript files
        if len(self.js_files) > 0:
            observations.append(f"Found {len(self.js_files)} JavaScript file(s) - review for sensitive information")
        
        return observations
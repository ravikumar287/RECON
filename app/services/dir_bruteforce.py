"""
Directory Bruteforce Service
Discovers hidden directories and files on web servers
"""

import requests
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin
import threading
import re
import time

from app.services.utils import (
    normalize_url,
    make_request,
    generate_scan_id,
    load_wordlist,
    get_base_url
)


class DirectoryBruteforce:
    """
    Directory and File Bruteforce Scanner
    
    Features:
    - Multi-threaded directory enumeration
    - File extension fuzzing
    - Recursive scanning
    - Custom wordlist support
    - Response filtering (size, status code)
    - Backup file detection
    - Hidden file detection
    - Rate limiting
    - Progress callbacks
    - WAF detection and evasion
    """
    
    # Common directories to check
    DEFAULT_DIRECTORIES = [
        'admin', 'administrator', 'login', 'wp-admin', 'wp-login', 'dashboard',
        'cpanel', 'phpmyadmin', 'pma', 'mysql', 'database', 'db', 'sql',
        'backup', 'backups', 'bak', 'old', 'temp', 'tmp', 'test', 'testing',
        'dev', 'development', 'stage', 'staging', 'prod', 'production',
        'api', 'apis', 'v1', 'v2', 'v3', 'rest', 'graphql', 'swagger',
        'docs', 'documentation', 'doc', 'help', 'support', 'faq',
        'images', 'img', 'assets', 'static', 'media', 'files', 'uploads',
        'css', 'js', 'javascript', 'scripts', 'styles', 'fonts',
        'includes', 'include', 'inc', 'lib', 'libs', 'library', 'vendor',
        'modules', 'plugins', 'components', 'templates', 'themes',
        'config', 'configuration', 'settings', 'conf', 'cfg',
        'data', 'logs', 'log', 'cache', 'caches', 'sessions',
        'private', 'public', 'protected', 'secure', 'ssl',
        'cgi-bin', 'cgi', 'bin', 'scripts', 'exec',
        'app', 'application', 'apps', 'src', 'source', 'core',
        'user', 'users', 'member', 'members', 'account', 'accounts', 'profile',
        'upload', 'downloads', 'download', 'file', 'attachment', 'attachments',
        'wp-content', 'wp-includes', 'wordpress', 'joomla', 'drupal', 'magento',
        'panel', 'control', 'manager', 'manage', 'webmaster', 'sysadmin',
        'portal', 'gateway', 'home', 'index', 'main', 'default',
        'error', 'errors', '404', '500', 'maintenance',
        'robots.txt', 'sitemap.xml', 'sitemap', '.htaccess', '.htpasswd',
        'web.config', 'crossdomain.xml', 'clientaccesspolicy.xml',
        '.git', '.svn', '.hg', '.env', '.DS_Store', 'Thumbs.db',
        'server-status', 'server-info', 'status', 'info', 'health', 'ping',
        'console', 'terminal', 'shell', 'cmd', 'command',
        'install', 'installer', 'setup', 'update', 'upgrade',
        'email', 'mail', 'webmail', 'smtp', 'imap', 'pop',
        'ftp', 'sftp', 'ssh', 'telnet', 'remote',
        'blog', 'news', 'articles', 'posts', 'content',
        'shop', 'store', 'cart', 'checkout', 'payment', 'order', 'orders',
        'forum', 'forums', 'community', 'social', 'chat',
        'report', 'reports', 'analytics', 'stats', 'statistics', 'metrics',
        'export', 'import', 'migrate', 'migration', 'transfer'
    ]
    
    # Common file extensions
    DEFAULT_EXTENSIONS = [
        '', '.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
        '.txt', '.xml', '.json', '.yaml', '.yml', '.csv', '.log',
        '.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.temp',
        '.sql', '.db', '.sqlite', '.mdb', '.sql.gz', '.sql.zip',
        '.zip', '.tar', '.tar.gz', '.tgz', '.rar', '.7z', '.gz',
        '.conf', '.config', '.cfg', '.ini', '.env', '.properties',
        '.inc', '.include', '.class', '.jar',
        '.sh', '.bash', '.py', '.pl', '.rb', '.cgi',
        '.key', '.pem', '.crt', '.cer', '.p12', '.pfx',
        '.htaccess', '.htpasswd', '.DS_Store'
    ]
    
    # Backup file patterns
    BACKUP_PATTERNS = [
        '{name}.bak', '{name}.backup', '{name}.old', '{name}.orig',
        '{name}.save', '{name}.swp', '{name}.tmp', '{name}~',
        '{name}.copy', '{name}.1', '{name}.2',
        'backup_{name}', 'old_{name}', 'copy_{name}',
        '{name}_backup', '{name}_old', '{name}_copy',
        '{name}.bkp', '{name}.bck'
    ]
    
    # Status codes indicating found resources
    SUCCESS_CODES = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403]
    
    # Status codes indicating interesting findings
    INTERESTING_CODES = [401, 403, 405, 500, 502, 503]
    
    def __init__(
        self,
        target_url: str,
        timeout: float = 10.0,
        max_threads: int = 20,
        delay: float = 0.0,
        user_agent: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        follow_redirects: bool = False
    ):
        """
        Initialize Directory Bruteforce Scanner
        
        Args:
            target_url: Target base URL
            timeout: Request timeout in seconds
            max_threads: Maximum concurrent threads
            delay: Delay between requests (rate limiting)
            user_agent: Custom User-Agent header
            cookies: Cookies to include in requests
            headers: Custom headers to include
            proxy: Proxy server URL
            follow_redirects: Follow HTTP redirects
        """
        self.target_url = normalize_url(target_url).rstrip('/')
        self.base_url = get_base_url(self.target_url)
        self.timeout = timeout
        self.max_threads = max_threads
        self.delay = delay
        self.follow_redirects = follow_redirects
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
        self.found_paths: List[Dict] = []
        self.scanned_paths: Set[str] = set()
        self.is_scanning = False
        self.stop_scan = False
        self._lock = threading.Lock()
        
        # Baseline for comparison
        self.baseline_404_length = 0
        self.baseline_404_words = 0
        self.has_custom_404 = False
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'found': 0,
            'errors': 0,
            'filtered': 0
        }
    
    def _detect_custom_404(self) -> None:
        """Detect custom 404 page to filter false positives"""
        try:
            # Request a random non-existent path
            random_path = f"/{''.join([chr(ord('a') + i % 26) for i in range(16)])}"
            response = self.session.get(
                f"{self.target_url}{random_path}",
                timeout=self.timeout,
                allow_redirects=self.follow_redirects
            )
            
            if response.status_code == 200:
                self.has_custom_404 = True
                self.baseline_404_length = len(response.text)
                self.baseline_404_words = len(response.text.split())
            
        except Exception:
            pass
    
    def _is_false_positive(self, response: requests.Response) -> bool:
        """Check if response is a false positive (custom 404)"""
        if not self.has_custom_404:
            return False
        
        # Compare with baseline
        content_length = len(response.text)
        word_count = len(response.text.split())
        
        # If very similar to baseline 404, it's likely a false positive
        length_diff = abs(content_length - self.baseline_404_length)
        word_diff = abs(word_count - self.baseline_404_words)
        
        # Allow 10% variance
        if self.baseline_404_length > 0:
            if length_diff / self.baseline_404_length < 0.1:
                return True
        
        if self.baseline_404_words > 0:
            if word_diff / self.baseline_404_words < 0.1:
                return True
        
        return False
    
    def check_path(
        self,
        path: str,
        method: str = 'GET'
    ) -> Optional[Dict[str, Any]]:
        """
        Check if a path exists on the server
        
        Args:
            path: Path to check (e.g., '/admin')
            method: HTTP method to use
            
        Returns:
            Dict with path info if found, None otherwise
        """
        if self.stop_scan:
            return None
        
        # Normalize path
        if not path.startswith('/'):
            path = '/' + path
        
        full_url = f"{self.target_url}{path}"
        
        # Skip if already scanned
        with self._lock:
            if full_url in self.scanned_paths:
                return None
            self.scanned_paths.add(full_url)
        
        try:
            # Rate limiting
            if self.delay > 0:
                time.sleep(self.delay)
            
            # Make request
            if method.upper() == 'HEAD':
                response = self.session.head(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
            else:
                response = self.session.get(
                    full_url,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects
                )
            
            with self._lock:
                self.stats['total_requests'] += 1
            
            # Check if path exists
            if response.status_code in self.SUCCESS_CODES:
                # Filter false positives
                if response.status_code == 200 and self._is_false_positive(response):
                    with self._lock:
                        self.stats['filtered'] += 1
                    return None
                
                result = {
                    'path': path,
                    'url': full_url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                    'redirect_url': response.url if response.url != full_url else None,
                    'server': response.headers.get('Server', ''),
                    'interesting': response.status_code in self.INTERESTING_CODES,
                    'title': self._extract_title(response.text) if response.status_code == 200 else None
                }
                
                # Determine severity/importance
                result['severity'] = self._determine_severity(path, response.status_code)
                
                with self._lock:
                    self.stats['found'] += 1
                
                return result
        
        except requests.exceptions.Timeout:
            with self._lock:
                self.stats['errors'] += 1
        except requests.exceptions.RequestException:
            with self._lock:
                self.stats['errors'] += 1
        except Exception:
            with self._lock:
                self.stats['errors'] += 1
        
        return None
    
    def _extract_title(self, html_content: str) -> Optional[str]:
        """Extract page title from HTML"""
        try:
            match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:100]
        except Exception:
            pass
        return None
    
    def _determine_severity(self, path: str, status_code: int) -> str:
        """Determine severity of found path"""
        path_lower = path.lower()
        
        # Critical findings
        critical_patterns = [
            '.git', '.svn', '.env', '.htpasswd', 'wp-config', 'config.php',
            'database', '.sql', 'backup', 'dump', 'export', '.bak',
            'phpmyadmin', 'adminer', 'shell', 'cmd', 'console',
            'id_rsa', 'id_dsa', '.pem', '.key', 'credentials',
            'password', 'passwd', 'shadow', 'secret'
        ]
        
        for pattern in critical_patterns:
            if pattern in path_lower:
                return 'critical'
        
        # High severity
        high_patterns = [
            'admin', 'administrator', 'login', 'dashboard', 'panel',
            'manager', 'control', 'private', 'secure', 'internal',
            'cpanel', 'webmail', 'api', 'swagger', 'graphql'
        ]
        
        for pattern in high_patterns:
            if pattern in path_lower:
                return 'high'
        
        # Medium severity (access restricted)
        if status_code in [401, 403]:
            return 'medium'
        
        # Low severity
        return 'low'
    
    def scan(
        self,
        wordlist: str = 'default',
        extensions: Optional[List[str]] = None,
        recursive: bool = False,
        max_depth: int = 2,
        filter_codes: Optional[List[int]] = None,
        filter_size: Optional[int] = None,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Perform directory bruteforce scan
        
        Args:
            wordlist: Path to wordlist file or 'default'
            extensions: File extensions to append
            recursive: Scan found directories recursively
            max_depth: Maximum recursion depth
            filter_codes: Status codes to filter out
            filter_size: Filter responses with this content length
            callback: Progress callback(path, status_code, found)
            
        Returns:
            Dict with scan results
        """
        start_time = datetime.now()
        self.is_scanning = True
        self.stop_scan = False
        self.found_paths = []
        self.scanned_paths = set()
        self.stats = {'total_requests': 0, 'found': 0, 'errors': 0, 'filtered': 0}
        
        # Detect custom 404
        self._detect_custom_404()
        
        # Load wordlist
        if wordlist == 'default':
            paths_to_check = self.DEFAULT_DIRECTORIES.copy()
        else:
            paths_to_check = load_wordlist(wordlist)
            if not paths_to_check:
                paths_to_check = self.DEFAULT_DIRECTORIES.copy()
        
        # Add extensions
        if extensions:
            extended_paths = []
            for path in paths_to_check:
                extended_paths.append(path)
                for ext in extensions:
                    if not ext.startswith('.'):
                        ext = '.' + ext
                    extended_paths.append(path + ext)
            paths_to_check = extended_paths
        
        # First level scan
        found_directories = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {
                executor.submit(self.check_path, path): path
                for path in paths_to_check
            }
            
            for future in concurrent.futures.as_completed(future_to_path):
                if self.stop_scan:
                    executor.shutdown(wait=False)
                    break
                
                path = future_to_path[future]
                
                try:
                    result = future.result()
                    
                    if result:
                        # Apply filters
                        if filter_codes and result['status_code'] in filter_codes:
                            continue
                        if filter_size and result['content_length'] == filter_size:
                            continue
                        
                        with self._lock:
                            self.found_paths.append(result)
                        
                        # Track directories for recursive scan
                        if recursive and result['status_code'] in [200, 301, 302, 403]:
                            if not any(ext in path for ext in ['.', '?', '#']):
                                found_directories.append(result['path'])
                        
                        if callback:
                            try:
                                callback(path, result['status_code'], True)
                            except Exception:
                                pass
                    else:
                        if callback:
                            try:
                                callback(path, 404, False)
                            except Exception:
                                pass
                
                except Exception:
                    pass
        
        # Recursive scanning
        if recursive and found_directories and max_depth > 1:
            self._recursive_scan(
                found_directories,
                paths_to_check,
                max_depth - 1,
                filter_codes,
                filter_size,
                callback
            )
        
        end_time = datetime.now()
        self.is_scanning = False
        
        # Sort results by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        self.found_paths.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'found_paths': self.found_paths,
            'total_found': len(self.found_paths),
            'statistics': self.stats,
            'has_custom_404': self.has_custom_404,
            'severity_summary': self._get_severity_summary(),
            'interesting_findings': self._get_interesting_findings(),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _recursive_scan(
        self,
        directories: List[str],
        wordlist: List[str],
        depth: int,
        filter_codes: Optional[List[int]],
        filter_size: Optional[int],
        callback: Optional[Callable]
    ) -> None:
        """Perform recursive scanning of found directories"""
        if depth <= 0 or self.stop_scan:
            return
        
        new_directories = []
        
        for directory in directories:
            if self.stop_scan:
                break
            
            # Create paths under this directory
            paths_to_check = [f"{directory.rstrip('/')}/{path}" for path in wordlist[:50]]  # Limit
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_path = {
                    executor.submit(self.check_path, path): path
                    for path in paths_to_check
                }
                
                for future in concurrent.futures.as_completed(future_to_path):
                    if self.stop_scan:
                        break
                    
                    try:
                        result = future.result()
                        
                        if result:
                            if filter_codes and result['status_code'] in filter_codes:
                                continue
                            if filter_size and result['content_length'] == filter_size:
                                continue
                            
                            with self._lock:
                                self.found_paths.append(result)
                            
                            if result['status_code'] in [200, 301, 302, 403]:
                                path = result['path']
                                if not any(ext in path for ext in ['.', '?', '#']):
                                    new_directories.append(path)
                            
                            if callback:
                                try:
                                    callback(result['path'], result['status_code'], True)
                                except Exception:
                                    pass
                    
                    except Exception:
                        pass
        
        # Continue recursion
        if new_directories and depth > 1:
            self._recursive_scan(
                new_directories[:10],  # Limit directories per level
                wordlist,
                depth - 1,
                filter_codes,
                filter_size,
                callback
            )
    
    def scan_backups(
        self,
        known_files: Optional[List[str]] = None,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan for backup files of known files
        
        Args:
            known_files: List of known file paths to check backups for
            callback: Progress callback
            
        Returns:
            Dict with backup scan results
        """
        start_time = datetime.now()
        backup_files = []
        
        # Default files to check backups for
        if known_files is None:
            known_files = [
                'index.php', 'index.html', 'config.php', 'wp-config.php',
                'configuration.php', 'settings.php', 'database.php', 'db.php',
                'web.config', '.htaccess', 'config.xml', 'config.yml',
                'application.properties', 'app.config', 'settings.py',
                'config.json', 'package.json', 'composer.json'
            ]
        
        paths_to_check = []
        
        for filename in known_files:
            name = filename.rsplit('.', 1)[0] if '.' in filename else filename
            
            for pattern in self.BACKUP_PATTERNS:
                backup_path = pattern.format(name=filename)
                paths_to_check.append(backup_path)
            
            # Also check with common backup extensions
            for ext in ['.bak', '.backup', '.old', '.orig', '.save', '~', '.swp']:
                paths_to_check.append(filename + ext)
        
        # Scan for backups
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {
                executor.submit(self.check_path, path): path
                for path in paths_to_check
            }
            
            for future in concurrent.futures.as_completed(future_to_path):
                if self.stop_scan:
                    break
                
                try:
                    result = future.result()
                    
                    if result:
                        result['type'] = 'backup'
                        result['severity'] = 'critical'
                        backup_files.append(result)
                        
                        with self._lock:
                            self.found_paths.append(result)
                        
                        if callback:
                            try:
                                callback(result['path'], result['status_code'], True)
                            except Exception:
                                pass
                
                except Exception:
                    pass
        
        end_time = datetime.now()
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'backup_files': backup_files,
            'total_found': len(backup_files),
            'files_checked': len(known_files),
            'patterns_used': len(self.BACKUP_PATTERNS),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds()
        }
    
    def scan_sensitive_files(
        self,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Scan for common sensitive files
        
        Returns:
            Dict with sensitive file scan results
        """
        sensitive_paths = [
            # Git/SVN
            '.git/HEAD', '.git/config', '.gitignore', '.git/logs/HEAD',
            '.svn/entries', '.svn/wc.db',
            '.hg/requires', '.hg/store',
            
            # Environment files
            '.env', '.env.local', '.env.production', '.env.development',
            '.env.backup', '.env.bak', '.env.old', 'env.js', 'env.json',
            
            # Configuration files
            'config.php', 'config.php.bak', 'configuration.php',
            'wp-config.php', 'wp-config.php.bak', 'wp-config.php~',
            'LocalSettings.php', 'settings.php', 'database.php',
            'config.yml', 'config.yaml', 'config.json', 'config.xml',
            'web.config', 'app.config', 'appsettings.json',
            'application.properties', 'application.yml',
            
            # Backup/Debug files
            'debug.log', 'error.log', 'errors.log', 'access.log',
            'php_errors.log', 'laravel.log', 'debug.txt',
            'dump.sql', 'database.sql', 'backup.sql', 'db.sql',
            'backup.zip', 'backup.tar.gz', 'site.zip', 'www.zip',
            
            # Info/Debug pages
            'phpinfo.php', 'info.php', 'test.php', 'i.php',
            'server-status', 'server-info', 'elmah.axd',
            'trace.axd', 'debug', 'status',
            
            # Credentials
            '.htpasswd', 'htpasswd', 'passwd', '.passwd',
            'credentials.xml', 'credentials.json', 'secrets.yml',
            'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_dsa.pub',
            'authorized_keys', 'known_hosts',
            
            # Package managers
            'package.json', 'package-lock.json', 'composer.json',
            'composer.lock', 'yarn.lock', 'Gemfile', 'Gemfile.lock',
            'requirements.txt', 'Pipfile', 'Pipfile.lock',
            
            # CMS specific
            'readme.html', 'readme.txt', 'README.md', 'CHANGELOG.md',
            'license.txt', 'LICENSE', 'INSTALL', 'UPGRADE',
            'xmlrpc.php', 'install.php', 'setup.php',
            
            # IDE/Editor files
            '.idea/workspace.xml', '.vscode/settings.json',
            '.project', '.classpath', '.settings',
            
            # AWS/Cloud
            '.aws/credentials', '.s3cfg', '.boto',
            'aws.yml', 'firebase.json', 'google-services.json',
            
            # Other
            'crossdomain.xml', 'clientaccesspolicy.xml',
            'security.txt', '.well-known/security.txt',
            'humans.txt', 'ads.txt', 'app-ads.txt'
        ]
        
        start_time = datetime.now()
        sensitive_files = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_path = {
                executor.submit(self.check_path, path): path
                for path in sensitive_paths
            }
            
            for future in concurrent.futures.as_completed(future_to_path):
                if self.stop_scan:
                    break
                
                try:
                    result = future.result()
                    
                    if result:
                        result['type'] = 'sensitive'
                        result['severity'] = 'critical'
                        sensitive_files.append(result)
                        
                        with self._lock:
                            self.found_paths.append(result)
                        
                        if callback:
                            try:
                                callback(result['path'], result['status_code'], True)
                            except Exception:
                                pass
                
                except Exception:
                    pass
        
        end_time = datetime.now()
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'sensitive_files': sensitive_files,
            'total_found': len(sensitive_files),
            'paths_checked': len(sensitive_paths),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds()
        }
    
    def _get_severity_summary(self) -> Dict[str, int]:
        """Get summary of findings by severity"""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for finding in self.found_paths:
            severity = finding.get('severity', 'low')
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _get_interesting_findings(self) -> List[Dict]:
        """Get list of interesting findings"""
        interesting = []
        
        for finding in self.found_paths:
            if finding.get('interesting') or finding.get('severity') in ['critical', 'high']:
                interesting.append(finding)
        
        return interesting
    
    def stop(self) -> None:
        """Stop ongoing scan"""
        self.stop_scan = True
    
    def get_found_paths(self) -> List[Dict]:
        """Get list of found paths"""
        with self._lock:
            return list(self.found_paths)
    
    def quick_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform quick directory scan with minimal wordlist"""
        quick_dirs = [
            'admin', 'login', 'dashboard', 'api', 'backup', 'config',
            'test', 'dev', 'old', '.git', '.env', 'uploads', 'private',
            'phpmyadmin', 'wp-admin', 'administrator', 'panel', 'console'
        ]
        
        # Temporarily replace default directories
        original = self.DEFAULT_DIRECTORIES.copy()
        self.DEFAULT_DIRECTORIES = quick_dirs
        
        result = self.scan(wordlist='default', callback=callback)
        
        # Restore
        self.DEFAULT_DIRECTORIES = original
        
        return result
    
    def full_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform comprehensive directory scan"""
        # Main directory scan
        main_result = self.scan(
            wordlist='default',
            extensions=['.php', '.html', '.txt', '.bak'],
            recursive=True,
            max_depth=2,
            callback=callback
        )
        
        # Sensitive files scan
        sensitive_result = self.scan_sensitive_files(callback=callback)
        
        # Backup files scan
        backup_result = self.scan_backups(callback=callback)
        
        # Combine results
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target_url': self.target_url,
            'found_paths': self.found_paths,
            'total_found': len(self.found_paths),
            'statistics': self.stats,
            'severity_summary': self._get_severity_summary(),
            'scan_types': ['directories', 'sensitive_files', 'backups'],
            'duration': (
                main_result.get('duration', 0) +
                sensitive_result.get('duration', 0) +
                backup_result.get('duration', 0)
            ),
            'timestamp': datetime.now().isoformat()
        }
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate detailed directory scan report"""
        return {
            'scan_id': self.scan_id,
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_found': len(self.found_paths),
                'severity_breakdown': self._get_severity_summary(),
                'requests_made': self.stats['total_requests'],
                'errors': self.stats['errors']
            },
            'findings': self.found_paths,
            'interesting_findings': self._get_interesting_findings(),
            'recommendations': self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        critical_findings = [f for f in self.found_paths if f.get('severity') == 'critical']
        high_findings = [f for f in self.found_paths if f.get('severity') == 'high']
        
        if critical_findings:
            recommendations.append("URGENT: Remove or restrict access to sensitive files immediately")
            
            # Check specific file types
            paths = [f['path'].lower() for f in critical_findings]
            
            if any('.git' in p for p in paths):
                recommendations.append("Remove .git directory from production server or block access via web server configuration")
            
            if any('.env' in p for p in paths):
                recommendations.append("Remove or protect .env files - they may contain credentials and API keys")
            
            if any('backup' in p or '.bak' in p or '.sql' in p for p in paths):
                recommendations.append("Remove backup files from web-accessible directories")
            
            if any('config' in p for p in paths):
                recommendations.append("Protect configuration files or move them outside web root")
        
        if high_findings:
            recommendations.append("Review and restrict access to administrative interfaces")
            recommendations.append("Implement proper authentication for sensitive endpoints")
        
        # General recommendations
        if self.found_paths:
            recommendations.append("Implement proper access controls for discovered directories")
            recommendations.append("Consider using a Web Application Firewall (WAF)")
            recommendations.append("Regularly audit web-accessible files and directories")
            recommendations.append("Remove unnecessary files and directories from production")
        
        return recommendations
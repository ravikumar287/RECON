"""
Subdomain Enumeration Service
Discovers subdomains using various techniques
"""

import dns.resolver
import requests
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any, Set
from datetime import datetime
import threading
import re
import socket

from app.services.utils import (
    is_valid_domain,
    load_wordlist,
    generate_scan_id,
    make_request,
    get_ip_from_domain
)


class SubdomainEnumerator:
    """
    Subdomain Enumeration Service
    
    Features:
    - Dictionary-based enumeration
    - Certificate Transparency logs
    - Search engine dorking
    - DNS brute force
    - Recursive enumeration
    - Wildcard detection
    """
    
    # Default subdomain wordlist (common subdomains)
    DEFAULT_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'ns3', 'ns4', 'imap', 'test', 'dev', 'development', 'stage', 'staging',
        'prod', 'production', 'admin', 'administrator', 'api', 'app', 'apps',
        'blog', 'cdn', 'cloud', 'cpanel', 'dashboard', 'demo', 'dns', 'dns1',
        'dns2', 'docs', 'download', 'email', 'exchange', 'files', 'forum', 'forums',
        'git', 'gitlab', 'help', 'helpdesk', 'home', 'host', 'hosting', 'image',
        'images', 'img', 'info', 'internal', 'intranet', 'jenkins', 'jira', 'kb',
        'ldap', 'legacy', 'linux', 'login', 'mail2', 'mailhost', 'manage', 'manager',
        'mobile', 'monitor', 'mysql', 'new', 'news', 'ns', 'owa', 'panel', 'partner',
        'partners', 'payment', 'payments', 'portal', 'preview', 'private', 'proxy',
        'public', 'remote', 'report', 'reports', 'sales', 'search', 'secure',
        'security', 'server', 'shop', 'sites', 'sms', 'sql', 'ssh', 'ssl', 'static',
        'stats', 'status', 'store', 'support', 'sync', 'syslog', 'system', 'test1',
        'test2', 'testing', 'tools', 'update', 'upload', 'v1', 'v2', 'video', 'videos',
        'vpn', 'web', 'web1', 'web2', 'webdisk', 'weblog', 'webserver', 'wiki',
        'windows', 'ww', 'www1', 'www2', 'www3', 'xml', 'backup', 'beta', 'billing',
        'crm', 'data', 'db', 'dev1', 'dev2', 'erp', 'grafana', 'kibana', 'kubernetes',
        'k8s', 'logs', 'metrics', 'nagios', 'nexus', 'prometheus', 'redis', 'sonar',
        'vault', 'zabbix', 'elastic', 'elasticsearch', 'kafka', 'rabbitmq', 'mq'
    ]
    
    def __init__(
        self,
        domain: str,
        timeout: float = 3.0,
        max_threads: int = 50,
        resolver_nameservers: Optional[List[str]] = None
    ):
        """
        Initialize Subdomain Enumerator
        
        Args:
            domain: Target domain
            timeout: DNS query timeout
            max_threads: Maximum concurrent threads
            resolver_nameservers: Custom DNS servers
        """
        self.domain = domain.strip().lower()
        self.timeout = timeout
        self.max_threads = max_threads
        self.scan_id = generate_scan_id()
        self.found_subdomains: Set[str] = set()
        self.is_scanning = False
        self.stop_scan = False
        self._lock = threading.Lock()
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        if resolver_nameservers:
            self.resolver.nameservers = resolver_nameservers
        
        # Wildcard detection
        self.has_wildcard = False
        self.wildcard_ips: Set[str] = set()
    
    def check_wildcard(self) -> bool:
        """Check if domain has wildcard DNS"""
        import random
        import string
        
        # Generate random subdomain
        random_sub = ''.join(random.choices(string.ascii_lowercase, k=16))
        test_domain = f"{random_sub}.{self.domain}"
        
        try:
            answers = self.resolver.resolve(test_domain, 'A')
            self.has_wildcard = True
            self.wildcard_ips = {str(rdata) for rdata in answers}
            return True
        except Exception:
            return False
    
    def resolve_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Resolve a single subdomain
        
        Args:
            subdomain: Subdomain prefix to check
            
        Returns:
            Dict with subdomain info if exists, None otherwise
        """
        if self.stop_scan:
            return None
        
        full_domain = f"{subdomain}.{self.domain}"
        
        result = {
            'subdomain': subdomain,
            'full_domain': full_domain,
            'ips': [],
            'cname': None,
            'alive': False
        }
        
        try:
            # Try A record
            try:
                answers = self.resolver.resolve(full_domain, 'A')
                ips = [str(rdata) for rdata in answers]
                
                # Check for wildcard
                if self.has_wildcard and set(ips) == self.wildcard_ips:
                    return None
                
                result['ips'] = ips
                result['alive'] = True
                
            except dns.resolver.NoAnswer:
                pass
            
            # Try CNAME record
            try:
                answers = self.resolver.resolve(full_domain, 'CNAME')
                for rdata in answers:
                    result['cname'] = str(rdata.target).rstrip('.')
                    result['alive'] = True
                    break
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            
            if result['alive']:
                # Check HTTP connectivity
                result['http_status'] = self._check_http(full_domain)
                return result
            
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.Timeout:
            pass
        except Exception:
            pass
        
        return None
    
    def _check_http(self, domain: str) -> Optional[int]:
        """Check HTTP status of domain"""
        for protocol in ['https', 'http']:
            try:
                response = requests.head(
                    f"{protocol}://{domain}",
                    timeout=3,
                    allow_redirects=True,
                    verify=False
                )
                return response.status_code
            except Exception:
                continue
        return None
    
    def enumerate(
        self,
        wordlist: str = 'default',
        use_crt: bool = True,
        recursive: bool = False,
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Enumerate subdomains
        
        Args:
            wordlist: Path to wordlist file or 'default'
            use_crt: Use Certificate Transparency logs
            recursive: Perform recursive enumeration
            callback: Progress callback function(subdomain, status)
            
        Returns:
            Dict with enumeration results
        """
        start_time = datetime.now()
        self.is_scanning = True
        self.stop_scan = False
        self.found_subdomains = set()
        
        # Validate domain
        if not is_valid_domain(self.domain):
            return {
                'success': False,
                'error': 'Invalid domain',
                'domain': self.domain
            }
        
        # Check for wildcard DNS
        self.check_wildcard()
        
        # Load wordlist
        if wordlist == 'default':
            subdomains_to_check = self.DEFAULT_SUBDOMAINS.copy()
        else:
            subdomains_to_check = load_wordlist(wordlist)
            if not subdomains_to_check:
                subdomains_to_check = self.DEFAULT_SUBDOMAINS.copy()
        
        found_subdomains = []
        
        # Use Certificate Transparency logs
        if use_crt:
            crt_subdomains = self._fetch_from_crt_sh()
            for sub in crt_subdomains:
                if sub not in subdomains_to_check:
                    subdomains_to_check.append(sub)
        
        total = len(subdomains_to_check)
        checked = 0
        
        # Multi-threaded enumeration
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_subdomain = {
                executor.submit(self.resolve_subdomain, sub): sub
                for sub in subdomains_to_check
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                if self.stop_scan:
                    break
                
                subdomain = future_to_subdomain[future]
                checked += 1
                
                try:
                    result = future.result()
                    
                    if result:
                        found_subdomains.append(result)
                        with self._lock:
                            self.found_subdomains.add(result['full_domain'])
                        
                        if callback:
                            try:
                                callback(result['full_domain'], 'found')
                            except Exception:
                                pass
                    else:
                        if callback:
                            try:
                                callback(f"{subdomain}.{self.domain}", 'not_found')
                            except Exception:
                                pass
                
                except Exception:
                    pass
        
        # Recursive enumeration
        if recursive and found_subdomains:
            recursive_found = self._recursive_enum(found_subdomains, callback)
            found_subdomains.extend(recursive_found)
        
        end_time = datetime.now()
        self.is_scanning = False
        
        # Sort by subdomain name
        found_subdomains.sort(key=lambda x: x['full_domain'])
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'domain': self.domain,
            'subdomains': found_subdomains,
            'total_found': len(found_subdomains),
            'wordlist_size': total,
            'has_wildcard': self.has_wildcard,
            'used_crt': use_crt,
            'recursive': recursive,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def _fetch_from_crt_sh(self) -> List[str]:
        """Fetch subdomains from crt.sh Certificate Transparency logs"""
        subdomains = []
        
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple domains in one certificate
                    for domain in name.split('\n'):
                        domain = domain.strip().lower()
                        if domain.endswith(f".{self.domain}"):
                            subdomain = domain.replace(f".{self.domain}", '')
                            # Skip wildcards and the domain itself
                            if subdomain and '*' not in subdomain and subdomain != self.domain:
                                subdomains.append(subdomain)
        
        except Exception:
            pass
        
        return list(set(subdomains))
    
    def _recursive_enum(
        self,
        found: List[Dict],
        callback: Optional[Callable]
    ) -> List[Dict]:
        """Perform recursive enumeration on found subdomains"""
        additional_found = []
        
        for item in found:
            subdomain = item['subdomain']
            
            # Try common prefixes on found subdomains
            prefixes = ['dev', 'test', 'staging', 'api', 'admin', 'internal']
            
            for prefix in prefixes:
                new_sub = f"{prefix}.{subdomain}"
                if new_sub not in self.found_subdomains:
                    result = self.resolve_subdomain(new_sub)
                    if result:
                        additional_found.append(result)
                        self.found_subdomains.add(result['full_domain'])
                        
                        if callback:
                            try:
                                callback(result['full_domain'], 'found')
                            except Exception:
                                pass
        
        return additional_found
    
    def stop(self) -> None:
        """Stop ongoing enumeration"""
        self.stop_scan = True
    
    def get_found_subdomains(self) -> List[str]:
        """Get list of found subdomains"""
        with self._lock:
            return list(self.found_subdomains)
    
    def search_virustotal(self, api_key: str) -> List[str]:
        """Search VirusTotal for subdomains (requires API key)"""
        subdomains = []
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': api_key,
                'domain': self.domain
            }
            
            response = requests.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                subs = data.get('subdomains', [])
                subdomains = [s for s in subs if s.endswith(self.domain)]
        
        except Exception:
            pass
        
        return subdomains
    
    def quick_enum(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Quick enumeration with minimal wordlist"""
        quick_list = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test',
            'staging', 'blog', 'shop', 'app', 'cdn', 'static'
        ]
        
        # Save original list
        original = self.DEFAULT_SUBDOMAINS.copy()
        self.DEFAULT_SUBDOMAINS = quick_list
        
        result = self.enumerate(wordlist='default', use_crt=False, callback=callback)
        
        # Restore original list
        self.DEFAULT_SUBDOMAINS = original
        
        return result
"""
Main Vulnerability Scanner Service
Orchestrates all scanning modules for comprehensive assessment
"""

import concurrent.futures
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import threading
import json
import os

from app.services.utils import (
    normalize_url,
    validate_target,
    generate_scan_id,
    save_json_report,
    get_domain_from_url,
    calculate_risk_score
)
from app.services.port_scanner import PortScanner
from app.services.dns_lookup import DNSLookup
from app.services.whois_lookup import WhoisLookup
from app.services.subdomain_enum import SubdomainEnumerator
from app.services.tech_detector import TechDetector
from app.services.ssl_analyzer import SSLAnalyzer
from app.services.header_analyzer import HeaderAnalyzer
from app.services.xss_scanner import XSSScanner
from app.services.sqli_scanner import SQLiScanner
from app.services.dir_bruteforce import DirectoryBruteforce
from app.services.crawler import WebCrawler


class VulnerabilityScanner:
    """
    Main Vulnerability Scanner that orchestrates all scanning modules
    
    Features:
    - Full comprehensive scan
    - Modular scanning
    - Progress callbacks
    - Report generation
    - Risk scoring
    """
    
    # Scan stages
    STAGES = [
        'initialization',
        'reconnaissance',
        'technology_detection',
        'ssl_analysis',
        'header_analysis',
        'port_scanning',
        'web_crawling',
        'vulnerability_scanning',
        'report_generation'
    ]
    
    def __init__(self, target: str, options: Optional[Dict] = None):
        """
        Initialize Vulnerability Scanner
        
        Args:
            target: Target URL, domain, or IP
            options: Scan configuration options
        """
        self.original_target = target
        self.target = normalize_url(target) if '://' in target or '.' in target else target
        self.options = options or {}
        self.scan_id = generate_scan_id()
        self.results = {}
        self.vulnerabilities = []
        self.is_scanning = False
        self.stop_scan = False
        self.current_stage = None
        self.progress = 0
        self._lock = threading.Lock()
        
        # Parse options
        self.scan_ports = self.options.get('scan_ports', True)
        self.scan_subdomains = self.options.get('scan_subdomains', False)
        self.scan_directories = self.options.get('scan_directories', True)
        self.scan_xss = self.options.get('scan_xss', True)
        self.scan_sqli = self.options.get('scan_sqli', True)
        self.crawl_depth = self.options.get('crawl_depth', 2)
        self.max_pages = self.options.get('max_pages', 50)
        self.threads = self.options.get('threads', 10)
    
    def full_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """
        Perform full comprehensive vulnerability scan
        
        Args:
            callback: Progress callback function(stage, progress, message)
            
        Returns:
            Dict with complete scan results
        """
        start_time = datetime.now()
        self.is_scanning = True
        self.stop_scan = False
        
        result = {
            'success': False,
            'scan_id': self.scan_id,
            'target': self.target,
            'original_target': self.original_target,
            'scan_type': 'full',
            'modules': {},
            'vulnerabilities': [],
            'summary': {},
            'risk_score': 0,
            'risk_level': 'unknown',
            'recommendations': [],
            'error': None
        }
        
        try:
            # Validate target
            is_valid, target_type, normalized = validate_target(self.original_target)
            if not is_valid:
                result['error'] = 'Invalid target'
                return result
            
            result['target_type'] = target_type
            domain = get_domain_from_url(self.target) if target_type == 'url' else normalized
            
            total_stages = len(self.STAGES)
            completed_stages = 0
            
            # Stage 1: Initialization
            self._update_progress(callback, 'initialization', 5, 'Starting scan...')
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 2: Reconnaissance (DNS, WHOIS)
            self._update_progress(callback, 'reconnaissance', 10, 'Gathering reconnaissance data...')
            
            # DNS Lookup
            try:
                dns_scanner = DNSLookup(domain)
                result['modules']['dns'] = dns_scanner.lookup_all()
            except Exception as e:
                result['modules']['dns'] = {'error': str(e)}
            
            # WHOIS Lookup
            try:
                whois_scanner = WhoisLookup(domain)
                result['modules']['whois'] = whois_scanner.lookup()
            except Exception as e:
                result['modules']['whois'] = {'error': str(e)}
            
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 3: Technology Detection
            self._update_progress(callback, 'technology_detection', 20, 'Detecting technologies...')
            
            try:
                tech_detector = TechDetector(self.target)
                result['modules']['technology'] = tech_detector.detect()
            except Exception as e:
                result['modules']['technology'] = {'error': str(e)}
            
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 4: SSL/TLS Analysis
            self._update_progress(callback, 'ssl_analysis', 30, 'Analyzing SSL/TLS configuration...')
            
            if self.target.startswith('https://'):
                try:
                    ssl_analyzer = SSLAnalyzer(domain)
                    result['modules']['ssl'] = ssl_analyzer.analyze()
                    
                    # Add SSL vulnerabilities
                    if result['modules']['ssl'].get('vulnerabilities'):
                        for vuln in result['modules']['ssl']['vulnerabilities']:
                            self.vulnerabilities.append({
                                'type': 'ssl',
                                'name': vuln['name'],
                                'severity': vuln['severity'],
                                'description': vuln['description'],
                                'cve': vuln.get('cve')
                            })
                except Exception as e:
                    result['modules']['ssl'] = {'error': str(e)}
            
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 5: HTTP Header Analysis
            self._update_progress(callback, 'header_analysis', 40, 'Analyzing HTTP headers...')
            
            try:
                header_analyzer = HeaderAnalyzer(self.target)
                result['modules']['headers'] = header_analyzer.analyze()
                
                # Add header vulnerabilities
                if result['modules']['headers'].get('security_headers', {}).get('missing'):
                    for missing in result['modules']['headers']['security_headers']['missing']:
                        if missing['severity'] in ['high', 'medium']:
                            self.vulnerabilities.append({
                                'type': 'header',
                                'name': f"Missing {missing['header']}",
                                'severity': missing['severity'],
                                'description': missing['description'],
                                'recommendation': missing['recommendation']
                            })
            except Exception as e:
                result['modules']['headers'] = {'error': str(e)}
            
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 6: Port Scanning
            if self.scan_ports:
                self._update_progress(callback, 'port_scanning', 50, 'Scanning ports...')
                
                try:
                    port_scanner = PortScanner(domain)
                    result['modules']['ports'] = port_scanner.scan(ports='1-1000', scan_type='tcp')
                    
                    # Check for risky open ports
                    risky_ports = [21, 23, 25, 110, 143, 445, 3389]
                    if result['modules']['ports'].get('open_ports'):
                        for port_info in result['modules']['ports']['open_ports']:
                            if port_info['port'] in risky_ports:
                                self.vulnerabilities.append({
                                    'type': 'port',
                                    'name': f"Risky port {port_info['port']} open",
                                    'severity': 'medium',
                                    'description': f"Port {port_info['port']} ({port_info['service']}) is open",
                                    'port': port_info['port'],
                                    'service': port_info['service']
                                })
                except Exception as e:
                    result['modules']['ports'] = {'error': str(e)}
            
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 7: Web Crawling
            self._update_progress(callback, 'web_crawling', 60, 'Crawling website...')
            
            crawled_urls = []
            forms = []
            
            try:
                crawler = WebCrawler(self.target, max_depth=self.crawl_depth, max_pages=self.max_pages)
                crawl_result = crawler.crawl()
                result['modules']['crawler'] = crawl_result
                
                if crawl_result.get('success'):
                    crawled_urls = [p['url'] for p in crawl_result.get('pages', [])]
                    forms = crawl_result.get('forms', [])
            except Exception as e:
                result['modules']['crawler'] = {'error': str(e)}
            
            completed_stages += 1
            
            if self.stop_scan:
                return self._create_cancelled_result(result)
            
            # Stage 8: Vulnerability Scanning (XSS, SQLi, Directory)
            self._update_progress(callback, 'vulnerability_scanning', 70, 'Scanning for vulnerabilities...')
            
            # XSS Scanning
            if self.scan_xss and crawled_urls:
                try:
                    xss_scanner = XSSScanner(self.target)
                    xss_result = xss_scanner.scan(urls=crawled_urls[:20], forms=forms)
                    result['modules']['xss'] = xss_result
                    
                    if xss_result.get('vulnerabilities'):
                        for vuln in xss_result['vulnerabilities']:
                            self.vulnerabilities.append({
                                'type': 'xss',
                                'name': 'Cross-Site Scripting (XSS)',
                                'severity': 'high',
                                'url': vuln.get('url'),
                                'parameter': vuln.get('parameter'),
                                'payload': vuln.get('payload'),
                                'description': 'XSS vulnerability allows injection of malicious scripts'
                            })
                except Exception as e:
                    result['modules']['xss'] = {'error': str(e)}
            
            self._update_progress(callback, 'vulnerability_scanning', 80, 'Checking SQL injection...')
            
            # SQLi Scanning
            if self.scan_sqli and crawled_urls:
                try:
                    sqli_scanner = SQLiScanner(self.target)
                    sqli_result = sqli_scanner.scan(urls=crawled_urls[:20], forms=forms)
                    result['modules']['sqli'] = sqli_result
                    
                    if sqli_result.get('vulnerabilities'):
                        for vuln in sqli_result['vulnerabilities']:
                            self.vulnerabilities.append({
                                'type': 'sqli',
                                'name': 'SQL Injection',
                                'severity': 'critical',
                                'url': vuln.get('url'),
                                'parameter': vuln.get('parameter'),
                                'payload': vuln.get('payload'),
                                'description': 'SQL injection vulnerability allows database manipulation'
                            })
                except Exception as e:
                    result['modules']['sqli'] = {'error': str(e)}
            
            self._update_progress(callback, 'vulnerability_scanning', 85, 'Bruteforcing directories...')
            
            # Directory Bruteforce
            if self.scan_directories:
                try:
                    dir_scanner = DirectoryBruteforce(self.target)
                    dir_result = dir_scanner.scan(wordlist='default')
                    result['modules']['directories'] = dir_result
                    
                    # Check for sensitive directories
                    sensitive_paths = ['admin', 'backup', 'config', 'database', '.git', '.env']
                    if dir_result.get('found'):
                        for item in dir_result['found']:
                            path = item.get('path', '').lower()
                            if any(s in path for s in sensitive_paths):
                                self.vulnerabilities.append({
                                    'type': 'directory',
                                    'name': 'Sensitive Directory Exposed',
                                    'severity': 'medium',
                                    'url': item.get('url'),
                                    'path': item.get('path'),
                                    'description': 'Sensitive directory or file is publicly accessible'
                                })
                except Exception as e:
                    result['modules']['directories'] = {'error': str(e)}
            
            completed_stages += 1
            
            # Stage 9: Report Generation
            self._update_progress(callback, 'report_generation', 95, 'Generating report...')
            
            # Add all vulnerabilities to result
            result['vulnerabilities'] = self.vulnerabilities
            
            # Calculate risk score
            result['risk_score'] = calculate_risk_score(self.vulnerabilities)
            result['risk_level'] = self._get_risk_level(result['risk_score'])
            
            # Generate summary
            result['summary'] = self._generate_summary(result)
            
            # Generate recommendations
            result['recommendations'] = self._generate_recommendations(result)
            
            # Save report
            report_path = f"reports/{self.scan_id}.json"
            save_json_report(result, report_path)
            result['report_path'] = report_path
            
            self._update_progress(callback, 'complete', 100, 'Scan complete!')
            
            result['success'] = True
            
        except Exception as e:
            result['error'] = str(e)
        
        end_time = datetime.now()
        result['start_time'] = start_time.isoformat()
        result['end_time'] = end_time.isoformat()
        result['duration'] = (end_time - start_time).total_seconds()
        result['timestamp'] = datetime.now().isoformat()
        
        self.is_scanning = False
        self.results = result
        
        return result
    
    def _update_progress(
        self,
        callback: Optional[Callable],
        stage: str,
        progress: int,
        message: str
    ) -> None:
        """Update scan progress"""
        self.current_stage = stage
        self.progress = progress
        
        if callback:
            try:
                callback(stage, progress, message)
            except Exception:
                pass
    
    def _create_cancelled_result(self, result: Dict) -> Dict:
        """Create result for cancelled scan"""
        result['success'] = False
        result['error'] = 'Scan was cancelled'
        result['cancelled'] = True
        return result
    
    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to risk level"""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        elif score >= 20:
            return 'low'
        else:
            return 'info'
    
    def _generate_summary(self, result: Dict) -> Dict:
        """Generate scan summary"""
        vulns = result.get('vulnerabilities', [])
        
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for vuln in vulns:
            severity = vuln.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        return {
            'total_vulnerabilities': len(vulns),
            'severity_breakdown': severity_counts,
            'modules_run': len(result.get('modules', {})),
            'risk_score': result.get('risk_score', 0),
            'risk_level': result.get('risk_level', 'unknown')
        }
    
    def _generate_recommendations(self, result: Dict) -> List[Dict]:
        """Generate security recommendations"""
        recommendations = []
        
        vulns = result.get('vulnerabilities', [])
        
        # Group by type
        vuln_types = set(v.get('type') for v in vulns)
        
        if 'xss' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'category': 'XSS Prevention',
                'recommendation': 'Implement proper output encoding and Content Security Policy',
                'details': [
                    'Encode all user input before rendering',
                    'Use CSP headers to prevent inline scripts',
                    'Validate and sanitize all input data'
                ]
            })
        
        if 'sqli' in vuln_types:
            recommendations.append({
                'priority': 'critical',
                'category': 'SQL Injection Prevention',
                'recommendation': 'Use parameterized queries and prepared statements',
                'details': [
                    'Never concatenate user input into SQL queries',
                    'Use ORM or prepared statements',
                    'Implement proper input validation',
                    'Apply principle of least privilege for database accounts'
                ]
            })
        
        if 'header' in vuln_types:
            recommendations.append({
                'priority': 'medium',
                'category': 'Security Headers',
                'recommendation': 'Implement all recommended security headers',
                'details': [
                    'Add Strict-Transport-Security header',
                    'Implement Content-Security-Policy',
                    'Add X-Content-Type-Options: nosniff',
                    'Add X-Frame-Options: DENY'
                ]
            })
        
        if 'ssl' in vuln_types:
            recommendations.append({
                'priority': 'high',
                'category': 'SSL/TLS Configuration',
                'recommendation': 'Update SSL/TLS configuration',
                'details': [
                    'Disable TLS 1.0 and TLS 1.1',
                    'Enable TLS 1.3',
                    'Use strong cipher suites',
                    'Renew certificates before expiration'
                ]
            })
        
        return recommendations
    
    def stop(self) -> None:
        """Stop ongoing scan"""
        self.stop_scan = True
    
    def get_progress(self) -> Dict:
        """Get current scan progress"""
        return {
            'scan_id': self.scan_id,
            'is_scanning': self.is_scanning,
            'current_stage': self.current_stage,
            'progress': self.progress
        }
    
    def quick_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform quick scan (headers, SSL, basic checks only)"""
        self.scan_ports = False
        self.scan_subdomains = False
        self.scan_directories = False
        self.scan_xss = False
        self.scan_sqli = False
        self.crawl_depth = 1
        self.max_pages = 10
        
        return self.full_scan(callback)
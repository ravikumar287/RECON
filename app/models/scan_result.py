"""
Scan Result Models
Comprehensive data models for all types of scan results
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
from enum import Enum
import json
import os
import hashlib
import uuid


# ============================================================
# ENUMS
# ============================================================

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def score(self) -> int:
        """Get numeric score for severity"""
        scores = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 2,
            "info": 0
        }
        return scores.get(self.value, 0)
    
    @property
    def color(self) -> str:
        """Get color code for severity"""
        colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#16a34a",
            "info": "#2563eb"
        }
        return colors.get(self.value, "#6b7280")


class Confidence(Enum):
    """Confidence levels for findings"""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


class ScanStatus(Enum):
    """Scan status values"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


class ScanType(Enum):
    """Types of scans"""
    FULL_SCAN = "full_scan"
    PORT_SCAN = "port_scan"
    DNS_LOOKUP = "dns_lookup"
    WHOIS_LOOKUP = "whois_lookup"
    SUBDOMAIN_ENUM = "subdomain_enum"
    TECH_DETECTION = "tech_detection"
    SSL_ANALYSIS = "ssl_analysis"
    HEADER_ANALYSIS = "header_analysis"
    DIRECTORY_SCAN = "directory_scan"
    CRAWL = "crawl"
    XSS_SCAN = "xss_scan"
    SQLI_SCAN = "sqli_scan"
    VULN_SCAN = "vuln_scan"


# ============================================================
# BASE MODELS
# ============================================================

@dataclass
class BaseModel:
    """Base model with common functionality"""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary"""
        def serialize(obj):
            if isinstance(obj, Enum):
                return obj.value
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, BaseModel):
                return obj.to_dict()
            elif isinstance(obj, list):
                return [serialize(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: serialize(v) for k, v in obj.items()}
            elif isinstance(obj, set):
                return list(obj)
            return obj
        
        return {k: serialize(v) for k, v in asdict(self).items()}
    
    def to_json(self, indent: int = 2) -> str:
        """Convert model to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BaseModel':
        """Create model from dictionary"""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> 'BaseModel':
        """Create model from JSON string"""
        return cls.from_dict(json.loads(json_str))


# ============================================================
# TARGET MODELS
# ============================================================

@dataclass
class Target(BaseModel):
    """Target information model"""
    
    # Primary identifier
    target: str
    
    # Target details
    target_type: str = "unknown"  # domain, ip, url
    normalized: str = ""
    ip_address: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    protocol: str = "https"
    
    # Metadata
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __post_init__(self):
        """Normalize target after initialization"""
        if not self.normalized:
            self.normalized = self.target.strip().lower()
    
    @property
    def full_url(self) -> str:
        """Get full URL for target"""
        if self.target.startswith(('http://', 'https://')):
            return self.target
        
        port_str = f":{self.port}" if self.port and self.port not in [80, 443] else ""
        return f"{self.protocol}://{self.target}{port_str}"
    
    @property
    def identifier(self) -> str:
        """Get unique identifier for target"""
        return hashlib.md5(self.normalized.encode()).hexdigest()[:12]


# ============================================================
# VULNERABILITY MODELS
# ============================================================

@dataclass
class Vulnerability(BaseModel):
    """Base vulnerability model"""
    
    # Identification
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    name: str = ""
    type: str = ""
    
    # Location
    url: str = ""
    parameter: Optional[str] = None
    method: str = "GET"
    
    # Severity and confidence
    severity: str = "info"
    confidence: str = "low"
    
    # Details
    description: str = ""
    payload: Optional[str] = None
    evidence: Optional[str] = None
    
    # Recommendations
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # Metadata
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Additional data
    extra: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def severity_score(self) -> int:
        """Get numeric severity score"""
        scores = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}
        return scores.get(self.severity.lower(), 0)
    
    @property
    def is_critical(self) -> bool:
        """Check if vulnerability is critical"""
        return self.severity.lower() in ["critical", "high"]


@dataclass
class XSSVulnerability(Vulnerability):
    """XSS-specific vulnerability model"""
    
    type: str = "XSS"
    xss_type: str = "reflected"  # reflected, stored, dom
    context: str = "html_body"  # html_body, attribute, script, etc.
    would_execute: bool = False
    
    # XSS-specific fields
    sink: Optional[str] = None
    source: Optional[str] = None
    
    def __post_init__(self):
        if not self.name:
            self.name = f"{self.xss_type.title()} XSS"
        if not self.description:
            self.description = f"{self.xss_type.title()} Cross-Site Scripting vulnerability detected"
        if not self.remediation:
            self.remediation = "Implement proper output encoding and Content Security Policy (CSP)"


@dataclass
class SQLiVulnerability(Vulnerability):
    """SQL Injection-specific vulnerability model"""
    
    type: str = "SQLi"
    sqli_type: str = "error-based"  # error-based, boolean, time-based, union
    database: Optional[str] = None  # MySQL, PostgreSQL, MSSQL, Oracle, SQLite
    
    # SQLi-specific fields
    delay_time: Optional[float] = None
    columns_count: Optional[int] = None
    
    def __post_init__(self):
        if not self.name:
            self.name = f"{self.sqli_type.replace('-', ' ').title()} SQL Injection"
        if not self.description:
            db_info = f" ({self.database})" if self.database else ""
            self.description = f"{self.sqli_type.title()} SQL Injection vulnerability detected{db_info}"
        if not self.remediation:
            self.remediation = "Use parameterized queries (prepared statements) for all database operations"


# ============================================================
# PORT SCAN MODELS
# ============================================================

@dataclass
class PortInfo(BaseModel):
    """Information about a scanned port"""
    
    port: int
    state: str = "closed"  # open, closed, filtered
    service: str = "unknown"
    version: Optional[str] = None
    banner: Optional[str] = None
    protocol: str = "tcp"
    
    # Risk assessment
    risk_level: str = "low"  # low, medium, high
    
    @property
    def is_open(self) -> bool:
        return self.state == "open"


@dataclass
class PortScanResult(BaseModel):
    """Port scan result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"port_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "port_scan"
    
    # Target
    target: str = ""
    target_ip: Optional[str] = None
    
    # Results
    open_ports: List[Dict[str, Any]] = field(default_factory=list)
    filtered_ports: int = 0
    closed_ports: int = 0
    
    # Statistics
    ports_scanned: int = 0
    open_count: int = 0
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_port(self, port_info: Union[PortInfo, Dict]) -> None:
        """Add a port to results"""
        if isinstance(port_info, PortInfo):
            port_info = port_info.to_dict()
        self.open_ports.append(port_info)
        self.open_count = len(self.open_ports)
    
    def get_high_risk_ports(self) -> List[Dict]:
        """Get ports with high risk level"""
        return [p for p in self.open_ports if p.get('risk_level') == 'high']
    
    @property
    def has_critical_ports(self) -> bool:
        """Check if critical ports are open"""
        critical_ports = [21, 23, 25, 110, 139, 445, 1433, 3306, 3389]
        open_port_numbers = [p.get('port') for p in self.open_ports]
        return any(p in open_port_numbers for p in critical_ports)


# ============================================================
# DNS LOOKUP MODELS
# ============================================================

@dataclass
class DNSRecord(BaseModel):
    """DNS record model"""
    
    record_type: str
    value: str
    ttl: Optional[int] = None
    priority: Optional[int] = None  # For MX records
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSLookupResult(BaseModel):
    """DNS lookup result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"dns_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "dns_lookup"
    
    # Target
    target: str = ""
    
    # Results by record type
    records: Dict[str, List[Dict]] = field(default_factory=dict)
    all_records: List[Dict] = field(default_factory=list)
    
    # Summary
    total_records: int = 0
    record_types_found: List[str] = field(default_factory=list)
    
    # Special records
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    dkim_found: bool = False
    dnssec_enabled: bool = False
    
    # Name servers
    nameservers: List[str] = field(default_factory=list)
    mail_servers: List[Dict] = field(default_factory=list)
    
    # Zone transfer
    zone_transfer_vulnerable: bool = False
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_record(self, record_type: str, record: Union[DNSRecord, Dict]) -> None:
        """Add a DNS record"""
        if isinstance(record, DNSRecord):
            record = record.to_dict()
        
        if record_type not in self.records:
            self.records[record_type] = []
            self.record_types_found.append(record_type)
        
        self.records[record_type].append(record)
        self.all_records.append({**record, 'type': record_type})
        self.total_records = len(self.all_records)


# ============================================================
# WHOIS MODELS
# ============================================================

@dataclass
class WhoisResult(BaseModel):
    """WHOIS lookup result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"whois_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "whois_lookup"
    
    # Target
    target: str = ""
    
    # Domain information
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    
    # Dates
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    
    # Domain age
    domain_age_days: Optional[int] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    
    # Name servers
    name_servers: List[str] = field(default_factory=list)
    
    # Status
    status: List[str] = field(default_factory=list)
    
    # Registrant information
    registrant: Dict[str, Any] = field(default_factory=dict)
    
    # DNSSEC
    dnssec: Optional[str] = None
    
    # Raw data
    raw_text: Optional[str] = None
    
    # Timing
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def is_expiring_soon(self) -> bool:
        """Check if domain expires within 90 days"""
        return self.days_until_expiry is not None and self.days_until_expiry < 90
    
    @property
    def registrant_info(self) -> str:
        """Get formatted registrant information"""
        org = self.registrant.get('organization', 'N/A')
        country = self.registrant.get('country', 'N/A')
        return f"{org} ({country})"


# ============================================================
# SUBDOMAIN MODELS
# ============================================================

@dataclass
class SubdomainInfo(BaseModel):
    """Subdomain information model"""
    
    subdomain: str
    full_domain: str
    ips: List[str] = field(default_factory=list)
    cname: Optional[str] = None
    alive: bool = False
    http_status: Optional[int] = None
    title: Optional[str] = None


@dataclass
class SubdomainResult(BaseModel):
    """Subdomain enumeration result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"subdomain_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "subdomain_enum"
    
    # Target
    domain: str = ""
    
    # Results
    subdomains: List[Dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    
    # Configuration
    wordlist_size: int = 0
    used_crt: bool = False
    recursive: bool = False
    has_wildcard: bool = False
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_subdomain(self, subdomain: Union[SubdomainInfo, Dict]) -> None:
        """Add a subdomain to results"""
        if isinstance(subdomain, SubdomainInfo):
            subdomain = subdomain.to_dict()
        self.subdomains.append(subdomain)
        self.total_found = len(self.subdomains)
    
    def get_live_subdomains(self) -> List[Dict]:
        """Get only live subdomains"""
        return [s for s in self.subdomains if s.get('alive', False)]


# ============================================================
# TECHNOLOGY DETECTION MODELS
# ============================================================

@dataclass
class Technology(BaseModel):
    """Detected technology model"""
    
    name: str
    category: str = "unknown"
    version: Optional[str] = None
    confidence: int = 100
    website: Optional[str] = None
    cpe: Optional[str] = None
    
    # Security implications
    known_vulnerabilities: List[str] = field(default_factory=list)
    outdated: bool = False


@dataclass
class TechDetectionResult(BaseModel):
    """Technology detection result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"tech_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "tech_detection"
    
    # Target
    url: str = ""
    
    # Results
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    categories: Dict[str, List[str]] = field(default_factory=dict)
    
    # Specific detections
    cms: Optional[str] = None
    web_server: Optional[str] = None
    programming_language: Optional[str] = None
    javascript_frameworks: List[str] = field(default_factory=list)
    css_frameworks: List[str] = field(default_factory=list)
    
    # Headers information
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Timing
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_technology(self, tech: Union[Technology, Dict]) -> None:
        """Add a detected technology"""
        if isinstance(tech, Technology):
            tech = tech.to_dict()
        
        self.technologies.append(tech)
        
        # Organize by category
        category = tech.get('category', 'unknown')
        if category not in self.categories:
            self.categories[category] = []
        self.categories[category].append(tech.get('name', 'Unknown'))


# ============================================================
# SSL/TLS ANALYSIS MODELS
# ============================================================

@dataclass
class CertificateInfo(BaseModel):
    """SSL Certificate information model"""
    
    # Subject
    subject: Dict[str, str] = field(default_factory=dict)
    common_name: Optional[str] = None
    
    # Issuer
    issuer: Dict[str, str] = field(default_factory=dict)
    issuer_name: Optional[str] = None
    
    # Validity
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False
    is_valid: bool = True
    
    # Details
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    version: Optional[int] = None
    
    # Extensions
    san: List[str] = field(default_factory=list)  # Subject Alternative Names
    key_usage: List[str] = field(default_factory=list)
    
    # Key information
    public_key_type: Optional[str] = None
    public_key_bits: Optional[int] = None
    
    # Trust
    is_self_signed: bool = False
    chain_valid: bool = True


@dataclass
class SSLAnalysisResult(BaseModel):
    """SSL/TLS analysis result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"ssl_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "ssl_analysis"
    
    # Target
    host: str = ""
    port: int = 443
    
    # Certificate
    certificate: Dict[str, Any] = field(default_factory=dict)
    certificate_chain: List[Dict] = field(default_factory=list)
    
    # Protocol support
    protocols: Dict[str, bool] = field(default_factory=dict)
    preferred_protocol: Optional[str] = None
    
    # Cipher suites
    cipher_suites: List[Dict] = field(default_factory=list)
    preferred_cipher: Optional[str] = None
    weak_ciphers: List[str] = field(default_factory=list)
    
    # Security features
    hsts_enabled: bool = False
    hsts_max_age: Optional[int] = None
    ocsp_stapling: bool = False
    
    # Vulnerabilities
    vulnerabilities: List[str] = field(default_factory=list)
    
    # Grade
    grade: str = "Unknown"
    score: int = 0
    
    # Timing
    duration: float = 0.0
    
    # Status
    success: bool = True
    ssl_enabled: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    @property
    def is_secure(self) -> bool:
        """Check if SSL configuration is secure"""
        return (
            self.grade in ['A+', 'A', 'A-', 'B+', 'B'] and
            not self.vulnerabilities and
            not self.weak_ciphers
        )


# ============================================================
# HEADER ANALYSIS MODELS
# ============================================================

@dataclass
class SecurityHeader(BaseModel):
    """Security header model"""
    
    name: str
    value: Optional[str] = None
    present: bool = False
    valid: bool = False
    score: int = 0
    max_score: int = 10
    recommendation: str = ""


@dataclass
class HeaderAnalysisResult(BaseModel):
    """HTTP header analysis result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"header_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "header_analysis"
    
    # Target
    url: str = ""
    
    # All headers
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Security headers analysis
    security_headers: List[Dict[str, Any]] = field(default_factory=list)
    missing_headers: List[str] = field(default_factory=list)
    
    # Specific headers
    content_security_policy: Optional[str] = None
    x_frame_options: Optional[str] = None
    x_content_type_options: Optional[str] = None
    x_xss_protection: Optional[str] = None
    strict_transport_security: Optional[str] = None
    referrer_policy: Optional[str] = None
    permissions_policy: Optional[str] = None
    
    # Information disclosure
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    information_disclosure: List[str] = field(default_factory=list)
    
    # Cookies
    cookies: List[Dict] = field(default_factory=list)
    insecure_cookies: List[str] = field(default_factory=list)
    
    # Score
    score: int = 0
    max_score: int = 100
    grade: str = "F"
    
    # Timing
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def calculate_grade(self) -> str:
        """Calculate grade based on score"""
        if self.score >= 90:
            return "A+"
        elif self.score >= 80:
            return "A"
        elif self.score >= 70:
            return "B"
        elif self.score >= 60:
            return "C"
        elif self.score >= 50:
            return "D"
        else:
            return "F"


# ============================================================
# DIRECTORY SCAN MODELS
# ============================================================

@dataclass
class FoundPath(BaseModel):
    """Found path/directory model"""
    
    path: str
    url: str
    status_code: int
    content_length: int = 0
    content_type: str = ""
    title: Optional[str] = None
    redirect_url: Optional[str] = None
    severity: str = "low"
    interesting: bool = False
    type: str = "directory"  # directory, file, backup, sensitive


@dataclass
class DirectoryScanResult(BaseModel):
    """Directory bruteforce result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"dir_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "directory_scan"
    
    # Target
    target_url: str = ""
    
    # Results
    found_paths: List[Dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    
    # Statistics
    statistics: Dict[str, int] = field(default_factory=dict)
    
    # Severity breakdown
    severity_summary: Dict[str, int] = field(default_factory=dict)
    
    # Interesting findings
    interesting_findings: List[Dict] = field(default_factory=list)
    sensitive_files: List[Dict] = field(default_factory=list)
    backup_files: List[Dict] = field(default_factory=list)
    
    # Configuration
    has_custom_404: bool = False
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_path(self, path: Union[FoundPath, Dict]) -> None:
        """Add a found path"""
        if isinstance(path, FoundPath):
            path = path.to_dict()
        self.found_paths.append(path)
        self.total_found = len(self.found_paths)
        
        # Update severity summary
        severity = path.get('severity', 'low')
        self.severity_summary[severity] = self.severity_summary.get(severity, 0) + 1
    
    def get_critical_findings(self) -> List[Dict]:
        """Get critical and high severity findings"""
        return [p for p in self.found_paths if p.get('severity') in ['critical', 'high']]


# ============================================================
# CRAWL MODELS
# ============================================================

@dataclass
class CrawledPage(BaseModel):
    """Crawled page model"""
    
    url: str
    depth: int = 0
    status_code: Optional[int] = None
    content_type: str = ""
    title: Optional[str] = None
    links: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)


@dataclass
class CrawlResult(BaseModel):
    """Web crawl result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"crawl_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "crawl"
    
    # Target
    target_url: str = ""
    
    # Results
    urls: List[str] = field(default_factory=list)
    urls_found: int = 0
    pages: List[Dict] = field(default_factory=list)
    
    # Discovered items
    forms: List[Dict] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    comments: List[Dict] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)
    
    # Special forms
    login_forms: List[Dict] = field(default_factory=list)
    search_forms: List[Dict] = field(default_factory=list)
    upload_forms: List[Dict] = field(default_factory=list)
    
    # Robots/Sitemap
    robots: Dict[str, Any] = field(default_factory=dict)
    sitemap_urls: int = 0
    
    # Statistics
    statistics: Dict[str, int] = field(default_factory=dict)
    
    # Configuration
    max_depth: int = 3
    scope: str = "domain"
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================
# XSS SCAN MODELS
# ============================================================

@dataclass
class XSSScanResult(BaseModel):
    """XSS scan result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"xss_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "xss_scan"
    
    # Target
    target_url: str = ""
    
    # Results
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    total_tests: int = 0
    urls_tested: int = 0
    
    # DOM XSS
    dom_xss: Dict[str, Any] = field(default_factory=dict)
    
    # Severity breakdown
    severity_summary: Dict[str, int] = field(default_factory=dict)
    
    # Risk score
    risk_score: int = 0
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_vulnerability(self, vuln: Union[XSSVulnerability, Dict]) -> None:
        """Add an XSS vulnerability"""
        if isinstance(vuln, XSSVulnerability):
            vuln = vuln.to_dict()
        self.vulnerabilities.append(vuln)
        self.total_found = len(self.vulnerabilities)
        
        # Update severity summary
        severity = vuln.get('severity', 'medium')
        self.severity_summary[severity] = self.severity_summary.get(severity, 0) + 1


# ============================================================
# SQLI SCAN MODELS
# ============================================================

@dataclass
class SQLiScanResult(BaseModel):
    """SQL Injection scan result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"sqli_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "sqli_scan"
    
    # Target
    target_url: str = ""
    
    # Results
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    total_found: int = 0
    total_tests: int = 0
    injection_points: int = 0
    
    # Techniques used
    techniques_used: List[str] = field(default_factory=list)
    
    # Databases detected
    databases_detected: List[str] = field(default_factory=list)
    
    # Severity breakdown
    severity_summary: Dict[str, int] = field(default_factory=dict)
    
    # Risk score
    risk_score: int = 0
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_vulnerability(self, vuln: Union[SQLiVulnerability, Dict]) -> None:
        """Add a SQL Injection vulnerability"""
        if isinstance(vuln, SQLiVulnerability):
            vuln = vuln.to_dict()
        self.vulnerabilities.append(vuln)
        self.total_found = len(self.vulnerabilities)
        
        # Update severity summary
        severity = vuln.get('severity', 'critical')
        self.severity_summary[severity] = self.severity_summary.get(severity, 0) + 1
        
        # Track database
        db = vuln.get('database')
        if db and db not in self.databases_detected:
            self.databases_detected.append(db)


# ============================================================
# FULL SCAN MODELS
# ============================================================

@dataclass
class FullScanResult(BaseModel):
    """Full vulnerability scan result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"full_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "full_scan"
    
    # Target
    target: str = ""
    target_info: Dict[str, Any] = field(default_factory=dict)
    
    # Individual scan results
    port_scan: Optional[Dict] = None
    dns_lookup: Optional[Dict] = None
    whois_lookup: Optional[Dict] = None
    subdomain_enum: Optional[Dict] = None
    tech_detection: Optional[Dict] = None
    ssl_analysis: Optional[Dict] = None
    header_analysis: Optional[Dict] = None
    directory_scan: Optional[Dict] = None
    crawl: Optional[Dict] = None
    xss_scan: Optional[Dict] = None
    sqli_scan: Optional[Dict] = None
    
    # Aggregated vulnerabilities
    all_vulnerabilities: List[Dict] = field(default_factory=list)
    total_vulnerabilities: int = 0
    
    # Severity summary
    severity_summary: Dict[str, int] = field(default_factory=dict)
    
    # Risk assessment
    risk_score: int = 0
    risk_level: str = "low"  # low, medium, high, critical
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Progress
    progress: int = 0
    current_stage: str = ""
    completed_stages: List[str] = field(default_factory=list)
    
    # Status
    status: str = "pending"  # pending, running, completed, failed
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def calculate_risk_level(self) -> str:
        """Calculate overall risk level"""
        if self.severity_summary.get('critical', 0) > 0:
            return "critical"
        elif self.severity_summary.get('high', 0) > 0:
            return "high"
        elif self.severity_summary.get('medium', 0) > 0:
            return "medium"
        else:
            return "low"
    
    def aggregate_vulnerabilities(self) -> None:
        """Aggregate vulnerabilities from all scans"""
        self.all_vulnerabilities = []
        self.severity_summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        # Collect from XSS scan
        if self.xss_scan and 'vulnerabilities' in self.xss_scan:
            for vuln in self.xss_scan['vulnerabilities']:
                self.all_vulnerabilities.append(vuln)
                severity = vuln.get('severity', 'medium')
                self.severity_summary[severity] = self.severity_summary.get(severity, 0) + 1
        
        # Collect from SQLi scan
        if self.sqli_scan and 'vulnerabilities' in self.sqli_scan:
            for vuln in self.sqli_scan['vulnerabilities']:
                self.all_vulnerabilities.append(vuln)
                severity = vuln.get('severity', 'critical')
                self.severity_summary[severity] = self.severity_summary.get(severity, 0) + 1
        
        # Collect from directory scan (sensitive files)
        if self.directory_scan and 'found_paths' in self.directory_scan:
            for path in self.directory_scan['found_paths']:
                if path.get('severity') in ['critical', 'high']:
                    self.all_vulnerabilities.append({
                        'type': 'Sensitive File Exposure',
                        'url': path.get('url'),
                        'severity': path.get('severity'),
                        'description': f"Sensitive path found: {path.get('path')}"
                    })
                    severity = path.get('severity', 'medium')
                    self.severity_summary[severity] = self.severity_summary.get(severity, 0) + 1
        
        self.total_vulnerabilities = len(self.all_vulnerabilities)
        self.risk_level = self.calculate_risk_level()


# ============================================================
# REPORT MODELS
# ============================================================

@dataclass
class ReportSummary(BaseModel):
    """Report summary model"""
    
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    
    risk_score: int = 0
    risk_level: str = "low"
    grade: str = "A"
    
    scans_performed: List[str] = field(default_factory=list)
    duration: float = 0.0


@dataclass
class Report(BaseModel):
    """Full report model"""
    
    # Identification
    report_id: str = field(default_factory=lambda: f"report_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_id: str = ""
    
    # Target
    target: str = ""
    target_info: Dict[str, Any] = field(default_factory=dict)
    
    # Summary
    summary: Dict[str, Any] = field(default_factory=dict)
    
    # Executive summary (text)
    executive_summary: str = ""
    
    # Detailed findings
    vulnerabilities: List[Dict] = field(default_factory=list)
    
    # Scan results
    scan_results: Dict[str, Any] = field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    
    # Remediation priority
    remediation_priority: List[Dict] = field(default_factory=list)
    
    # Metadata
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    generated_by: str = "VulnScanner"
    version: str = "1.0.0"
    
    # Export options
    format: str = "json"  # json, html, pdf
    
    def generate_executive_summary(self) -> str:
        """Generate executive summary text"""
        summary = self.summary
        total = summary.get('total_vulnerabilities', 0)
        critical = summary.get('critical', 0)
        high = summary.get('high', 0)
        
        if total == 0:
            return f"Security assessment of {self.target} completed. No vulnerabilities were identified during this scan."
        
        severity_text = []
        if critical > 0:
            severity_text.append(f"{critical} critical")
        if high > 0:
            severity_text.append(f"{high} high")
        
        severity_str = ", ".join(severity_text) if severity_text else "various"
        
        return (
            f"Security assessment of {self.target} identified {total} vulnerabilities, "
            f"including {severity_str} severity issues. "
            f"The overall risk level is {summary.get('risk_level', 'unknown').upper()}. "
            f"Immediate remediation is recommended for critical and high severity findings."
        )


# ============================================================
# GENERIC SCAN RESULT
# ============================================================

@dataclass
class ScanResult(BaseModel):
    """Generic scan result model"""
    
    # Identification
    scan_id: str = field(default_factory=lambda: f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    scan_type: str = "unknown"
    
    # Target
    target: str = ""
    
    # Results
    results: Dict[str, Any] = field(default_factory=dict)
    
    # Timing
    start_time: str = ""
    end_time: str = ""
    duration: float = 0.0
    
    # Status
    success: bool = True
    error: Optional[str] = None
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================
# UTILITY FUNCTIONS
# ============================================================

def create_scan_result(scan_type: str, target: str, **kwargs) -> BaseModel:
    """
    Factory function to create appropriate scan result model
    
    Args:
        scan_type: Type of scan
        target: Target URL/domain/IP
        **kwargs: Additional arguments for the model
        
    Returns:
        Appropriate scan result model instance
    """
    models = {
        'port_scan': PortScanResult,
        'dns_lookup': DNSLookupResult,
        'whois_lookup': WhoisResult,
        'subdomain_enum': SubdomainResult,
        'tech_detection': TechDetectionResult,
        'ssl_analysis': SSLAnalysisResult,
        'header_analysis': HeaderAnalysisResult,
        'directory_scan': DirectoryScanResult,
        'crawl': CrawlResult,
        'xss_scan': XSSScanResult,
        'sqli_scan': SQLiScanResult,
        'full_scan': FullScanResult
    }
    
    model_class = models.get(scan_type, ScanResult)
    
    # Determine the target field name
    if scan_type == 'subdomain_enum':
        return model_class(domain=target, **kwargs)
    elif scan_type in ['ssl_analysis']:
        return model_class(host=target, **kwargs)
    elif scan_type in ['tech_detection', 'header_analysis']:
        return model_class(url=target, **kwargs)
    elif scan_type in ['directory_scan', 'crawl', 'xss_scan', 'sqli_scan']:
        return model_class(target_url=target, **kwargs)
    else:
        return model_class(target=target, **kwargs)


def save_scan_result(result: BaseModel, directory: str = 'reports') -> str:
    """
    Save scan result to JSON file
    
    Args:
        result: Scan result model
        directory: Directory to save to
        
    Returns:
        Path to saved file
    """
    os.makedirs(directory, exist_ok=True)
    
    # Get scan_id from result
    scan_id = getattr(result, 'scan_id', f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}")
    
    filepath = os.path.join(directory, f"{scan_id}.json")
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(result.to_json())
    
    return filepath


def load_scan_result(filepath: str) -> Optional[Dict[str, Any]]:
    """
    Load scan result from JSON file
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Dict with scan result data or None
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def get_severity_color(severity: str) -> str:
    """Get color code for severity level"""
    colors = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#ca8a04',
        'low': '#16a34a',
        'info': '#2563eb'
    }
    return colors.get(severity.lower(), '#6b7280')


def get_severity_score(severity: str) -> int:
    """Get numeric score for severity level"""
    scores = {
        'critical': 10,
        'high': 8,
        'medium': 5,
        'low': 2,
        'info': 0
    }
    return scores.get(severity.lower(), 0)


def calculate_risk_score(vulnerabilities: List[Dict]) -> int:
    """
    Calculate overall risk score from vulnerabilities
    
    Args:
        vulnerabilities: List of vulnerability dicts
        
    Returns:
        Risk score (0-100)
    """
    if not vulnerabilities:
        return 0
    
    total_score = 0
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'info').lower()
        confidence = vuln.get('confidence', 'medium').lower()
        
        # Base score
        base = get_severity_score(severity) * 4
        
        # Confidence multiplier
        confidence_mult = {'confirmed': 1.0, 'high': 0.9, 'medium': 0.7, 'low': 0.5, 'tentative': 0.3}
        multiplier = confidence_mult.get(confidence, 0.7)
        
        total_score += base * multiplier
    
    return min(100, int(total_score))
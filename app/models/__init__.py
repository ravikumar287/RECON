"""
VulnScanner Models Package
Data models for scan results, vulnerabilities, and reports
"""

from app.models.scan_result import (
    # Base Models
    BaseModel,
    Severity,
    Confidence,
    ScanStatus,
    ScanType,
    
    # Target Models
    Target,
    
    # Vulnerability Models
    Vulnerability,
    XSSVulnerability,
    SQLiVulnerability,
    
    # Scan Result Models
    ScanResult,
    PortScanResult,
    DNSLookupResult,
    WhoisResult,
    SubdomainResult,
    TechDetectionResult,
    SSLAnalysisResult,
    HeaderAnalysisResult,
    DirectoryScanResult,
    CrawlResult,
    XSSScanResult,
    SQLiScanResult,
    FullScanResult,
    
    # Report Models
    Report,
    ReportSummary,
    
    # Utility Functions
    create_scan_result,
    load_scan_result,
    save_scan_result
)

__all__ = [
    # Base Models
    'BaseModel',
    'Severity',
    'Confidence',
    'ScanStatus',
    'ScanType',
    
    # Target Models
    'Target',
    
    # Vulnerability Models
    'Vulnerability',
    'XSSVulnerability',
    'SQLiVulnerability',
    
    # Scan Result Models
    'ScanResult',
    'PortScanResult',
    'DNSLookupResult',
    'WhoisResult',
    'SubdomainResult',
    'TechDetectionResult',
    'SSLAnalysisResult',
    'HeaderAnalysisResult',
    'DirectoryScanResult',
    'CrawlResult',
    'XSSScanResult',
    'SQLiScanResult',
    'FullScanResult',
    
    # Report Models
    'Report',
    'ReportSummary',
    
    # Utility Functions
    'create_scan_result',
    'load_scan_result',
    'save_scan_result'
]
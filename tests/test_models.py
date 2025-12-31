"""
Tests for Data Models
Tests for app/models/scan_result.py
"""

import pytest
import sys
import os
import json
import tempfile
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.scan_result import (
    Severity,
    Confidence,
    ScanStatus,
    ScanType,
    BaseModel,
    Target,
    Vulnerability,
    XSSVulnerability,
    SQLiVulnerability,
    PortScanResult,
    DNSLookupResult,
    WhoisResult,
    SubdomainResult,
    XSSScanResult,
    SQLiScanResult,
    FullScanResult,
    Report,
    create_scan_result,
    save_scan_result,
    load_scan_result,
    calculate_risk_score
)


# ============================================================
# ENUM TESTS
# ============================================================

class TestEnums:
    """Tests for enum classes"""
    
    @pytest.mark.unit
    def test_severity_values(self):
        """Test Severity enum values"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"
    
    @pytest.mark.unit
    def test_severity_score(self):
        """Test Severity score property"""
        assert Severity.CRITICAL.score == 10
        assert Severity.HIGH.score == 8
        assert Severity.MEDIUM.score == 5
        assert Severity.LOW.score == 2
        assert Severity.INFO.score == 0
    
    @pytest.mark.unit
    def test_severity_color(self):
        """Test Severity color property"""
        assert Severity.CRITICAL.color == "#dc2626"
        assert Severity.HIGH.color == "#ea580c"
        assert Severity.INFO.color == "#2563eb"
    
    @pytest.mark.unit
    def test_confidence_values(self):
        """Test Confidence enum values"""
        assert Confidence.CONFIRMED.value == "confirmed"
        assert Confidence.HIGH.value == "high"
        assert Confidence.LOW.value == "low"
    
    @pytest.mark.unit
    def test_scan_status_values(self):
        """Test ScanStatus enum values"""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
    
    @pytest.mark.unit
    def test_scan_type_values(self):
        """Test ScanType enum values"""
        assert ScanType.FULL_SCAN.value == "full_scan"
        assert ScanType.XSS_SCAN.value == "xss_scan"
        assert ScanType.SQLI_SCAN.value == "sqli_scan"


# ============================================================
# TARGET MODEL TESTS
# ============================================================

class TestTargetModel:
    """Tests for Target model"""
    
    @pytest.mark.unit
    def test_target_creation(self):
        """Test Target model creation"""
        target = Target(target="example.com")
        
        assert target.target == "example.com"
        assert target.target_type == "unknown"
        assert target.normalized == "example.com"
    
    @pytest.mark.unit
    def test_target_with_full_details(self):
        """Test Target with all details"""
        target = Target(
            target="example.com",
            target_type="domain",
            ip_address="93.184.216.34",
            domain="example.com",
            port=443,
            protocol="https"
        )
        
        assert target.target_type == "domain"
        assert target.ip_address == "93.184.216.34"
        assert target.port == 443
    
    @pytest.mark.unit
    def test_target_full_url(self):
        """Test Target full_url property"""
        target = Target(
            target="example.com",
            protocol="https"
        )
        
        assert target.full_url == "https://example.com"
    
    @pytest.mark.unit
    def test_target_full_url_with_port(self):
        """Test Target full_url with non-standard port"""
        target = Target(
            target="example.com",
            protocol="https",
            port=8443
        )
        
        assert target.full_url == "https://example.com:8443"
    
    @pytest.mark.unit
    def test_target_identifier(self):
        """Test Target identifier generation"""
        target = Target(target="example.com")
        
        assert target.identifier is not None
        assert len(target.identifier) == 12


# ============================================================
# VULNERABILITY MODEL TESTS
# ============================================================

class TestVulnerabilityModels:
    """Tests for Vulnerability models"""
    
    @pytest.mark.unit
    def test_vulnerability_creation(self):
        """Test Vulnerability model creation"""
        vuln = Vulnerability(
            name="Test Vulnerability",
            type="XSS",
            url="https://example.com",
            severity="high"
        )
        
        assert vuln.name == "Test Vulnerability"
        assert vuln.type == "XSS"
        assert vuln.severity == "high"
        assert vuln.id is not None
    
    @pytest.mark.unit
    def test_vulnerability_severity_score(self):
        """Test Vulnerability severity_score property"""
        vuln = Vulnerability(severity="critical")
        assert vuln.severity_score == 10
        
        vuln = Vulnerability(severity="low")
        assert vuln.severity_score == 2
    
    @pytest.mark.unit
    def test_vulnerability_is_critical(self):
        """Test Vulnerability is_critical property"""
        critical_vuln = Vulnerability(severity="critical")
        assert critical_vuln.is_critical is True
        
        high_vuln = Vulnerability(severity="high")
        assert high_vuln.is_critical is True
        
        low_vuln = Vulnerability(severity="low")
        assert low_vuln.is_critical is False
    
    @pytest.mark.unit
    def test_xss_vulnerability_creation(self):
        """Test XSSVulnerability model creation"""
        vuln = XSSVulnerability(
            url="https://example.com/search",
            parameter="q",
            xss_type="reflected",
            context="html_body"
        )
        
        assert vuln.type == "XSS"
        assert vuln.xss_type == "reflected"
        assert vuln.context == "html_body"
        assert "XSS" in vuln.name
    
    @pytest.mark.unit
    def test_sqli_vulnerability_creation(self):
        """Test SQLiVulnerability model creation"""
        vuln = SQLiVulnerability(
            url="https://example.com/login",
            parameter="username",
            sqli_type="error-based",
            database="MySQL"
        )
        
        assert vuln.type == "SQLi"
        assert vuln.sqli_type == "error-based"
        assert vuln.database == "MySQL"
        assert "SQL Injection" in vuln.name


# ============================================================
# SCAN RESULT MODEL TESTS
# ============================================================

class TestPortScanResult:
    """Tests for PortScanResult model"""
    
    @pytest.mark.unit
    def test_port_scan_result_creation(self):
        """Test PortScanResult creation"""
        result = PortScanResult(
            target="example.com",
            target_ip="93.184.216.34"
        )
        
        assert result.target == "example.com"
        assert result.scan_type == "port_scan"
        assert result.open_ports == []
        assert result.success is True
    
    @pytest.mark.unit
    def test_add_port(self):
        """Test adding port to result"""
        result = PortScanResult(target="example.com")
        
        result.add_port({
            'port': 80,
            'state': 'open',
            'service': 'HTTP'
        })
        
        assert len(result.open_ports) == 1
        assert result.open_count == 1
    
    @pytest.mark.unit
    def test_has_critical_ports(self):
        """Test checking for critical ports"""
        result = PortScanResult(target="example.com")
        
        # No critical ports
        result.open_ports = [{'port': 80}]
        assert result.has_critical_ports is False
        
        # With critical port
        result.open_ports = [{'port': 22}, {'port': 3389}]
        assert result.has_critical_ports is True


class TestDNSLookupResult:
    """Tests for DNSLookupResult model"""
    
    @pytest.mark.unit
    def test_dns_lookup_result_creation(self):
        """Test DNSLookupResult creation"""
        result = DNSLookupResult(target="example.com")
        
        assert result.target == "example.com"
        assert result.scan_type == "dns_lookup"
        assert result.records == {}
    
    @pytest.mark.unit
    def test_add_record(self):
        """Test adding DNS record"""
        result = DNSLookupResult(target="example.com")
        
        result.add_record('A', {'ip': '93.184.216.34'})
        
        assert 'A' in result.records
        assert len(result.all_records) == 1
        assert result.total_records == 1


class TestXSSScanResult:
    """Tests for XSSScanResult model"""
    
    @pytest.mark.unit
    def test_xss_scan_result_creation(self):
        """Test XSSScanResult creation"""
        result = XSSScanResult(target_url="https://example.com")
        
        assert result.target_url == "https://example.com"
        assert result.scan_type == "xss_scan"
        assert result.vulnerabilities == []
    
    @pytest.mark.unit
    def test_add_xss_vulnerability(self):
        """Test adding XSS vulnerability"""
        result = XSSScanResult(target_url="https://example.com")
        
        vuln = XSSVulnerability(
            url="https://example.com/search",
            parameter="q",
            severity="high"
        )
        
        result.add_vulnerability(vuln)
        
        assert result.total_found == 1
        assert result.severity_summary.get('high', 0) == 1


class TestFullScanResult:
    """Tests for FullScanResult model"""
    
    @pytest.mark.unit
    def test_full_scan_result_creation(self):
        """Test FullScanResult creation"""
        result = FullScanResult(target="example.com")
        
        assert result.target == "example.com"
        assert result.scan_type == "full_scan"
        assert result.status == "pending"
    
    @pytest.mark.unit
    def test_calculate_risk_level(self):
        """Test risk level calculation"""
        result = FullScanResult(target="example.com")
        
        # No vulnerabilities
        result.severity_summary = {}
        assert result.calculate_risk_level() == "low"
        
        # Critical vulnerability
        result.severity_summary = {'critical': 1}
        assert result.calculate_risk_level() == "critical"
        
        # High vulnerability
        result.severity_summary = {'high': 2}
        assert result.calculate_risk_level() == "high"
    
    @pytest.mark.unit
    def test_aggregate_vulnerabilities(self):
        """Test vulnerability aggregation"""
        result = FullScanResult(target="example.com")
        
        result.xss_scan = {
            'vulnerabilities': [
                {'type': 'XSS', 'severity': 'high'}
            ]
        }
        result.sqli_scan = {
            'vulnerabilities': [
                {'type': 'SQLi', 'severity': 'critical'}
            ]
        }
        
        result.aggregate_vulnerabilities()
        
        assert result.total_vulnerabilities == 2
        assert result.severity_summary['high'] == 1
        assert result.severity_summary['critical'] == 1
        assert result.risk_level == "critical"


# ============================================================
# SERIALIZATION TESTS
# ============================================================

class TestSerialization:
    """Tests for model serialization"""
    
    @pytest.mark.unit
    def test_to_dict(self):
        """Test converting model to dictionary"""
        vuln = Vulnerability(
            name="Test",
            type="XSS",
            severity="high"
        )
        
        data = vuln.to_dict()
        
        assert isinstance(data, dict)
        assert data['name'] == "Test"
        assert data['type'] == "XSS"
        assert data['severity'] == "high"
    
    @pytest.mark.unit
    def test_to_json(self):
        """Test converting model to JSON"""
        result = PortScanResult(
            target="example.com",
            target_ip="93.184.216.34"
        )
        
        json_str = result.to_json()
        
        assert isinstance(json_str, str)
        
        # Verify valid JSON
        data = json.loads(json_str)
        assert data['target'] == "example.com"
    
    @pytest.mark.unit
    def test_enum_serialization(self):
        """Test that enums are serialized correctly"""
        result = FullScanResult(target="example.com")
        
        data = result.to_dict()
        
        # Enums should be converted to strings
        assert isinstance(data.get('scan_type'), str)


# ============================================================
# UTILITY FUNCTION TESTS
# ============================================================

class TestUtilityFunctions:
    """Tests for model utility functions"""
    
    @pytest.mark.unit
    def test_create_scan_result_port_scan(self):
        """Test creating port scan result"""
        result = create_scan_result('port_scan', 'example.com')
        
        assert isinstance(result, PortScanResult)
        assert result.target == 'example.com'
    
    @pytest.mark.unit
    def test_create_scan_result_xss_scan(self):
        """Test creating XSS scan result"""
        result = create_scan_result('xss_scan', 'https://example.com')
        
        assert isinstance(result, XSSScanResult)
        assert result.target_url == 'https://example.com'
    
    @pytest.mark.unit
    def test_create_scan_result_sqli_scan(self):
        """Test creating SQLi scan result"""
        result = create_scan_result('sqli_scan', 'https://example.com')
        
        assert isinstance(result, SQLiScanResult)
        assert result.target_url == 'https://example.com'
    
    @pytest.mark.unit
    def test_save_and_load_scan_result(self, temp_dir):
        """Test saving and loading scan result"""
        result = PortScanResult(
            target="example.com",
            target_ip="93.184.216.34"
        )
        result.add_port({'port': 80, 'state': 'open', 'service': 'HTTP'})
        
        # Save
        filepath = save_scan_result(result, temp_dir)
        
        assert os.path.exists(filepath)
        
        # Load
        loaded = load_scan_result(filepath)
        
        assert loaded is not None
        assert loaded['target'] == 'example.com'
        assert len(loaded['open_ports']) == 1
    
    @pytest.mark.unit
    def test_calculate_risk_score_empty(self):
        """Test risk score with no vulnerabilities"""
        score = calculate_risk_score([])
        assert score == 0
    
    @pytest.mark.unit
    def test_calculate_risk_score_with_vulns(self):
        """Test risk score calculation"""
        vulns = [
            {'severity': 'critical', 'confidence': 'high'},
            {'severity': 'high', 'confidence': 'medium'},
            {'severity': 'medium', 'confidence': 'low'}
        ]
        
        score = calculate_risk_score(vulns)
        
        assert score > 0
        assert score <= 100


# ============================================================
# REPORT MODEL TESTS
# ============================================================

class TestReportModel:
    """Tests for Report model"""
    
    @pytest.mark.unit
    def test_report_creation(self):
        """Test Report model creation"""
        report = Report(
            target="example.com",
            scan_id="scan_123"
        )
        
        assert report.target == "example.com"
        assert report.scan_id == "scan_123"
        assert report.report_id is not None
    
    @pytest.mark.unit
    def test_generate_executive_summary_no_vulns(self):
        """Test executive summary with no vulnerabilities"""
        report = Report(
            target="example.com",
            summary={'total_vulnerabilities': 0}
        )
        
        summary = report.generate_executive_summary()
        
        assert "No vulnerabilities" in summary
    
    @pytest.mark.unit
    def test_generate_executive_summary_with_vulns(self):
        """Test executive summary with vulnerabilities"""
        report = Report(
            target="example.com",
            summary={
                'total_vulnerabilities': 5,
                'critical': 1,
                'high': 2,
                'risk_level': 'high'
            }
        )
        
        summary = report.generate_executive_summary()
        
        assert "5 vulnerabilities" in summary
        assert "critical" in summary.lower()
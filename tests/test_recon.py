"""
Tests for Reconnaissance Modules
Tests for port scanner, DNS lookup, WHOIS, subdomain enumeration, etc.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import socket

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.port_scanner import PortScanner
from app.services.dns_lookup import DNSLookup
from app.services.whois_lookup import WhoisLookup
from app.services.subdomain_enum import SubdomainEnumerator


# ============================================================
# PORT SCANNER TESTS
# ============================================================

class TestPortScanner:
    """Tests for PortScanner class"""
    
    @pytest.mark.unit
    def test_port_scanner_initialization(self, test_domain):
        """Test PortScanner initialization"""
        scanner = PortScanner(test_domain)
        
        assert scanner.original_target == test_domain
        assert scanner.timeout == 2.0
        assert scanner.max_threads == 100
        assert scanner.scan_id is not None
    
    @pytest.mark.unit
    def test_port_scanner_with_ip(self, test_ip):
        """Test PortScanner with IP address"""
        scanner = PortScanner(test_ip)
        
        assert scanner.target_ip == test_ip
    
    @pytest.mark.unit
    def test_port_scanner_custom_settings(self, test_domain):
        """Test PortScanner with custom settings"""
        scanner = PortScanner(
            test_domain,
            timeout=5.0,
            max_threads=50
        )
        
        assert scanner.timeout == 5.0
        assert scanner.max_threads == 50
    
    @pytest.mark.unit
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket, test_ip):
        """Test scanning an open port"""
        # Setup mock
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect_ex.return_value = 0  # 0 means success/open
        mock_sock_instance.recv.return_value = b"SSH-2.0-OpenSSH"
        mock_socket.return_value = mock_sock_instance
        
        scanner = PortScanner(test_ip)
        result = scanner.scan_port(22)
        
        assert result['port'] == 22
        assert result['state'] == 'open'
    
    @pytest.mark.unit
    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket, test_ip):
        """Test scanning a closed port"""
        # Setup mock for closed port
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect_ex.return_value = 111  # Connection refused
        mock_socket.return_value = mock_sock_instance
        
        scanner = PortScanner(test_ip)
        result = scanner.scan_port(12345)
        
        assert result['port'] == 12345
        assert result['state'] == 'closed'
    
    @pytest.mark.unit
    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket, test_ip):
        """Test scanning a filtered port (timeout)"""
        mock_sock_instance = MagicMock()
        mock_sock_instance.connect_ex.side_effect = socket.timeout()
        mock_socket.return_value = mock_sock_instance
        
        scanner = PortScanner(test_ip)
        result = scanner.scan_port(12345)
        
        assert result['state'] == 'filtered'
    
    @pytest.mark.unit
    def test_quick_scan_ports(self):
        """Test quick scan port list"""
        assert len(PortScanner.QUICK_SCAN_PORTS) > 0
        assert 80 in PortScanner.QUICK_SCAN_PORTS
        assert 443 in PortScanner.QUICK_SCAN_PORTS
    
    @pytest.mark.unit
    def test_get_risk_level(self):
        """Test port risk level classification"""
        assert PortScanner.get_risk_level(21, 'FTP') == 'high'
        assert PortScanner.get_risk_level(22, 'SSH') == 'medium'
        assert PortScanner.get_risk_level(80, 'HTTP') == 'low'
        assert PortScanner.get_risk_level(8080, 'HTTP-Proxy') == 'low'
    
    @pytest.mark.unit
    @patch.object(PortScanner, 'scan_port')
    def test_scan_with_callback(self, mock_scan_port, test_ip):
        """Test scan with progress callback"""
        mock_scan_port.return_value = {
            'port': 80,
            'state': 'open',
            'service': 'HTTP',
            'banner': None,
            'version': None
        }
        
        callback_calls = []
        
        def callback(port, status, service):
            callback_calls.append((port, status, service))
        
        scanner = PortScanner(test_ip)
        scanner.scan(ports='80', callback=callback)
        
        assert len(callback_calls) > 0
    
    @pytest.mark.unit
    def test_stop_scan(self, test_ip):
        """Test stopping a scan"""
        scanner = PortScanner(test_ip)
        scanner.stop()
        
        assert scanner.stop_scan is True


# ============================================================
# DNS LOOKUP TESTS
# ============================================================

class TestDNSLookup:
    """Tests for DNSLookup class"""
    
    @pytest.mark.unit
    def test_dns_lookup_initialization(self, test_domain):
        """Test DNSLookup initialization"""
        dns = DNSLookup(test_domain)
        
        assert dns.target == test_domain.lower()
        assert dns.timeout == 5.0
        assert dns.scan_id is not None
    
    @pytest.mark.unit
    def test_dns_lookup_with_custom_nameservers(self, test_domain):
        """Test DNSLookup with custom nameservers"""
        nameservers = ['8.8.8.8', '8.8.4.4']
        dns = DNSLookup(test_domain, nameservers=nameservers)
        
        assert dns.resolver.nameservers == nameservers
    
    @pytest.mark.unit
    @patch('dns.resolver.Resolver')
    def test_lookup_a_record(self, mock_resolver_class, test_domain):
        """Test A record lookup"""
        # Setup mock
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda x: "93.184.216.34"
        mock_answer.__iter__ = lambda x: iter([mock_rdata])
        mock_answer.rrset = MagicMock()
        mock_answer.rrset.ttl = 3600
        mock_resolver.resolve.return_value = mock_answer
        mock_resolver_class.return_value = mock_resolver
        
        dns = DNSLookup(test_domain)
        dns.resolver = mock_resolver
        
        result = dns.lookup('A')
        
        assert result['record_type'] == 'A'
        assert result['success'] is True
    
    @pytest.mark.unit
    @patch('dns.resolver.Resolver')
    def test_lookup_nxdomain(self, mock_resolver_class, invalid_domain):
        """Test lookup for non-existent domain"""
        import dns.resolver
        
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_resolver_class.return_value = mock_resolver
        
        dns_lookup = DNSLookup(invalid_domain)
        dns_lookup.resolver = mock_resolver
        
        result = dns_lookup.lookup('A')
        
        assert result['success'] is False
        assert 'does not exist' in result['error']
    
    @pytest.mark.unit
    def test_record_types(self):
        """Test supported record types"""
        assert 'A' in DNSLookup.RECORD_TYPES
        assert 'AAAA' in DNSLookup.RECORD_TYPES
        assert 'MX' in DNSLookup.RECORD_TYPES
        assert 'NS' in DNSLookup.RECORD_TYPES
        assert 'TXT' in DNSLookup.RECORD_TYPES


# ============================================================
# WHOIS LOOKUP TESTS
# ============================================================

class TestWhoisLookup:
    """Tests for WhoisLookup class"""
    
    @pytest.mark.unit
    def test_whois_lookup_initialization(self, test_domain):
        """Test WhoisLookup initialization"""
        whois = WhoisLookup(test_domain)
        
        assert whois.target == test_domain.lower()
        assert whois.scan_id is not None
    
    @pytest.mark.unit
    @patch('whois.whois')
    def test_whois_lookup_success(self, mock_whois, test_domain):
        """Test successful WHOIS lookup"""
        # Setup mock
        mock_result = MagicMock()
        mock_result.domain_name = test_domain
        mock_result.registrar = "Test Registrar"
        mock_result.creation_date = "2020-01-01"
        mock_result.expiration_date = "2025-01-01"
        mock_result.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_result.status = ["clientTransferProhibited"]
        mock_whois.return_value = mock_result
        
        lookup = WhoisLookup(test_domain)
        result = lookup.lookup()
        
        assert result['success'] is True
        assert 'whois_data' in result
    
    @pytest.mark.unit
    @patch('whois.whois')
    def test_whois_lookup_failure(self, mock_whois, invalid_domain):
        """Test WHOIS lookup failure"""
        mock_whois.side_effect = Exception("Domain not found")
        
        lookup = WhoisLookup(invalid_domain)
        result = lookup.lookup()
        
        assert result['success'] is False
        assert result['error'] is not None
    
    @pytest.mark.unit
    def test_get_summary(self, test_domain):
        """Test getting WHOIS summary"""
        with patch.object(WhoisLookup, 'lookup') as mock_lookup:
            mock_lookup.return_value = {
                'success': True,
                'whois_data': {
                    'domain_name': test_domain,
                    'registrar': 'Test Registrar',
                    'creation_date': '2020-01-01',
                    'expiration_date': '2025-01-01',
                    'domain_age': {'total_days': 365},
                    'name_servers': ['ns1.example.com'],
                    'registrant': {'organization': 'Test Org', 'country': 'US'},
                    'status': []
                }
            }
            
            lookup = WhoisLookup(test_domain)
            summary = lookup.get_summary()
            
            assert summary['success'] is True
            assert summary['domain'] == test_domain


# ============================================================
# SUBDOMAIN ENUMERATION TESTS
# ============================================================

class TestSubdomainEnumerator:
    """Tests for SubdomainEnumerator class"""
    
    @pytest.mark.unit
    def test_subdomain_enum_initialization(self, test_domain):
        """Test SubdomainEnumerator initialization"""
        enum = SubdomainEnumerator(test_domain)
        
        assert enum.domain == test_domain.lower()
        assert enum.timeout == 3.0
        assert enum.max_threads == 50
        assert enum.scan_id is not None
    
    @pytest.mark.unit
    def test_default_subdomains_list(self):
        """Test default subdomains list"""
        assert len(SubdomainEnumerator.DEFAULT_SUBDOMAINS) > 0
        assert 'www' in SubdomainEnumerator.DEFAULT_SUBDOMAINS
        assert 'mail' in SubdomainEnumerator.DEFAULT_SUBDOMAINS
        assert 'admin' in SubdomainEnumerator.DEFAULT_SUBDOMAINS
    
    @pytest.mark.unit
    @patch('dns.resolver.Resolver')
    def test_check_wildcard_no_wildcard(self, mock_resolver_class, test_domain):
        """Test wildcard detection when no wildcard exists"""
        import dns.resolver
        
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_resolver_class.return_value = mock_resolver
        
        enum = SubdomainEnumerator(test_domain)
        enum.resolver = mock_resolver
        
        has_wildcard = enum.check_wildcard()
        
        assert has_wildcard is False
    
    @pytest.mark.unit
    @patch('dns.resolver.Resolver')
    def test_resolve_subdomain_found(self, mock_resolver_class, test_domain):
        """Test resolving an existing subdomain"""
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda x: "93.184.216.34"
        mock_answer.__iter__ = lambda x: iter([mock_rdata])
        mock_resolver.resolve.return_value = mock_answer
        mock_resolver_class.return_value = mock_resolver
        
        enum = SubdomainEnumerator(test_domain)
        enum.resolver = mock_resolver
        
        with patch('requests.head') as mock_head:
            mock_head.return_value = MagicMock(status_code=200)
            result = enum.resolve_subdomain('www')
        
        assert result is not None
        assert result['subdomain'] == 'www'
        assert result['alive'] is True
    
    @pytest.mark.unit
    @patch('dns.resolver.Resolver')
    def test_resolve_subdomain_not_found(self, mock_resolver_class, test_domain):
        """Test resolving a non-existing subdomain"""
        import dns.resolver
        
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_resolver_class.return_value = mock_resolver
        
        enum = SubdomainEnumerator(test_domain)
        enum.resolver = mock_resolver
        
        result = enum.resolve_subdomain('nonexistent123456')
        
        assert result is None
    
    @pytest.mark.unit
    def test_stop_enumeration(self, test_domain):
        """Test stopping enumeration"""
        enum = SubdomainEnumerator(test_domain)
        enum.stop()
        
        assert enum.stop_scan is True
    
    @pytest.mark.unit
    def test_get_found_subdomains(self, test_domain):
        """Test getting found subdomains"""
        enum = SubdomainEnumerator(test_domain)
        enum.found_subdomains.add('www.example.com')
        enum.found_subdomains.add('mail.example.com')
        
        found = enum.get_found_subdomains()
        
        assert len(found) == 2
        assert 'www.example.com' in found


# ============================================================
# INTEGRATION TESTS (Live Network)
# ============================================================

@pytest.mark.live
@pytest.mark.slow
class TestReconIntegration:
    """Integration tests that require live network access"""
    
    def test_port_scan_live(self, test_domain):
        """Live port scan test"""
        scanner = PortScanner(test_domain, timeout=3.0)
        result = scanner.scan(ports='80,443', scan_type='tcp')
        
        assert result['success'] is True
        assert result['ports_scanned'] == 2
    
    def test_dns_lookup_live(self, test_domain):
        """Live DNS lookup test"""
        dns = DNSLookup(test_domain)
        result = dns.lookup_all(['A', 'NS'])
        
        assert result['success'] is True
        assert result['total_records'] > 0
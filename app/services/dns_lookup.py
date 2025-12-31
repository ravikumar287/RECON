"""
DNS Lookup Service
Performs comprehensive DNS record enumeration
"""

import dns.resolver
import dns.reversename
import dns.zone
import dns.query
from typing import List, Dict, Optional, Any
from datetime import datetime
import socket

from app.services.utils import (
    is_valid_domain,
    is_valid_ip,
    generate_scan_id
)


class DNSLookup:
    """
    DNS Lookup Service for domain reconnaissance
    
    Features:
    - Multiple record type queries (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR)
    - Reverse DNS lookup
    - Zone transfer attempts
    - DNS server enumeration
    """
    
    RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
    
    def __init__(self, target: str, nameservers: Optional[List[str]] = None, timeout: float = 5.0):
        """
        Initialize DNS Lookup
        
        Args:
            target: Domain name or IP address
            nameservers: Custom DNS servers to use
            timeout: Query timeout in seconds
        """
        self.target = target.strip().lower()
        self.timeout = timeout
        self.scan_id = generate_scan_id()
        
        # Configure resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        if nameservers:
            self.resolver.nameservers = nameservers
    
    def lookup(self, record_type: str) -> Dict[str, Any]:
        """
        Perform DNS lookup for specific record type
        
        Args:
            record_type: DNS record type (A, AAAA, MX, etc.)
            
        Returns:
            Dict with lookup results
        """
        result = {
            'record_type': record_type,
            'records': [],
            'success': False,
            'error': None
        }
        
        try:
            answers = self.resolver.resolve(self.target, record_type)
            
            for rdata in answers:
                record_data = self._parse_record(record_type, rdata)
                if record_data:
                    result['records'].append(record_data)
            
            result['success'] = True
            result['ttl'] = answers.rrset.ttl
            
        except dns.resolver.NXDOMAIN:
            result['error'] = 'Domain does not exist'
        except dns.resolver.NoAnswer:
            result['error'] = f'No {record_type} records found'
        except dns.resolver.NoNameservers:
            result['error'] = 'No nameservers available'
        except dns.resolver.Timeout:
            result['error'] = 'Query timed out'
        except dns.exception.DNSException as e:
            result['error'] = str(e)
        except Exception as e:
            result['error'] = f'Unexpected error: {str(e)}'
        
        return result
    
    def _parse_record(self, record_type: str, rdata: Any) -> Optional[Dict]:
        """Parse DNS record data into structured format"""
        try:
            if record_type == 'A':
                return {'ip': str(rdata)}
            
            elif record_type == 'AAAA':
                return {'ipv6': str(rdata)}
            
            elif record_type == 'MX':
                return {
                    'priority': rdata.preference,
                    'mail_server': str(rdata.exchange).rstrip('.')
                }
            
            elif record_type == 'NS':
                return {'nameserver': str(rdata).rstrip('.')}
            
            elif record_type == 'TXT':
                # Handle TXT record (may contain multiple strings)
                txt_data = b''.join(rdata.strings).decode('utf-8', errors='ignore')
                return {'text': txt_data}
            
            elif record_type == 'CNAME':
                return {'canonical_name': str(rdata.target).rstrip('.')}
            
            elif record_type == 'SOA':
                return {
                    'primary_ns': str(rdata.mname).rstrip('.'),
                    'admin_email': str(rdata.rname).rstrip('.').replace('.', '@', 1),
                    'serial': rdata.serial,
                    'refresh': rdata.refresh,
                    'retry': rdata.retry,
                    'expire': rdata.expire,
                    'minimum_ttl': rdata.minimum
                }
            
            elif record_type == 'PTR':
                return {'hostname': str(rdata).rstrip('.')}
            
            elif record_type == 'SRV':
                return {
                    'priority': rdata.priority,
                    'weight': rdata.weight,
                    'port': rdata.port,
                    'target': str(rdata.target).rstrip('.')
                }
            
            elif record_type == 'CAA':
                return {
                    'flags': rdata.flags,
                    'tag': rdata.tag.decode() if isinstance(rdata.tag, bytes) else rdata.tag,
                    'value': rdata.value.decode() if isinstance(rdata.value, bytes) else rdata.value
                }
            
            else:
                return {'raw': str(rdata)}
                
        except Exception:
            return {'raw': str(rdata)}
    
    def lookup_all(self, record_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Perform DNS lookup for multiple record types
        
        Args:
            record_types: List of record types to query (default: all common types)
            
        Returns:
            Dict with all lookup results
        """
        if record_types is None:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        start_time = datetime.now()
        results = {}
        all_records = []
        
        for record_type in record_types:
            lookup_result = self.lookup(record_type)
            results[record_type] = lookup_result
            
            if lookup_result['success']:
                for record in lookup_result['records']:
                    all_records.append({
                        'type': record_type,
                        **record
                    })
        
        end_time = datetime.now()
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target': self.target,
            'results': results,
            'all_records': all_records,
            'total_records': len(all_records),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def reverse_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform reverse DNS lookup
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Dict with reverse lookup results
        """
        result = {
            'success': False,
            'ip': ip_address,
            'hostnames': [],
            'error': None
        }
        
        if not is_valid_ip(ip_address):
            result['error'] = 'Invalid IP address'
            return result
        
        try:
            rev_name = dns.reversename.from_address(ip_address)
            answers = self.resolver.resolve(rev_name, 'PTR')
            
            for rdata in answers:
                result['hostnames'].append(str(rdata).rstrip('.'))
            
            result['success'] = True
            
        except dns.resolver.NXDOMAIN:
            result['error'] = 'No PTR record found'
        except dns.resolver.NoAnswer:
            result['error'] = 'No answer for PTR query'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def attempt_zone_transfer(self) -> Dict[str, Any]:
        """
        Attempt DNS zone transfer
        
        Returns:
            Dict with zone transfer results
        """
        result = {
            'success': False,
            'vulnerable': False,
            'nameservers_tested': [],
            'records': [],
            'error': None
        }
        
        # First, get nameservers
        ns_result = self.lookup('NS')
        if not ns_result['success']:
            result['error'] = 'Could not retrieve nameservers'
            return result
        
        nameservers = [r['nameserver'] for r in ns_result['records']]
        
        for ns in nameservers:
            ns_test = {
                'nameserver': ns,
                'vulnerable': False,
                'records_count': 0
            }
            
            try:
                # Resolve nameserver IP
                ns_ip = socket.gethostbyname(ns)
                
                # Attempt zone transfer
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, self.target, timeout=self.timeout)
                )
                
                # If we get here, zone transfer succeeded
                ns_test['vulnerable'] = True
                result['vulnerable'] = True
                
                # Extract records
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            result['records'].append({
                                'name': str(name),
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'data': str(rdata)
                            })
                
                ns_test['records_count'] = len(result['records'])
                
            except dns.xfr.TransferError:
                ns_test['error'] = 'Transfer refused'
            except dns.exception.FormError:
                ns_test['error'] = 'Form error'
            except socket.timeout:
                ns_test['error'] = 'Timeout'
            except Exception as e:
                ns_test['error'] = str(e)
            
            result['nameservers_tested'].append(ns_test)
        
        result['success'] = True
        return result
    
    def get_nameservers(self) -> List[str]:
        """Get list of nameservers for domain"""
        ns_result = self.lookup('NS')
        if ns_result['success']:
            return [r['nameserver'] for r in ns_result['records']]
        return []
    
    def get_mail_servers(self) -> List[Dict]:
        """Get list of mail servers for domain"""
        mx_result = self.lookup('MX')
        if mx_result['success']:
            return sorted(mx_result['records'], key=lambda x: x['priority'])
        return []
    
    def check_dnssec(self) -> Dict[str, Any]:
        """Check if DNSSEC is enabled"""
        result = {
            'enabled': False,
            'records': []
        }
        
        try:
            # Try to get DNSKEY records
            answers = self.resolver.resolve(self.target, 'DNSKEY')
            result['enabled'] = True
            for rdata in answers:
                result['records'].append({
                    'flags': rdata.flags,
                    'protocol': rdata.protocol,
                    'algorithm': rdata.algorithm
                })
        except Exception:
            pass
        
        return result
    
    def get_spf_record(self) -> Optional[str]:
        """Extract SPF record from TXT records"""
        txt_result = self.lookup('TXT')
        if txt_result['success']:
            for record in txt_result['records']:
                text = record.get('text', '')
                if text.startswith('v=spf1'):
                    return text
        return None
    
    def get_dmarc_record(self) -> Optional[str]:
        """Get DMARC record"""
        dmarc_domain = f'_dmarc.{self.target}'
        original_target = self.target
        self.target = dmarc_domain
        
        txt_result = self.lookup('TXT')
        self.target = original_target
        
        if txt_result['success']:
            for record in txt_result['records']:
                text = record.get('text', '')
                if text.startswith('v=DMARC1'):
                    return text
        return None
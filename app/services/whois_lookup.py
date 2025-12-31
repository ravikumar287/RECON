"""
WHOIS Lookup Service
Retrieves domain registration information
"""

import whois
from typing import Dict, Any, Optional, List
from datetime import datetime
import socket
import re

from app.services.utils import (
    is_valid_domain,
    is_valid_ip,
    generate_scan_id
)


class WhoisLookup:
    """
    WHOIS Lookup Service for domain registration information
    
    Features:
    - Domain WHOIS lookup
    - IP WHOIS lookup
    - Registrar information
    - Domain age calculation
    - Expiration alerts
    """
    
    def __init__(self, target: str):
        """
        Initialize WHOIS Lookup
        
        Args:
            target: Domain name or IP address
        """
        self.target = target.strip().lower()
        self.scan_id = generate_scan_id()
    
    def lookup(self) -> Dict[str, Any]:
        """
        Perform WHOIS lookup
        
        Returns:
            Dict with WHOIS information
        """
        start_time = datetime.now()
        
        result = {
            'success': False,
            'scan_id': self.scan_id,
            'target': self.target,
            'whois_data': {},
            'error': None
        }
        
        try:
            # Perform WHOIS lookup
            w = whois.whois(self.target)
            
            if w is None:
                result['error'] = 'No WHOIS data returned'
                return result
            
            # Parse WHOIS data
            result['whois_data'] = self._parse_whois_data(w)
            result['success'] = True
            
        except whois.parser.PywhoisError as e:
            result['error'] = f'WHOIS parsing error: {str(e)}'
        except socket.timeout:
            result['error'] = 'WHOIS lookup timed out'
        except socket.error as e:
            result['error'] = f'Network error: {str(e)}'
        except Exception as e:
            result['error'] = f'Unexpected error: {str(e)}'
        
        end_time = datetime.now()
        result['duration'] = (end_time - start_time).total_seconds()
        result['timestamp'] = datetime.now().isoformat()
        
        return result
    
    def _parse_whois_data(self, w: Any) -> Dict[str, Any]:
        """Parse WHOIS data into structured format"""
        data = {}
        
        # Domain name
        data['domain_name'] = self._get_first_value(w.domain_name)
        
        # Registrar information
        data['registrar'] = w.registrar
        data['registrar_url'] = getattr(w, 'registrar_url', None)
        data['registrar_iana_id'] = getattr(w, 'registrar_iana_id', None)
        
        # Registration dates
        data['creation_date'] = self._format_date(self._get_first_value(w.creation_date))
        data['expiration_date'] = self._format_date(self._get_first_value(w.expiration_date))
        data['updated_date'] = self._format_date(self._get_first_value(w.updated_date))
        
        # Calculate domain age
        if data['creation_date']:
            data['domain_age'] = self._calculate_age(data['creation_date'])
        else:
            data['domain_age'] = None
        
        # Check expiration status
        if data['expiration_date']:
            data['expiration_status'] = self._check_expiration(data['expiration_date'])
        else:
            data['expiration_status'] = None
        
        # Name servers
        if w.name_servers:
            if isinstance(w.name_servers, list):
                data['name_servers'] = [ns.lower() for ns in w.name_servers if ns]
            else:
                data['name_servers'] = [w.name_servers.lower()]
        else:
            data['name_servers'] = []
        
        # Remove duplicates from name servers
        data['name_servers'] = list(set(data['name_servers']))
        
        # Status
        if w.status:
            if isinstance(w.status, list):
                data['status'] = w.status
            else:
                data['status'] = [w.status]
        else:
            data['status'] = []
        
        # Registrant information
        data['registrant'] = {
            'name': getattr(w, 'name', None),
            'organization': getattr(w, 'org', None),
            'email': self._get_first_value(getattr(w, 'emails', None)),
            'country': getattr(w, 'country', None),
            'state': getattr(w, 'state', None),
            'city': getattr(w, 'city', None),
            'address': getattr(w, 'address', None),
            'zipcode': getattr(w, 'zipcode', None)
        }
        
        # DNSSEC
        data['dnssec'] = getattr(w, 'dnssec', None)
        
        # Whois server
        data['whois_server'] = getattr(w, 'whois_server', None)
        
        # Raw text (if available)
        if hasattr(w, 'text'):
            data['raw_text'] = w.text[:5000] if w.text else None  # Limit size
        
        return data
    
    def _get_first_value(self, value: Any) -> Any:
        """Get first value from list or return value directly"""
        if isinstance(value, list):
            return value[0] if value else None
        return value
    
    def _format_date(self, date_value: Any) -> Optional[str]:
        """Format date value to ISO string"""
        if date_value is None:
            return None
        
        if isinstance(date_value, datetime):
            return date_value.isoformat()
        
        if isinstance(date_value, str):
            try:
                # Try to parse common date formats
                for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%Y/%m/%d', '%d/%m/%Y']:
                    try:
                        dt = datetime.strptime(date_value, fmt)
                        return dt.isoformat()
                    except ValueError:
                        continue
            except Exception:
                pass
            return date_value
        
        return str(date_value)
    
    def _calculate_age(self, creation_date: str) -> Dict[str, int]:
        """Calculate domain age from creation date"""
        try:
            if isinstance(creation_date, str):
                created = datetime.fromisoformat(creation_date.replace('Z', '+00:00'))
            else:
                created = creation_date
            
            now = datetime.now()
            if created.tzinfo:
                now = datetime.now(created.tzinfo)
            
            delta = now - created
            
            years = delta.days // 365
            months = (delta.days % 365) // 30
            days = delta.days % 30
            
            return {
                'years': years,
                'months': months,
                'days': days,
                'total_days': delta.days
            }
        except Exception:
            return None
    
    def _check_expiration(self, expiration_date: str) -> Dict[str, Any]:
        """Check domain expiration status"""
        try:
            if isinstance(expiration_date, str):
                expires = datetime.fromisoformat(expiration_date.replace('Z', '+00:00'))
            else:
                expires = expiration_date
            
            now = datetime.now()
            if expires.tzinfo:
                now = datetime.now(expires.tzinfo)
            
            delta = expires - now
            
            status = {
                'expired': delta.days < 0,
                'days_until_expiry': delta.days,
                'warning': False,
                'critical': False
            }
            
            if delta.days < 0:
                status['message'] = 'Domain has expired!'
                status['critical'] = True
            elif delta.days < 30:
                status['message'] = 'Domain expires in less than 30 days'
                status['critical'] = True
            elif delta.days < 90:
                status['message'] = 'Domain expires in less than 90 days'
                status['warning'] = True
            else:
                status['message'] = f'Domain expires in {delta.days} days'
            
            return status
        except Exception:
            return None
    
    def get_registrar(self) -> Optional[str]:
        """Get domain registrar"""
        result = self.lookup()
        if result['success']:
            return result['whois_data'].get('registrar')
        return None
    
    def get_creation_date(self) -> Optional[str]:
        """Get domain creation date"""
        result = self.lookup()
        if result['success']:
            return result['whois_data'].get('creation_date')
        return None
    
    def get_expiration_date(self) -> Optional[str]:
        """Get domain expiration date"""
        result = self.lookup()
        if result['success']:
            return result['whois_data'].get('expiration_date')
        return None
    
    def get_name_servers(self) -> List[str]:
        """Get domain name servers"""
        result = self.lookup()
        if result['success']:
            return result['whois_data'].get('name_servers', [])
        return []
    
    def is_expired(self) -> bool:
        """Check if domain is expired"""
        result = self.lookup()
        if result['success']:
            exp_status = result['whois_data'].get('expiration_status')
            if exp_status:
                return exp_status.get('expired', False)
        return False
    
    def get_domain_age_days(self) -> Optional[int]:
        """Get domain age in days"""
        result = self.lookup()
        if result['success']:
            age = result['whois_data'].get('domain_age')
            if age:
                return age.get('total_days')
        return None
    
    def extract_emails(self) -> List[str]:
        """Extract all email addresses from WHOIS data"""
        result = self.lookup()
        emails = []
        
        if result['success']:
            raw_text = result['whois_data'].get('raw_text', '')
            if raw_text:
                # Find all email patterns
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                found = re.findall(email_pattern, raw_text)
                emails = list(set(found))
        
        return emails
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summarized WHOIS information"""
        result = self.lookup()
        
        if not result['success']:
            return {
                'success': False,
                'error': result.get('error')
            }
        
        data = result['whois_data']
        
        return {
            'success': True,
            'domain': data.get('domain_name'),
            'registrar': data.get('registrar'),
            'created': data.get('creation_date'),
            'expires': data.get('expiration_date'),
            'age_days': data.get('domain_age', {}).get('total_days') if data.get('domain_age') else None,
            'name_servers': data.get('name_servers', []),
            'registrant_org': data.get('registrant', {}).get('organization'),
            'registrant_country': data.get('registrant', {}).get('country'),
            'status': data.get('status', [])
        }
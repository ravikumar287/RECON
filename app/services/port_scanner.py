"""
Port Scanner Service
Scans target hosts for open ports and identifies services
"""

import socket
import concurrent.futures
from typing import List, Dict, Optional, Callable, Any
from datetime import datetime
import threading

from app.services.utils import (
    validate_target,
    get_ip_from_domain,
    parse_ports,
    get_service_name,
    is_valid_ip,
    generate_scan_id
)


class PortScanner:
    """
    Port Scanner for discovering open ports on target hosts
    
    Features:
    - TCP Connect Scan
    - Multi-threaded scanning
    - Service detection
    - Banner grabbing
    - Progress callbacks
    """
    
    # Common ports for quick scan
    QUICK_SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443]
    
    # Top 1000 ports for standard scan
    TOP_PORTS = [
        1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 82, 88, 100,
        106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 254, 255, 280, 311,
        389, 427, 443, 444, 445, 464, 465, 497, 513, 514, 515, 543, 544, 548, 554,
        587, 593, 625, 631, 636, 646, 787, 808, 873, 902, 990, 993, 995, 1000, 1022,
        1024, 1025, 1026, 1027, 1028, 1029, 1030, 1110, 1433, 1521, 1720, 1723, 1755,
        1900, 2000, 2049, 2100, 2103, 2121, 2199, 2717, 3000, 3128, 3306, 3389, 3986,
        4000, 4001, 4045, 4443, 4444, 5000, 5001, 5050, 5060, 5101, 5190, 5357, 5432,
        5631, 5666, 5800, 5900, 5901, 6000, 6001, 6379, 6646, 7000, 7001, 7070, 7100,
        8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9001, 9090, 9100, 9999, 10000,
        11211, 27017, 32768, 49152, 49153, 49154, 49155, 49156, 49157
    ]
    
    def __init__(self, target: str, timeout: float = 2.0, max_threads: int = 100):
        """
        Initialize Port Scanner
        
        Args:
            target: Target IP or domain
            timeout: Connection timeout in seconds
            max_threads: Maximum concurrent threads
        """
        self.original_target = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.target_ip = None
        self.scan_id = generate_scan_id()
        self.results = []
        self.is_scanning = False
        self.stop_scan = False
        self._lock = threading.Lock()
        
        # Resolve target
        self._resolve_target()
    
    def _resolve_target(self) -> None:
        """Resolve target to IP address"""
        if is_valid_ip(self.original_target):
            self.target_ip = self.original_target
        else:
            self.target_ip = get_ip_from_domain(self.original_target)
    
    def scan_port(self, port: int) -> Dict[str, Any]:
        """
        Scan a single port
        
        Args:
            port: Port number to scan
            
        Returns:
            Dict with port scan results
        """
        result = {
            'port': port,
            'state': 'closed',
            'service': get_service_name(port),
            'banner': None,
            'version': None
        }
        
        if self.stop_scan:
            return result
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            connection_result = sock.connect_ex((self.target_ip, port))
            
            if connection_result == 0:
                result['state'] = 'open'
                
                # Try banner grabbing
                try:
                    sock.settimeout(2)
                    
                    # Send probe for certain services
                    if port in [80, 8080, 8443, 443]:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    elif port in [21, 22, 25, 110, 143]:
                        pass  # These services send banner automatically
                    else:
                        sock.send(b'\r\n')
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner[:200]  # Limit banner length
                        result['version'] = self._extract_version(banner)
                except Exception:
                    pass
            
            sock.close()
            
        except socket.timeout:
            result['state'] = 'filtered'
        except socket.error:
            result['state'] = 'closed'
        except Exception as e:
            result['state'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version information from banner"""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)',  # Standard version: X.X.X.X
            r'v(\d+\.\d+)',  # v1.0 format
            r'version\s+(\S+)',  # version X format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def scan(
        self,
        ports: str = '1-1000',
        scan_type: str = 'tcp',
        callback: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Perform port scan
        
        Args:
            ports: Port specification (e.g., '80', '1-1000', '80,443,8080')
            scan_type: Type of scan ('tcp', 'quick', 'full')
            callback: Progress callback function(port, status, service)
            
        Returns:
            Dict with scan results
        """
        start_time = datetime.now()
        self.is_scanning = True
        self.stop_scan = False
        self.results = []
        
        # Validate target
        if not self.target_ip:
            return {
                'success': False,
                'error': 'Could not resolve target',
                'target': self.original_target
            }
        
        # Determine ports to scan
        if scan_type == 'quick':
            port_list = self.QUICK_SCAN_PORTS
        elif scan_type == 'full':
            port_list = list(range(1, 65536))
        elif ports == 'top':
            port_list = self.TOP_PORTS
        else:
            port_list = parse_ports(ports)
        
        if not port_list:
            return {
                'success': False,
                'error': 'Invalid port specification',
                'target': self.original_target
            }
        
        open_ports = []
        filtered_ports = []
        total_ports = len(port_list)
        scanned = 0
        
        # Multi-threaded scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in port_list
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                if self.stop_scan:
                    executor.shutdown(wait=False)
                    break
                
                result = future.result()
                scanned += 1
                
                if result['state'] == 'open':
                    open_ports.append(result)
                    with self._lock:
                        self.results.append(result)
                elif result['state'] == 'filtered':
                    filtered_ports.append(result)
                
                # Call progress callback
                if callback:
                    try:
                        callback(
                            result['port'],
                            result['state'],
                            result['service']
                        )
                    except Exception:
                        pass
        
        end_time = datetime.now()
        self.is_scanning = False
        
        # Sort results by port number
        open_ports.sort(key=lambda x: x['port'])
        
        return {
            'success': True,
            'scan_id': self.scan_id,
            'target': self.original_target,
            'target_ip': self.target_ip,
            'scan_type': scan_type,
            'ports_scanned': total_ports,
            'open_ports': open_ports,
            'filtered_ports': len(filtered_ports),
            'open_count': len(open_ports),
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration': (end_time - start_time).total_seconds(),
            'timestamp': datetime.now().isoformat()
        }
    
    def quick_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform quick scan of common ports"""
        return self.scan(scan_type='quick', callback=callback)
    
    def full_scan(self, callback: Optional[Callable] = None) -> Dict[str, Any]:
        """Perform full scan of all ports (1-65535)"""
        return self.scan(scan_type='full', callback=callback)
    
    def stop(self) -> None:
        """Stop ongoing scan"""
        self.stop_scan = True
    
    def get_results(self) -> List[Dict]:
        """Get current scan results"""
        with self._lock:
            return list(self.results)
    
    def is_port_open(self, port: int) -> bool:
        """Check if specific port is open"""
        result = self.scan_port(port)
        return result['state'] == 'open'
    
    @staticmethod
    def get_risk_level(port: int, service: str) -> str:
        """Determine risk level of open port"""
        high_risk_ports = [21, 23, 25, 110, 139, 445, 1433, 3306, 3389, 5432, 5900]
        medium_risk_ports = [22, 53, 135, 143, 993, 995, 8080]
        
        if port in high_risk_ports:
            return 'high'
        elif port in medium_risk_ports:
            return 'medium'
        else:
            return 'low'
"""
Reconnaissance routes - Information Gathering
"""

from flask import Blueprint, render_template, request, jsonify
from flask_socketio import emit
from app import socketio

recon_bp = Blueprint('recon', __name__)


# ============ PAGE ROUTES ============

@recon_bp.route('/port-scan')
def port_scan_page():
    """Port scanning page"""
    return render_template('recon/port_scan.html')


@recon_bp.route('/dns-lookup')
def dns_lookup_page():
    """DNS lookup page"""
    return render_template('recon/dns_lookup.html')


@recon_bp.route('/whois')
def whois_page():
    """WHOIS lookup page"""
    return render_template('recon/whois.html')


@recon_bp.route('/subdomain')
def subdomain_page():
    """Subdomain enumeration page"""
    return render_template('recon/subdomain.html')


@recon_bp.route('/headers')
def headers_page():
    """HTTP headers analysis page"""
    return render_template('recon/headers.html')


@recon_bp.route('/ssl-check')
def ssl_check_page():
    """SSL/TLS check page"""
    return render_template('recon/ssl_check.html')


@recon_bp.route('/tech-detect')
def tech_detect_page():
    """Technology detection page"""
    return render_template('recon/tech_detect.html')


# ============ API ROUTES ============

@recon_bp.route('/api/port-scan', methods=['POST'])
def port_scan_api():
    """Port scan API endpoint"""
    from app.services.port_scanner import PortScanner
    
    data = request.get_json()
    target = data.get('target')
    ports = data.get('ports', '1-1000')
    scan_type = data.get('scan_type', 'tcp')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    scanner = PortScanner(target)
    results = scanner.scan(ports=ports, scan_type=scan_type)
    
    return jsonify(results)


@recon_bp.route('/api/dns-lookup', methods=['POST'])
def dns_lookup_api():
    """DNS lookup API endpoint"""
    from app.services.dns_lookup import DNSLookup
    
    data = request.get_json()
    domain = data.get('domain')
    record_types = data.get('record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'])
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    dns_lookup = DNSLookup(domain)
    results = dns_lookup.lookup_all(record_types)
    
    return jsonify(results)


@recon_bp.route('/api/whois', methods=['POST'])
def whois_api():
    """WHOIS lookup API endpoint"""
    from app.services.whois_lookup import WhoisLookup
    
    data = request.get_json()
    domain = data.get('domain')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    whois_lookup = WhoisLookup(domain)
    results = whois_lookup.lookup()
    
    return jsonify(results)


@recon_bp.route('/api/subdomain', methods=['POST'])
def subdomain_api():
    """Subdomain enumeration API endpoint"""
    from app.services.subdomain_enum import SubdomainEnumerator
    
    data = request.get_json()
    domain = data.get('domain')
    wordlist = data.get('wordlist', 'default')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    enumerator = SubdomainEnumerator(domain)
    results = enumerator.enumerate(wordlist=wordlist)
    
    return jsonify(results)


@recon_bp.route('/api/headers', methods=['POST'])
def headers_api():
    """HTTP headers analysis API endpoint"""
    from app.services.header_analyzer import HeaderAnalyzer
    
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    analyzer = HeaderAnalyzer(url)
    results = analyzer.analyze()
    
    return jsonify(results)


@recon_bp.route('/api/ssl-check', methods=['POST'])
def ssl_check_api():
    """SSL/TLS check API endpoint"""
    from app.services.ssl_analyzer import SSLAnalyzer
    
    data = request.get_json()
    host = data.get('host')
    port = data.get('port', 443)
    
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    
    analyzer = SSLAnalyzer(host, port)
    results = analyzer.analyze()
    
    return jsonify(results)


@recon_bp.route('/api/tech-detect', methods=['POST'])
def tech_detect_api():
    """Technology detection API endpoint"""
    from app.services.tech_detector import TechDetector
    
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    detector = TechDetector(url)
    results = detector.detect()
    
    return jsonify(results)


# ============ WEBSOCKET EVENTS ============

@socketio.on('start_port_scan')
def handle_port_scan(data):
    """Handle real-time port scanning via WebSocket"""
    from app.services.port_scanner import PortScanner
    
    target = data.get('target')
    ports = data.get('ports', '1-1000')
    
    scanner = PortScanner(target)
    
    def progress_callback(port, status, service):
        emit('port_scan_progress', {
            'port': port,
            'status': status,
            'service': service
        })
    
    results = scanner.scan(ports=ports, callback=progress_callback)
    emit('port_scan_complete', results)


@socketio.on('start_subdomain_enum')
def handle_subdomain_enum(data):
    """Handle real-time subdomain enumeration via WebSocket"""
    from app.services.subdomain_enum import SubdomainEnumerator
    
    domain = data.get('domain')
    
    enumerator = SubdomainEnumerator(domain)
    
    def progress_callback(subdomain, status):
        emit('subdomain_progress', {
            'subdomain': subdomain,
            'status': status
        })
    
    results = enumerator.enumerate(callback=progress_callback)
    emit('subdomain_complete', results)
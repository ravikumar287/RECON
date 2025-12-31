"""
Vulnerability Scanner routes
"""

from flask import Blueprint, render_template, request, jsonify
from flask_socketio import emit
from app import socketio

scanner_bp = Blueprint('scanner', __name__)


# ============ PAGE ROUTES ============

@scanner_bp.route('/full-scan')
def full_scan_page():
    """Full vulnerability scan page"""
    return render_template('scanner/full_scan.html')


@scanner_bp.route('/xss-scan')
def xss_scan_page():
    """XSS vulnerability scan page"""
    return render_template('scanner/xss_scan.html')


@scanner_bp.route('/sqli-scan')
def sqli_scan_page():
    """SQL Injection scan page"""
    return render_template('scanner/sqli_scan.html')


@scanner_bp.route('/dir-scan')
def dir_scan_page():
    """Directory bruteforce page"""
    return render_template('scanner/dir_scan.html')


@scanner_bp.route('/security-headers')
def security_headers_page():
    """Security headers check page"""
    return render_template('scanner/security_headers.html')


@scanner_bp.route('/results/<scan_id>')
def scan_results_page(scan_id):
    """Scan results page"""
    return render_template('reports/report.html', scan_id=scan_id)


@scanner_bp.route('/history')
def scan_history_page():
    """Scan history page"""
    return render_template('reports/history.html')


# ============ API ROUTES ============

@scanner_bp.route('/api/full-scan', methods=['POST'])
def full_scan_api():
    """Full vulnerability scan API endpoint"""
    from app.services.vuln_scanner import VulnerabilityScanner
    
    data = request.get_json()
    target = data.get('target')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    scanner = VulnerabilityScanner(target, options)
    results = scanner.full_scan()
    
    return jsonify(results)


@scanner_bp.route('/api/xss-scan', methods=['POST'])
def xss_scan_api():
    """XSS scan API endpoint"""
    from app.services.xss_scanner import XSSScanner
    
    data = request.get_json()
    url = data.get('url')
    crawl = data.get('crawl', False)
    depth = data.get('depth', 2)
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    scanner = XSSScanner(url)
    results = scanner.scan(crawl=crawl, depth=depth)
    
    return jsonify(results)


@scanner_bp.route('/api/sqli-scan', methods=['POST'])
def sqli_scan_api():
    """SQL Injection scan API endpoint"""
    from app.services.sqli_scanner import SQLiScanner
    
    data = request.get_json()
    url = data.get('url')
    method = data.get('method', 'GET')
    params = data.get('params', {})
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    scanner = SQLiScanner(url)
    results = scanner.scan(method=method, params=params)
    
    return jsonify(results)


@scanner_bp.route('/api/dir-scan', methods=['POST'])
def dir_scan_api():
    """Directory bruteforce API endpoint"""
    from app.services.dir_bruteforce import DirectoryBruteforce
    
    data = request.get_json()
    url = data.get('url')
    wordlist = data.get('wordlist', 'default')
    extensions = data.get('extensions', [])
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    scanner = DirectoryBruteforce(url)
    results = scanner.scan(wordlist=wordlist, extensions=extensions)
    
    return jsonify(results)


@scanner_bp.route('/api/security-headers', methods=['POST'])
def security_headers_api():
    """Security headers check API endpoint"""
    from app.services.header_analyzer import HeaderAnalyzer
    
    data = request.get_json()
    url = data.get('url')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    analyzer = HeaderAnalyzer(url)
    results = analyzer.check_security_headers()
    
    return jsonify(results)


# ============ WEBSOCKET EVENTS ============

@socketio.on('start_full_scan')
def handle_full_scan(data):
    """Handle real-time full scan via WebSocket"""
    from app.services.vuln_scanner import VulnerabilityScanner
    
    target = data.get('target')
    options = data.get('options', {})
    
    scanner = VulnerabilityScanner(target, options)
    
    def progress_callback(stage, progress, message):
        emit('scan_progress', {
            'stage': stage,
            'progress': progress,
            'message': message
        })
    
    results = scanner.full_scan(callback=progress_callback)
    emit('scan_complete', results)


@socketio.on('start_xss_scan')
def handle_xss_scan(data):
    """Handle real-time XSS scan via WebSocket"""
    from app.services.xss_scanner import XSSScanner
    
    url = data.get('url')
    
    scanner = XSSScanner(url)
    
    def progress_callback(payload, vulnerable, details):
        emit('xss_progress', {
            'payload': payload,
            'vulnerable': vulnerable,
            'details': details
        })
    
    results = scanner.scan(callback=progress_callback)
    emit('xss_complete', results)


@socketio.on('start_dir_scan')
def handle_dir_scan(data):
    """Handle real-time directory scan via WebSocket"""
    from app.services.dir_bruteforce import DirectoryBruteforce
    
    url = data.get('url')
    wordlist = data.get('wordlist', 'default')
    
    scanner = DirectoryBruteforce(url)
    
    def progress_callback(path, status_code, found):
        emit('dir_progress', {
            'path': path,
            'status_code': status_code,
            'found': found
        })
    
    results = scanner.scan(wordlist=wordlist, callback=progress_callback)
    emit('dir_complete', results)
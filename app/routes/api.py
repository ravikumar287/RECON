"""
General API routes
"""

from flask import Blueprint, request, jsonify, send_file
import json
import os
from datetime import datetime

api_bp = Blueprint('api', __name__)


@api_bp.route('/health')
def health_check():
    """API health check"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })


@api_bp.route('/validate-target', methods=['POST'])
def validate_target():
    """Validate target URL/IP"""
    from app.services.utils import validate_target
    
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    is_valid, target_type, normalized = validate_target(target)
    
    return jsonify({
        'valid': is_valid,
        'type': target_type,
        'normalized': normalized
    })


@api_bp.route('/reports', methods=['GET'])
def list_reports():
    """List all generated reports"""
    reports_dir = 'reports'
    reports = []
    
    if os.path.exists(reports_dir):
        for filename in os.listdir(reports_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(reports_dir, filename)
                with open(filepath, 'r') as f:
                    report_data = json.load(f)
                    reports.append({
                        'id': filename.replace('.json', ''),
                        'target': report_data.get('target'),
                        'scan_type': report_data.get('scan_type'),
                        'date': report_data.get('timestamp'),
                        'findings': len(report_data.get('findings', []))
                    })
    
    return jsonify({'reports': reports})


@api_bp.route('/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Get specific report"""
    filepath = f'reports/{report_id}.json'
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    
    with open(filepath, 'r') as f:
        report_data = json.load(f)
    
    return jsonify(report_data)


@api_bp.route('/reports/<report_id>/download', methods=['GET'])
def download_report(report_id):
    """Download report as JSON"""
    filepath = f'reports/{report_id}.json'
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    
    return send_file(
        filepath,
        as_attachment=True,
        download_name=f'scan_report_{report_id}.json',
        mimetype='application/json'
    )


@api_bp.route('/reports/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    """Delete specific report"""
    filepath = f'reports/{report_id}.json'
    
    if not os.path.exists(filepath):
        return jsonify({'error': 'Report not found'}), 404
    
    os.remove(filepath)
    return jsonify({'message': 'Report deleted successfully'})


@api_bp.route('/export/pdf/<report_id>', methods=['GET'])
def export_pdf(report_id):
    """Export report as PDF"""
    # This would require additional PDF generation library
    return jsonify({'error': 'PDF export not implemented yet'}), 501


@api_bp.route('/scan-status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get status of running scan"""
    # In a real implementation, this would check a database or cache
    return jsonify({
        'scan_id': scan_id,
        'status': 'running',
        'progress': 45,
        'current_stage': 'Port Scanning'
    })


@api_bp.route('/stop-scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    """Stop a running scan"""
    # In a real implementation, this would stop the scan process
    return jsonify({
        'scan_id': scan_id,
        'status': 'stopped',
        'message': 'Scan stopped successfully'
    })
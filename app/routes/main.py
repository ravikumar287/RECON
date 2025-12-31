"""
Main routes - Home, Dashboard, About
"""

from flask import Blueprint, render_template, request, jsonify
from datetime import datetime

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@main_bp.route('/dashboard')
def dashboard():
    """Main dashboard"""
    stats = {
        'total_scans': 0,
        'vulnerabilities_found': 0,
        'targets_scanned': 0,
        'critical_issues': 0,
    }
    
    recent_scans = []
    
    return render_template('dashboard.html', stats=stats, recent_scans=recent_scans)


@main_bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')


@main_bp.route('/settings')
def settings():
    """Settings page"""
    return render_template('settings.html')


@main_bp.errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('errors/404.html'), 404


@main_bp.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template('errors/500.html'), 500
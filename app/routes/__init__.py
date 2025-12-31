"""
Routes package initialization
"""

from app.routes.main import main_bp
from app.routes.recon import recon_bp
from app.routes.scanner import scanner_bp
from app.routes.api import api_bp

__all__ = ['main_bp', 'recon_bp', 'scanner_bp', 'api_bp']
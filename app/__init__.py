"""
Flask Application Factory
"""

from flask import Flask
from flask_socketio import SocketIO

socketio = SocketIO()

def create_app(config_class=None):
    """Create and configure the Flask application"""
    
    app = Flask(__name__)
    
    # Load configuration
    if config_class:
        app.config.from_object(config_class)
    else:
        from app.config import Config
        app.config.from_object(Config)
    
    # Initialize extensions
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    
    # Register blueprints
    from app.routes.main import main_bp
    from app.routes.recon import recon_bp
    from app.routes.scanner import scanner_bp
    from app.routes.api import api_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(recon_bp, url_prefix='/recon')
    app.register_blueprint(scanner_bp, url_prefix='/scanner')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Create necessary directories
    import os
    os.makedirs('reports', exist_ok=True)
    os.makedirs('wordlists/payloads', exist_ok=True)
    
    return app
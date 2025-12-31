#!/usr/bin/env python3
"""
Vulnerability Scanner & Information Gathering Tool
Main entry point
"""

from app import create_app, socketio

app = create_app()

if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     🔒 VulnScanner - Security Assessment Tool 🔒         ║
    ║                                                          ║
    ║  ⚠️  Use responsibly and only on authorized targets!     ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
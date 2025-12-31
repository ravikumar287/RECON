"""
Application Configuration
"""

import os
from datetime import timedelta

class Config:
    """Base configuration"""
    
    # Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your-secret-key-change-in-production'
    DEBUG = True
    
    # Scanner settings
    SCAN_TIMEOUT = 30
    MAX_THREADS = 50
    REQUEST_DELAY = 0.1
    USER_AGENT = 'VulnScanner/1.0 (Security Research Tool)'
    
    # Port scanning settings
    DEFAULT_PORTS = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443'
    PORT_SCAN_TIMEOUT = 2
    
    # Directory bruteforce settings
    DIR_THREADS = 20
    DIR_TIMEOUT = 10
    
    # Rate limiting
    REQUESTS_PER_SECOND = 10
    
    # Report settings
    REPORTS_FOLDER = 'reports'
    
    # Wordlist paths
    SUBDOMAIN_WORDLIST = 'wordlists/subdomains.txt'
    DIRECTORY_WORDLIST = 'wordlists/directories.txt'
    XSS_PAYLOADS = 'wordlists/payloads/xss_payloads.txt'
    SQLI_PAYLOADS = 'wordlists/payloads/sqli_payloads.txt'


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SCAN_TIMEOUT = 60
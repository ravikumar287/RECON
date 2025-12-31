"""
VulnScanner Test Suite
Comprehensive tests for all scanner and reconnaissance modules
"""

import os
import sys

# Add project root to path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Test configuration
TEST_CONFIG = {
    'test_domain': 'example.com',
    'test_ip': '93.184.216.34',
    'test_url': 'https://example.com',
    'timeout': 10,
    'skip_live_tests': os.environ.get('SKIP_LIVE_TESTS', 'false').lower() == 'true'
}

__all__ = ['TEST_CONFIG']
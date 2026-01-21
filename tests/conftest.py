"""
Pytest configuration and fixtures
"""
import pytest
import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

@pytest.fixture
def db_path(tmp_path):
    """Provide a temporary database path for testing"""
    return tmp_path / "test_ncrt.db"

@pytest.fixture
def sample_config():
    """Sample configuration file content for testing"""
    return """version 15.2
service timestamps debug datetime msec
service timestamps log datetime msec
hostname TestRouter
interface GigabitEthernet0/1
 no ip address
 shutdown
interface GigabitEthernet0/2
 ip address 192.168.1.1 255.255.255.0
"""


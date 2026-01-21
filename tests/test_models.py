"""
Unit tests for database models
"""
import pytest
from models.audit import Audit, Finding
from models.rule import Rule
from services.database import init_database, get_db_connection
import tempfile
import os

@pytest.mark.unit
class TestRule:
    """Test Rule model"""
    
    def test_create_rule(self):
        """Test creating a rule"""
        rule_id = Rule.create(
            name="Test Rule",
            description="Test description",
            rule_type="pattern",
            category="authentication",
            severity="high",
            yaml_content="pattern: 'test'",
            tags="test,generic",
            enabled=1
        )
        assert rule_id > 0
        
        rule = Rule.get_by_id(rule_id)
        assert rule is not None
        assert rule['name'] == "Test Rule"
        assert rule['rule_type'] == "pattern"
    
    def test_get_all_rules(self):
        """Test getting all rules"""
        rules = Rule.get_all()
        assert isinstance(rules, list)
    
    def test_get_enabled_rules(self):
        """Test getting only enabled rules"""
        rules = Rule.get_all(enabled_only=True)
        for rule in rules:
            assert rule['enabled'] == 1

@pytest.mark.unit
class TestAudit:
    """Test Audit model"""
    
    def test_create_audit(self):
        """Test creating an audit"""
        audit_id = Audit.create(
            status="Pending",
            device_identifier="test-device-001",
            config_file="test.cfg"
        )
        assert audit_id > 0
        
        audit = Audit.get_by_id(audit_id)
        assert audit is not None
        assert audit['status'] == "Pending"
        assert audit['device_identifier'] == "test-device-001"
    
    def test_update_status(self):
        """Test updating audit status"""
        audit_id = Audit.create(
            status="Pending",
            device_identifier="test-device-002",
            config_file="test.cfg"
        )
        
        Audit.update_status(audit_id, "Completed")
        audit = Audit.get_by_id(audit_id)
        assert audit['status'] == "Completed"
        assert audit['completed_at'] is not None

@pytest.mark.unit
class TestFinding:
    """Test Finding model"""
    
    def test_create_finding(self):
        """Test creating a finding"""
        # Create audit first
        audit_id = Audit.create(
            status="Completed",
            device_identifier="test-device-003",
            config_file="test.cfg"
        )
        
        # Create rule first
        rule_id = Rule.create(
            name="Test Finding Rule",
            rule_type="pattern",
            category="security",
            severity="critical",
            yaml_content="pattern: 'test'",
            enabled=1
        )
        
        finding_id = Finding.create(
            audit_id=audit_id,
            rule_id=rule_id,
            severity="critical",
            message="Test finding message",
            config_path="Line 10: interface test"
        )
        assert finding_id > 0
        
        findings = Finding.get_by_audit(audit_id)
        assert len(findings) > 0
        assert any(f['id'] == finding_id for f in findings)


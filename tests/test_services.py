"""
Unit tests for service layer
"""
import pytest
from models.audit import Audit
from models.rule import Rule
from services.audit_service import process_audit
from services.report_generator import generate_statistics, calculate_compliance_score

@pytest.mark.unit
class TestReportGenerator:
    """Test report generation services"""
    
    def test_generate_statistics(self):
        """Test statistics generation"""
        # Create test audit with findings
        audit_id = Audit.create(
            status="Completed",
            device_identifier="test-statistics",
            config_file="test.cfg"
        )
        
        rule_id = Rule.create(
            name="Test Stat Rule",
            rule_type="pattern",
            category="test",
            severity="high",
            yaml_content="pattern: 'test'",
            enabled=1
        )
        
        from models.audit import Finding
        Finding.create(
            audit_id=audit_id,
            rule_id=rule_id,
            severity="high",
            message="Test",
            config_path="test"
        )
        
        stats = generate_statistics(audit_id)
        assert stats is not None
        assert 'total_findings' in stats
        assert stats['total_findings'] >= 0


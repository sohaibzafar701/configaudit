#!/usr/bin/env python3
"""
Initialize database with sample rules
"""

from services.database import init_database
from models.rule import Rule

def add_sample_rules():
    """Add sample rules to database"""
    # Sample pattern rule
    Rule.create(
        name="Default Password Check",
        description="Check for default passwords in configuration",
        rule_type=Rule.TYPE_PATTERN,
        category="Authentication",
        severity="high",
        yaml_content="""
name: Default Password Check
type: pattern
pattern: 'password\\s+\\d+'
severity: high
message: "Default password detected"
"""
    )
    
    # Sample pattern rule
    Rule.create(
        name="SSH Enabled Check",
        description="Check if SSH is enabled",
        rule_type=Rule.TYPE_PATTERN,
        category="Encryption",
        severity="medium",
        yaml_content="""
name: SSH Enabled Check
type: pattern
pattern: 'ip\\s+ssh'
severity: medium
message: "SSH is enabled"
"""
    )
    
    # Sample pattern rule
    Rule.create(
        name="No Access List",
        description="Check if access lists are configured",
        rule_type=Rule.TYPE_PATTERN,
        category="Access Control",
        severity="low",
        yaml_content="""
name: No Access List
type: pattern
pattern: 'ip\\s+access-list'
severity: low
message: "Access list found"
"""
    )
    
    print("Sample rules added successfully!")

if __name__ == "__main__":
    print("Initializing database...")
    init_database()
    print("Adding sample rules...")
    add_sample_rules()
    print("Done!")


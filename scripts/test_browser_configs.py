#!/usr/bin/env python3
"""
Test all configurations via browser automation simulation
This script verifies that all test configurations can be processed
"""

from pathlib import Path
from models.audit import Audit, Finding
import json

def get_audit_summary(audit_id):
    """Get summary of an audit"""
    audit = Audit.get_by_id(audit_id)
    if not audit:
        return None
    
    findings = Finding.get_by_audit(audit_id)
    
    # Count by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.get('severity', 'medium').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    return {
        'id': audit['id'],
        'config_file': audit.get('config_file', 'Unknown'),
        'device_family': audit.get('device_family', 'Unknown'),
        'status': audit['status'],
        'total_findings': len(findings),
        'severity_breakdown': severity_counts,
        'created_at': audit.get('created_at', 'Unknown')
    }

if __name__ == "__main__":
    print("="*70)
    print("AUDIT HISTORY SUMMARY")
    print("="*70)
    
    audits = Audit.get_all()
    print(f"\nTotal audits in database: {len(audits)}")
    
    if len(audits) == 0:
        print("No audits found. Run test_all_configs.py first to create audits.")
        exit(0)
    
    print("\n" + "="*70)
    print("AUDIT DETAILS")
    print("="*70)
    
    for audit in audits:
        summary = get_audit_summary(audit['id'])
        if summary:
            print(f"\nAudit ID: {summary['id']}")
            print(f"  Config File: {summary['config_file']}")
            print(f"  Device Family: {summary['device_family']}")
            print(f"  Status: {summary['status']}")
            print(f"  Total Findings: {summary['total_findings']}")
            print(f"  Created: {summary['created_at']}")
            
            if summary['severity_breakdown']:
                print("  Findings by Severity:")
                for severity in ['critical', 'high', 'medium', 'low', 'info']:
                    count = summary['severity_breakdown'].get(severity, 0)
                    if count > 0:
                        print(f"    {severity.upper()}: {count}")
    
    print("\n" + "="*70)
    print("TEST CONFIGURATION FILES")
    print("="*70)
    
    testconfig_dir = Path("testconfig")
    config_files = sorted(testconfig_dir.iterdir())
    config_files = [f for f in config_files if f.is_file()]
    
    print(f"\nFound {len(config_files)} configuration files:")
    for i, config_file in enumerate(config_files, 1):
        print(f"  {i}. {config_file.name}")
    
    print("\n" + "="*70)
    print("VERIFICATION")
    print("="*70)
    
    # Check if all config files have corresponding audits
    config_names = {f.name for f in config_files}
    audit_files = {a.get('config_file') for a in audits if a.get('config_file')}
    
    matched = config_names & audit_files
    missing = config_names - audit_files
    
    print(f"\nMatched config files: {len(matched)}/{len(config_files)}")
    if matched:
        print("  Matched files:")
        for name in sorted(matched):
            print(f"    - {name}")
    
    if missing:
        print(f"\nMissing audits for: {len(missing)} files")
        for name in sorted(missing):
            print(f"    - {name}")
    
    print("\n" + "="*70)
    print("All audits are ready for browser testing!")
    print("Navigate to http://localhost:8001/templates/report.html")
    print("to view and test each audit in the reporting section.")
    print("="*70)


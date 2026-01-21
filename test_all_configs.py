#!/usr/bin/env python3
"""
Test all configuration files in testconfig folder
"""

import os
from pathlib import Path
from models.audit import Audit, Finding
from services.audit_service import process_audit
from parsers.factory import create_parser

def test_config_file(file_path):
    """Test a single configuration file"""
    file_name = Path(file_path).name
    print(f"\n{'='*70}")
    print(f"Testing: {file_name}")
    print(f"{'='*70}")
    
    # Read configuration file
    config_path = Path(file_path)
    if not config_path.exists():
        print(f"ERROR: File not found: {config_path}")
        return None
    
    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
        config_content = f.read()
    
    print(f"File size: {len(config_content)} characters")
    
    # Detect vendor
    try:
        parser = create_parser(vendor=None, config_text=config_content)
        vendor = parser.get_vendor()
        device_family = parser.detect_device_family(config_content)
        print(f"Detected vendor: {vendor}")
        print(f"Device family: {device_family}")
    except Exception as e:
        print(f"ERROR detecting vendor: {e}")
        vendor = "Unknown"
        device_family = "Unknown"
    
    # Parse configuration
    try:
        parsed_config = parser.parse(config_content)
        print(f"Parsed successfully")
    except Exception as e:
        print(f"ERROR parsing config: {e}")
        return None
    
    # Create audit
    print("Creating audit...")
    audit_id = Audit.create(
        device_family=device_family,
        config_file=file_name
    )
    print(f"Audit ID: {audit_id}")
    
    # Process audit
    print("Processing audit...")
    try:
        process_audit(audit_id, config_content, device_family)
        print("Audit processing completed")
    except Exception as e:
        print(f"ERROR processing audit: {e}")
        import traceback
        traceback.print_exc()
        return None
    
    # Get findings
    findings = Finding.get_by_audit(audit_id)
    print(f"Findings generated: {len(findings)}")
    
    # Get audit status
    audit = Audit.get_by_id(audit_id)
    print(f"Final audit status: {audit['status']}")
    
    # Summary by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.get('severity', 'medium').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    if severity_counts:
        print("\nFindings by severity:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
    
    return audit_id

if __name__ == "__main__":
    testconfig_dir = Path("testconfig")
    
    if not testconfig_dir.exists():
        print(f"ERROR: testconfig directory not found")
        exit(1)
    
    # Get all files in testconfig directory
    config_files = sorted(testconfig_dir.iterdir())
    config_files = [f for f in config_files if f.is_file()]
    
    print(f"Found {len(config_files)} configuration files to test")
    
    results = []
    for config_file in config_files:
        audit_id = test_config_file(config_file)
        if audit_id:
            results.append({
                'file': config_file.name,
                'audit_id': audit_id,
                'status': 'success'
            })
        else:
            results.append({
                'file': config_file.name,
                'audit_id': None,
                'status': 'failed'
            })
    
    # Summary
    print(f"\n{'='*70}")
    print("TEST SUMMARY")
    print(f"{'='*70}")
    print(f"Total files tested: {len(config_files)}")
    print(f"Successful: {sum(1 for r in results if r['status'] == 'success')}")
    print(f"Failed: {sum(1 for r in results if r['status'] == 'failed')}")
    print("\nResults:")
    for result in results:
        status_icon = "[OK]" if result['status'] == 'success' else "[FAIL]"
        print(f"  {status_icon} {result['file']} - Audit ID: {result['audit_id'] or 'N/A'}")


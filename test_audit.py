#!/usr/bin/env python3
"""
Test audit functionality with provided configuration files
"""

from pathlib import Path
from models.audit import Audit, Finding
from models.rule import Rule
from services.audit_service import process_audit
from parsers.factory import create_parser

def test_audit_with_file(file_path, file_name):
    """Test audit with a configuration file"""
    print(f"\n{'='*60}")
    print(f"Testing audit with: {file_name}")
    print(f"{'='*60}")
    
    # Read configuration file
    config_path = Path(file_path)
    if not config_path.exists():
        print(f"ERROR: File not found: {config_path}")
        return
    
    with open(config_path, 'r', encoding='utf-8', errors='ignore') as f:
        config_content = f.read()
    
    print(f"File size: {len(config_content)} characters")
    print(f"First 200 chars: {config_content[:200]}...")
    
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
        print(f"Parsed config keys: {list(parsed_config.keys())}")
    except Exception as e:
        print(f"ERROR parsing config: {e}")
        return
    
    # Create audit
    print("\nCreating audit...")
    audit_id = Audit.create(
        device_family=device_family,
        config_file=file_name
    )
    print(f"Audit ID: {audit_id}")
    
    # Process audit
    print("\nProcessing audit...")
    try:
        process_audit(audit_id, config_content, device_family)
        print("Audit processing completed")
    except Exception as e:
        print(f"ERROR processing audit: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Get findings
    findings = Finding.get_by_audit(audit_id)
    print(f"\nFindings generated: {len(findings)}")
    
    if findings:
        print("\nSample findings:")
        for finding in findings[:5]:
            print(f"  - Rule: {finding.get('rule_name', 'Unknown')}")
            print(f"    Severity: {finding.get('severity', 'N/A')}")
            print(f"    Message: {finding.get('message', 'N/A')}")
    else:
        print("No findings generated - this might indicate an issue with rule execution")
    
    # Get audit status
    audit = Audit.get_by_id(audit_id)
    print(f"\nFinal audit status: {audit['status']}")
    
    return audit_id, findings

if __name__ == "__main__":
    # Test with SEG-Switch (Cisco)
    test_audit_with_file(
        "testconfig/SEG-Switch",
        "SEG-Switch"
    )
    
    # Test with Datacenter-Switch (Juniper)
    test_audit_with_file(
        "testconfig/Datacenter-Switch",
        "Datacenter-Switch"
    )
    
    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)


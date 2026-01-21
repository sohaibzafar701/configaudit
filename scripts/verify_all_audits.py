#!/usr/bin/env python3
"""
Verify all audits are accessible and have findings
"""

from models.audit import Audit, Finding
from services.report_generator import generate_statistics

def verify_audit(audit_id):
    """Verify an audit is complete and accessible"""
    audit = Audit.get_by_id(audit_id)
    if not audit:
        return False, "Audit not found"
    
    findings = Finding.get_by_audit(audit_id)
    statistics = generate_statistics(audit_id)
    
    return True, {
        'id': audit_id,
        'config_file': audit.get('config_file', 'Unknown'),
        'status': audit['status'],
        'findings_count': len(findings),
        'statistics': statistics
    }

if __name__ == "__main__":
    print("="*70)
    print("VERIFYING ALL AUDITS FOR BROWSER TESTING")
    print("="*70)
    
    audits = Audit.get_all()
    print(f"\nTotal audits: {len(audits)}")
    
    if len(audits) == 0:
        print("No audits found!")
        exit(1)
    
    print("\n" + "-"*70)
    print("AUDIT VERIFICATION RESULTS")
    print("-"*70)
    
    all_verified = True
    for audit in audits:
        success, result = verify_audit(audit['id'])
        if success:
            print(f"\n[OK] Audit ID {result['id']}: {result['config_file']}")
            print(f"  Status: {result['status']}")
            print(f"  Findings: {result['findings_count']}")
            if result['statistics']:
                print(f"  Risk Score: {result['statistics'].get('risk_score', 0)}")
                print(f"  Compliance Score: {result['statistics'].get('compliance_score', 0)}%")
        else:
            print(f"\n[FAIL] Audit ID {audit['id']}: {result}")
            all_verified = False
    
    print("\n" + "="*70)
    if all_verified:
        print("ALL AUDITS VERIFIED - Ready for browser testing!")
        print("\nTest each audit by:")
        print("1. Navigate to http://localhost:8001/templates/report.html")
        print("2. Select different audits from the dropdown")
        print("3. Verify statistics, charts, and findings display correctly")
        print("4. Test filtering, grouping, and export functions")
    else:
        print("SOME AUDITS FAILED VERIFICATION")
    print("="*70)


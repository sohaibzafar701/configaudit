#!/usr/bin/env python3
"""Test API endpoints directly"""

import urllib.request
import json

def test_api(url):
    """Test an API endpoint"""
    try:
        response = urllib.request.urlopen(f'http://localhost:8001{url}')
        data = json.loads(response.read().decode())
        return True, data
    except Exception as e:
        return False, str(e)

print("Testing API endpoints...")
print("="*70)

# Test audit history endpoint
success, result = test_api('/api/audits?history=true')
if success:
    print(f"\n✓ Audit History API: SUCCESS")
    print(f"  Total audits: {len(result.get('audits', []))}")
    for audit in result.get('audits', [])[:5]:
        print(f"    - ID {audit['id']}: {audit.get('config_file', 'Unknown')} ({audit.get('finding_count', 0)} findings)")
else:
    print(f"\n[FAIL] Audit History API: FAILED - {result}")

# Test reports endpoint for each audit
print("\n" + "="*70)
print("Testing Reports API for each audit:")
print("="*70)

audits = result.get('audits', []) if success else []
for audit in audits[:5]:
    audit_id = audit['id']
    success, report_data = test_api(f'/api/reports?audit_id={audit_id}&include_statistics=true')
    if success:
        findings_count = len(report_data.get('findings', []))
        stats = report_data.get('statistics', {})
        print(f"\n✓ Audit ID {audit_id} ({audit.get('config_file', 'Unknown')}):")
        print(f"    Findings: {findings_count}")
        print(f"    Risk Score: {stats.get('risk_score', 0)}")
        print(f"    Compliance: {stats.get('compliance_score', 0)}%")
    else:
        print(f"\n[FAIL] Audit ID {audit_id}: FAILED - {report_data}")

print("\n" + "="*70)
print("API Testing Complete")
print("="*70)


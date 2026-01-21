#!/usr/bin/env python3
"""Verify specific security findings"""

from models.audit import Audit, Finding

# Check SEG-Switch audit (Cisco)
print("="*60)
print("SEG-Switch (Cisco) Audit Findings")
print("="*60)
audit = Audit.get_by_id(6)
if audit:
    findings = Finding.get_by_audit(6)
    print(f"Total findings: {len(findings)}")
    
    # Check for specific security issues
    print("\nKey Security Findings:")
    
    # Check for "no aaa new-model" - should be flagged
    aaa_findings = [f for f in findings if 'aaa' in f.get('rule_name', '').lower()]
    print(f"\nAAA-related findings: {len(aaa_findings)}")
    for f in aaa_findings:
        print(f"  - {f['rule_name']}: {f['message']} (severity: {f['severity']})")
    
    # Check for SNMP community strings
    snmp_findings = [f for f in findings if 'snmp' in f.get('rule_name', '').lower()]
    print(f"\nSNMP-related findings: {len(snmp_findings)}")
    for f in snmp_findings:
        print(f"  - {f['rule_name']}: {f['message']} (severity: {f['severity']})")
    
    # Check for SSH
    ssh_findings = [f for f in findings if 'ssh' in f.get('rule_name', '').lower()]
    print(f"\nSSH-related findings: {len(ssh_findings)}")
    for f in ssh_findings:
        print(f"  - {f['rule_name']}: {f['message']} (severity: {f['severity']})")
    
    # High/Critical severity findings
    critical_findings = [f for f in findings if f['severity'] in ['high', 'critical']]
    print(f"\nHigh/Critical severity findings: {len(critical_findings)}")
    for f in critical_findings[:10]:
        print(f"  [{f['severity']}] {f['rule_name']}: {f['message']}")

# Check Datacenter-Switch audit (Juniper)
print("\n" + "="*60)
print("Datacenter-Switch (Juniper) Audit Findings")
print("="*60)
audit = Audit.get_by_id(7)
if audit:
    findings = Finding.get_by_audit(7)
    print(f"Total findings: {len(findings)}")
    
    # Check for SNMP community strings (Juniper has them)
    snmp_findings = [f for f in findings if 'snmp' in f.get('rule_name', '').lower()]
    print(f"\nSNMP-related findings: {len(snmp_findings)}")
    for f in snmp_findings:
        print(f"  - {f['rule_name']}: {f['message']} (severity: {f['severity']})")
    
    # Check for SSH
    ssh_findings = [f for f in findings if 'ssh' in f.get('rule_name', '').lower()]
    print(f"\nSSH-related findings: {len(ssh_findings)}")
    for f in ssh_findings:
        print(f"  - {f['rule_name']}: {f['message']} (severity: {f['severity']})")


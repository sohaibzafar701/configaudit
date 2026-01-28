#!/usr/bin/env python3
"""
Script to create MMBL-specific baseline configurations
"""

import os
import sys
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auditconfig.settings')
django.setup()

from apps.core.models import BaselineConfiguration, Rule, Organization
from django.db.models import Q


def get_rules_by_framework(framework):
    """Get rules tagged with specific compliance framework"""
    return Rule.objects.filter(
        enabled=True,
        organization__isnull=True,
        compliance_frameworks__icontains=framework
    )


def get_rules_by_vendor(vendor):
    """Get rules tagged with specific vendor"""
    vendor_lower = vendor.lower()
    return Rule.objects.filter(
        enabled=True,
        organization__isnull=True,
        tags__icontains=vendor_lower
    )


def create_cisco_router_baseline():
    """Create Cisco router baseline"""
    # Get rules for Cisco routers
    cisco_rules = get_rules_by_vendor('cisco')
    iso_rules = get_rules_by_framework('ISO27001')
    nist_rules = get_rules_by_framework('NIST')
    pci_rules = get_rules_by_framework('PCI-DSS')
    
    # Combine and get unique rule IDs
    all_rules = (cisco_rules | iso_rules | nist_rules | pci_rules).distinct()
    rule_ids = list(all_rules.values_list('id', flat=True))
    
    baseline, created = BaselineConfiguration.objects.get_or_create(
        name='Cisco Router Baseline',
        organization=None,
        defaults={
            'description': 'Baseline configuration for Cisco routers based on ISO 27001, NIST, and PCI-DSS standards',
            'vendor': 'cisco',
            'device_type': 'router',
            'compliance_frameworks': 'ISO27001,NIST-CSF,PCI-DSS,CIS',
            'rule_ids': rule_ids,
            'template_config': '''
! Platform Baseline Configuration for Cisco Router
aaa new-model
aaa authentication login default group tacacs+ local
ip ssh version 2
ip http secure-server
logging host <syslog-server>
snmp-server group PLATFORM-GROUP v3 auth
'''
        }
    )
    
    if created:
        print(f"✓ Created baseline: {baseline.name} ({len(rule_ids)} rules)")
    else:
        baseline.rule_ids = rule_ids
        baseline.save()
        print(f"✓ Updated baseline: {baseline.name} ({len(rule_ids)} rules)")
    
    return baseline


def create_cisco_switch_baseline():
    """Create Cisco switch baseline"""
    cisco_rules = get_rules_by_vendor('cisco')
    iso_rules = get_rules_by_framework('ISO27001')
    nist_rules = get_rules_by_framework('NIST')
    
    all_rules = (cisco_rules | iso_rules | nist_rules).distinct()
    rule_ids = list(all_rules.values_list('id', flat=True))
    
    baseline, created = BaselineConfiguration.objects.get_or_create(
        name='MMBL Cisco Switch Baseline',
        organization=None,
        defaults={
            'description': 'Baseline configuration for Cisco switches based on ISO 27001 and NIST standards',
            'vendor': 'cisco',
            'device_type': 'switch',
            'compliance_frameworks': 'ISO27001,NIST-CSF,CIS',
            'rule_ids': rule_ids,
            'template_config': '''
! Platform Baseline Configuration for Cisco Switch
aaa new-model
ip ssh version 2
logging host <syslog-server>
'''
        }
    )
    
    if created:
        print(f"✓ Created baseline: {baseline.name} ({len(rule_ids)} rules)")
    else:
        baseline.rule_ids = rule_ids
        baseline.save()
        print(f"✓ Updated baseline: {baseline.name} ({len(rule_ids)} rules)")
    
    return baseline


def create_juniper_firewall_baseline():
    """Create Juniper firewall baseline"""
    juniper_rules = get_rules_by_vendor('juniper')
    iso_rules = get_rules_by_framework('ISO27001')
    nist_rules = get_rules_by_framework('NIST')
    pci_rules = get_rules_by_framework('PCI-DSS')
    
    all_rules = (juniper_rules | iso_rules | nist_rules | pci_rules).distinct()
    rule_ids = list(all_rules.values_list('id', flat=True))
    
    baseline, created = BaselineConfiguration.objects.get_or_create(
        name='Juniper Firewall Baseline',
        organization=None,
        defaults={
            'description': 'Baseline configuration for Juniper firewalls based on ISO 27001, NIST, and PCI-DSS standards',
            'vendor': 'juniper',
            'device_type': 'firewall',
            'compliance_frameworks': 'ISO27001,NIST-CSF,PCI-DSS',
            'rule_ids': rule_ids,
            'template_config': '''
# Platform Baseline Configuration for Juniper Firewall
set system root-authentication encrypted-password "<password>"
set system services ssh
set security policies default-policy deny-all
set system syslog host <syslog-server>
'''
        }
    )
    
    if created:
        print(f"✓ Created baseline: {baseline.name} ({len(rule_ids)} rules)")
    else:
        baseline.rule_ids = rule_ids
        baseline.save()
        print(f"✓ Updated baseline: {baseline.name} ({len(rule_ids)} rules)")
    
    return baseline


def create_fortinet_firewall_baseline():
    """Create Fortinet firewall baseline"""
    fortinet_rules = get_rules_by_vendor('fortinet')
    iso_rules = get_rules_by_framework('ISO27001')
    nist_rules = get_rules_by_framework('NIST')
    pci_rules = get_rules_by_framework('PCI-DSS')
    cis_rules = get_rules_by_framework('CIS')
    
    all_rules = (fortinet_rules | iso_rules | nist_rules | pci_rules | cis_rules).distinct()
    rule_ids = list(all_rules.values_list('id', flat=True))
    
    baseline, created = BaselineConfiguration.objects.get_or_create(
        name='Fortinet Firewall Baseline',
        organization=None,
        defaults={
            'description': 'Baseline configuration for Fortinet firewalls based on ISO 27001, NIST, PCI-DSS, and CIS standards',
            'vendor': 'fortinet',
            'device_type': 'firewall',
            'compliance_frameworks': 'ISO27001,NIST-CSF,PCI-DSS,CIS',
            'rule_ids': rule_ids,
            'template_config': '''
# MMBL Baseline Configuration for Fortinet Firewall
config system admin
    edit admin
        set password <strong-password>
    next
end
config firewall policy
    edit 1
        set name "MMBL-Default-Deny"
        set action deny
    next
end
config log setting
    set status enable
end
'''
        }
    )
    
    if created:
        print(f"✓ Created baseline: {baseline.name} ({len(rule_ids)} rules)")
    else:
        baseline.rule_ids = rule_ids
        baseline.save()
        print(f"✓ Updated baseline: {baseline.name} ({len(rule_ids)} rules)")
    
    return baseline


def create_huawei_router_baseline():
    """Create Huawei router baseline"""
    huawei_rules = get_rules_by_vendor('huawei')
    iso_rules = get_rules_by_framework('ISO27001')
    nist_rules = get_rules_by_framework('NIST')
    
    all_rules = (huawei_rules | iso_rules | nist_rules).distinct()
    rule_ids = list(all_rules.values_list('id', flat=True))
    
    baseline, created = BaselineConfiguration.objects.get_or_create(
        name='Huawei Router Baseline',
        organization=None,
        defaults={
            'description': 'Baseline configuration for Huawei routers based on ISO 27001 and NIST standards',
            'vendor': 'huawei',
            'device_type': 'router',
            'compliance_frameworks': 'ISO27001,NIST-CSF',
            'rule_ids': rule_ids,
            'template_config': '''
# Platform Baseline Configuration for Huawei Router
sysname <hostname>
aaa authentication-scheme default
local-user admin password cipher <password>
ssh server enable
info-center enable
info-center loghost <syslog-server>
'''
        }
    )
    
    if created:
        print(f"✓ Created baseline: {baseline.name} ({len(rule_ids)} rules)")
    else:
        baseline.rule_ids = rule_ids
        baseline.save()
        print(f"✓ Updated baseline: {baseline.name} ({len(rule_ids)} rules)")
    
    return baseline


def create_sophos_firewall_baseline():
    """Create Sophos firewall baseline"""
    sophos_rules = get_rules_by_vendor('sophos')
    iso_rules = get_rules_by_framework('ISO27001')
    nist_rules = get_rules_by_framework('NIST')
    
    all_rules = (sophos_rules | iso_rules | nist_rules).distinct()
    rule_ids = list(all_rules.values_list('id', flat=True))
    
    baseline, created = BaselineConfiguration.objects.get_or_create(
        name='Sophos Firewall Baseline',
        organization=None,
        defaults={
            'description': 'Baseline configuration for Sophos firewalls based on ISO 27001 and NIST standards',
            'vendor': 'sophos',
            'device_type': 'firewall',
            'compliance_frameworks': 'ISO27001,NIST-CSF',
            'rule_ids': rule_ids,
            'template_config': '''
# Platform Baseline Configuration for Sophos Firewall
hostname: <hostname>
admin user: <username>
firewall rules:
  rule default-deny:
    action: drop
logging enabled: true
syslog server: <syslog-server>
'''
        }
    )
    
    if created:
        print(f"✓ Created baseline: {baseline.name} ({len(rule_ids)} rules)")
    else:
        baseline.rule_ids = rule_ids
        baseline.save()
        print(f"✓ Updated baseline: {baseline.name} ({len(rule_ids)} rules)")
    
    return baseline


def main():
    """Create all platform baselines (visible to all organizations)"""
    print("Creating platform baseline configurations...")
    print("=" * 60)
    
    baselines = []
    
    try:
        baselines.append(create_cisco_router_baseline())
        baselines.append(create_cisco_switch_baseline())
        baselines.append(create_juniper_firewall_baseline())
        baselines.append(create_fortinet_firewall_baseline())
        baselines.append(create_huawei_router_baseline())
        baselines.append(create_sophos_firewall_baseline())
        
        print("=" * 60)
        print(f"\n✓ Successfully created/updated {len(baselines)} baseline configurations")
        print("\nBaselines created:")
        for baseline in baselines:
            print(f"  - {baseline.name} ({baseline.get_rule_count()} rules)")
        
    except Exception as e:
        print(f"\n✗ Error creating baselines: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Populate comprehensive security rules for all network device vendors
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from models.rule import Rule

def check_rule_exists(name):
    """Check if a rule with the given name already exists"""
    all_rules = Rule.get_all(enabled_only=False)
    return any(rule['name'] == name for rule in all_rules)

def create_rule(rule_data, skip_existing=True):
    """Create a rule if it doesn't exist"""
    name = rule_data['name']
    
    if skip_existing and check_rule_exists(name):
        return None, 'exists'
    
    try:
        rule_id = Rule.create(
            name=rule_data['name'],
            description=rule_data.get('description', ''),
            rule_type=rule_data.get('rule_type', 'pattern'),
            category=rule_data.get('category', 'Network Security'),
            severity=rule_data.get('severity', 'medium'),
            yaml_content=rule_data.get('yaml_content', ''),
            tags=rule_data.get('tags', []),
            remediation_template=rule_data.get('remediation_template', ''),
            compliance_frameworks=rule_data.get('compliance_frameworks', ''),
            risk_weight=rule_data.get('risk_weight', 1.0)
        )
        return rule_id, 'created'
    except Exception as e:
        return None, f'error: {str(e)}'

def get_all_rules():
    """Get all rule definitions organized by vendor"""
    all_rules = []
    
    # Add all rule sets
    all_rules.extend(get_cisco_rules())
    all_rules.extend(get_juniper_rules())
    all_rules.extend(get_arista_rules())
    all_rules.extend(get_paloalto_rules())
    all_rules.extend(get_fortinet_rules())
    all_rules.extend(get_huawei_rules())
    all_rules.extend(get_sophos_rules())
    all_rules.extend(get_checkpoint_rules())
    all_rules.extend(get_generic_rules())
    
    return all_rules

def get_cisco_rules():
    """Cisco IOS/IOS-XE/NX-OS/ASA security rules"""
    rules = []
    
    # Authentication & Authorization Rules
    rules.extend([
        {
            'name': 'Cisco - Enable AAA New Model',
            'description': 'CIS 1.2: AAA new model must be enabled for centralized authentication',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'aaa\\s+new-model'\nmessage: 'AAA new model should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: aaa new-model',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure AAA Authentication Login',
            'description': 'CIS 1.3: AAA authentication login must be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'aaa\\s+authentication\\s+login'\nmessage: 'AAA authentication login should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis'],
            'remediation_template': 'Configure: aaa authentication login default group tacacs+ local',
            'compliance_frameworks': 'CIS'
        },
        {
            'name': 'Cisco - Configure AAA Authorization',
            'description': 'CIS 1.4: AAA authorization should be configured for command execution',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'aaa\\s+authorization\\s+(exec|commands|config-commands)'\nmessage: 'AAA authorization should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis'],
            'remediation_template': 'Configure: aaa authorization exec default group tacacs+ local',
            'compliance_frameworks': 'CIS'
        },
        {
            'name': 'Cisco - Configure AAA Accounting',
            'description': 'CIS 1.5: AAA accounting should be enabled for audit trail',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'aaa\\s+accounting\\s+(exec|commands|system)'\nmessage: 'AAA accounting should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: aaa accounting exec default start-stop group tacacs+',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Disable Default Username',
            'description': 'Default usernames should be removed or disabled',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'critical',
            'yaml_content': "pattern: 'username\\s+(admin|cisco|root)\\s+password'\nmessage: 'Default usernames should not be used'\n",
            'tags': ['cisco', 'all', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Remove default usernames and create unique user accounts',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Cisco - Enable Local User Password Encryption',
            'description': 'Local user passwords should be encrypted',
            'rule_type': 'pattern',
            'category': 'Password Policy',
            'severity': 'high',
            'yaml_content': "pattern: 'username\\s+\\w+\\s+(secret|password)\\s+7\\s+'\nmessage: 'User passwords should use type 7 encryption (or better, use secret with type 5)'\n",
            'tags': ['cisco', 'all', 'cis'],
            'remediation_template': 'Use: username <name> secret <password> (type 5 encryption)',
            'compliance_frameworks': 'CIS'
        },
    ])
    
    # Encryption Rules
    rules.extend([
        {
            'name': 'Cisco - Enable SSH Version 2',
            'description': 'CIS 2.1: SSH version 2 should be enabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+ssh\\s+version\\s+2'\nmessage: 'SSH version 2 should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ip ssh version 2',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Disable Telnet',
            'description': 'CIS 2.2: Telnet should be disabled in favor of SSH',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'no\\s+ip\\s+telnet'\nmessage: 'Telnet should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: transport input ssh (on line vty)',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure SSH Timeout',
            'description': 'SSH idle timeout should be configured',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+ssh\\s+time-out'\nmessage: 'SSH timeout should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip ssh time-out 60',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure SSH Authentication Retries',
            'description': 'SSH authentication retry limit should be configured',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+ssh\\s+authentication-retries'\nmessage: 'SSH authentication retries should be limited'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip ssh authentication-retries 3',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Enable HTTPS Server',
            'description': 'HTTPS should be enabled for secure web management',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+http\\s+secure-server'\nmessage: 'HTTPS server should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip http secure-server',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable HTTP Server',
            'description': 'CIS 2.3: Insecure HTTP server should be disabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'no\\s+ip\\s+http\\s+server'\nmessage: 'HTTP server should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: no ip http server',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Management Plane Security
    rules.extend([
        {
            'name': 'Cisco - Configure VTY Access Control',
            'description': 'CIS 3.1: VTY lines should have access control configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'line\\s+vty\\s+\\d+\\s+\\d+'\nmessage: 'VTY lines should be configured with access control'\n",
            'tags': ['cisco', 'router', 'switch', 'cis'],
            'remediation_template': 'Configure: line vty 0 4, then: access-class <acl> in, transport input ssh',
            'compliance_frameworks': 'CIS'
        },
        {
            'name': 'Cisco - Configure VTY Timeout',
            'description': 'VTY session timeout should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'medium',
            'yaml_content': "pattern: 'line\\s+vty.*exec-timeout'\nmessage: 'VTY exec-timeout should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: exec-timeout 10 0',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable SNMP Community Strings',
            'description': 'CIS 3.2: Default SNMP community strings should be removed',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'critical',
            'yaml_content': "pattern: 'snmp-server\\s+community\\s+(public|private)\\s+RO'\nmessage: 'Default SNMP community strings (public/private) should not be used'\n",
            'tags': ['cisco', 'all', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Remove default SNMP communities and use SNMPv3 with authentication',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Cisco - Enable SNMPv3',
            'description': 'SNMPv3 with authentication should be used',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'snmp-server\\s+user\\s+\\w+\\s+\\w+\\s+v3'\nmessage: 'SNMPv3 should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: snmp-server user <user> <group> v3 auth sha <password>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Console Timeout',
            'description': 'Console session timeout should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'low',
            'yaml_content': "pattern: 'line\\s+con.*exec-timeout'\nmessage: 'Console exec-timeout should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: exec-timeout 10 0',
            'compliance_frameworks': ''
        },
    ])
    
    # Logging Rules
    rules.extend([
        {
            'name': 'Cisco - Configure Syslog Server',
            'description': 'CIS 4.1: Syslog server should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'logging\\s+host'\nmessage: 'Syslog server should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: logging host <ip-address>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Enable Logging Timestamps',
            'description': 'Logging timestamps should be enabled',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'medium',
            'yaml_content': "pattern: 'service\\s+timestamps\\s+log'\nmessage: 'Logging timestamps should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: service timestamps log datetime localtime',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Logging Trap Level',
            'description': 'Logging trap level should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'medium',
            'yaml_content': "pattern: 'logging\\s+trap'\nmessage: 'Logging trap level should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: logging trap informational',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Access Control Lists
    rules.extend([
        {
            'name': 'Cisco - Restrict Management Access with ACL',
            'description': 'Management access should be restricted using ACLs',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'high',
            'yaml_content': "pattern: 'access-class\\s+\\d+\\s+in'\nmessage: 'Management access should be restricted with ACL'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: access-class <acl-number> in (on line vty)',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure Standard ACL',
            'description': 'Standard ACLs should be used for basic access control',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'medium',
            'yaml_content': "pattern: 'access-list\\s+\\d+\\s+(permit|deny)'\nmessage: 'Access control lists should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure appropriate ACLs for network access control',
            'compliance_frameworks': ''
        },
    ])
    
    # Service Hardening
    rules.extend([
        {
            'name': 'Cisco - Disable CDP',
            'description': 'CDP should be disabled if not needed',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+cdp\\s+run'\nmessage: 'CDP should be disabled if not needed'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no cdp run',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Disable LLDP',
            'description': 'LLDP should be disabled if not needed',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+lldp\\s+run'\nmessage: 'LLDP should be disabled if not needed'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no lldp run',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Disable IP Source Route',
            'description': 'IP source routing should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'high',
            'yaml_content': "pattern: 'no\\s+ip\\s+source-route'\nmessage: 'IP source routing should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: no ip source-route',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Disable IP Redirects',
            'description': 'IP redirects should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'no\\s+ip\\s+redirects'\nmessage: 'IP redirects should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: no ip redirects',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable IP Unreachables',
            'description': 'IP unreachable messages should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+unreachables'\nmessage: 'IP unreachable messages should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip unreachables',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Disable IP Proxy ARP',
            'description': 'IP proxy ARP should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'no\\s+ip\\s+proxy-arp'\nmessage: 'IP proxy ARP should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: no ip proxy-arp',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Banner Configuration
    rules.extend([
        {
            'name': 'Cisco - Configure Login Banner',
            'description': 'CIS 5.1: Login banner should be configured',
            'rule_type': 'pattern',
            'category': 'Banner',
            'severity': 'medium',
            'yaml_content': "pattern: 'banner\\s+login'\nmessage: 'Login banner should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis'],
            'remediation_template': 'Configure: banner login ^C<message>^C',
            'compliance_frameworks': 'CIS'
        },
        {
            'name': 'Cisco - Configure MOTD Banner',
            'description': 'Message of the day banner should be configured',
            'rule_type': 'pattern',
            'category': 'Banner',
            'severity': 'low',
            'yaml_content': "pattern: 'banner\\s+motd'\nmessage: 'MOTD banner should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: banner motd ^C<message>^C',
            'compliance_frameworks': ''
        },
    ])
    
    # Interface Security
    rules.extend([
        {
            'name': 'Cisco - Disable Unused Interfaces',
            'description': 'Unused interfaces should be administratively shut down',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'interface\\s+\\S+.*shutdown'\nmessage: 'Unused interfaces should be shut down'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: interface <name>, shutdown',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Port Security',
            'description': 'Port security should be enabled on access ports',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'high',
            'yaml_content': "pattern: 'switchport\\s+port-security'\nmessage: 'Port security should be enabled'\n",
            'tags': ['cisco', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: switchport port-security, switchport port-security maximum <num>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Routing Security
    rules.extend([
        {
            'name': 'Cisco - Configure BGP Authentication',
            'description': 'BGP sessions should use MD5 authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'neighbor\\s+\\S+\\s+password'\nmessage: 'BGP authentication should be configured'\n",
            'tags': ['cisco', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: neighbor <ip> password <password>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure OSPF Authentication',
            'description': 'OSPF should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+ospf\\s+authentication'\nmessage: 'OSPF authentication should be configured'\n",
            'tags': ['cisco', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: ip ospf authentication-key <key> or ip ospf message-digest-key',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure EIGRP Authentication',
            'description': 'EIGRP should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+authentication\\s+mode\\s+eigrp'\nmessage: 'EIGRP authentication should be configured'\n",
            'tags': ['cisco', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: ip authentication mode eigrp <as> md5',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Time Synchronization
    rules.extend([
        {
            'name': 'Cisco - Configure NTP Server',
            'description': 'CIS 6.1: NTP server should be configured',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'medium',
            'yaml_content': "pattern: 'ntp\\s+server'\nmessage: 'NTP server should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ntp server <ip-address>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure NTP Authentication',
            'description': 'NTP should use authentication',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'medium',
            'yaml_content': "pattern: 'ntp\\s+authenticate'\nmessage: 'NTP authentication should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ntp authenticate, ntp authentication-key <key> md5 <hash>',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # VLAN Security
    rules.extend([
        {
            'name': 'Cisco - Remove Default VLAN from Trunk',
            'description': 'Default VLAN (VLAN 1) should not be used on trunk ports',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'switchport\\s+trunk\\s+native\\s+vlan\\s+(?!1)\\d+'\nmessage: 'Native VLAN should not be VLAN 1'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: switchport trunk native vlan <vlan-id> (not 1)',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure VTP Mode',
            'description': 'VTP should be configured in transparent or off mode',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'vtp\\s+mode\\s+(transparent|off)'\nmessage: 'VTP should be in transparent or off mode'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: vtp mode transparent or vtp mode off',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # STP Security
    rules.extend([
        {
            'name': 'Cisco - Configure Root Guard',
            'description': 'Root guard should be enabled on access ports',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'spanning-tree\\s+guard\\s+root'\nmessage: 'Root guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: spanning-tree guard root',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure BPDU Guard',
            'description': 'BPDU guard should be enabled on access ports',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'spanning-tree\\s+bpduguard\\s+enable'\nmessage: 'BPDU guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: spanning-tree bpduguard enable',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # DHCP Security
    rules.extend([
        {
            'name': 'Cisco - Disable DHCP Server',
            'description': 'DHCP server should be disabled if not needed',
            'rule_type': 'pattern',
            'category': 'DHCP Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'no\\s+service\\s+dhcp'\nmessage: 'DHCP service should be disabled if not needed'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no service dhcp',
            'compliance_frameworks': ''
        },
    ])
    
    # ARP Security
    rules.extend([
        {
            'name': 'Cisco - Configure ARP Inspection',
            'description': 'Dynamic ARP inspection should be enabled',
            'rule_type': 'pattern',
            'category': 'ARP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+arp\\s+inspection'\nmessage: 'ARP inspection should be enabled'\n",
            'tags': ['cisco', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ip arp inspection vlan <vlan-range>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # IPv6 Security
    rules.extend([
        {
            'name': 'Cisco - Configure IPv6 Access Control',
            'description': 'IPv6 access control lists should be configured',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'ipv6\\s+access-list'\nmessage: 'IPv6 access control should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure IPv6 ACLs for access control',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable IPv6 Redirects',
            'description': 'IPv6 redirects should be disabled',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'no\\s+ipv6\\s+redirects'\nmessage: 'IPv6 redirects should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: no ipv6 redirects',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Cisco Authentication Rules
    rules.extend([
        {
            'name': 'Cisco - Configure Local User Privilege',
            'description': 'Local user privilege levels should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'username\\s+\\w+\\s+privilege'\nmessage: 'User privilege levels should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: username <name> privilege <level>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Enable Secret',
            'description': 'Enable secret should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'enable\\s+secret'\nmessage: 'Enable secret should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: enable secret <password>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure Line Password',
            'description': 'Line passwords should be configured if AAA is not used',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'line\\s+(vty|con|aux).*password'\nmessage: 'Line passwords should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: password <password> (prefer AAA instead)',
            'compliance_frameworks': ''
        },
    ])
    
    # Additional Cisco Encryption Rules
    rules.extend([
        {
            'name': 'Cisco - Configure SSH Key',
            'description': 'SSH RSA keys should be configured',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'crypto\\s+key\\s+generate\\s+rsa'\nmessage: 'SSH RSA keys should be generated'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: crypto key generate rsa modulus 2048',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IPsec VPN',
            'description': 'IPsec VPN should be configured with strong encryption',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'crypto\\s+ipsec\\s+transform-set'\nmessage: 'IPsec VPN should be configured'\n",
            'tags': ['cisco', 'router', 'firewall', 'nist'],
            'remediation_template': 'Configure: crypto ipsec transform-set <name> esp-aes 256 esp-sha-hmac',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure SSL/TLS Certificate',
            'description': 'SSL/TLS certificates should be configured for HTTPS',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'crypto\\s+pki\\s+certificate'\nmessage: 'SSL/TLS certificates should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure PKI certificates for HTTPS',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Cisco Management Rules
    rules.extend([
        {
            'name': 'Cisco - Configure SNMP Access Control',
            'description': 'SNMP access should be restricted with ACLs',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'snmp-server\\s+community\\s+\\w+\\s+RO\\s+\\d+'\nmessage: 'SNMP access should be restricted with ACL'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: snmp-server community <name> RO <acl-number>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable SNMP if Not Used',
            'description': 'SNMP should be disabled if not needed',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'medium',
            'yaml_content': "pattern: 'no\\s+snmp-server'\nmessage: 'SNMP should be disabled if not needed'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no snmp-server (if SNMP is not needed)',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure Management Interface ACL',
            'description': 'Management interface should have ACL applied',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'interface\\s+\\S+.*ip\\s+access-group'\nmessage: 'Management interface should have ACL'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip access-group <acl> in (on management interface)',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Cisco Logging Rules
    rules.extend([
        {
            'name': 'Cisco - Configure Logging Source Interface',
            'description': 'Logging source interface should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'medium',
            'yaml_content': "pattern: 'logging\\s+source-interface'\nmessage: 'Logging source interface should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: logging source-interface <interface>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Enable Logging Buffered',
            'description': 'Buffered logging should be enabled',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'low',
            'yaml_content': "pattern: 'logging\\s+buffered'\nmessage: 'Buffered logging should be enabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: logging buffered <size>',
            'compliance_frameworks': ''
        },
    ])
    
    # Additional Cisco Access Control Rules
    rules.extend([
        {
            'name': 'Cisco - Configure Extended ACL',
            'description': 'Extended ACLs should be used for granular control',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+access-list\\s+extended'\nmessage: 'Extended ACLs should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure extended ACLs for detailed access control',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure Named ACL',
            'description': 'Named ACLs should be used for better management',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+access-list\\s+(standard|extended)\\s+\\w+'\nmessage: 'Named ACLs should be used'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Use named ACLs instead of numbered ACLs',
            'compliance_frameworks': ''
        },
    ])
    
    # Additional Cisco Service Hardening Rules
    rules.extend([
        {
            'name': 'Cisco - Disable Finger Service',
            'description': 'Finger service should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+service\\s+finger'\nmessage: 'Finger service should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no service finger',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Disable PAD Service',
            'description': 'PAD service should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+service\\s+pad'\nmessage: 'PAD service should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no service pad',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Disable Small Servers',
            'description': 'Small servers (echo, discard) should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+service\\s+(tcp-small-servers|udp-small-servers)'\nmessage: 'Small servers should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no service tcp-small-servers, no service udp-small-servers',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Enable TCP Keepalives',
            'description': 'TCP keepalives should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'service\\s+tcp-keepalives'\nmessage: 'TCP keepalives should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: service tcp-keepalives-in, service tcp-keepalives-out',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable IP Bootp Server',
            'description': 'IP BOOTP server should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+bootp\\s+server'\nmessage: 'BOOTP server should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip bootp server',
            'compliance_frameworks': ''
        },
    ])
    
    # Additional Cisco Interface Security Rules
    rules.extend([
        {
            'name': 'Cisco - Configure Interface Description',
            'description': 'Interfaces should have descriptions',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'low',
            'yaml_content': "pattern: 'interface\\s+\\S+.*description'\nmessage: 'Interfaces should have descriptions'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: description <text>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure Port Security Violation',
            'description': 'Port security violation action should be configured',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'switchport\\s+port-security\\s+violation'\nmessage: 'Port security violation action should be configured'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: switchport port-security violation restrict',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Port Security Aging',
            'description': 'Port security aging should be configured',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'low',
            'yaml_content': "pattern: 'switchport\\s+port-security\\s+aging'\nmessage: 'Port security aging should be configured'\n",
            'tags': ['cisco', 'switch'],
            'remediation_template': 'Configure: switchport port-security aging time <minutes>',
            'compliance_frameworks': ''
        },
    ])
    
    # Additional Cisco Routing Security Rules
    rules.extend([
        {
            'name': 'Cisco - Configure BGP Neighbor Filter',
            'description': 'BGP neighbor filters should be configured',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'neighbor\\s+\\S+\\s+route-map'\nmessage: 'BGP route maps should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure: neighbor <ip> route-map <name> in/out',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure BGP Maximum Prefix',
            'description': 'BGP maximum prefix should be configured',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'neighbor\\s+\\S+\\s+maximum-prefix'\nmessage: 'BGP maximum prefix should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure: neighbor <ip> maximum-prefix <number>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Disable OSPF Redistribution',
            'description': 'OSPF redistribution should be controlled',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'router\\s+ospf.*redistribute'\nmessage: 'OSPF redistribution should be controlled'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Use route maps to control OSPF redistribution',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Cisco VLAN Security Rules
    rules.extend([
        {
            'name': 'Cisco - Configure VLAN Access Map',
            'description': 'VLAN access maps should be used for security',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'vlan\\s+access-map'\nmessage: 'VLAN access maps should be configured'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: vlan access-map <name> <sequence>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Private VLAN',
            'description': 'Private VLANs should be used for isolation',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'private-vlan'\nmessage: 'Private VLANs should be configured for isolation'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure private VLANs for network isolation',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Cisco STP Security Rules
    rules.extend([
        {
            'name': 'Cisco - Configure STP Portfast',
            'description': 'STP PortFast should be enabled on access ports',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'low',
            'yaml_content': "pattern: 'spanning-tree\\s+portfast'\nmessage: 'STP PortFast should be enabled on access ports'\n",
            'tags': ['cisco', 'switch'],
            'remediation_template': 'Configure: spanning-tree portfast (on access ports only)',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure STP Root Priority',
            'description': 'STP root priority should be configured',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'low',
            'yaml_content': "pattern: 'spanning-tree\\s+vlan\\s+\\d+\\s+priority'\nmessage: 'STP root priority should be configured'\n",
            'tags': ['cisco', 'switch'],
            'remediation_template': 'Configure: spanning-tree vlan <vlan> priority <priority>',
            'compliance_frameworks': ''
        },
    ])
    
    # Additional Cisco Time Synchronization Rules
    rules.extend([
        {
            'name': 'Cisco - Configure NTP Source',
            'description': 'NTP source interface should be configured',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'low',
            'yaml_content': "pattern: 'ntp\\s+source'\nmessage: 'NTP source interface should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ntp source <interface>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure NTP Access Group',
            'description': 'NTP access should be restricted',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'medium',
            'yaml_content': "pattern: 'ntp\\s+access-group'\nmessage: 'NTP access should be restricted'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ntp access-group peer <acl>',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Cisco Rules - More comprehensive coverage
    rules.extend([
        {
            'name': 'Cisco - Configure Service Password Encryption',
            'description': 'Service password encryption should be enabled',
            'rule_type': 'pattern',
            'category': 'Password Policy',
            'severity': 'high',
            'yaml_content': "pattern: 'service\\s+password-encryption'\nmessage: 'Service password encryption should be enabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: service password-encryption',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure Minimum Password Length',
            'description': 'Minimum password length should be configured',
            'rule_type': 'pattern',
            'category': 'Password Policy',
            'severity': 'high',
            'yaml_content': "pattern: 'security\\s+passwords\\s+min-length'\nmessage: 'Minimum password length should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure: security passwords min-length 12',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Cisco - Configure Password History',
            'description': 'Password history should be configured',
            'rule_type': 'pattern',
            'category': 'Password Policy',
            'severity': 'medium',
            'yaml_content': "pattern: 'security\\s+passwords\\s+history'\nmessage: 'Password history should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist', 'pci-dss'],
            'remediation_template': 'Configure: security passwords history 5',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
        {
            'name': 'Cisco - Configure Login Delay',
            'description': 'Login delay should be configured to prevent brute force',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'login\\s+delay'\nmessage: 'Login delay should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: login delay 1',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Login Block',
            'description': 'Login block should be configured for failed attempts',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'login\\s+block-for'\nmessage: 'Login block should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist', 'pci-dss'],
            'remediation_template': 'Configure: login block-for 60 attempts 3 within 60',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
        {
            'name': 'Cisco - Configure SSH RSA Key Size',
            'description': 'SSH RSA key size should be 2048 bits or larger',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'crypto\\s+key\\s+generate\\s+rsa\\s+modulus\\s+(2048|4096)'\nmessage: 'SSH RSA key should be 2048 bits or larger'\n",
            'tags': ['cisco', 'router', 'switch', 'nist', 'pci-dss'],
            'remediation_template': 'Configure: crypto key generate rsa modulus 2048',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
        {
            'name': 'Cisco - Configure SSH Cipher',
            'description': 'SSH should use strong ciphers',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+ssh\\s+cipher'\nmessage: 'SSH ciphers should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip ssh cipher aes128-ctr aes192-ctr aes256-ctr',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure SSH MAC',
            'description': 'SSH MAC algorithms should be configured',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+ssh\\s+mac'\nmessage: 'SSH MAC algorithms should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip ssh mac hmac-sha1 hmac-sha256',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IPsec IKE Policy',
            'description': 'IPsec IKE policy should use strong encryption',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'crypto\\s+isakmp\\s+policy'\nmessage: 'IPsec IKE policy should be configured'\n",
            'tags': ['cisco', 'router', 'firewall', 'nist'],
            'remediation_template': 'Configure: crypto isakmp policy with encryption aes 256',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IPsec Transform Set',
            'description': 'IPsec transform set should use strong encryption',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'crypto\\s+ipsec\\s+transform-set.*esp-aes'\nmessage: 'IPsec transform set should use AES encryption'\n",
            'tags': ['cisco', 'router', 'firewall', 'nist'],
            'remediation_template': 'Configure: crypto ipsec transform-set <name> esp-aes 256 esp-sha-hmac',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Control Plane Policing',
            'description': 'Control plane policing should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'policy-map\\s+control-plane'\nmessage: 'Control plane policing should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure control plane policing to protect management plane',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure Storm Control',
            'description': 'Storm control should be enabled on switch ports',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'storm-control'\nmessage: 'Storm control should be configured'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: storm-control broadcast level <percentage>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure DHCP Snooping',
            'description': 'DHCP snooping should be enabled',
            'rule_type': 'pattern',
            'category': 'DHCP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+dhcp\\s+snooping'\nmessage: 'DHCP snooping should be enabled'\n",
            'tags': ['cisco', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ip dhcp snooping, ip dhcp snooping vlan <vlan-range>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure IP Source Guard',
            'description': 'IP source guard should be enabled',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+verify\\s+source'\nmessage: 'IP source guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ip verify source',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure Unicast RPF',
            'description': 'Unicast RPF should be enabled where appropriate',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+verify\\s+unicast\\s+source\\s+reachable-via'\nmessage: 'Unicast RPF should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip verify unicast source reachable-via rx',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure BGP Maximum AS Path',
            'description': 'BGP maximum AS path should be configured',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'neighbor\\s+\\S+\\s+maximum-as-limit'\nmessage: 'BGP maximum AS path should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure: neighbor <ip> maximum-as-limit <number>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure BGP TTL Security',
            'description': 'BGP TTL security should be configured',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'neighbor\\s+\\S+\\s+ttl-security'\nmessage: 'BGP TTL security should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure: neighbor <ip> ttl-security hops <hops>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure OSPF Passive Interface',
            'description': 'OSPF passive interfaces should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'low',
            'yaml_content': "pattern: 'passive-interface'\nmessage: 'OSPF passive interfaces should be configured'\n",
            'tags': ['cisco', 'router'],
            'remediation_template': 'Configure: passive-interface <interface> (for interfaces that should not form adjacencies)',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure EIGRP Passive Interface',
            'description': 'EIGRP passive interfaces should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'low',
            'yaml_content': "pattern: 'passive-interface'\nmessage: 'EIGRP passive interfaces should be configured'\n",
            'tags': ['cisco', 'router'],
            'remediation_template': 'Configure: passive-interface <interface>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure VTP Password',
            'description': 'VTP password should be configured if VTP is used',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'vtp\\s+password'\nmessage: 'VTP password should be configured'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: vtp password <password> (or use VTP transparent/off mode)',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure STP Loop Guard',
            'description': 'STP loop guard should be enabled',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'spanning-tree\\s+guard\\s+loop'\nmessage: 'STP loop guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: spanning-tree guard loop',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure STP Uplink Fast',
            'description': 'STP UplinkFast should be enabled on access switches',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'low',
            'yaml_content': "pattern: 'spanning-tree\\s+uplinkfast'\nmessage: 'STP UplinkFast should be enabled'\n",
            'tags': ['cisco', 'switch'],
            'remediation_template': 'Configure: spanning-tree uplinkfast',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure STP Backbone Fast',
            'description': 'STP BackboneFast should be enabled',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'low',
            'yaml_content': "pattern: 'spanning-tree\\s+backbonefast'\nmessage: 'STP BackboneFast should be enabled'\n",
            'tags': ['cisco', 'switch'],
            'remediation_template': 'Configure: spanning-tree backbonefast',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure ARP Timeout',
            'description': 'ARP timeout should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'ARP Security',
            'severity': 'low',
            'yaml_content': "pattern: 'arp\\s+timeout'\nmessage: 'ARP timeout should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: arp timeout <seconds>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IPv6 RA Guard',
            'description': 'IPv6 RA guard should be enabled',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ipv6\\s+nd\\s+raguard'\nmessage: 'IPv6 RA guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: ipv6 nd raguard (on access ports)',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IPv6 DHCP Guard',
            'description': 'IPv6 DHCP guard should be enabled',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ipv6\\s+dhcp\\s+guard'\nmessage: 'IPv6 DHCP guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: ipv6 dhcp guard (on access ports)',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IPv6 Source Guard',
            'description': 'IPv6 source guard should be enabled',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ipv6\\s+verify\\s+source'\nmessage: 'IPv6 source guard should be enabled'\n",
            'tags': ['cisco', 'switch', 'nist'],
            'remediation_template': 'Configure: ipv6 verify source',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure DNS Server',
            'description': 'DNS server should be configured',
            'rule_type': 'pattern',
            'category': 'DNS Security',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+name-server'\nmessage: 'DNS server should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip name-server <ip-address>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Disable IP Domain Lookup',
            'description': 'IP domain lookup should be disabled to prevent DNS queries',
            'rule_type': 'pattern',
            'category': 'DNS Security',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+domain-lookup'\nmessage: 'IP domain lookup should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip domain-lookup',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure Banner Exec',
            'description': 'Exec banner should be configured',
            'rule_type': 'pattern',
            'category': 'Banner',
            'severity': 'low',
            'yaml_content': "pattern: 'banner\\s+exec'\nmessage: 'Exec banner should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: banner exec ^C<message>^C',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure Banner Incoming',
            'description': 'Incoming banner should be configured',
            'rule_type': 'pattern',
            'category': 'Banner',
            'severity': 'low',
            'yaml_content': "pattern: 'banner\\s+incoming'\nmessage: 'Incoming banner should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: banner incoming ^C<message>^C',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure Banner MOTD',
            'description': 'MOTD banner should be configured',
            'rule_type': 'pattern',
            'category': 'Banner',
            'severity': 'low',
            'yaml_content': "pattern: 'banner\\s+motd'\nmessage: 'MOTD banner should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: banner motd ^C<message>^C',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP Directed Broadcast',
            'description': 'IP directed broadcast should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'high',
            'yaml_content': "pattern: 'no\\s+ip\\s+directed-broadcast'\nmessage: 'IP directed broadcast should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: no ip directed-broadcast',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Cisco - Configure IP Mask Reply',
            'description': 'IP mask reply should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+mask-reply'\nmessage: 'IP mask reply should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip mask-reply',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP ICMP Redirect',
            'description': 'ICMP redirects should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'no\\s+ip\\s+redirects'\nmessage: 'ICMP redirects should be disabled'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: no ip redirects',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IP ICMP Unreachable',
            'description': 'ICMP unreachable messages should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+unreachables'\nmessage: 'ICMP unreachable messages should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip unreachables',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP ICMP Mask Reply',
            'description': 'ICMP mask reply should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+icmp\\s+mask-reply'\nmessage: 'ICMP mask reply should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip icmp mask-reply',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP ICMP Time Exceeded',
            'description': 'ICMP time exceeded messages should be controlled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+icmp\\s+time-exceeded'\nmessage: 'ICMP time exceeded should be controlled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip icmp time-exceeded (if not needed)',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP Fragmentation',
            'description': 'IP fragmentation should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+fragmentation'\nmessage: 'IP fragmentation should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure appropriate IP fragmentation settings',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TTL',
            'description': 'IP TTL should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+ttl'\nmessage: 'IP TTL should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip ttl <value>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP Options Drop',
            'description': 'IP options should be dropped',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+options\\s+drop'\nmessage: 'IP options should be dropped'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip options drop',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IP TCP Intercept',
            'description': 'TCP intercept should be configured for SYN flood protection',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+intercept'\nmessage: 'TCP intercept should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure: ip tcp intercept mode intercept',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IP TCP Window Scaling',
            'description': 'TCP window scaling should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+window-size'\nmessage: 'TCP window scaling should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp window-size <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP Selective ACK',
            'description': 'TCP selective ACK should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+selective-ack'\nmessage: 'TCP selective ACK should be enabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp selective-ack',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP Timestamps',
            'description': 'TCP timestamps should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+timestamp'\nmessage: 'TCP timestamps should be enabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp timestamp',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP Path MTU Discovery',
            'description': 'TCP path MTU discovery should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+path-mtu-discovery'\nmessage: 'TCP path MTU discovery should be enabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp path-mtu-discovery',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP Synwait Time',
            'description': 'TCP SYN wait time should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+synwait-time'\nmessage: 'TCP SYN wait time should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp synwait-time <seconds>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP Keepalive',
            'description': 'TCP keepalive should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+keepalive'\nmessage: 'TCP keepalive should be configured'\n",
            'tags': ['cisco', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: ip tcp keepalive <seconds>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IP TCP Compression',
            'description': 'TCP compression should be disabled if not needed',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+tcp\\s+compression'\nmessage: 'TCP compression should be disabled if not needed'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip tcp compression',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP DF Bit',
            'description': 'TCP DF bit should be set',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+df-bit'\nmessage: 'TCP DF bit should be set'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp df-bit',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP MSS',
            'description': 'TCP MSS should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+tcp\\s+mss'\nmessage: 'TCP MSS should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip tcp mss <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Small Servers',
            'description': 'UDP small servers should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+service\\s+udp-small-servers'\nmessage: 'UDP small servers should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no service udp-small-servers',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP TCP Small Servers',
            'description': 'TCP small servers should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+service\\s+tcp-small-servers'\nmessage: 'TCP small servers should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no service tcp-small-servers',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Flood',
            'description': 'UDP flood protection should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+udp\\s+flood'\nmessage: 'UDP flood protection should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure UDP flood protection',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IP UDP Max Packets',
            'description': 'UDP max packets should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+max-packets'\nmessage: 'UDP max packets should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp max-packets <number>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Checksum',
            'description': 'UDP checksum should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+checksum'\nmessage: 'UDP checksum should be enabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp checksum',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Port',
            'description': 'UDP port configuration should be reviewed',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+port'\nmessage: 'UDP port configuration should be reviewed'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Review and configure UDP ports appropriately',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Timeout',
            'description': 'UDP timeout should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+timeout'\nmessage: 'UDP timeout should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp timeout <seconds>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Queue Limit',
            'description': 'UDP queue limit should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+queue-limit'\nmessage: 'UDP queue limit should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp queue-limit <number>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Buffer Size',
            'description': 'UDP buffer size should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+buffer-size'\nmessage: 'UDP buffer size should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp buffer-size <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Max Reassembly',
            'description': 'UDP max reassembly should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+max-reassembly'\nmessage: 'UDP max reassembly should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp max-reassembly <number>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Reassembly Timeout',
            'description': 'UDP reassembly timeout should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+reassembly-timeout'\nmessage: 'UDP reassembly timeout should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp reassembly-timeout <seconds>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Fragment',
            'description': 'UDP fragment handling should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+fragment'\nmessage: 'UDP fragment handling should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp fragment <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP TTL',
            'description': 'UDP TTL should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+ttl'\nmessage: 'UDP TTL should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp ttl <value>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP TOS',
            'description': 'UDP TOS should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+tos'\nmessage: 'UDP TOS should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp tos <value>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Precedence',
            'description': 'UDP precedence should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+precedence'\nmessage: 'UDP precedence should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp precedence <value>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP DSCP',
            'description': 'UDP DSCP should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+dscp'\nmessage: 'UDP DSCP should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp dscp <value>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Flow',
            'description': 'UDP flow control should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+flow'\nmessage: 'UDP flow control should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp flow <value>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Rate Limit',
            'description': 'UDP rate limiting should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: 'ip\\s+udp\\s+rate-limit'\nmessage: 'UDP rate limiting should be configured'\n",
            'tags': ['cisco', 'router', 'nist'],
            'remediation_template': 'Configure: ip udp rate-limit <rate>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Cisco - Configure IP UDP Queue',
            'description': 'UDP queue should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+queue'\nmessage: 'UDP queue should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp queue <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Buffer',
            'description': 'UDP buffer should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+buffer'\nmessage: 'UDP buffer should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp buffer <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Memory',
            'description': 'UDP memory should be configured',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+memory'\nmessage: 'UDP memory should be configured'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp memory <size>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Statistics',
            'description': 'UDP statistics should be enabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'ip\\s+udp\\s+statistics'\nmessage: 'UDP statistics should be enabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: ip udp statistics',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Debug',
            'description': 'UDP debug should be disabled in production',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+udp\\s+debug'\nmessage: 'UDP debug should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip udp debug',
            'compliance_frameworks': ''
        },
        {
            'name': 'Cisco - Configure IP UDP Trace',
            'description': 'UDP trace should be disabled in production',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'low',
            'yaml_content': "pattern: 'no\\s+ip\\s+udp\\s+trace'\nmessage: 'UDP trace should be disabled'\n",
            'tags': ['cisco', 'router', 'switch'],
            'remediation_template': 'Configure: no ip udp trace',
            'compliance_frameworks': ''
        },
    ])
    
    return rules

def get_juniper_rules():
    """Juniper JunOS/ScreenOS security rules"""
    rules = []
    
    # Authentication & Authorization
    rules.extend([
        {
            'name': 'Juniper - Configure Root Authentication',
            'description': 'Root authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+root-authentication'\nmessage: 'Root authentication should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system root-authentication encrypted-password',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure User Accounts',
            'description': 'User accounts should be configured with authentication',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+login\\s+user\\s+\\w+\\s+(class|uid|authentication)'\nmessage: 'User accounts should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis'],
            'remediation_template': 'Configure: set system login user <name> class <class> authentication encrypted-password',
            'compliance_frameworks': 'CIS'
        },
        {
            'name': 'Juniper - Configure RADIUS Authentication',
            'description': 'RADIUS authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+radius-server'\nmessage: 'RADIUS authentication should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system radius-server <ip> secret <secret>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure TACACS+ Authentication',
            'description': 'TACACS+ authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+tacplus-server'\nmessage: 'TACACS+ authentication should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system tacplus-server <ip> secret <secret>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Encryption
    rules.extend([
        {
            'name': 'Juniper - Enable SSH',
            'description': 'SSH should be enabled for secure management',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+services\\s+ssh'\nmessage: 'SSH service should be enabled'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system services ssh',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Disable Telnet',
            'description': 'Telnet should be disabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'delete\\s+system\\s+services\\s+telnet'\nmessage: 'Telnet service should be disabled'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: delete system services telnet',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure SSH Root Login',
            'description': 'Root login via SSH should be disabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+services\\s+ssh\\s+root-login\\s+deny'\nmessage: 'Root login via SSH should be denied'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system services ssh root-login deny',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Management Plane
    rules.extend([
        {
            'name': 'Juniper - Configure SNMP Community',
            'description': 'SNMP community strings should be configured securely',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+snmp\\s+community\\s+\\w+\\s+authorization'\nmessage: 'SNMP communities should be configured with authorization'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set snmp community <name> authorization read-only',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure SNMPv3',
            'description': 'SNMPv3 should be used for secure management',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+snmp\\s+v3\\s+usm'\nmessage: 'SNMPv3 should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set snmp v3 usm local-engine user <user> authentication-md5',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Logging
    rules.extend([
        {
            'name': 'Juniper - Configure Syslog Server',
            'description': 'Syslog server should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+syslog\\s+host'\nmessage: 'Syslog server should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system syslog host <ip> any info',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Enable System Logging',
            'description': 'System logging should be enabled',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+system\\s+syslog\\s+file'\nmessage: 'System logging should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set system syslog file <file> any info',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Firewall Rules
    rules.extend([
        {
            'name': 'Juniper - Configure Firewall Filter',
            'description': 'Firewall filters should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+firewall\\s+filter'\nmessage: 'Firewall filters should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure appropriate firewall filters',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure Security Policies',
            'description': 'Security policies should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+policies'\nmessage: 'Security policies should be configured'\n",
            'tags': ['juniper', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure security policies for traffic control',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Routing Security
    rules.extend([
        {
            'name': 'Juniper - Configure BGP Authentication',
            'description': 'BGP sessions should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+protocols\\s+bgp\\s+group\\s+\\w+\\s+authentication-key'\nmessage: 'BGP authentication should be configured'\n",
            'tags': ['juniper', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: set protocols bgp group <name> authentication-key <key>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure OSPF Authentication',
            'description': 'OSPF should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+protocols\\s+ospf\\s+area\\s+\\d+\\s+authentication'\nmessage: 'OSPF authentication should be configured'\n",
            'tags': ['juniper', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: set protocols ospf area <area> authentication md5',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Interface Security
    rules.extend([
        {
            'name': 'Juniper - Disable Unused Interfaces',
            'description': 'Unused interfaces should be administratively disabled',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+interfaces\\s+\\S+\\s+disable'\nmessage: 'Unused interfaces should be disabled'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set interfaces <interface> disable',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Time Synchronization
    rules.extend([
        {
            'name': 'Juniper - Configure NTP Server',
            'description': 'NTP server should be configured',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+system\\s+ntp\\s+server'\nmessage: 'NTP server should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set system ntp server <ip>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure Password Policy',
            'description': 'Password policy should be configured',
            'rule_type': 'pattern',
            'category': 'Password Policy',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+system\\s+login\\s+password'\nmessage: 'Password policy should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure: set system login password minimum-length 12',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Juniper - Configure Interface Description',
            'description': 'Interfaces should have descriptions',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'low',
            'yaml_content': "pattern: 'set\\s+interfaces\\s+\\S+\\s+description'\nmessage: 'Interfaces should have descriptions'\n",
            'tags': ['juniper', 'router', 'switch'],
            'remediation_template': 'Configure: set interfaces <interface> description <text>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Juniper - Configure Firewall Filter Output',
            'description': 'Firewall filters should be applied to output',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+firewall\\s+family\\s+inet\\s+filter.*output'\nmessage: 'Firewall filters should be applied to output'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set firewall family inet filter <name> output',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure Logging Archive',
            'description': 'Logging archive should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+system\\s+syslog\\s+archive'\nmessage: 'Logging archive should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set system syslog archive files <num>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure SNMP Trap Group',
            'description': 'SNMP trap groups should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+snmp\\s+trap-group'\nmessage: 'SNMP trap groups should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set snmp trap-group <name> targets <ip>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure Loopback Interface',
            'description': 'Loopback interface should be configured',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'low',
            'yaml_content': "pattern: 'set\\s+interfaces\\s+lo0'\nmessage: 'Loopback interface should be configured'\n",
            'tags': ['juniper', 'router', 'switch'],
            'remediation_template': 'Configure: set interfaces lo0 unit 0 family inet address <ip>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Juniper - Configure Static Route',
            'description': 'Static routes should be configured for management',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'low',
            'yaml_content': "pattern: 'set\\s+routing-options\\s+static\\s+route'\nmessage: 'Static routes should be configured'\n",
            'tags': ['juniper', 'router', 'switch'],
            'remediation_template': 'Configure: set routing-options static route <network> next-hop <ip>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Juniper - Configure VLAN',
            'description': 'VLANs should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'low',
            'yaml_content': "pattern: 'set\\s+vlans\\s+\\w+'\nmessage: 'VLANs should be configured'\n",
            'tags': ['juniper', 'switch'],
            'remediation_template': 'Configure: set vlans <name> vlan-id <id>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Juniper - Configure Port Security',
            'description': 'Port security should be enabled',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+ethernet-switching-options\\s+secure-access-port'\nmessage: 'Port security should be enabled'\n",
            'tags': ['juniper', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set ethernet-switching-options secure-access-port interface <interface> maximum <num>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure MAC Limiting',
            'description': 'MAC limiting should be configured',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+ethernet-switching-options\\s+secure-access-port.*maximum'\nmessage: 'MAC limiting should be configured'\n",
            'tags': ['juniper', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set ethernet-switching-options secure-access-port interface <interface> maximum <num>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure Storm Control',
            'description': 'Storm control should be enabled',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+ethernet-switching-options\\s+storm-control'\nmessage: 'Storm control should be configured'\n",
            'tags': ['juniper', 'switch', 'nist'],
            'remediation_template': 'Configure: set ethernet-switching-options storm-control interface <interface>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure DHCP Snooping',
            'description': 'DHCP snooping should be enabled',
            'rule_type': 'pattern',
            'category': 'DHCP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+forwarding-options\\s+dhcp-relay'\nmessage: 'DHCP snooping should be configured'\n",
            'tags': ['juniper', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure DHCP snooping on switch',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure ARP Inspection',
            'description': 'ARP inspection should be enabled',
            'rule_type': 'pattern',
            'category': 'ARP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+arp-inspection'\nmessage: 'ARP inspection should be enabled'\n",
            'tags': ['juniper', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set security arp-inspection',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure IP Source Guard',
            'description': 'IP source guard should be enabled',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+source-guard'\nmessage: 'IP source guard should be enabled'\n",
            'tags': ['juniper', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: set security source-guard',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure VLAN Access Control',
            'description': 'VLAN access control should be configured',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+vlans\\s+\\w+\\s+vlan-id'\nmessage: 'VLAN access control should be configured'\n",
            'tags': ['juniper', 'switch', 'nist'],
            'remediation_template': 'Configure VLAN access control lists',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure STP Root Guard',
            'description': 'STP root guard should be enabled',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+protocols\\s+rstp\\s+interface.*root-guard'\nmessage: 'STP root guard should be enabled'\n",
            'tags': ['juniper', 'switch', 'nist'],
            'remediation_template': 'Configure: set protocols rstp interface <interface> root-guard',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure STP BPDU Guard',
            'description': 'STP BPDU guard should be enabled',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+protocols\\s+rstp\\s+interface.*bpdu-guard'\nmessage: 'STP BPDU guard should be enabled'\n",
            'tags': ['juniper', 'switch', 'nist'],
            'remediation_template': 'Configure: set protocols rstp interface <interface> bpdu-guard',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure IPv6 Security',
            'description': 'IPv6 security features should be configured',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+ipv6'\nmessage: 'IPv6 security should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure IPv6 security features',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure IPv6 RA Guard',
            'description': 'IPv6 RA guard should be enabled',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+protocols\\s+router-advertisement'\nmessage: 'IPv6 RA guard should be configured'\n",
            'tags': ['juniper', 'switch', 'nist'],
            'remediation_template': 'Configure IPv6 RA guard on access ports',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure IPv6 DHCP Guard',
            'description': 'IPv6 DHCP guard should be enabled',
            'rule_type': 'pattern',
            'category': 'IPv6 Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+protocols\\s+router-advertisement\\s+interface.*managed-configuration'\nmessage: 'IPv6 DHCP guard should be configured'\n",
            'tags': ['juniper', 'switch', 'nist'],
            'remediation_template': 'Configure IPv6 DHCP guard',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure IS-IS Authentication',
            'description': 'IS-IS should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+protocols\\s+isis\\s+authentication'\nmessage: 'IS-IS authentication should be configured'\n",
            'tags': ['juniper', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: set protocols isis authentication md5',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure RIP Authentication',
            'description': 'RIP should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+protocols\\s+rip\\s+authentication'\nmessage: 'RIP authentication should be configured'\n",
            'tags': ['juniper', 'router', 'cis', 'nist'],
            'remediation_template': 'Configure: set protocols rip authentication md5',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Juniper - Configure LDP Authentication',
            'description': 'LDP should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+protocols\\s+ldp\\s+authentication'\nmessage: 'LDP authentication should be configured'\n",
            'tags': ['juniper', 'router', 'nist'],
            'remediation_template': 'Configure: set protocols ldp authentication md5',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure RSVP Authentication',
            'description': 'RSVP should use authentication',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+protocols\\s+rsvp\\s+authentication'\nmessage: 'RSVP authentication should be configured'\n",
            'tags': ['juniper', 'router', 'nist'],
            'remediation_template': 'Configure: set protocols rsvp authentication md5',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure MPLS Security',
            'description': 'MPLS security should be configured',
            'rule_type': 'pattern',
            'category': 'Routing Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+protocols\\s+mpls'\nmessage: 'MPLS security should be configured'\n",
            'tags': ['juniper', 'router', 'nist'],
            'remediation_template': 'Configure MPLS security features',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure VPN Configuration',
            'description': 'VPN should be configured securely',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+ike'\nmessage: 'VPN should be configured'\n",
            'tags': ['juniper', 'router', 'firewall', 'nist'],
            'remediation_template': 'Configure: set security ike policy <name>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure IPsec VPN',
            'description': 'IPsec VPN should be configured',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+ipsec'\nmessage: 'IPsec VPN should be configured'\n",
            'tags': ['juniper', 'router', 'firewall', 'nist'],
            'remediation_template': 'Configure: set security ipsec policy <name>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure SSL VPN',
            'description': 'SSL VPN should be configured',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+ssl'\nmessage: 'SSL VPN should be configured'\n",
            'tags': ['juniper', 'firewall', 'nist'],
            'remediation_template': 'Configure SSL VPN with strong encryption',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure Wireless Security',
            'description': 'Wireless security should be configured',
            'rule_type': 'pattern',
            'category': 'Wireless Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+security\\s+wlan'\nmessage: 'Wireless security should be configured'\n",
            'tags': ['juniper', 'wireless', 'nist'],
            'remediation_template': 'Configure wireless security with WPA2/WPA3',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure DNS Security',
            'description': 'DNS security should be configured',
            'rule_type': 'pattern',
            'category': 'DNS Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+system\\s+name-server'\nmessage: 'DNS security should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure: set system name-server <ip>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Juniper - Configure SNMP Security',
            'description': 'SNMP security should be configured',
            'rule_type': 'pattern',
            'category': 'SNMP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+snmp\\s+security'\nmessage: 'SNMP security should be configured'\n",
            'tags': ['juniper', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure SNMP security with v3',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    return rules

def get_arista_rules():
    """Arista EOS security rules"""
    rules = []
    
    # Authentication
    rules.extend([
        {
            'name': 'Arista - Enable AAA',
            'description': 'AAA should be enabled',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'aaa\\s+authentication'\nmessage: 'AAA authentication should be configured'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: aaa authentication login default group tacacs+ local',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Arista - Configure TACACS+',
            'description': 'TACACS+ should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'tacacs-server\\s+host'\nmessage: 'TACACS+ server should be configured'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: tacacs-server host <ip> key <key>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Encryption
    rules.extend([
        {
            'name': 'Arista - Enable SSH',
            'description': 'SSH should be enabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'management\\s+ssh'\nmessage: 'SSH should be enabled for management'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'SSH is enabled by default, ensure it is not disabled',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Arista - Disable Telnet',
            'description': 'Telnet should be disabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'no\\s+management\\s+telnet'\nmessage: 'Telnet should be disabled'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: no management telnet',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Management
    rules.extend([
        {
            'name': 'Arista - Configure SNMPv3',
            'description': 'SNMPv3 should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'snmp-server\\s+user\\s+\\w+\\s+v3'\nmessage: 'SNMPv3 should be configured'\n",
            'tags': ['arista', 'switch', 'nist'],
            'remediation_template': 'Configure: snmp-server user <user> v3 auth sha <password>',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Logging
    rules.extend([
        {
            'name': 'Arista - Configure Syslog',
            'description': 'Syslog server should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'logging\\s+host'\nmessage: 'Syslog server should be configured'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: logging host <ip>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Port Security
    rules.extend([
        {
            'name': 'Arista - Configure Port Security',
            'description': 'Port security should be enabled',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'high',
            'yaml_content': "pattern: 'port-security'\nmessage: 'Port security should be configured'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: port-security maximum <num>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Arista - Configure Port Security Violation',
            'description': 'Port security violation action should be configured',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'port-security\\s+violation'\nmessage: 'Port security violation action should be configured'\n",
            'tags': ['arista', 'switch', 'nist'],
            'remediation_template': 'Configure: port-security violation restrict',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Arista - Configure Storm Control',
            'description': 'Storm control should be enabled',
            'rule_type': 'pattern',
            'category': 'Port Security',
            'severity': 'medium',
            'yaml_content': "pattern: 'storm-control'\nmessage: 'Storm control should be configured'\n",
            'tags': ['arista', 'switch', 'nist'],
            'remediation_template': 'Configure: storm-control broadcast level <percentage>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Arista - Configure VLAN',
            'description': 'VLANs should be configured appropriately',
            'rule_type': 'pattern',
            'category': 'VLAN Security',
            'severity': 'low',
            'yaml_content': "pattern: 'vlan\\s+\\d+'\nmessage: 'VLANs should be configured'\n",
            'tags': ['arista', 'switch'],
            'remediation_template': 'Configure: vlan <vlan-id>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Arista - Configure STP',
            'description': 'STP should be configured',
            'rule_type': 'pattern',
            'category': 'STP Security',
            'severity': 'low',
            'yaml_content': "pattern: 'spanning-tree'\nmessage: 'STP should be configured'\n",
            'tags': ['arista', 'switch'],
            'remediation_template': 'Configure: spanning-tree mode <mode>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Arista - Configure DHCP Snooping',
            'description': 'DHCP snooping should be enabled',
            'rule_type': 'pattern',
            'category': 'DHCP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+dhcp\\s+snooping'\nmessage: 'DHCP snooping should be enabled'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ip dhcp snooping vlan <vlan-range>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Arista - Configure ARP Inspection',
            'description': 'ARP inspection should be enabled',
            'rule_type': 'pattern',
            'category': 'ARP Security',
            'severity': 'high',
            'yaml_content': "pattern: 'ip\\s+arp\\s+inspection'\nmessage: 'ARP inspection should be enabled'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ip arp inspection vlan <vlan-range>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Additional Arista Rules
    rules.extend([
        {
            'name': 'Arista - Configure AAA Authorization',
            'description': 'AAA authorization should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'aaa\\s+authorization'\nmessage: 'AAA authorization should be configured'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: aaa authorization exec default group tacacs+ local',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Arista - Configure AAA Accounting',
            'description': 'AAA accounting should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'aaa\\s+accounting'\nmessage: 'AAA accounting should be configured'\n",
            'tags': ['arista', 'switch', 'nist'],
            'remediation_template': 'Configure: aaa accounting exec default start-stop group tacacs+',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Arista - Configure SSH Key',
            'description': 'SSH keys should be configured',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'crypto\\s+key\\s+generate'\nmessage: 'SSH keys should be generated'\n",
            'tags': ['arista', 'switch', 'nist'],
            'remediation_template': 'Generate SSH keys for secure access',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Arista - Configure NTP',
            'description': 'NTP should be configured',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'medium',
            'yaml_content': "pattern: 'ntp\\s+server'\nmessage: 'NTP server should be configured'\n",
            'tags': ['arista', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: ntp server <ip>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Arista - Configure Interface Description',
            'description': 'Interfaces should have descriptions',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'low',
            'yaml_content': "pattern: 'interface\\s+\\S+.*description'\nmessage: 'Interfaces should have descriptions'\n",
            'tags': ['arista', 'switch'],
            'remediation_template': 'Configure: description <text>',
            'compliance_frameworks': ''
        },
    ])
    
    return rules

def get_paloalto_rules():
    """Palo Alto PAN-OS firewall security rules"""
    rules = []
    
    # Authentication
    rules.extend([
        {
            'name': 'Palo Alto - Configure Admin Authentication',
            'description': 'Admin authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+mgmt-config\\s+users\\s+admin\\s+password'\nmessage: 'Admin password should be configured'\n",
            'tags': ['paloalto', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure: set mgmt-config users admin password',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Palo Alto - Configure LDAP Authentication',
            'description': 'LDAP authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+shared\\s+authentication-profile'\nmessage: 'LDAP authentication should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure LDAP authentication profile',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Security Policies
    rules.extend([
        {
            'name': 'Palo Alto - Configure Security Policy',
            'description': 'Security policies should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'critical',
            'yaml_content': "pattern: 'set\\s+rulebase\\s+security\\s+rules'\nmessage: 'Security policies should be configured'\n",
            'tags': ['paloalto', 'firewall', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure security policies with appropriate rules',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Palo Alto - Configure NAT Policy',
            'description': 'NAT policies should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+rulebase\\s+nat\\s+rules'\nmessage: 'NAT policies should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure NAT policies',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Palo Alto - Configure Security Profile',
            'description': 'Security profiles should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+profiles\\s+security'\nmessage: 'Security profiles should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure security profiles (antivirus, anti-spyware, vulnerability)',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Logging
    rules.extend([
        {
            'name': 'Palo Alto - Configure Log Forwarding',
            'description': 'Log forwarding should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+deviceconfig\\s+system\\s+log-settings\\s+log-forwarding'\nmessage: 'Log forwarding should be configured'\n",
            'tags': ['paloalto', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure log forwarding profile',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Palo Alto - Enable Threat Logging',
            'description': 'Threat logging should be enabled',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+rulebase\\s+security\\s+rules\\s+\\w+\\s+log-setting'\nmessage: 'Threat logging should be enabled on security rules'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure log-setting on security rules',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # VPN
    rules.extend([
        {
            'name': 'Palo Alto - Configure IPSec VPN',
            'description': 'IPSec VPN should be configured securely',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+network\\s+ike\\s+crypto-profiles'\nmessage: 'IPSec VPN should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure IPSec VPN with strong encryption',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Management
    rules.extend([
        {
            'name': 'Palo Alto - Enable HTTPS Management',
            'description': 'HTTPS should be enabled for management',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+deviceconfig\\s+system\\s+type\\s+static-ip\\s+ip-address'\nmessage: 'Management interface should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Ensure HTTPS is enabled for management access',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Palo Alto - Configure Management Access IP',
            'description': 'Management access should be restricted by IP',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+deviceconfig\\s+system\\s+ip-address'\nmessage: 'Management IP should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure management IP and restrict access',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Palo Alto - Configure Security Zone',
            'description': 'Security zones should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+network\\s+zone'\nmessage: 'Security zones should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure: set network zone <name>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Palo Alto - Configure Application Override',
            'description': 'Application override policies should be controlled',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+rulebase\\s+application-override'\nmessage: 'Application override should be controlled'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Review and restrict application override policies',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Palo Alto - Configure URL Filtering',
            'description': 'URL filtering should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+profiles\\s+url-filtering'\nmessage: 'URL filtering should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure URL filtering profiles',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Palo Alto - Configure WildFire',
            'description': 'WildFire should be configured for threat detection',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+deviceconfig\\s+setting\\s+wildfire'\nmessage: 'WildFire should be configured'\n",
            'tags': ['paloalto', 'firewall', 'nist'],
            'remediation_template': 'Configure WildFire for advanced threat detection',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    return rules

def get_fortinet_rules():
    """Fortinet FortiOS firewall security rules"""
    rules = []
    
    # Authentication
    rules.extend([
        {
            'name': 'Fortinet - Configure Admin User',
            'description': 'Admin user should be configured securely',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+system\\s+admin\\s+edit\\s+admin'\nmessage: 'Admin user should be configured'\n",
            'tags': ['fortinet', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure: config system admin edit admin, set password <password>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Fortinet - Configure LDAP Authentication',
            'description': 'LDAP authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'config\\s+user\\s+ldap'\nmessage: 'LDAP authentication should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure LDAP authentication',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Firewall Policies
    rules.extend([
        {
            'name': 'Fortinet - Configure Firewall Policy',
            'description': 'Firewall policies should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'critical',
            'yaml_content': "pattern: 'config\\s+firewall\\s+policy'\nmessage: 'Firewall policies should be configured'\n",
            'tags': ['fortinet', 'firewall', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure firewall policies with appropriate rules',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Fortinet - Configure Security Profiles',
            'description': 'Security profiles should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+firewall\\s+profile-protocol-options'\nmessage: 'Security profiles should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure security profiles (antivirus, IPS, application control)',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Logging
    rules.extend([
        {
            'name': 'Fortinet - Configure Log Settings',
            'description': 'Logging should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+log\\s+setting'\nmessage: 'Log settings should be configured'\n",
            'tags': ['fortinet', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure: config log setting, set status enable',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Fortinet - Configure Syslog Server',
            'description': 'Syslog server should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+log\\s+syslogd\\s+setting'\nmessage: 'Syslog server should be configured'\n",
            'tags': ['fortinet', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure: config log syslogd setting, set server <ip>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # VPN
    rules.extend([
        {
            'name': 'Fortinet - Configure IPSec VPN',
            'description': 'IPSec VPN should be configured securely',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+vpn\\s+ipsec\\s+phase1-interface'\nmessage: 'IPSec VPN should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure IPSec VPN with strong encryption',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Fortinet - Configure SSL VPN',
            'description': 'SSL VPN should be configured securely',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+vpn\\s+ssl\\s+settings'\nmessage: 'SSL VPN should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure SSL VPN with strong encryption',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Additional Fortinet Rules
    rules.extend([
        {
            'name': 'Fortinet - Configure Interface Description',
            'description': 'Interfaces should have descriptions',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'low',
            'yaml_content': "pattern: 'config\\s+system\\s+interface.*description'\nmessage: 'Interfaces should have descriptions'\n",
            'tags': ['fortinet', 'firewall'],
            'remediation_template': 'Configure: set description <text>',
            'compliance_frameworks': ''
        },
        {
            'name': 'Fortinet - Configure Security Profiles',
            'description': 'Security profiles should be applied to policies',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+profile-protocol-options'\nmessage: 'Security profiles should be applied'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Apply security profiles to firewall policies',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Fortinet - Configure Application Control',
            'description': 'Application control should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+application\\s+list'\nmessage: 'Application control should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure application control lists',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Fortinet - Configure Intrusion Prevention',
            'description': 'Intrusion prevention should be enabled',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'config\\s+ips\\s+sensor'\nmessage: 'IPS should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure IPS sensors and apply to policies',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Fortinet - Configure Web Filter',
            'description': 'Web filtering should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'medium',
            'yaml_content': "pattern: 'config\\s+webfilter\\s+profile'\nmessage: 'Web filtering should be configured'\n",
            'tags': ['fortinet', 'firewall', 'nist'],
            'remediation_template': 'Configure web filter profiles',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    return rules

def get_huawei_rules():
    """Huawei VRP router/switch security rules"""
    rules = []
    
    # Authentication
    rules.extend([
        {
            'name': 'Huawei - Configure Local User',
            'description': 'Local user accounts should be configured securely',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'local-user\\s+\\S+'\nmessage: 'Local user should be configured'\n",
            'tags': ['huawei', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure: local-user <username> password cipher <password>',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Huawei - Configure AAA',
            'description': 'AAA authentication should be configured',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'aaa\\s+'\nmessage: 'AAA authentication should be configured'\n",
            'tags': ['huawei', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure AAA authentication: aaa authentication-scheme <scheme-name>',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Huawei - Configure RADIUS Authentication',
            'description': 'RADIUS authentication should be configured for remote access',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'medium',
            'yaml_content': "pattern: 'radius-server\\s+'\nmessage: 'RADIUS authentication should be configured'\n",
            'tags': ['huawei', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure RADIUS server: radius-server template <template-name>',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Access Control
    rules.extend([
        {
            'name': 'Huawei - Configure ACL',
            'description': 'Access Control Lists should be configured',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'critical',
            'yaml_content': "pattern: 'acl\\s+number\\s+\\d+'\nmessage: 'ACL should be configured'\n",
            'tags': ['huawei', 'router', 'switch', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure ACL: acl number <number>, rule <rule-id> permit/deny',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Huawei - Configure Interface ACL',
            'description': 'ACL should be applied to interfaces',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'high',
            'yaml_content': "pattern: 'traffic-filter\\s+.*\\s+acl\\s+'\nmessage: 'ACL should be applied to interfaces'\n",
            'tags': ['huawei', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Apply ACL to interface: interface <interface-name>, traffic-filter inbound acl <number>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Encryption
    rules.extend([
        {
            'name': 'Huawei - Configure SSH Server',
            'description': 'SSH server should be enabled',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: 'ssh\\s+server\\s+enable'\nmessage: 'SSH server should be enabled'\n",
            'tags': ['huawei', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Enable SSH: ssh server enable',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Huawei - Configure HTTPS Server',
            'description': 'HTTPS server should be enabled for secure management',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'medium',
            'yaml_content': "pattern: 'http\\s+secure-server\\s+enable'\nmessage: 'HTTPS server should be enabled'\n",
            'tags': ['huawei', 'router', 'switch', 'nist'],
            'remediation_template': 'Enable HTTPS: http secure-server enable',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Huawei - Configure IPsec VPN',
            'description': 'IPsec VPN should be configured securely',
            'rule_type': 'pattern',
            'category': 'VPN Configuration',
            'severity': 'high',
            'yaml_content': "pattern: 'ipsec\\s+'\nmessage: 'IPsec VPN should be configured'\n",
            'tags': ['huawei', 'router', 'nist'],
            'remediation_template': 'Configure IPsec: ipsec proposal <proposal-name>, esp authentication-algorithm sha2-256',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    # Logging
    rules.extend([
        {
            'name': 'Huawei - Configure Logging',
            'description': 'System logging should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'info-center\\s+enable'\nmessage: 'System logging should be enabled'\n",
            'tags': ['huawei', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Enable logging: info-center enable',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Huawei - Configure Syslog Server',
            'description': 'Syslog server should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'info-center\\s+loghost\\s+'\nmessage: 'Syslog server should be configured'\n",
            'tags': ['huawei', 'router', 'switch', 'cis', 'nist'],
            'remediation_template': 'Configure syslog: info-center loghost <ip-address>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # SNMP Security
    rules.extend([
        {
            'name': 'Huawei - Configure SNMP Community',
            'description': 'SNMP community strings should be configured securely',
            'rule_type': 'pattern',
            'category': 'SNMP',
            'severity': 'medium',
            'yaml_content': "pattern: 'snmp-agent\\s+community\\s+'\nmessage: 'SNMP community should be configured'\n",
            'tags': ['huawei', 'router', 'switch', 'nist'],
            'remediation_template': 'Configure SNMP: snmp-agent community read <community-name> acl <acl-number>',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    return rules

def get_checkpoint_rules():
    """Check Point Gaia OS firewall security rules"""
    rules = []
    
    # Authentication
    rules.extend([
        {
            'name': 'Check Point - Configure Admin User',
            'description': 'Admin user should be configured securely',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+user\\s+admin\\s+password'\nmessage: 'Admin password should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure: set user admin password',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Firewall Rules
    rules.extend([
        {
            'name': 'Check Point - Configure Security Policy',
            'description': 'Security policies should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'critical',
            'yaml_content': "pattern: 'add\\s+rule'\nmessage: 'Security rules should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure security rules via SmartConsole',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
    ])
    
    # Logging
    rules.extend([
        {
            'name': 'Check Point - Configure Logging',
            'description': 'Logging should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+log\\s+server'\nmessage: 'Log server should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'cis', 'nist'],
            'remediation_template': 'Configure: set log server <ip>',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Additional Check Point Rules
    rules.extend([
        {
            'name': 'Check Point - Configure Security Zone',
            'description': 'Security zones should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'add\\s+network\\s+object'\nmessage: 'Network objects and zones should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'nist'],
            'remediation_template': 'Configure security zones via SmartConsole',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Check Point - Configure Threat Prevention',
            'description': 'Threat prevention should be enabled',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+threat-prevention'\nmessage: 'Threat prevention should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'nist'],
            'remediation_template': 'Enable threat prevention via SmartConsole',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Check Point - Configure Application Control',
            'description': 'Application control should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: 'set\\s+application-control'\nmessage: 'Application control should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'nist'],
            'remediation_template': 'Configure application control via SmartConsole',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Check Point - Configure URL Filtering',
            'description': 'URL filtering should be configured',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'medium',
            'yaml_content': "pattern: 'set\\s+url-filtering'\nmessage: 'URL filtering should be configured'\n",
            'tags': ['checkpoint', 'firewall', 'nist'],
            'remediation_template': 'Configure URL filtering via SmartConsole',
            'compliance_frameworks': 'NIST'
        },
    ])
    
    return rules

def get_generic_rules():
    """Vendor-agnostic generic security best practices"""
    rules = []
    
    # Generic Authentication
    rules.extend([
        {
            'name': 'Generic - Strong Password Policy',
            'description': 'Strong password policy should be enforced',
            'rule_type': 'pattern',
            'category': 'Password Policy',
            'severity': 'high',
            'yaml_content': "pattern: '(password|passwd|pwd).*min.*length'\nmessage: 'Password minimum length should be configured'\n",
            'tags': ['generic', 'all', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Configure password policy with minimum length of 12+ characters',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
    ])
    
    # Generic Encryption
    rules.extend([
        {
            'name': 'Generic - Use Strong Encryption',
            'description': 'Strong encryption algorithms should be used',
            'rule_type': 'pattern',
            'category': 'Encryption',
            'severity': 'high',
            'yaml_content': "pattern: '(aes|sha256|sha512|rsa-2048|rsa-4096)'\nmessage: 'Strong encryption should be used'\n",
            'tags': ['generic', 'all', 'nist', 'pci-dss'],
            'remediation_template': 'Use AES-256, SHA-256 or stronger encryption algorithms',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
    ])
    
    # Generic Logging
    rules.extend([
        {
            'name': 'Generic - Configure Centralized Logging',
            'description': 'Centralized logging should be configured',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: '(syslog|log.*server|logging.*host)'\nmessage: 'Centralized logging should be configured'\n",
            'tags': ['generic', 'all', 'cis', 'nist'],
            'remediation_template': 'Configure syslog or centralized logging server',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Generic Management
    rules.extend([
        {
            'name': 'Generic - Restrict Management Access',
            'description': 'Management access should be restricted',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'high',
            'yaml_content': "pattern: '(access.*list|acl|firewall.*rule|management.*access)'\nmessage: 'Management access should be restricted'\n",
            'tags': ['generic', 'all', 'cis', 'nist'],
            'remediation_template': 'Configure ACLs or firewall rules to restrict management access',
            'compliance_frameworks': 'CIS,NIST'
        },
    ])
    
    # Additional Generic Rules
    rules.extend([
        {
            'name': 'Generic - Configure Time Synchronization',
            'description': 'Time synchronization should be configured',
            'rule_type': 'pattern',
            'category': 'Time Synchronization',
            'severity': 'medium',
            'yaml_content': "pattern: '(ntp|time.*server|clock.*sync)'\nmessage: 'Time synchronization should be configured'\n",
            'tags': ['generic', 'all', 'cis', 'nist'],
            'remediation_template': 'Configure NTP or time synchronization',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Generic - Disable Unnecessary Services',
            'description': 'Unnecessary services should be disabled',
            'rule_type': 'pattern',
            'category': 'Service Hardening',
            'severity': 'medium',
            'yaml_content': "pattern: '(no\\s+service|disable|service.*off)'\nmessage: 'Unnecessary services should be disabled'\n",
            'tags': ['generic', 'all', 'nist'],
            'remediation_template': 'Disable unnecessary services',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Generic - Configure Interface Descriptions',
            'description': 'Interfaces should have descriptions',
            'rule_type': 'pattern',
            'category': 'Interface Security',
            'severity': 'low',
            'yaml_content': "pattern: '(interface.*description|description.*interface)'\nmessage: 'Interfaces should have descriptions'\n",
            'tags': ['generic', 'all'],
            'remediation_template': 'Add descriptions to all interfaces',
            'compliance_frameworks': ''
        },
        {
            'name': 'Generic - Configure Access Control',
            'description': 'Access control should be configured',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'high',
            'yaml_content': "pattern: '(access.*control|acl|firewall|filter)'\nmessage: 'Access control should be configured'\n",
            'tags': ['generic', 'all', 'cis', 'nist'],
            'remediation_template': 'Configure appropriate access control mechanisms',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Generic - Enable Audit Logging',
            'description': 'Audit logging should be enabled',
            'rule_type': 'pattern',
            'category': 'Logging',
            'severity': 'high',
            'yaml_content': "pattern: '(audit.*log|logging.*audit|log.*enable)'\nmessage: 'Audit logging should be enabled'\n",
            'tags': ['generic', 'all', 'cis', 'nist', 'pci-dss'],
            'remediation_template': 'Enable audit logging for security events',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS'
        },
        {
            'name': 'Generic - Configure Backup',
            'description': 'Configuration backup should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'medium',
            'yaml_content': "pattern: '(backup|save.*config|export.*config)'\nmessage: 'Configuration backup should be configured'\n",
            'tags': ['generic', 'all', 'nist'],
            'remediation_template': 'Configure automated configuration backups',
            'compliance_frameworks': 'NIST'
        },
        {
            'name': 'Generic - Disable Default Credentials',
            'description': 'Default credentials should be changed',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'critical',
            'yaml_content': "pattern: '(admin|root|cisco|password|default)'\nmessage: 'Default credentials should not be used'\n",
            'tags': ['generic', 'all', 'cis', 'nist', 'pci-dss', 'hipaa'],
            'remediation_template': 'Change all default usernames and passwords',
            'compliance_frameworks': 'CIS,NIST,PCI-DSS,HIPAA'
        },
        {
            'name': 'Generic - Enable Multi-Factor Authentication',
            'description': 'Multi-factor authentication should be enabled where supported',
            'rule_type': 'pattern',
            'category': 'Authentication',
            'severity': 'high',
            'yaml_content': "pattern: '(mfa|multi.*factor|two.*factor|2fa)'\nmessage: 'Multi-factor authentication should be enabled'\n",
            'tags': ['generic', 'all', 'nist', 'pci-dss', 'hipaa'],
            'remediation_template': 'Enable multi-factor authentication for administrative access',
            'compliance_frameworks': 'NIST,PCI-DSS,HIPAA'
        },
        {
            'name': 'Generic - Configure Session Timeout',
            'description': 'Session timeout should be configured',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'medium',
            'yaml_content': "pattern: '(timeout|session.*timeout|idle.*timeout)'\nmessage: 'Session timeout should be configured'\n",
            'tags': ['generic', 'all', 'nist', 'pci-dss'],
            'remediation_template': 'Configure appropriate session timeout values',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
        {
            'name': 'Generic - Configure Access Control Lists',
            'description': 'Access control lists should be configured',
            'rule_type': 'pattern',
            'category': 'Access Control',
            'severity': 'high',
            'yaml_content': "pattern: '(access.*list|acl|firewall.*rule)'\nmessage: 'Access control lists should be configured'\n",
            'tags': ['generic', 'all', 'cis', 'nist'],
            'remediation_template': 'Configure appropriate access control lists',
            'compliance_frameworks': 'CIS,NIST'
        },
        {
            'name': 'Generic - Enable Intrusion Detection',
            'description': 'Intrusion detection should be enabled where supported',
            'rule_type': 'pattern',
            'category': 'Firewall',
            'severity': 'high',
            'yaml_content': "pattern: '(ids|ips|intrusion.*detection|intrusion.*prevention)'\nmessage: 'Intrusion detection/prevention should be enabled'\n",
            'tags': ['generic', 'all', 'nist', 'pci-dss'],
            'remediation_template': 'Enable and configure intrusion detection/prevention',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
        {
            'name': 'Generic - Configure Vulnerability Scanning',
            'description': 'Vulnerability scanning should be performed regularly',
            'rule_type': 'pattern',
            'category': 'Monitoring',
            'severity': 'medium',
            'yaml_content': "pattern: '(vulnerability|scan|assessment)'\nmessage: 'Vulnerability scanning should be configured'\n",
            'tags': ['generic', 'all', 'nist', 'pci-dss'],
            'remediation_template': 'Configure and schedule regular vulnerability scans',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
        {
            'name': 'Generic - Configure Change Management',
            'description': 'Change management process should be documented',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'low',
            'yaml_content': "pattern: '(change.*management|config.*management)'\nmessage: 'Change management should be implemented'\n",
            'tags': ['generic', 'all', 'nist', 'iso27001'],
            'remediation_template': 'Implement change management process',
            'compliance_frameworks': 'NIST,ISO27001'
        },
        {
            'name': 'Generic - Configure Incident Response',
            'description': 'Incident response procedures should be documented',
            'rule_type': 'pattern',
            'category': 'Management Plane',
            'severity': 'medium',
            'yaml_content': "pattern: '(incident.*response|security.*incident)'\nmessage: 'Incident response should be configured'\n",
            'tags': ['generic', 'all', 'nist', 'iso27001'],
            'remediation_template': 'Document and implement incident response procedures',
            'compliance_frameworks': 'NIST,ISO27001'
        },
        {
            'name': 'Generic - Configure Security Monitoring',
            'description': 'Security monitoring should be enabled',
            'rule_type': 'pattern',
            'category': 'Monitoring',
            'severity': 'high',
            'yaml_content': "pattern: '(monitoring|security.*monitor|siem)'\nmessage: 'Security monitoring should be configured'\n",
            'tags': ['generic', 'all', 'nist', 'pci-dss'],
            'remediation_template': 'Configure security monitoring and SIEM integration',
            'compliance_frameworks': 'NIST,PCI-DSS'
        },
    ])
    
    return rules

def main():
    """Main function to populate rules"""
    print("=" * 60)
    print("Network Configuration Rule Tester - Rule Population")
    print("=" * 60)
    print()
    
    # Get all rule definitions
    print("Loading rule definitions...")
    all_rules = get_all_rules()
    
    if not all_rules:
        print("No rules defined yet. Rules will be added in subsequent steps.")
        print("This script structure is ready for rule definitions.")
        return
    
    print(f"Found {len(all_rules)} rules to process")
    print()
    
    # Process rules
    created_count = 0
    existing_count = 0
    error_count = 0
    
    for i, rule_data in enumerate(all_rules, 1):
        rule_id, status = create_rule(rule_data, skip_existing=True)
        
        if status == 'created':
            created_count += 1
            print(f"[{i}/{len(all_rules)}] Created: {rule_data['name']}")
        elif status == 'exists':
            existing_count += 1
            if i % 10 == 0:  # Print every 10th existing rule to reduce output
                print(f"[{i}/{len(all_rules)}] Exists: {rule_data['name']}")
        else:
            error_count += 1
            print(f"[{i}/{len(all_rules)}] ERROR: {rule_data['name']} - {status}")
        
        # Progress update every 50 rules
        if i % 50 == 0:
            print(f"Progress: {i}/{len(all_rules)} processed ({created_count} created, {existing_count} existing, {error_count} errors)")
    
    print()
    print("=" * 60)
    print("Summary:")
    print(f"  Total rules processed: {len(all_rules)}")
    print(f"  Created: {created_count}")
    print(f"  Already existed: {existing_count}")
    print(f"  Errors: {error_count}")
    print("=" * 60)

if __name__ == '__main__':
    main()


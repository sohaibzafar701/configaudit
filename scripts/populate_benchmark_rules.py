#!/usr/bin/env python3
"""
Populate database with rules based on major security benchmarks:
- CIS Benchmarks for Network Devices
- NIST Cybersecurity Framework
- PCI DSS Requirements
- Common Security Best Practices
"""

from services.database import init_database
from models.rule import Rule

def populate_benchmark_rules():
    """Populate database with comprehensive security rules from major benchmarks"""
    
    rules = [
        # ========== AUTHENTICATION & ACCESS CONTROL (CIS, NIST) ==========
        {
            "name": "Default Credentials Check",
            "description": "CIS 1.1: Ensure default credentials are changed",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Authentication",
            "severity": "critical",
            "yaml_content": """
name: Default Credentials Check
type: pattern
pattern: '(password|enable password|secret)\\s+(cisco|admin|password|changeme|default)'
severity: critical
message: "Default or weak credentials detected"
"""
        },
        {
            "name": "AAA Authentication Required",
            "description": "CIS 1.2: Ensure AAA authentication is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Authentication",
            "severity": "high",
            "yaml_content": """
name: AAA Authentication Required
type: pattern
pattern: 'aaa\\s+new-model'
severity: high
message: "AAA authentication should be enabled"
"""
        },
        {
            "name": "Local User Accounts",
            "description": "CIS 1.3: Ensure local user accounts are configured with strong passwords",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Authentication",
            "severity": "high",
            "yaml_content": """
name: Local User Accounts
type: pattern
pattern: 'username\\s+\\S+\\s+(password|secret)\\s+\\d+'
severity: high
message: "Local user account found - verify strong password policy"
"""
        },
        {
            "name": "TACACS+ or RADIUS Configuration",
            "description": "CIS 1.4: Ensure TACACS+ or RADIUS is configured for authentication",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Authentication",
            "severity": "high",
            "yaml_content": """
name: TACACS+ or RADIUS Configuration
type: pattern
pattern: '(tacacs|radius)\\s+server'
severity: high
message: "Centralized authentication server should be configured"
"""
        },
        {
            "name": "Console Password Required",
            "description": "CIS 1.5: Ensure console access requires authentication",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Authentication",
            "severity": "high",
            "yaml_content": """
name: Console Password Required
type: pattern
pattern: 'line\\s+console\\s+0'
severity: high
message: "Console line should have password authentication configured"
"""
        },
        {
            "name": "VTY Password Required",
            "description": "CIS 1.6: Ensure VTY access requires authentication",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Authentication",
            "severity": "high",
            "yaml_content": """
name: VTY Password Required
type: pattern
pattern: 'line\\s+vty\\s+0\\s+4'
severity: high
message: "VTY lines should have password authentication configured"
"""
        },
        {
            "name": "Privilege Level Restrictions",
            "description": "CIS 1.7: Ensure privilege levels are properly configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Access Control",
            "severity": "medium",
            "yaml_content": """
name: Privilege Level Restrictions
type: pattern
pattern: 'privilege\\s+\\w+\\s+level\\s+15'
severity: medium
message: "Review privilege level assignments - level 15 provides full access"
"""
        },
        
        # ========== ENCRYPTION & SECURE COMMUNICATIONS (CIS, NIST) ==========
        {
            "name": "SSH Enabled",
            "description": "CIS 2.1: Ensure SSH is enabled for remote access",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Encryption",
            "severity": "high",
            "yaml_content": """
name: SSH Enabled
type: pattern
pattern: 'ip\\s+ssh'
severity: high
message: "SSH should be enabled for secure remote access"
"""
        },
        {
            "name": "SSH Version 2 Only",
            "description": "CIS 2.2: Ensure SSH version 2 is used",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Encryption",
            "severity": "high",
            "yaml_content": """
name: SSH Version 2 Only
type: pattern
pattern: 'ip\\s+ssh\\s+version\\s+1'
severity: high
message: "SSH version 1 is insecure - use version 2 only"
"""
        },
        {
            "name": "HTTPS Enabled",
            "description": "CIS 2.3: Ensure HTTPS is enabled for web management",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Encryption",
            "severity": "high",
            "yaml_content": """
name: HTTPS Enabled
type: pattern
pattern: 'ip\\s+http\\s+secure-server'
severity: high
message: "HTTPS should be enabled for secure web management"
"""
        },
        {
            "name": "HTTP Disabled",
            "description": "CIS 2.4: Ensure HTTP is disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Encryption",
            "severity": "high",
            "yaml_content": """
name: HTTP Disabled
type: pattern
pattern: 'ip\\s+http\\s+server'
severity: high
message: "HTTP server should be disabled - use HTTPS only"
"""
        },
        {
            "name": "SNMPv3 Required",
            "description": "CIS 2.5: Ensure SNMPv3 is used instead of SNMPv1/v2",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Encryption",
            "severity": "high",
            "yaml_content": """
name: SNMPv3 Required
type: pattern
pattern: 'snmp-server\\s+(community|host)\\s+\\S+\\s+(ro|rw)'
severity: high
message: "SNMPv1/v2 community strings are insecure - use SNMPv3"
"""
        },
        {
            "name": "Telnet Disabled",
            "description": "CIS 2.6: Ensure Telnet is disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Encryption",
            "severity": "critical",
            "yaml_content": """
name: Telnet Disabled
type: pattern
pattern: 'transport\\s+input\\s+telnet'
severity: critical
message: "Telnet is insecure - should be disabled"
"""
        },
        
        # ========== ACCESS CONTROL LISTS (CIS, NIST) ==========
        {
            "name": "Access Control Lists Configured",
            "description": "CIS 3.1: Ensure access control lists are configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Access Control",
            "severity": "high",
            "yaml_content": """
name: Access Control Lists Configured
type: pattern
pattern: 'ip\\s+access-list'
severity: high
message: "Access control lists should be configured for network security"
"""
        },
        {
            "name": "Restrictive ACL on Management Interface",
            "description": "CIS 3.2: Ensure management interface has restrictive ACL",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Access Control",
            "severity": "high",
            "yaml_content": """
name: Restrictive ACL on Management Interface
type: pattern
pattern: 'ip\\s+access-group\\s+\\d+\\s+in'
severity: high
message: "Management interfaces should have restrictive access control lists"
"""
        },
        {
            "name": "ACL Deny All at End",
            "description": "CIS 3.3: Ensure ACLs have explicit deny all at the end",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Access Control",
            "severity": "medium",
            "yaml_content": """
name: ACL Deny All at End
type: pattern
pattern: 'deny\\s+ip\\s+any\\s+any'
severity: medium
message: "ACLs should have explicit deny all statement at the end"
"""
        },
        
        # ========== LOGGING & MONITORING (CIS, NIST, PCI DSS) ==========
        {
            "name": "Syslog Server Configured",
            "description": "CIS 4.1: Ensure syslog server is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Logging",
            "severity": "high",
            "yaml_content": """
name: Syslog Server Configured
type: pattern
pattern: 'logging\\s+\\d+\\.\\d+\\.\\d+\\.\\d+'
severity: high
message: "Syslog server should be configured for centralized logging"
"""
        },
        {
            "name": "Logging Timestamps Enabled",
            "description": "CIS 4.2: Ensure logging timestamps are enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Logging",
            "severity": "medium",
            "yaml_content": """
name: Logging Timestamps Enabled
type: pattern
pattern: 'service\\s+timestamps\\s+log'
severity: medium
message: "Log timestamps should be enabled for audit trail"
"""
        },
        {
            "name": "SNMP Traps Configured",
            "description": "CIS 4.3: Ensure SNMP traps are configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Monitoring",
            "severity": "medium",
            "yaml_content": """
name: SNMP Traps Configured
type: pattern
pattern: 'snmp-server\\s+host'
severity: medium
message: "SNMP traps should be configured for monitoring"
"""
        },
        
        # ========== SERVICE HARDENING (CIS, NIST) ==========
        {
            "name": "CDP Disabled",
            "description": "CIS 5.1: Ensure CDP is disabled on untrusted interfaces",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "medium",
            "yaml_content": """
name: CDP Disabled
type: pattern
pattern: 'cdp\\s+run'
severity: medium
message: "CDP should be disabled on untrusted interfaces"
"""
        },
        {
            "name": "LLDP Disabled",
            "description": "CIS 5.2: Ensure LLDP is disabled on untrusted interfaces",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "medium",
            "yaml_content": """
name: LLDP Disabled
type: pattern
pattern: 'lldp\\s+run'
severity: medium
message: "LLDP should be disabled on untrusted interfaces"
"""
        },
        {
            "name": "Finger Service Disabled",
            "description": "CIS 5.3: Ensure finger service is disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "low",
            "yaml_content": """
name: Finger Service Disabled
type: pattern
pattern: 'service\\s+finger'
severity: low
message: "Finger service should be disabled"
"""
        },
        {
            "name": "TCP Small Servers Disabled",
            "description": "CIS 5.4: Ensure TCP small servers are disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "medium",
            "yaml_content": """
name: TCP Small Servers Disabled
type: pattern
pattern: 'service\\s+tcp-small-servers'
severity: medium
message: "TCP small servers should be disabled"
"""
        },
        {
            "name": "UDP Small Servers Disabled",
            "description": "CIS 5.5: Ensure UDP small servers are disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "medium",
            "yaml_content": """
name: UDP Small Servers Disabled
type: pattern
pattern: 'service\\s+udp-small-servers'
severity: medium
message: "UDP small servers should be disabled"
"""
        },
        {
            "name": "IP Source Routing Disabled",
            "description": "CIS 5.6: Ensure IP source routing is disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "high",
            "yaml_content": """
name: IP Source Routing Disabled
type: pattern
pattern: 'no\\s+ip\\s+source-route'
severity: high
message: "IP source routing should be disabled"
"""
        },
        {
            "name": "IP Redirects Disabled",
            "description": "CIS 5.7: Ensure IP redirects are disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "medium",
            "yaml_content": """
name: IP Redirects Disabled
type: pattern
pattern: 'no\\s+ip\\s+redirects'
severity: medium
message: "IP redirects should be disabled"
"""
        },
        {
            "name": "IP Unreachables Disabled",
            "description": "CIS 5.8: Ensure IP unreachables are disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Service Hardening",
            "severity": "low",
            "yaml_content": """
name: IP Unreachables Disabled
type: pattern
pattern: 'no\\s+ip\\s+unreachables'
severity: low
message: "IP unreachables should be disabled to prevent information disclosure"
"""
        },
        
        # ========== PASSWORD POLICY (CIS, NIST, PCI DSS) ==========
        {
            "name": "Password Encryption Enabled",
            "description": "CIS 6.1: Ensure password encryption is enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Password Policy",
            "severity": "high",
            "yaml_content": """
name: Password Encryption Enabled
type: pattern
pattern: 'service\\s+password-encryption'
severity: high
message: "Password encryption should be enabled"
"""
        },
        {
            "name": "Minimum Password Length",
            "description": "CIS 6.2: Ensure minimum password length is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Password Policy",
            "severity": "high",
            "yaml_content": """
name: Minimum Password Length
type: pattern
pattern: 'security\\s+passwords\\s+min-length\\s+\\d+'
severity: high
message: "Minimum password length should be at least 8 characters"
"""
        },
        
        # ========== BANNER CONFIGURATION (CIS) ==========
        {
            "name": "Login Banner Configured",
            "description": "CIS 7.1: Ensure login banner is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Banner",
            "severity": "low",
            "yaml_content": """
name: Login Banner Configured
type: pattern
pattern: 'banner\\s+login'
severity: low
message: "Login banner should be configured for legal compliance"
"""
        },
        {
            "name": "MOTD Banner Configured",
            "description": "CIS 7.2: Ensure MOTD banner is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Banner",
            "severity": "low",
            "yaml_content": """
name: MOTD Banner Configured
type: pattern
pattern: 'banner\\s+motd'
severity: low
message: "MOTD banner should be configured"
"""
        },
        
        # ========== ROUTING SECURITY (CIS, NIST) ==========
        {
            "name": "BGP Authentication",
            "description": "CIS 8.1: Ensure BGP authentication is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Routing Security",
            "severity": "high",
            "yaml_content": """
name: BGP Authentication
type: pattern
pattern: 'neighbor\\s+\\S+\\s+password'
severity: high
message: "BGP neighbors should have authentication configured"
"""
        },
        {
            "name": "OSPF Authentication",
            "description": "CIS 8.2: Ensure OSPF authentication is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Routing Security",
            "severity": "high",
            "yaml_content": """
name: OSPF Authentication
type: pattern
pattern: 'ip\\s+ospf\\s+authentication'
severity: high
message: "OSPF should have authentication configured"
"""
        },
        {
            "name": "EIGRP Authentication",
            "description": "CIS 8.3: Ensure EIGRP authentication is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Routing Security",
            "severity": "high",
            "yaml_content": """
name: EIGRP Authentication
type: pattern
pattern: 'ip\\s+authentication\\s+mode\\s+eigrp'
severity: high
message: "EIGRP should have authentication configured"
"""
        },
        
        # ========== INTERFACE SECURITY (CIS, NIST) ==========
        {
            "name": "Unused Interfaces Shutdown",
            "description": "CIS 9.1: Ensure unused interfaces are shutdown",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Interface Security",
            "severity": "medium",
            "yaml_content": """
name: Unused Interfaces Shutdown
type: pattern
pattern: 'interface\\s+\\S+\\s*\\n(?!.*shutdown)'
severity: medium
message: "Unused interfaces should be shutdown"
"""
        },
        {
            "name": "IP Directed Broadcast Disabled",
            "description": "CIS 9.2: Ensure IP directed broadcast is disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Interface Security",
            "severity": "high",
            "yaml_content": """
name: IP Directed Broadcast Disabled
type: pattern
pattern: 'no\\s+ip\\s+directed-broadcast'
severity: high
message: "IP directed broadcast should be disabled"
"""
        },
        {
            "name": "Proxy ARP Disabled",
            "description": "CIS 9.3: Ensure proxy ARP is disabled on untrusted interfaces",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Interface Security",
            "severity": "medium",
            "yaml_content": """
name: Proxy ARP Disabled
type: pattern
pattern: 'no\\s+ip\\s+proxy-arp'
severity: medium
message: "Proxy ARP should be disabled on untrusted interfaces"
"""
        },
        
        # ========== NTP CONFIGURATION (CIS, NIST) ==========
        {
            "name": "NTP Server Configured",
            "description": "CIS 10.1: Ensure NTP server is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Time Synchronization",
            "severity": "high",
            "yaml_content": """
name: NTP Server Configured
type: pattern
pattern: 'ntp\\s+server'
severity: high
message: "NTP server should be configured for time synchronization"
"""
        },
        {
            "name": "NTP Authentication",
            "description": "CIS 10.2: Ensure NTP authentication is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Time Synchronization",
            "severity": "high",
            "yaml_content": """
name: NTP Authentication
type: pattern
pattern: 'ntp\\s+authenticate'
severity: high
message: "NTP authentication should be configured"
"""
        },
        
        # ========== VLAN SECURITY (CIS, NIST) ==========
        {
            "name": "VLAN Trunking Protocol Disabled",
            "description": "CIS 11.1: Ensure VTP is disabled if not needed",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "VLAN Security",
            "severity": "medium",
            "yaml_content": """
name: VLAN Trunking Protocol Disabled
type: pattern
pattern: 'vtp\\s+mode'
severity: medium
message: "VTP should be disabled or set to transparent mode if not needed"
"""
        },
        {
            "name": "VLAN Access Control",
            "description": "CIS 11.2: Ensure VLAN access control is properly configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "VLAN Security",
            "severity": "high",
            "yaml_content": """
name: VLAN Access Control
type: pattern
pattern: 'switchport\\s+access\\s+vlan'
severity: high
message: "VLAN access should be properly configured"
"""
        },
        
        # ========== FIREWALL RULES (NIST, PCI DSS) ==========
        {
            "name": "Firewall Rules Configured",
            "description": "NIST: Ensure firewall rules are configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Firewall",
            "severity": "high",
            "yaml_content": """
name: Firewall Rules Configured
type: pattern
pattern: '(access-list|ip\\s+access-group)'
severity: high
message: "Firewall rules should be configured"
"""
        },
        {
            "name": "Default Deny Policy",
            "description": "NIST: Ensure default deny policy is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Firewall",
            "severity": "high",
            "yaml_content": """
name: Default Deny Policy
type: pattern
pattern: 'deny\\s+ip\\s+any\\s+any'
severity: high
message: "Default deny policy should be configured"
"""
        },
        
        # ========== PORT SECURITY (CIS) ==========
        {
            "name": "Port Security Enabled",
            "description": "CIS 12.1: Ensure port security is enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Port Security",
            "severity": "high",
            "yaml_content": """
name: Port Security Enabled
type: pattern
pattern: 'switchport\\s+port-security'
severity: high
message: "Port security should be enabled on switch ports"
"""
        },
        {
            "name": "Port Security Maximum MACs",
            "description": "CIS 12.2: Ensure port security maximum MACs is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Port Security",
            "severity": "medium",
            "yaml_content": """
name: Port Security Maximum MACs
type: pattern
pattern: 'switchport\\s+port-security\\s+maximum'
severity: medium
message: "Port security maximum MAC addresses should be configured"
"""
        },
        
        # ========== STP SECURITY (CIS) ==========
        {
            "name": "Root Guard Enabled",
            "description": "CIS 13.1: Ensure root guard is enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "STP Security",
            "severity": "medium",
            "yaml_content": """
name: Root Guard Enabled
type: pattern
pattern: 'spanning-tree\\s+guard\\s+root'
severity: medium
message: "Root guard should be enabled on switch ports"
"""
        },
        {
            "name": "BPDU Guard Enabled",
            "description": "CIS 13.2: Ensure BPDU guard is enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "STP Security",
            "severity": "medium",
            "yaml_content": """
name: BPDU Guard Enabled
type: pattern
pattern: 'spanning-tree\\s+bpduguard\\s+enable'
severity: medium
message: "BPDU guard should be enabled on switch ports"
"""
        },
        
        # ========== DHCP SECURITY (CIS, NIST) ==========
        {
            "name": "DHCP Snooping Enabled",
            "description": "CIS 14.1: Ensure DHCP snooping is enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "DHCP Security",
            "severity": "high",
            "yaml_content": """
name: DHCP Snooping Enabled
type: pattern
pattern: 'ip\\s+dhcp\\s+snooping'
severity: high
message: "DHCP snooping should be enabled to prevent rogue DHCP servers"
"""
        },
        {
            "name": "DHCP Snooping Trust",
            "description": "CIS 14.2: Ensure DHCP snooping trust is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "DHCP Security",
            "severity": "high",
            "yaml_content": """
name: DHCP Snooping Trust
type: pattern
pattern: 'ip\\s+dhcp\\s+snooping\\s+trust'
severity: high
message: "DHCP snooping trust should be configured on uplink ports"
"""
        },
        
        # ========== ARP SECURITY (CIS, NIST) ==========
        {
            "name": "Dynamic ARP Inspection Enabled",
            "description": "CIS 15.1: Ensure dynamic ARP inspection is enabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "ARP Security",
            "severity": "high",
            "yaml_content": """
name: Dynamic ARP Inspection Enabled
type: pattern
pattern: 'ip\\s+arp\\s+inspection'
severity: high
message: "Dynamic ARP inspection should be enabled to prevent ARP spoofing"
"""
        },
        
        # ========== IPV6 SECURITY (CIS, NIST) ==========
        {
            "name": "IPv6 Unused Features Disabled",
            "description": "CIS 16.1: Ensure unused IPv6 features are disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "IPv6 Security",
            "severity": "medium",
            "yaml_content": """
name: IPv6 Unused Features Disabled
type: pattern
pattern: 'no\\s+ipv6\\s+(redirects|unreachables)'
severity: medium
message: "Unused IPv6 features should be disabled"
"""
        },
        
        # ========== MANAGEMENT PLANE SECURITY (CIS) ==========
        {
            "name": "Management Plane Protection",
            "description": "CIS 17.1: Ensure management plane protection is configured",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Management Plane",
            "severity": "high",
            "yaml_content": """
name: Management Plane Protection
type: pattern
pattern: 'control-plane'
severity: high
message: "Management plane protection should be configured"
"""
        },
        
        # ========== ADDITIONAL SECURITY BEST PRACTICES ==========
        {
            "name": "Unicast RPF Enabled",
            "description": "NIST: Ensure unicast RPF is enabled where appropriate",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Network Security",
            "severity": "medium",
            "yaml_content": """
name: Unicast RPF Enabled
type: pattern
pattern: 'ip\\s+verify\\s+unicast\\s+source'
severity: medium
message: "Unicast RPF should be enabled to prevent spoofing"
"""
        },
        {
            "name": "ICMP Redirects Disabled",
            "description": "Best Practice: Ensure ICMP redirects are disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Network Security",
            "severity": "medium",
            "yaml_content": """
name: ICMP Redirects Disabled
type: pattern
pattern: 'no\\s+ip\\s+redirects'
severity: medium
message: "ICMP redirects should be disabled"
"""
        },
        {
            "name": "Gratuitous ARP Disabled",
            "description": "Best Practice: Ensure gratuitous ARP is disabled",
            "rule_type": Rule.TYPE_PATTERN,
            "category": "Network Security",
            "severity": "low",
            "yaml_content": """
name: Gratuitous ARP Disabled
type: pattern
pattern: 'no\\s+ip\\s+gratuitous-arps'
severity: low
message: "Gratuitous ARP should be disabled"
"""
        },
    ]
    
    # Add all rules to database
    added_count = 0
    skipped_count = 0
    
    for rule_data in rules:
        try:
            # Check if rule already exists
            existing = Rule.get_by_id(rule_data.get('id', 0))
            if existing:
                skipped_count += 1
                continue
            
            # Determine tags based on rule name/content
            tags = rule_data.get('tags', ['cisco', 'all'])  # Default to cisco and all
            
            Rule.create(
                name=rule_data['name'],
                description=rule_data['description'],
                rule_type=rule_data['rule_type'],
                category=rule_data['category'],
                severity=rule_data['severity'],
                yaml_content=rule_data['yaml_content'],
                tags=tags
            )
            added_count += 1
        except Exception as e:
            print(f"Error adding rule '{rule_data['name']}': {e}")
            skipped_count += 1
    
    print(f"\nRules population complete!")
    print(f"  Added: {added_count} rules")
    print(f"  Skipped: {skipped_count} rules")
    print(f"  Total rules in database: {len(Rule.get_all(enabled_only=False))}")

if __name__ == "__main__":
    print("Initializing database...")
    init_database()
    print("Populating benchmark rules...")
    populate_benchmark_rules()
    print("Done!")


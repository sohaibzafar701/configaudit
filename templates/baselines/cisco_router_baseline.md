# MMBL Baseline Configuration: Cisco Router

## Overview
This baseline defines security requirements for Cisco routers based on international standards (ISO 27001, NIST Cybersecurity Framework, PCI-DSS) and MMBL security posture.

## Compliance Frameworks
- ISO 27001
- NIST Cybersecurity Framework
- PCI-DSS
- CIS Benchmarks

## Security Requirements by Category

### Authentication
- **AAA Authentication**: Enable AAA new-model for centralized authentication
- **Local User Accounts**: Configure secure local user accounts with strong passwords
- **TACACS+/RADIUS**: Configure external authentication servers
- **Password Encryption**: Enable password encryption (service password-encryption)

### Encryption
- **SSH Access**: Enable SSH version 2 for secure remote access
- **HTTPS Management**: Enable HTTPS for web-based management
- **Disable Insecure Protocols**: Disable Telnet, HTTP, SNMP v1/v2c

### Access Control
- **ACL Configuration**: Configure access control lists for traffic filtering
- **Management Plane Protection**: Implement control plane policing
- **VTY Access Control**: Restrict VTY access to authorized IP addresses

### Logging
- **Syslog Configuration**: Configure syslog server for centralized logging
- **Logging Levels**: Set appropriate logging levels for security events
- **Timestamp**: Enable timestamps on log messages

### SNMP Security
- **SNMPv3**: Use SNMPv3 with authentication and encryption
- **Community Strings**: Remove default community strings
- **Access Control**: Restrict SNMP access to authorized hosts

### Network Services
- **Disable Unused Services**: Disable unnecessary network services (CDP, NTP, etc.)
- **NTP Configuration**: Configure secure NTP synchronization
- **DNS Configuration**: Configure secure DNS resolution

## Example Configuration Template

```
! MMBL Baseline Configuration for Cisco Router
! Vendor: Cisco
! Device Type: Router
! Compliance: ISO27001, NIST, PCI-DSS

! Authentication
aaa new-model
aaa authentication login default group tacacs+ local
aaa authorization exec default group tacacs+ local
username admin privilege 15 secret <strong-password>

! Encryption
ip ssh version 2
ip http secure-server
no ip http server

! Access Control
ip access-list extended MANAGEMENT-ACL
 permit tcp <trusted-network> any eq 22
 permit tcp <trusted-network> any eq 443
 deny ip any any

! Logging
logging host <syslog-server>
logging trap informational
service timestamps log datetime msec

! SNMP Security
snmp-server group MMBL-GROUP v3 auth read MMBL-VIEW
snmp-server view MMBL-VIEW internet included
snmp-server user admin MMBL-GROUP v3 auth sha <auth-key> priv aes 128 <priv-key>

! Disable Unused Services
no cdp run
no ip bootp server
no ip domain-lookup
```

## MMBL-Specific Customizations
- Management network ACL: Restrict management access to MMBL internal networks
- Syslog server: Configure to send logs to MMBL SIEM system
- NTP server: Use MMBL internal NTP servers
- SNMP community: Use MMBL-specific community strings

## Remediation Priority
1. **Critical**: Authentication, Access Control, Encryption
2. **High**: Logging, SNMP Security
3. **Medium**: Network Services Configuration

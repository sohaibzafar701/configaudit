# MMBL Baseline Configuration: Cisco Switch

## Overview
This baseline defines security requirements for Cisco switches based on international standards and MMBL security posture.

## Compliance Frameworks
- ISO 27001
- NIST Cybersecurity Framework
- CIS Benchmarks

## Security Requirements by Category

### Authentication
- **AAA Authentication**: Enable AAA new-model
- **Local User Accounts**: Secure local user configuration
- **TACACS+/RADIUS**: External authentication servers

### Encryption
- **SSH Access**: Enable SSH version 2
- **HTTPS Management**: Secure web management

### Access Control
- **Port Security**: Configure port security on access ports
- **VLAN Security**: Implement VLAN access control
- **STP Security**: Configure spanning-tree security features

### Logging
- **Syslog Configuration**: Centralized logging
- **Logging Levels**: Appropriate security event logging

## Example Configuration Template

```
! MMBL Baseline Configuration for Cisco Switch
! Vendor: Cisco
! Device Type: Switch

! Authentication
aaa new-model
aaa authentication login default group tacacs+ local

! Encryption
ip ssh version 2

! Port Security
interface GigabitEthernet0/1
 switchport mode access
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation restrict

! Logging
logging host <syslog-server>
```

## MMBL-Specific Customizations
- Port security: Maximum 2 MAC addresses per port
- VLAN configuration: Use MMBL VLAN assignments
- Management VLAN: Dedicated VLAN for management traffic

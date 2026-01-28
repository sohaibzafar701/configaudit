# MMBL Baseline Configuration: Juniper Firewall

## Overview
This baseline defines security requirements for Juniper firewalls (SRX series) based on international standards and MMBL security posture.

## Compliance Frameworks
- ISO 27001
- NIST Cybersecurity Framework
- PCI-DSS

## Security Requirements by Category

### Authentication
- **Root Authentication**: Configure secure root password
- **User Accounts**: Create individual user accounts
- **RADIUS/TACACS**: External authentication

### Encryption
- **SSH Access**: Enable SSH with version 2
- **HTTPS Management**: Secure web management

### Firewall Rules
- **Security Policies**: Configure security policies
- **Default Deny**: Implement default deny policy
- **Zone Configuration**: Configure security zones

### Logging
- **Syslog Configuration**: Centralized logging
- **Security Event Logging**: Log security policy matches

## Example Configuration Template

```
# MMBL Baseline Configuration for Juniper Firewall
# Vendor: Juniper
# Device Type: Firewall

set system root-authentication encrypted-password "<encrypted-password>"
set system login user admin class super-user authentication encrypted-password "<password>"

set system services ssh
set system services web-management https

set security zones security-zone trust
set security zones security-zone untrust

set security policies default-policy deny-all

set system syslog host <syslog-server> any info
```

## MMBL-Specific Customizations
- Security zones: Trust, Untrust, DMZ zones
- Policy logging: Log all security policy matches
- Management access: Restrict to MMBL management network

# MMBL Baseline Configuration: Fortinet Firewall

## Overview
This baseline defines security requirements for Fortinet FortiOS firewalls based on international standards and MMBL security posture.

## Compliance Frameworks
- ISO 27001
- NIST Cybersecurity Framework
- PCI-DSS
- CIS Benchmarks

## Security Requirements by Category

### Authentication
- **Admin User**: Configure secure admin user
- **LDAP/RADIUS**: External authentication
- **Two-Factor Authentication**: Enable 2FA for admin access

### Firewall Policies
- **Security Policies**: Configure firewall policies
- **Default Deny**: Implement default deny policy
- **Security Profiles**: Configure antivirus, IPS, application control

### VPN Configuration
- **IPSec VPN**: Configure secure IPSec VPN
- **SSL VPN**: Configure SSL VPN with strong authentication

### Logging
- **Log Settings**: Enable comprehensive logging
- **Syslog Server**: Configure syslog forwarding

## Example Configuration Template

```
# MMBL Baseline Configuration for Fortinet Firewall
# Vendor: Fortinet
# Device Type: Firewall

config system admin
    edit admin
        set password <strong-password>
        set trusthost1 <mmbl-management-network>
    next
end

config firewall policy
    edit 1
        set name "MMBL-Default-Deny"
        set action deny
        set srcintf "any"
        set dstintf "any"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
    next
end

config log setting
    set status enable
    set log invalid-traffic enable
end

config log syslogd setting
    set status enable
    set server <syslog-server>
end
```

## MMBL-Specific Customizations
- Management access: Restricted to MMBL management network
- Security profiles: MMBL-approved security profiles
- VPN configuration: MMBL VPN policies

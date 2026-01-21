#!/usr/bin/env python3
"""
Add tags/vendor support to existing rules
"""

from services.database import get_db_connection
from models.rule import Rule

def add_tags_column():
    """Add tags column to rule table if it doesn't exist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Try to add tags column
        cursor.execute("ALTER TABLE rule ADD COLUMN tags TEXT")
        conn.commit()
        print("Added 'tags' column to rule table")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e).lower():
            print("Tags column already exists")
        else:
            raise
    
    conn.close()

def update_rules_with_tags():
    """Update existing rules with vendor tags based on their content"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Vendor mapping based on rule patterns
    vendor_tags = {
        # Cisco-specific rules
        'cisco': [
            'AAA Authentication Required',
            'CDP Disabled',
            'LLDP Disabled',
            'VLAN Trunking Protocol Disabled',
            'Port Security Enabled',
            'Port Security Maximum MACs',
            'Root Guard Enabled',
            'BPDU Guard Enabled',
            'DHCP Snooping Enabled',
            'DHCP Snooping Trust',
            'Dynamic ARP Inspection Enabled',
            'Management Plane Protection',
        ],
        # Multi-vendor rules (apply to all)
        'all': [
            'Default Credentials Check',
            'SSH Enabled',
            'SSH Version 2 Only',
            'HTTPS Enabled',
            'HTTP Disabled',
            'SNMPv3 Required',
            'Telnet Disabled',
            'Access Control Lists Configured',
            'Syslog Server Configured',
            'Logging Timestamps Enabled',
            'Password Encryption Enabled',
            'Minimum Password Length',
            'NTP Server Configured',
            'NTP Authentication',
        ],
        # Juniper-specific (if we had Juniper rules)
        'juniper': [],
        # Arista-specific (if we had Arista rules)
        'arista': [],
    }
    
    # Get all rules
    cursor.execute("SELECT id, name FROM rule")
    rules = cursor.fetchall()
    
    updated = 0
    for rule_id, rule_name in rules:
        tags = []
        
        # Check which vendors this rule applies to
        for vendor, rule_names in vendor_tags.items():
            if vendor == 'all' or rule_name in rule_names:
                tags.append(vendor)
        
        # If no specific vendor match, default to 'cisco' (most common)
        if not tags:
            tags = ['cisco']
        
        # Update rule with tags
        tags_str = ','.join(tags)
        cursor.execute("UPDATE rule SET tags = ? WHERE id = ?", (tags_str, rule_id))
        updated += 1
    
    conn.commit()
    conn.close()
    
    print(f"Updated {updated} rules with vendor tags")

if __name__ == "__main__":
    import sqlite3
    add_tags_column()
    update_rules_with_tags()
    print("Done!")


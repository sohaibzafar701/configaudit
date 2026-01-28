"""
Device metadata extraction from configuration files
"""

import re

def extract_metadata(config_text, device_family=None):
    """Extract device metadata from configuration text"""
    metadata = {
        'hostname': None,
        'model': None,
        'firmware': None,
        'location': None,
        'make': None,
        'type': None
    }
    
    if not config_text:
        return metadata
    
    # Extract hostname (common patterns)
    # Cisco: hostname <name>
    hostname_match = re.search(r'hostname\s+(\S+)', config_text, re.IGNORECASE)
    if hostname_match:
        metadata['hostname'] = hostname_match.group(1)
    
    # Juniper: system { host-name <name>; }
    if not metadata['hostname']:
        hostname_match = re.search(r'host-name\s+(\S+)', config_text, re.IGNORECASE)
        if hostname_match:
            metadata['hostname'] = hostname_match.group(1)
    
    # Huawei: sysname <name>
    if not metadata['hostname']:
        hostname_match = re.search(r'^sysname\s+(\S+)', config_text, re.MULTILINE | re.IGNORECASE)
        if hostname_match:
            metadata['hostname'] = hostname_match.group(1)
    
    # Sophos: hostname: <name> or hostname <name>
    if not metadata['hostname']:
        hostname_match = re.search(r'hostname:\s+(\S+)', config_text, re.IGNORECASE)
        if not hostname_match:
            hostname_match = re.search(r'hostname\s+(\S+)', config_text, re.IGNORECASE)
        if hostname_match:
            metadata['hostname'] = hostname_match.group(1)
    
    # Arista: hostname <name>
    if not metadata['hostname']:
        hostname_match = re.search(r'hostname\s+(\S+)', config_text, re.IGNORECASE)
        if hostname_match:
            metadata['hostname'] = hostname_match.group(1)
    
    # Extract model (Cisco: show version output often in configs)
    # Try generic "model" keyword first
    model_match = re.search(r'model\s+(\S+)', config_text, re.IGNORECASE)
    if model_match:
        metadata['model'] = model_match.group(1).strip()
    
    # Cisco: cisco <model> (revision) - e.g., "cisco WS-C2960X-48TS-L (revision"
    if not metadata['model']:
        model_match = re.search(r'cisco\s+([A-Z0-9\-]+)\s*\(revision', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Cisco: Model number patterns with full model name (e.g., "WS-C2960X-48TS-L")
    if not metadata['model']:
        model_match = re.search(r'(WS-[A-Z0-9\-]+|ASR\d+[A-Z0-9\-]*|ISR\d+[A-Z0-9\-]*|N[0-9]+[A-Z0-9\-]*)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Cisco: Catalyst/Nexus/ASR/ISR with model number (e.g., "Catalyst 9300", "Nexus 9000")
    if not metadata['model']:
        model_match = re.search(r'(?:Catalyst|Nexus|ASR|ISR)\s+(\d+[A-Z0-9\-]*)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = f"{model_match.group(0).strip()}"
    
    # Cisco: Full model string (e.g., "Cisco Catalyst 9300")
    if not metadata['model']:
        model_match = re.search(r'cisco\s+(?:catalyst|nexus|asr|isr)\s+(\d+[A-Z0-9\-]*)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = f"Catalyst {model_match.group(1).strip()}" if 'catalyst' in model_match.group(0).lower() else model_match.group(1).strip()
    
    # Juniper: Model patterns (e.g., "MX240", "EX4300", "SRX340")
    if not metadata['model']:
        model_match = re.search(r'(MX\d+|EX\d+|SRX\d+|QFX\d+|PTX\d+|ACX\d+|NFX\d+)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Juniper: chassis-type (e.g., "chassis-type mx240")
    if not metadata['model']:
        model_match = re.search(r'chassis-type\s+(\S+)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Arista: Model patterns (e.g., "DCS-7050SX-64")
    if not metadata['model']:
        model_match = re.search(r'(DCS-[A-Z0-9\-]+)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Arista: hardware model
    if not metadata['model']:
        model_match = re.search(r'hardware\s+model\s+(\S+)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Palo Alto: Model patterns (e.g., "PA-220", "PA-5220")
    if not metadata['model']:
        model_match = re.search(r'(PA-\d+[A-Z0-9\-]*)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Fortinet: Model patterns (e.g., "FortiGate-60E", "FortiGate-200E")
    if not metadata['model']:
        model_match = re.search(r'(FortiGate-\d+[A-Z0-9\-]*)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Check Point: Model patterns (e.g., "Check Point 2200", "Check Point 4200")
    if not metadata['model']:
        model_match = re.search(r'(?:check\s+point|gaia)\s+(\d+[A-Z0-9\-]*)', config_text, re.IGNORECASE)
        if model_match:
            metadata['model'] = model_match.group(1).strip()
    
    # Extract firmware/version
    # Cisco: version <version>
    version_match = re.search(r'version\s+(\S+)', config_text, re.IGNORECASE)
    if version_match:
        metadata['firmware'] = version_match.group(1)
    
    # Juniper: version <version>
    if not metadata['firmware']:
        version_match = re.search(r'junos:\s*(\S+)', config_text, re.IGNORECASE)
        if version_match:
            metadata['firmware'] = version_match.group(1)
    
    # Huawei: VRP version from display version output
    if not metadata['firmware']:
        version_match = re.search(r'VRP\s+\(R\)\s+software,\s+Version\s+(\S+)', config_text, re.IGNORECASE)
        if version_match:
            metadata['firmware'] = version_match.group(1)
        elif not metadata['firmware']:
            version_match = re.search(r'VRP\s+version\s+(\S+)', config_text, re.IGNORECASE)
            if version_match:
                metadata['firmware'] = version_match.group(1)
    
    # Sophos: UTM/XG version
    if not metadata['firmware']:
        version_match = re.search(r'utm\s+version\s+(\S+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'version:\s+(\S+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'xgsystem\s+(\S+)', config_text, re.IGNORECASE)
        if version_match:
            metadata['firmware'] = version_match.group(1)
    
    # Extract location (if present in config comments or snmp location)
    location_match = re.search(r'snmp-server\s+location\s+(.+?)(?:\n|$)', config_text, re.IGNORECASE)
    if location_match:
        metadata['location'] = location_match.group(1).strip()
    
    # Try to find location in comments
    if not metadata['location']:
        location_match = re.search(r'!.*location[:\s]+(.+?)(?:\n|$)', config_text, re.IGNORECASE)
        if location_match:
            metadata['location'] = location_match.group(1).strip()
    
    # Detect device make (vendor)
    # Cisco patterns
    if re.search(r'cisco\s+ios|cisco\s+ios-xe|cisco\s+nx-os|version\s+\d+\.\d+', config_text, re.IGNORECASE):
        metadata['make'] = 'Cisco'
    # Juniper patterns
    elif re.search(r'set\s+version|junos:|system\s+\{', config_text, re.IGNORECASE):
        metadata['make'] = 'Juniper'
    # Arista patterns
    elif re.search(r'arista|eos\s+\d+\.\d+', config_text, re.IGNORECASE):
        metadata['make'] = 'Arista'
    # Palo Alto patterns
    elif re.search(r'palo\s+alto|pan-os|set\s+deviceconfig', config_text, re.IGNORECASE):
        metadata['make'] = 'Palo Alto'
    # Fortinet patterns
    elif re.search(r'fortinet|fortios|config\s+system', config_text, re.IGNORECASE):
        metadata['make'] = 'Fortinet'
    # Check Point patterns
    elif re.search(r'check\s+point|gaia|set\s+hostname', config_text, re.IGNORECASE):
        metadata['make'] = 'Check Point'
    # Huawei patterns
    elif re.search(r'^sysname\s+|huawei|vrp\s+version|display\s+version', config_text, re.MULTILINE | re.IGNORECASE):
        metadata['make'] = 'Huawei'
    # Sophos patterns
    elif re.search(r'sophos|utm\s+version|xgsystem|interfaces:\s*ethernet', config_text, re.IGNORECASE):
        metadata['make'] = 'Sophos'
    
    # Detect device type (best effort)
    # Firewall indicators
    if re.search(r'security-policy|firewall|security-rule|nat\s+rule|security\s+zone', config_text, re.IGNORECASE):
        metadata['type'] = 'Firewall'
    # Switch indicators
    elif re.search(r'switchport|vlan\s+\d+|spanning-tree|ethernet-switching', config_text, re.IGNORECASE):
        metadata['type'] = 'Switch'
    # Router indicators
    elif re.search(r'router\s+(?:ospf|bgp|eigrp|isis)|routing-protocol|ip\s+route', config_text, re.IGNORECASE):
        metadata['type'] = 'Router'
    # Wireless controller indicators
    elif re.search(r'wireless|wlan|ap\s+group|radio', config_text, re.IGNORECASE):
        metadata['type'] = 'Wireless Controller'
    # Load balancer indicators
    elif re.search(r'load\s+balance|virtual-server|pool|health-check', config_text, re.IGNORECASE):
        metadata['type'] = 'Load Balancer'
    
    return metadata


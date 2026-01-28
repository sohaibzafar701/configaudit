"""
Sophos UTM/XG parser
"""

import re
from parsers.base import BaseParser

class SophosParser(BaseParser):
    """Parser for Sophos UTM/XG firewall configurations"""
    
    def get_vendor(self):
        return "Sophos"
    
    def can_parse(self, config_text):
        """Check if config text is Sophos format"""
        # Sophos indicators
        sophos_indicators = [
            r'hostname\s+',
            r'interfaces:\s*ethernet',
            r'firewall\s+rules',
            r'sophos',
            r'utm\s+version',
            r'xgsystem',
        ]
        
        for pattern in sophos_indicators:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return True
        return False
    
    def detect_device_family(self, config_text):
        """Detect device family from configuration"""
        # Try to extract version info
        version_match = re.search(r'utm\s+version\s+(\S+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'version:\s+(\S+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'xgsystem\s+(\S+)', config_text, re.IGNORECASE)
        version = version_match.group(1) if version_match else "Unknown"
        
        # Determine product type
        product = "UTM"
        if re.search(r'xgsystem|xg\s+firewall', config_text, re.IGNORECASE):
            product = "XG"
        
        # Try to detect hostname
        hostname_match = re.search(r'hostname:\s+(\S+)', config_text, re.IGNORECASE)
        if not hostname_match:
            hostname_match = re.search(r'hostname\s+(\S+)', config_text, re.IGNORECASE)
        hostname = hostname_match.group(1) if hostname_match else "Unknown"
        
        return f"Sophos {product} {version} ({hostname})"
    
    def parse(self, config_text):
        """Parse Sophos configuration"""
        # Simple parsing - extract key sections
        raw_ast = {
            'hostname': self._extract_hostname(config_text),
            'interfaces': self._extract_interfaces(config_text),
            'firewall_rules': self._extract_firewall_rules(config_text),
            'vpn_configs': self._extract_vpn_configs(config_text),
            'system': self._extract_system(config_text),
        }
        
        # Normalized security sections
        normalized = {
            'authentication': self._normalize_authentication(config_text),
            'encryption': self._normalize_encryption(config_text),
            'access_control': self._normalize_access_control(config_text),
        }
        
        return {
            'raw_ast': raw_ast,
            'normalized': normalized,
            'original': config_text
        }
    
    def _extract_hostname(self, config_text):
        """Extract hostname"""
        match = re.search(r'hostname:\s+(\S+)', config_text, re.IGNORECASE)
        if not match:
            match = re.search(r'hostname\s+(\S+)', config_text, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_interfaces(self, config_text):
        """Extract interface configurations"""
        interfaces = []
        current_interface = None
        current_config = []
        in_interface_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Start of interfaces block (UTM format)
            if re.match(r'interfaces:\s*$', line_stripped, re.IGNORECASE):
                in_interface_block = True
                continue
            # Interface declaration (UTM format)
            elif in_interface_block and re.match(r'ethernet\s+(\S+):', line_stripped, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'ethernet\s+(\S+):', line_stripped, re.IGNORECASE)
                current_interface = match.group(1) if match else None
                current_config = [line_stripped]
            # XG format interface
            elif re.match(r'interface\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'interface\s+(\S+)', line_stripped, re.IGNORECASE)
                current_interface = match.group(1) if match else None
                current_config = [line_stripped]
            # End of interface block
            elif in_interface_block and not line_stripped:
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                    current_interface = None
                    current_config = []
                    in_interface_block = False
            elif (in_interface_block or current_interface) and line_stripped:
                if not re.match(r'^firewall|^vpn|^system', line_stripped, re.IGNORECASE):
                    current_config.append(line_stripped)
        
        if current_interface:
            interfaces.append({
                'name': current_interface,
                'config': '\n'.join(current_config)
            })
        
        return interfaces
    
    def _extract_firewall_rules(self, config_text):
        """Extract firewall rule configurations"""
        rules = []
        current_rule = None
        current_lines = []
        in_rules_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Start of firewall rules block
            if re.match(r'firewall\s+rules:', line_stripped, re.IGNORECASE):
                in_rules_block = True
                continue
            # Rule declaration (UTM format)
            elif in_rules_block and re.match(r'rule\s+(\S+):', line_stripped, re.IGNORECASE):
                if current_rule:
                    rules.append({
                        'name': current_rule,
                        'lines': current_lines
                    })
                match = re.match(r'rule\s+(\S+):', line_stripped, re.IGNORECASE)
                current_rule = match.group(1) if match else None
                current_lines = [line_stripped]
            # XG format firewall rule
            elif re.match(r'firewall\s+rule\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_rule:
                    rules.append({
                        'name': current_rule,
                        'lines': current_lines
                    })
                match = re.match(r'firewall\s+rule\s+(\S+)', line_stripped, re.IGNORECASE)
                current_rule = match.group(1) if match else None
                current_lines = [line_stripped]
            # End of rules block
            elif in_rules_block and not line_stripped:
                if current_rule:
                    rules.append({
                        'name': current_rule,
                        'lines': current_lines
                    })
                    current_rule = None
                    current_lines = []
                    in_rules_block = False
            elif (in_rules_block or current_rule) and line_stripped:
                if not re.match(r'^vpn|^system|^interfaces', line_stripped, re.IGNORECASE):
                    current_lines.append(line_stripped)
        
        if current_rule:
            rules.append({
                'name': current_rule,
                'lines': current_lines
            })
        
        return rules
    
    def _extract_vpn_configs(self, config_text):
        """Extract VPN configurations"""
        vpn_configs = []
        current_vpn = None
        current_lines = []
        in_vpn_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Start of VPN block
            if re.match(r'vpn\s+configurations:', line_stripped, re.IGNORECASE) or \
               re.match(r'ipsec\s+vpn:', line_stripped, re.IGNORECASE):
                in_vpn_block = True
                continue
            # VPN declaration
            elif in_vpn_block and re.match(r'vpn\s+(\S+):', line_stripped, re.IGNORECASE):
                if current_vpn:
                    vpn_configs.append({
                        'name': current_vpn,
                        'lines': current_lines
                    })
                match = re.match(r'vpn\s+(\S+):', line_stripped, re.IGNORECASE)
                current_vpn = match.group(1) if match else None
                current_lines = [line_stripped]
            # End of VPN block
            elif in_vpn_block and not line_stripped:
                if current_vpn:
                    vpn_configs.append({
                        'name': current_vpn,
                        'lines': current_lines
                    })
                    current_vpn = None
                    current_lines = []
                    in_vpn_block = False
            elif (in_vpn_block or current_vpn) and line_stripped:
                if not re.match(r'^firewall|^system|^interfaces', line_stripped, re.IGNORECASE):
                    current_lines.append(line_stripped)
        
        if current_vpn:
            vpn_configs.append({
                'name': current_vpn,
                'lines': current_lines
            })
        
        return vpn_configs
    
    def _extract_system(self, config_text):
        """Extract system configuration"""
        system_config = []
        in_system_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            if re.match(r'system\s+configuration:', line_stripped, re.IGNORECASE) or \
               re.match(r'system:', line_stripped, re.IGNORECASE):
                in_system_block = True
                system_config.append(line_stripped)
            elif in_system_block:
                if not line_stripped or re.match(r'^firewall|^vpn|^interfaces', line_stripped, re.IGNORECASE):
                    in_system_block = False
                    if not line_stripped:
                        continue
                elif line_stripped:
                    system_config.append(line_stripped)
        
        return system_config
    
    def _normalize_authentication(self, config_text):
        """Normalize authentication settings"""
        return {
            'admin_configured': bool(re.search(r'admin\s+user|administrator', config_text, re.IGNORECASE)),
            'ldap_enabled': bool(re.search(r'ldap\s+authentication|ldap\s+server', config_text, re.IGNORECASE)),
            'radius_enabled': bool(re.search(r'radius\s+authentication|radius\s+server', config_text, re.IGNORECASE)),
            'local_users': len(re.findall(r'user\s+\S+', config_text, re.IGNORECASE)),
        }
    
    def _normalize_encryption(self, config_text):
        """Normalize encryption settings"""
        return {
            'ssh_enabled': bool(re.search(r'ssh\s+enabled|ssh\s+access', config_text, re.IGNORECASE)),
            'https_enabled': bool(re.search(r'https\s+enabled|https\s+access', config_text, re.IGNORECASE)),
            'ipsec_enabled': len(self._extract_vpn_configs(config_text)) > 0,
            'ssl_vpn_enabled': bool(re.search(r'ssl\s+vpn|remote\s+access\s+vpn', config_text, re.IGNORECASE)),
        }
    
    def _normalize_access_control(self, config_text):
        """Normalize access control settings"""
        return {
            'firewall_rules': len(self._extract_firewall_rules(config_text)),
            'security_zones': len(re.findall(r'zone\s+\S+', config_text, re.IGNORECASE)),
        }

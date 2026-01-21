"""
Juniper JunOS parser
"""

import re
from parsers.base import BaseParser

class JuniperParser(BaseParser):
    """Parser for Juniper JunOS configurations"""
    
    def get_vendor(self):
        return "Juniper"
    
    def can_parse(self, config_text):
        """Check if config text is Juniper format"""
        # Juniper indicators
        juniper_indicators = [
            r'set\s+version',
            r'set\s+system\s+host-name',
            r'set\s+interfaces\s+\S+',
            r'JUNOS',
            r'set\s+groups\s+',
        ]
        
        for pattern in juniper_indicators:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return True
        return False
    
    def detect_device_family(self, config_text):
        """Detect device family from configuration"""
        # Try to extract version info
        version_match = re.search(r'set\s+version\s+(\S+)', config_text, re.IGNORECASE)
        version = version_match.group(1) if version_match else "Unknown"
        
        # Try to detect model from hostname
        hostname_match = re.search(r'set\s+system\s+host-name\s+(\S+)', config_text, re.IGNORECASE)
        hostname = hostname_match.group(1) if hostname_match else "Unknown"
        
        # Check for JUNOS version in banner
        junos_match = re.search(r'JUNOS\s+(\S+)', config_text, re.IGNORECASE)
        if junos_match:
            version = junos_match.group(1)
        
        return f"Juniper JunOS {version} ({hostname})"
    
    def parse(self, config_text):
        """Parse Juniper configuration"""
        # Simple parsing - extract key sections
        raw_ast = {
            'hostname': self._extract_hostname(config_text),
            'interfaces': self._extract_interfaces(config_text),
            'firewall_filters': self._extract_firewall_filters(config_text),
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
        match = re.search(r'set\s+system\s+host-name\s+(\S+)', config_text, re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_interfaces(self, config_text):
        """Extract interface configurations"""
        interfaces = []
        current_interface = None
        current_config = []
        
        for line in config_text.split('\n'):
            if re.match(r'set\s+interfaces\s+(\S+)', line, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'set\s+interfaces\s+(\S+)', line, re.IGNORECASE)
                current_interface = match.group(1) if match else None
                current_config = [line.strip()]
            elif current_interface and line.strip() and line.strip().startswith('set'):
                current_config.append(line.strip())
        
        if current_interface:
            interfaces.append({
                'name': current_interface,
                'config': '\n'.join(current_config)
            })
        
        return interfaces
    
    def _extract_firewall_filters(self, config_text):
        """Extract firewall filter configurations"""
        filters = []
        current_filter = None
        current_lines = []
        
        for line in config_text.split('\n'):
            if re.match(r'set\s+firewall\s+family\s+\S+\s+filter\s+(\S+)', line, re.IGNORECASE):
                if current_filter:
                    filters.append({
                        'name': current_filter,
                        'lines': current_lines
                    })
                match = re.match(r'set\s+firewall\s+family\s+\S+\s+filter\s+(\S+)', line, re.IGNORECASE)
                current_filter = match.group(1) if match else None
                current_lines = []
            elif current_filter and line.strip() and line.strip().startswith('set'):
                current_lines.append(line.strip())
        
        if current_filter:
            filters.append({
                'name': current_filter,
                'lines': current_lines
            })
        
        return filters
    
    def _extract_system(self, config_text):
        """Extract system configuration"""
        system_config = []
        for line in config_text.split('\n'):
            if re.match(r'set\s+system\s+', line, re.IGNORECASE):
                system_config.append(line.strip())
        return system_config
    
    def _normalize_authentication(self, config_text):
        """Normalize authentication settings"""
        return {
            'root_auth': 'root-authentication' in config_text.lower(),
            'user_accounts': len(re.findall(r'set\s+system\s+login\s+user\s+', config_text, re.IGNORECASE)),
            'radius': 'radius-server' in config_text.lower(),
            'tacacs': 'tacplus' in config_text.lower(),
        }
    
    def _normalize_encryption(self, config_text):
        """Normalize encryption settings"""
        return {
            'ssh_enabled': 'ssh' in config_text.lower() and 'set system services ssh' in config_text.lower(),
            'ssh_version': 'protocol-version v2' in config_text.lower(),
        }
    
    def _normalize_access_control(self, config_text):
        """Normalize access control settings"""
        return {
            'firewall_filters': len(self._extract_firewall_filters(config_text)),
        }


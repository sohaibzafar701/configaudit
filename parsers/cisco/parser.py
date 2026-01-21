"""
Cisco IOS/IOS-XE parser
"""

import re
from parsers.base import BaseParser

class CiscoParser(BaseParser):
    """Parser for Cisco IOS/IOS-XE configurations"""
    
    def get_vendor(self):
        return "Cisco"
    
    def can_parse(self, config_text):
        """Check if config text is Cisco format"""
        # Simple detection: look for Cisco-specific commands
        cisco_indicators = [
            r'^hostname\s+',
            r'^interface\s+',
            r'^ip\s+address\s+',
            r'^version\s+\d+\.\d+',
        ]
        
        for pattern in cisco_indicators:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return True
        return False
    
    def detect_device_family(self, config_text):
        """Detect device family from configuration"""
        # Try to extract version info
        version_match = re.search(r'version\s+(\S+)', config_text, re.IGNORECASE)
        version = version_match.group(1) if version_match else "Unknown"
        
        # Try to detect model from hostname or other indicators
        hostname_match = re.search(r'^hostname\s+(\S+)', config_text, re.MULTILINE | re.IGNORECASE)
        hostname = hostname_match.group(1) if hostname_match else "Unknown"
        
        return f"Cisco IOS {version} ({hostname})"
    
    def parse(self, config_text):
        """Parse Cisco configuration"""
        # Simple parsing - extract key sections
        raw_ast = {
            'hostname': self._extract_hostname(config_text),
            'interfaces': self._extract_interfaces(config_text),
            'access_lists': self._extract_access_lists(config_text),
            'lines': self._extract_lines(config_text),
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
        match = re.search(r'^hostname\s+(\S+)', config_text, re.MULTILINE | re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_interfaces(self, config_text):
        """Extract interface configurations"""
        interfaces = []
        current_interface = None
        current_config = []
        
        for line in config_text.split('\n'):
            if re.match(r'^interface\s+\S+', line, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                current_interface = line.strip()
                current_config = []
            elif current_interface:
                if line.strip() and not line.startswith('!'):
                    current_config.append(line.strip())
        
        if current_interface:
            interfaces.append({
                'name': current_interface,
                'config': '\n'.join(current_config)
            })
        
        return interfaces
    
    def _extract_access_lists(self, config_text):
        """Extract access list configurations"""
        acls = []
        current_acl = None
        current_lines = []
        
        for line in config_text.split('\n'):
            if re.match(r'^ip\s+access-list\s+\S+', line, re.IGNORECASE):
                if current_acl:
                    acls.append({
                        'name': current_acl,
                        'lines': current_lines
                    })
                current_acl = line.strip()
                current_lines = []
            elif current_acl and line.strip() and not line.startswith('!'):
                current_lines.append(line.strip())
        
        if current_acl:
            acls.append({
                'name': current_acl,
                'lines': current_lines
            })
        
        return acls
    
    def _extract_lines(self, config_text):
        """Extract line (console, vty) configurations"""
        lines = []
        current_line = None
        current_config = []
        
        for line in config_text.split('\n'):
            if re.match(r'^line\s+\S+', line, re.IGNORECASE):
                if current_line:
                    lines.append({
                        'name': current_line,
                        'config': '\n'.join(current_config)
                    })
                current_line = line.strip()
                current_config = []
            elif current_line and line.strip() and not line.startswith('!'):
                current_config.append(line.strip())
        
        if current_line:
            lines.append({
                'name': current_line,
                'config': '\n'.join(current_config)
            })
        
        return lines
    
    def _normalize_authentication(self, config_text):
        """Normalize authentication settings"""
        return {
            'aaa_enabled': 'aaa new-model' in config_text.lower(),
            'local_auth': 'username' in config_text.lower(),
            'tacacs': 'tacacs' in config_text.lower(),
        }
    
    def _normalize_encryption(self, config_text):
        """Normalize encryption settings"""
        return {
            'ssh_enabled': 'ip ssh' in config_text.lower(),
            'https_enabled': 'ip http secure-server' in config_text.lower(),
        }
    
    def _normalize_access_control(self, config_text):
        """Normalize access control settings"""
        return {
            'access_lists': len(self._extract_access_lists(config_text)),
            'firewall_rules': 0,  # TODO: Parse firewall rules
        }


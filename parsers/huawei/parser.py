"""
Huawei VRP parser
"""

import re
from parsers.base import BaseParser

class HuaweiParser(BaseParser):
    """Parser for Huawei VRP (Versatile Routing Platform) configurations"""
    
    def get_vendor(self):
        return "Huawei"
    
    def can_parse(self, config_text):
        """Check if config text is Huawei VRP format"""
        # Huawei indicators
        huawei_indicators = [
            r'^sysname\s+',
            r'^interface\s+',
            r'^vlan\s+\d+',
            r'^acl\s+number',
            r'^ip\s+address\s+',
            r'^local-user\s+',
            r'^aaa\s+',
            r'^display\s+version',
        ]
        
        for pattern in huawei_indicators:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return True
        return False
    
    def detect_device_family(self, config_text):
        """Detect device family from configuration"""
        # Try to extract version info from display version output
        version_match = re.search(r'VRP\s+\(R\)\s+software,\s+Version\s+(\S+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'Version\s+(\d+\.\d+\.\d+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'VRP\s+version\s+(\S+)', config_text, re.IGNORECASE)
        version = version_match.group(1) if version_match else "Unknown"
        
        # Try to detect hostname
        hostname_match = re.search(r'^sysname\s+(\S+)', config_text, re.MULTILINE | re.IGNORECASE)
        hostname = hostname_match.group(1) if hostname_match else "Unknown"
        
        return f"Huawei VRP {version} ({hostname})"
    
    def parse(self, config_text):
        """Parse Huawei configuration"""
        # Simple parsing - extract key sections
        raw_ast = {
            'hostname': self._extract_hostname(config_text),
            'interfaces': self._extract_interfaces(config_text),
            'acls': self._extract_acls(config_text),
            'vlans': self._extract_vlans(config_text),
            'users': self._extract_users(config_text),
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
        match = re.search(r'^sysname\s+(\S+)', config_text, re.MULTILINE | re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_interfaces(self, config_text):
        """Extract interface configurations"""
        interfaces = []
        current_interface = None
        current_config = []
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Interface declaration
            if re.match(r'^interface\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'^interface\s+(\S+)', line_stripped, re.IGNORECASE)
                current_interface = match.group(1) if match else None
                current_config = [line_stripped]
            # End of interface (or start of new section)
            elif current_interface:
                if re.match(r'^interface\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^vlan\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^acl\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^sysname\s+', line_stripped, re.IGNORECASE):
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                    current_interface = None
                    current_config = []
                elif line_stripped and not line_stripped.startswith('#'):
                    current_config.append(line_stripped)
        
        if current_interface:
            interfaces.append({
                'name': current_interface,
                'config': '\n'.join(current_config)
            })
        
        return interfaces
    
    def _extract_acls(self, config_text):
        """Extract ACL configurations"""
        acls = []
        current_acl = None
        current_lines = []
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # ACL number declaration
            if re.match(r'^acl\s+number\s+(\d+)', line_stripped, re.IGNORECASE):
                if current_acl:
                    acls.append({
                        'name': current_acl,
                        'lines': current_lines
                    })
                match = re.match(r'^acl\s+number\s+(\d+)', line_stripped, re.IGNORECASE)
                current_acl = match.group(1) if match else None
                current_lines = [line_stripped]
            # ACL rule
            elif current_acl and re.match(r'^rule\s+', line_stripped, re.IGNORECASE):
                current_lines.append(line_stripped)
            # End of ACL (new section starts)
            elif current_acl:
                if re.match(r'^acl\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^interface\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^sysname\s+', line_stripped, re.IGNORECASE):
                    acls.append({
                        'name': current_acl,
                        'lines': current_lines
                    })
                    current_acl = None
                    current_lines = []
        
        if current_acl:
            acls.append({
                'name': current_acl,
                'lines': current_lines
            })
        
        return acls
    
    def _extract_vlans(self, config_text):
        """Extract VLAN configurations"""
        vlans = []
        current_vlan = None
        current_config = []
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # VLAN declaration
            if re.match(r'^vlan\s+(\d+)', line_stripped, re.IGNORECASE):
                if current_vlan:
                    vlans.append({
                        'name': current_vlan,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'^vlan\s+(\d+)', line_stripped, re.IGNORECASE)
                current_vlan = match.group(1) if match else None
                current_config = [line_stripped]
            # End of VLAN
            elif current_vlan:
                if re.match(r'^vlan\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^interface\s+', line_stripped, re.IGNORECASE):
                    vlans.append({
                        'name': current_vlan,
                        'config': '\n'.join(current_config)
                    })
                    current_vlan = None
                    current_config = []
                elif line_stripped and not line_stripped.startswith('#'):
                    current_config.append(line_stripped)
        
        if current_vlan:
            vlans.append({
                'name': current_vlan,
                'config': '\n'.join(current_config)
            })
        
        return vlans
    
    def _extract_users(self, config_text):
        """Extract user/authentication configurations"""
        users = []
        current_user = None
        current_config = []
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Local user declaration
            if re.match(r'^local-user\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_user:
                    users.append({
                        'name': current_user,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'^local-user\s+(\S+)', line_stripped, re.IGNORECASE)
                current_user = match.group(1) if match else None
                current_config = [line_stripped]
            # End of user block
            elif current_user:
                if re.match(r'^local-user\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^aaa\s+', line_stripped, re.IGNORECASE) or \
                   re.match(r'^interface\s+', line_stripped, re.IGNORECASE):
                    users.append({
                        'name': current_user,
                        'config': '\n'.join(current_config)
                    })
                    current_user = None
                    current_config = []
                elif line_stripped and not line_stripped.startswith('#'):
                    current_config.append(line_stripped)
        
        if current_user:
            users.append({
                'name': current_user,
                'config': '\n'.join(current_config)
            })
        
        return users
    
    def _normalize_authentication(self, config_text):
        """Normalize authentication settings"""
        return {
            'aaa_enabled': bool(re.search(r'^aaa\s+', config_text, re.MULTILINE | re.IGNORECASE)),
            'local_users': len(re.findall(r'^local-user\s+', config_text, re.MULTILINE | re.IGNORECASE)),
            'radius_enabled': bool(re.search(r'radius-server', config_text, re.IGNORECASE)),
            'tacacs_enabled': bool(re.search(r'tacacs-server', config_text, re.IGNORECASE)),
        }
    
    def _normalize_encryption(self, config_text):
        """Normalize encryption settings"""
        return {
            'ssh_enabled': bool(re.search(r'ssh\s+server\s+enable', config_text, re.IGNORECASE)),
            'https_enabled': bool(re.search(r'http\s+secure-server\s+enable', config_text, re.IGNORECASE)),
            'ipsec_enabled': bool(re.search(r'ipsec', config_text, re.IGNORECASE)),
        }
    
    def _normalize_access_control(self, config_text):
        """Normalize access control settings"""
        return {
            'acls': len(self._extract_acls(config_text)),
            'firewall_rules': 0,  # Huawei uses ACLs for firewall functionality
        }

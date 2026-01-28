"""
Fortinet FortiOS parser
"""

import re
from parsers.base import BaseParser

class FortinetParser(BaseParser):
    """Parser for Fortinet FortiOS firewall configurations"""
    
    def get_vendor(self):
        return "Fortinet"
    
    def can_parse(self, config_text):
        """Check if config text is Fortinet FortiOS format"""
        # Fortinet indicators
        fortinet_indicators = [
            r'config\s+system',
            r'config\s+firewall',
            r'FortiOS',
            r'FortiGate',
            r'config\s+vpn',
            r'config\s+user',
        ]
        
        for pattern in fortinet_indicators:
            if re.search(pattern, config_text, re.MULTILINE | re.IGNORECASE):
                return True
        return False
    
    def detect_device_family(self, config_text):
        """Detect device family from configuration"""
        # Try to extract version info
        version_match = re.search(r'FortiOS\s+(\S+)', config_text, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'set\s+version\s+(\S+)', config_text, re.IGNORECASE)
        version = version_match.group(1) if version_match else "Unknown"
        
        # Try to detect hostname
        hostname_match = re.search(r'set\s+hostname\s+(\S+)', config_text, re.IGNORECASE)
        if not hostname_match:
            hostname_match = re.search(r'config\s+system\s+global.*?set\s+hostname\s+(\S+)', config_text, re.DOTALL | re.IGNORECASE)
        hostname = hostname_match.group(1) if hostname_match else "Unknown"
        
        return f"Fortinet FortiOS {version} ({hostname})"
    
    def parse(self, config_text):
        """Parse Fortinet configuration"""
        # Simple parsing - extract key sections
        raw_ast = {
            'hostname': self._extract_hostname(config_text),
            'interfaces': self._extract_interfaces(config_text),
            'firewall_policies': self._extract_firewall_policies(config_text),
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
        # Try different patterns
        match = re.search(r'set\s+hostname\s+(\S+)', config_text, re.IGNORECASE)
        if not match:
            # Look in system global section
            match = re.search(r'config\s+system\s+global.*?set\s+hostname\s+(\S+)', config_text, re.DOTALL | re.IGNORECASE)
        return match.group(1) if match else None
    
    def _extract_interfaces(self, config_text):
        """Extract interface configurations"""
        interfaces = []
        current_interface = None
        current_config = []
        in_interface_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Start of interface block
            if re.match(r'config\s+system\s+interface', line_stripped, re.IGNORECASE):
                in_interface_block = True
                continue
            # End of interface block
            elif in_interface_block and re.match(r'^end$', line_stripped, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                in_interface_block = False
                current_interface = None
                current_config = []
            # Interface name
            elif in_interface_block and re.match(r'edit\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_interface:
                    interfaces.append({
                        'name': current_interface,
                        'config': '\n'.join(current_config)
                    })
                match = re.match(r'edit\s+(\S+)', line_stripped, re.IGNORECASE)
                current_interface = match.group(1) if match else None
                current_config = [line_stripped]
            elif in_interface_block and current_interface and line_stripped:
                if not re.match(r'^next$', line_stripped, re.IGNORECASE):
                    current_config.append(line_stripped)
        
        if current_interface:
            interfaces.append({
                'name': current_interface,
                'config': '\n'.join(current_config)
            })
        
        return interfaces
    
    def _extract_firewall_policies(self, config_text):
        """Extract firewall policy configurations"""
        policies = []
        current_policy = None
        current_lines = []
        in_policy_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Start of firewall policy block
            if re.match(r'config\s+firewall\s+policy', line_stripped, re.IGNORECASE):
                in_policy_block = True
                continue
            # End of policy block
            elif in_policy_block and re.match(r'^end$', line_stripped, re.IGNORECASE):
                if current_policy:
                    policies.append({
                        'name': current_policy,
                        'lines': current_lines
                    })
                in_policy_block = False
                current_policy = None
                current_lines = []
            # Policy name
            elif in_policy_block and re.match(r'edit\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_policy:
                    policies.append({
                        'name': current_policy,
                        'lines': current_lines
                    })
                match = re.match(r'edit\s+(\S+)', line_stripped, re.IGNORECASE)
                current_policy = match.group(1) if match else None
                current_lines = [line_stripped]
            elif in_policy_block and current_policy and line_stripped:
                if not re.match(r'^next$', line_stripped, re.IGNORECASE):
                    current_lines.append(line_stripped)
        
        if current_policy:
            policies.append({
                'name': current_policy,
                'lines': current_lines
            })
        
        return policies
    
    def _extract_vpn_configs(self, config_text):
        """Extract VPN configurations"""
        vpn_configs = []
        current_vpn = None
        current_lines = []
        in_vpn_block = False
        
        for line in config_text.split('\n'):
            line_stripped = line.strip()
            # Start of VPN block (IPSec or SSL)
            if re.match(r'config\s+vpn\s+(?:ipsec|ssl)', line_stripped, re.IGNORECASE):
                in_vpn_block = True
                continue
            # End of VPN block
            elif in_vpn_block and re.match(r'^end$', line_stripped, re.IGNORECASE):
                if current_vpn:
                    vpn_configs.append({
                        'name': current_vpn,
                        'lines': current_lines
                    })
                in_vpn_block = False
                current_vpn = None
                current_lines = []
            # VPN name
            elif in_vpn_block and re.match(r'edit\s+(\S+)', line_stripped, re.IGNORECASE):
                if current_vpn:
                    vpn_configs.append({
                        'name': current_vpn,
                        'lines': current_lines
                    })
                match = re.match(r'edit\s+(\S+)', line_stripped, re.IGNORECASE)
                current_vpn = match.group(1) if match else None
                current_lines = [line_stripped]
            elif in_vpn_block and current_vpn and line_stripped:
                if not re.match(r'^next$', line_stripped, re.IGNORECASE):
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
            if re.match(r'config\s+system', line_stripped, re.IGNORECASE):
                in_system_block = True
                system_config.append(line_stripped)
            elif in_system_block:
                if re.match(r'^end$', line_stripped, re.IGNORECASE):
                    in_system_block = False
                elif line_stripped:
                    system_config.append(line_stripped)
        
        return system_config
    
    def _normalize_authentication(self, config_text):
        """Normalize authentication settings"""
        return {
            'admin_configured': bool(re.search(r'config\s+system\s+admin', config_text, re.IGNORECASE)),
            'ldap_enabled': bool(re.search(r'config\s+user\s+ldap', config_text, re.IGNORECASE)),
            'radius_enabled': bool(re.search(r'config\s+user\s+radius', config_text, re.IGNORECASE)),
            'tacacs_enabled': bool(re.search(r'config\s+user\s+tacacs', config_text, re.IGNORECASE)),
            'local_users': len(re.findall(r'config\s+user\s+local', config_text, re.IGNORECASE)),
        }
    
    def _normalize_encryption(self, config_text):
        """Normalize encryption settings"""
        return {
            'ssh_enabled': bool(re.search(r'set\s+admin-ssh', config_text, re.IGNORECASE)),
            'https_enabled': bool(re.search(r'set\s+admin-https', config_text, re.IGNORECASE)),
            'ipsec_enabled': len(self._extract_vpn_configs(config_text)) > 0,
            'ssl_vpn_enabled': bool(re.search(r'config\s+vpn\s+ssl', config_text, re.IGNORECASE)),
        }
    
    def _normalize_access_control(self, config_text):
        """Normalize access control settings"""
        return {
            'firewall_policies': len(self._extract_firewall_policies(config_text)),
            'security_profiles': len(re.findall(r'config\s+firewall\s+profile-protocol-options', config_text, re.IGNORECASE)),
        }

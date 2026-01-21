"""
Base parser interface
"""

from abc import ABC, abstractmethod

class BaseParser(ABC):
    """Abstract base class for configuration parsers"""
    
    @abstractmethod
    def parse(self, config_text):
        """
        Parse configuration text
        
        Returns:
            dict: Parsed configuration with structure:
                {
                    'raw_ast': {...},  # Raw Abstract Syntax Tree
                    'normalized': {...},  # Normalized security sections
                    'original': config_text  # Original config text
                }
        """
        pass
    
    @abstractmethod
    def detect_device_family(self, config_text):
        """
        Detect device family from configuration
        
        Returns:
            str: Device family (e.g., "Cisco IOS-XE Catalyst 9300")
        """
        pass
    
    @abstractmethod
    def get_vendor(self):
        """Get vendor name"""
        pass


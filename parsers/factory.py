"""
Parser factory
"""

from parsers.registry import get_parser

def create_parser(vendor=None, config_text=None):
    """
    Create parser for vendor
    
    Args:
        vendor: Vendor name (optional, will auto-detect if not provided)
        config_text: Configuration text for auto-detection
    
    Returns:
        BaseParser instance
    """
    if vendor:
        return get_parser(vendor)
    
    # Auto-detect vendor from config text
    if config_text:
        # Try each registered parser
        from parsers.registry import get_all_parsers
        for parser_class in get_all_parsers():
            parser = parser_class()
            try:
                if parser.can_parse(config_text):
                    return parser
            except:
                continue
    
    # Default to Cisco if no detection
    return get_parser('cisco')


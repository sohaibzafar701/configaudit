"""
Parser registry
"""

_parsers = {}

def register_parser(vendor, parser_class):
    """Register a parser for a vendor"""
    _parsers[vendor.lower()] = parser_class

def get_parser(vendor):
    """Get parser for vendor"""
    parser_class = _parsers.get(vendor.lower())
    if parser_class:
        return parser_class()
    raise ValueError(f"No parser registered for vendor: {vendor}")

def get_all_parsers():
    """Get all registered parser classes"""
    return list(_parsers.values())

def get_registered_vendors():
    """Get list of registered vendors"""
    return list(_parsers.keys())

# Register parsers on import
def _register_default_parsers():
    """Register default parsers"""
    try:
        from parsers.cisco.parser import CiscoParser
        register_parser('cisco', CiscoParser)
    except ImportError:
        pass
    
    try:
        from parsers.juniper.parser import JuniperParser
        register_parser('juniper', JuniperParser)
    except ImportError:
        pass

_register_default_parsers()


"""
Configuration diff and comparison service
"""

import difflib
from models.audit import Audit

def compare_configs(audit_id1, audit_id2):
    """Compare two audit configurations and return diff"""
    audit1 = Audit.get_by_id(audit_id1)
    audit2 = Audit.get_by_id(audit_id2)
    
    if not audit1:
        return {'error': f'Audit {audit_id1} not found'}
    if not audit2:
        return {'error': f'Audit {audit_id2} not found'}
    
    # Validate both audits have parsed_config
    if not audit1.get('parsed_config'):
        return {'error': f'Audit {audit_id1} does not have parsed configuration. Please ensure the audit completed successfully.'}
    if not audit2.get('parsed_config'):
        return {'error': f'Audit {audit_id2} does not have parsed configuration. Please ensure the audit completed successfully.'}
    
    # Get original config text
    import json
    config1_text = ""
    config2_text = ""
    
    try:
        parsed1 = json.loads(audit1['parsed_config'])
        config1_text = parsed1.get('original', '')
    except Exception as e:
        return {'error': f'Failed to parse config for audit {audit_id1}: {str(e)}'}
    
    try:
        parsed2 = json.loads(audit2['parsed_config'])
        config2_text = parsed2.get('original', '')
    except Exception as e:
        return {'error': f'Failed to parse config for audit {audit_id2}: {str(e)}'}
    
    if not config1_text:
        return {'error': f'Audit {audit_id1} has empty configuration'}
    if not config2_text:
        return {'error': f'Audit {audit_id2} has empty configuration'}
    
    # Split into lines for comparison
    lines1 = config1_text.splitlines(keepends=True)
    lines2 = config2_text.splitlines(keepends=True)
    
    # Generate unified diff
    diff = list(difflib.unified_diff(
        lines1, lines2,
        fromfile=audit1.get('config_file', 'Config 1'),
        tofile=audit2.get('config_file', 'Config 2'),
        lineterm=''
    ))
    
    # Count changes
    added_lines = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
    removed_lines = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
    modified_lines = min(added_lines, removed_lines)  # Approximate
    
    return {
        'diff': diff,
        'diff_text': ''.join(diff),
        'stats': {
            'added': added_lines,
            'removed': removed_lines,
            'modified': modified_lines,
            'total_changes': added_lines + removed_lines
        },
        'audit1': {
            'id': audit_id1,
            'config_file': audit1.get('config_file'),
            'created_at': audit1.get('created_at')
        },
        'audit2': {
            'id': audit_id2,
            'config_file': audit2.get('config_file'),
            'created_at': audit2.get('created_at')
        }
    }

def get_config_summary(audit_id):
    """Get summary of configuration (line count, sections, etc.)"""
    audit = Audit.get_by_id(audit_id)
    if not audit:
        return None
    
    import json
    config_text = ""
    
    if audit.get('parsed_config'):
        try:
            parsed = json.loads(audit['parsed_config'])
            config_text = parsed.get('original', '')
        except:
            pass
    
    lines = config_text.splitlines()
    
    return {
        'total_lines': len(lines),
        'non_empty_lines': len([l for l in lines if l.strip()]),
        'config_file': audit.get('config_file'),
        'device_family': audit.get('device_family')
    }


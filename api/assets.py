"""
Assets API endpoint - Device identifier management
"""

import json
import urllib.parse
from models.audit import Audit
from models.audit import Finding
from services.timezone_utils import format_datetime_from_iso, parse_datetime_format

def handle_assets_request(handler, method):
    """Handle assets API requests"""
    if method == 'GET':
        parsed_path = urllib.parse.urlparse(handler.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        # Get timezone and format preferences
        timezone_str = query_params.get('timezone', ['UTC'])[0] or 'UTC'
        date_format_str = query_params.get('date_format', ['YYYY-MM-DD HH:mm:ss'])[0] or 'YYYY-MM-DD HH:mm:ss'
        date_format_py = parse_datetime_format(date_format_str)
        
        # Check if requesting specific device
        path_parts = parsed_path.path.split('/')
        if len(path_parts) > 3 and path_parts[3]:  # /api/assets/{device_identifier}
            device_identifier = urllib.parse.unquote(path_parts[3])
            
            # Check if requesting latest audit
            if len(path_parts) > 4 and path_parts[4] == 'latest':
                latest_audit = Audit.get_latest_by_device_identifier(device_identifier)
                if latest_audit:
                    findings = Finding.get_by_audit(latest_audit['id'])
                    latest_audit['findings'] = findings
                    latest_audit['finding_count'] = len(findings)
                    return latest_audit, 200
                return {'error': 'Device not found'}, 404
            
            # Get all audits for device
            audits = Audit.get_by_device_identifier(device_identifier)
            for audit in audits:
                findings = Finding.get_by_audit(audit['id'])
                audit['finding_count'] = len(findings)
            return {'device_identifier': device_identifier, 'audits': audits}, 200
        
        # Get list of all assets
        search_query = query_params.get('search', [None])[0]
        
        # Get all unique device identifiers
        device_identifiers = Audit.get_all_device_identifiers()
        
        # Filter by search query if provided
        if search_query:
            search_lower = search_query.lower()
            device_identifiers = [di for di in device_identifiers if search_lower in di.lower()]
        
        # Build asset list with metadata
        assets = []
        for device_id in device_identifiers:
            # Get all audits for this device
            audits = Audit.get_by_device_identifier(device_id)
            if not audits:
                continue
            
            # Get latest audit
            latest_audit = audits[0]  # Already sorted by created_at DESC
            
            # Get finding count for latest audit
            findings = Finding.get_by_audit(latest_audit['id'])
            finding_count = len(findings)
            
            # Calculate total audit count
            total_audits = len(audits)
            
            last_audit_date_iso = latest_audit.get('created_at')
            last_audit_date_formatted = format_datetime_from_iso(last_audit_date_iso, timezone_str, date_format_py) if last_audit_date_iso else None
            
            assets.append({
                'device_identifier': device_id,
                'last_audit_date': last_audit_date_iso,  # Keep ISO for sorting
                'last_audit_date_formatted': last_audit_date_formatted,  # Formatted for display
                'total_audits': total_audits,
                'latest_audit_status': latest_audit.get('status'),
                'latest_findings_count': finding_count,
                'latest_audit_id': latest_audit.get('id'),
                'device_hostname': latest_audit.get('device_hostname'),
                'device_model': latest_audit.get('device_model'),
                'device_firmware': latest_audit.get('device_firmware'),
                'device_location': latest_audit.get('device_location'),
                'device_make': latest_audit.get('device_make'),
                'device_type': latest_audit.get('device_type')
            })
        
        # Sort by last audit date (most recent first)
        assets.sort(key=lambda x: x['last_audit_date'] or '', reverse=True)
        
        return {'assets': assets, 'count': len(assets)}, 200
    
    return {'error': 'Method not allowed'}, 405


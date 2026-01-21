"""
Audit API endpoints
"""

import json
import threading
import urllib.parse
from models.audit import Audit, Finding
from services.audit_service import process_audit, get_audit_progress
from services.timezone_utils import format_datetime_from_iso, parse_datetime_format

def format_audit_dates(audit, timezone_str='UTC', date_format_py='%Y-%m-%d %H:%M:%S'):
    """Format audit date fields with timezone"""
    if audit.get('created_at'):
        audit['created_at_formatted'] = format_datetime_from_iso(audit['created_at'], timezone_str, date_format_py)
    if audit.get('completed_at'):
        audit['completed_at_formatted'] = format_datetime_from_iso(audit['completed_at'], timezone_str, date_format_py)
    return audit

def handle_audit_request(handler, method):
    """Handle audit API requests"""
    if method == 'GET':
        # Check if requesting audit history
        parsed_path = urllib.parse.urlparse(handler.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        # Get timezone and format preferences
        timezone_str = query_params.get('timezone', ['UTC'])[0] or 'UTC'
        date_format_str = query_params.get('date_format', ['YYYY-MM-DD HH:mm:ss'])[0] or 'YYYY-MM-DD HH:mm:ss'
        date_format_py = parse_datetime_format(date_format_str)
        
        history_param = query_params.get('history', [None])[0]
        if history_param == 'true':
            # Return audit history
            try:
                audits = Audit.get_all()
                # Add finding counts and format dates to each audit
                # Count only parent findings (not children) to reflect grouping
                for audit in audits:
                    try:
                        findings = Finding.get_parents(audit['id'])
                        audit['finding_count'] = len(findings)
                    except Exception as e:
                        print(f"Error getting findings for audit {audit.get('id')}: {e}")
                        audit['finding_count'] = 0
                    format_audit_dates(audit, timezone_str, date_format_py)
                return {'audits': audits}, 200
            except Exception as e:
                print(f"Error loading audit history: {e}")
                import traceback
                traceback.print_exc()
                return {'error': f'Failed to load audit history: {str(e)}', 'audits': []}, 500
        
        # Check if requesting specific audit by ID
        audit_id_param = query_params.get('audit_id', [None])[0]
        if audit_id_param:
            try:
                audit_id = int(audit_id_param)
                audit = Audit.get_by_id(audit_id)
                if audit:
                    findings = Finding.get_by_audit(audit['id'])
                    audit['findings'] = findings
                    format_audit_dates(audit, timezone_str, date_format_py)
                    return audit, 200
                return {'error': 'Audit not found'}, 404
            except ValueError:
                return {'error': 'Invalid audit_id'}, 400
        
        # Get current audit
        audit = Audit.get_current()
        if audit:
            findings = Finding.get_by_audit(audit['id'])
            audit['findings'] = findings
            format_audit_dates(audit, timezone_str, date_format_py)
        return audit or {}, 200
    
    elif method == 'POST':
        # Parse request body
        content_length = int(handler.headers['Content-Length'])
        post_data = handler.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))
        
        action = data.get('action')
        
        if action == 'create':
            # Note: Not deleting old audits to maintain history
            # Users can manually delete audits if needed
            
            # Validate config_content
            config_content = data.get('config_content', '')
            if not config_content or not config_content.strip():
                return {'error': 'Configuration content is required and cannot be empty'}, 400
            
            # Validate file size (default 10MB limit)
            MAX_CONFIG_SIZE = 10 * 1024 * 1024  # 10MB
            if len(config_content.encode('utf-8')) > MAX_CONFIG_SIZE:
                return {'error': f'Configuration file exceeds maximum size of {MAX_CONFIG_SIZE / (1024*1024):.0f}MB'}, 400
            
            # Validate rule tags selection
            from models.rule import Rule
            selected_tags = data.get('rule_tags', [])
            
            # Ensure selected_tags is a list
            if isinstance(selected_tags, str):
                selected_tags = [selected_tags] if selected_tags else []
            elif not isinstance(selected_tags, list):
                selected_tags = []
            
            # Filter out empty strings
            selected_tags = [tag.strip() for tag in selected_tags if tag and tag.strip()]
            
            if not selected_tags:
                return {'error': 'Please select at least one rule tag.'}, 400
            
            # Validate that rules exist for selected tags (only enabled rules)
            rules = Rule.get_by_tags(selected_tags)
            if not rules:
                return {'error': f'No enabled rules found for selected tags: {", ".join(selected_tags)}'}, 400
            
            # Validate device_identifier
            device_identifier = data.get('device_identifier')
            if not device_identifier or not device_identifier.strip():
                return {'error': 'device_identifier is required and cannot be empty'}, 400
            
            # Extract metadata from config
            from services.metadata_extractor import extract_metadata
            metadata = extract_metadata(config_content, data.get('device_family'))
            
            # Get device make, model, type from request (user-selected)
            device_make = data.get('device_make')
            device_type = data.get('device_type')
            device_model_user = data.get('device_model', '')  # User-entered model
            
            # Use user-provided model if available, otherwise use extracted
            device_model = device_model_user.strip() if device_model_user else metadata.get('model')
            
            # Build device_family from make, type, and model if not provided
            if not data.get('device_family') and device_make and device_type:
                device_family = f"{device_make} {device_type}"
                if device_model:
                    device_family += f" {device_model}"
            else:
                device_family = data.get('device_family')
            
            # Create new audit
            audit_id = Audit.create(
                device_identifier=device_identifier.strip(),
                device_family=device_family,
                config_file=data.get('config_file'),
                device_hostname=metadata.get('hostname'),
                device_model=device_model,
                device_firmware=metadata.get('firmware'),
                device_location=metadata.get('location'),
                device_make=device_make,
                device_type=device_type
            )
            
            # Start processing in background thread
            if config_content:
                # Process audit in background thread
                thread = threading.Thread(
                    target=process_audit,
                    args=(audit_id, config_content, data.get('device_family'), None, selected_tags),
                    daemon=True
                )
                thread.start()
            
            return {'id': audit_id, 'status': 'created'}, 201
        
        elif action == 'delete':
            audit_id = data.get('audit_id')
            if audit_id:
                # Delete specific audit
                Audit.delete(audit_id)
                return {'status': 'deleted', 'audit_id': audit_id}, 200
            else:
                # Delete all audits (for cleanup)
                Audit.delete_all()
                return {'status': 'deleted', 'all': True}, 200
        
        elif action == 'update_status':
            audit_id = data.get('audit_id')
            status = data.get('status')
            Audit.update_status(audit_id, status)
            return {'status': 'updated'}, 200
        
        elif action == 'get_progress':
            audit_id = data.get('audit_id')
            if audit_id:
                progress = get_audit_progress(audit_id)
                audit = Audit.get_by_id(audit_id)
                if audit:
                    progress['status'] = audit.get('status', 'Unknown')
                    progress['audit_id'] = audit_id
                return progress, 200
            return {'error': 'audit_id required'}, 400
        
        elif action == 'cancel':
            audit_id = data.get('audit_id')
            if audit_id:
                Audit.update_status(audit_id, Audit.STATUS_CANCELLED)
                return {'status': 'cancelled'}, 200
            return {'error': 'audit_id required'}, 400
        
        elif action == 'bulk_delete':
            audit_ids = data.get('audit_ids', [])
            if not audit_ids:
                return {'error': 'audit_ids required'}, 400
            
            deleted_count = 0
            for audit_id in audit_ids:
                try:
                    Audit.delete(audit_id)
                    deleted_count += 1
                except Exception as e:
                    print(f"Error deleting audit {audit_id}: {e}")
            
            return {'status': 'deleted', 'count': deleted_count}, 200
        
        elif action == 'create_snapshot':
            audit_id = data.get('audit_id')
            snapshot_name = data.get('snapshot_name', 'Snapshot')
            if not audit_id:
                return {'error': 'audit_id required'}, 400
            
            # Validate audit exists
            audit = Audit.get_by_id(audit_id)
            if not audit:
                return {'error': 'Audit not found'}, 404
            
            # Validate audit is completed
            if audit.get('status') != Audit.STATUS_COMPLETED:
                return {'error': 'Can only create snapshots of completed audits'}, 400
            
            snapshot_id = Audit.create_snapshot(audit_id, snapshot_name)
            if snapshot_id:
                return {'status': 'created', 'snapshot_id': snapshot_id}, 201
            return {'error': 'Failed to create snapshot'}, 400
        
        elif action == 'delete_snapshot':
            snapshot_id = data.get('snapshot_id')
            if not snapshot_id:
                return {'error': 'snapshot_id required'}, 400
            
            # Verify it's a snapshot
            snapshot = Audit.get_by_id(snapshot_id)
            if not snapshot:
                return {'error': 'Snapshot not found'}, 404
            
            if not snapshot.get('parent_audit_id'):
                return {'error': 'Not a snapshot'}, 400
            
            Audit.delete(snapshot_id)
            return {'status': 'deleted', 'snapshot_id': snapshot_id}, 200
        
        elif action == 'get_snapshots':
            audit_id = data.get('audit_id')
            if not audit_id:
                return {'error': 'audit_id required'}, 400
            
            snapshots = Audit.get_snapshots(audit_id)
            return {'snapshots': snapshots}, 200
        
        elif action == 'get_snapshot_chain':
            audit_id = data.get('audit_id')
            if not audit_id:
                return {'error': 'audit_id required'}, 400
            
            chain = Audit.get_snapshot_chain(audit_id)
            return {'chain': chain}, 200
        
        elif action == 'compare_configs':
            audit_id1 = data.get('audit_id1')
            audit_id2 = data.get('audit_id2')
            if not audit_id1 or not audit_id2:
                return {'error': 'audit_id1 and audit_id2 required'}, 400
            
            from services.config_diff import compare_configs
            diff_result = compare_configs(audit_id1, audit_id2)
            if diff_result:
                return diff_result, 200
            return {'error': 'Failed to compare configs'}, 400
        
        elif action == 'create_batch':
            # Batch upload removed - not supported
            return {'error': 'Batch upload is not supported'}, 400
            # Batch create audits from multiple configs
            configs = data.get('configs', [])
            selected_rule_ids = data.get('rule_ids')
            
            if not configs:
                return {'error': 'configs array required'}, 400
            
            # Validate rules before processing any configs
            from models.rule import Rule
            if selected_rule_ids:
                valid_rules = [Rule.get_by_id(rid) for rid in selected_rule_ids if Rule.get_by_id(rid)]
                if not valid_rules:
                    return {'error': 'No valid rules selected. Please select at least one enabled rule.'}, 400
            else:
                enabled_rules = Rule.get_all(enabled_only=True)
                if not enabled_rules:
                    return {'error': 'No enabled rules found. Please enable at least one rule before creating audits.'}, 400
            
            from services.metadata_extractor import extract_metadata
            created_audits = []
            failed_configs = []
            
            for config_data in configs:
                config_content = config_data.get('content', '')
                config_file = config_data.get('filename', 'Unknown')
                
                # Validate config content
                if not config_content or not config_content.strip():
                    failed_configs.append({
                        'filename': config_file,
                        'error': 'Configuration content is empty'
                    })
                    continue
                
                # Validate file size
                MAX_CONFIG_SIZE = 10 * 1024 * 1024  # 10MB
                if len(config_content.encode('utf-8')) > MAX_CONFIG_SIZE:
                    failed_configs.append({
                        'filename': config_file,
                        'error': f'File exceeds maximum size of {MAX_CONFIG_SIZE / (1024*1024):.0f}MB'
                    })
                    continue
                
                # Validate device_identifier for each config
                device_identifier = config_data.get('device_identifier')
                if not device_identifier or not device_identifier.strip():
                    failed_configs.append({
                        'filename': config_file,
                        'error': 'device_identifier is required and cannot be empty'
                    })
                    continue
                
                # Extract metadata
                metadata = extract_metadata(config_content, config_data.get('device_family'))
                
                # Create audit
                try:
                    audit_id = Audit.create(
                        device_identifier=device_identifier.strip(),
                        device_family=config_data.get('device_family'),
                        config_file=config_file,
                        device_hostname=metadata.get('hostname'),
                        device_model=metadata.get('model'),
                        device_firmware=metadata.get('firmware'),
                        device_location=metadata.get('location')
                    )
                    
                    # Start processing in background thread
                    if config_content:
                        thread = threading.Thread(
                            target=process_audit,
                            args=(audit_id, config_content, config_data.get('device_family'), selected_rule_ids),
                            daemon=True
                        )
                        thread.start()
                    
                    created_audits.append({
                        'id': audit_id,
                        'config_file': config_file,
                        'status': 'created'
                    })
                except Exception as e:
                    failed_configs.append({
                        'filename': config_file,
                        'error': f'Failed to create audit: {str(e)}'
                    })
            
            if not created_audits:
                return {'error': 'All configs failed validation', 'failed': failed_configs}, 400
            
            return {
                'status': 'created',
                'audits': created_audits,
                'count': len(created_audits),
                'failed_count': len(failed_configs),
                'failed': failed_configs
            }, 201
        
        elif action == 'update_remediation':
            finding_id = data.get('finding_id')
            status = data.get('status')
            notes = data.get('notes')
            
            if not finding_id:
                return {'error': 'finding_id required'}, 400
            
            # Validate remediation status values
            valid_statuses = ['Not Started', 'In Progress', 'Completed', 'Verified']
            if status and status not in valid_statuses:
                return {'error': f'Invalid remediation status. Must be one of: {", ".join(valid_statuses)}'}, 400
            
            Finding.update_remediation(finding_id, status, notes)
            return {'status': 'updated'}, 200
    
    return {'error': 'Invalid request'}, 400


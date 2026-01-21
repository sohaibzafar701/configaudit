"""
Rule API endpoints
"""

import json
from models.rule import Rule

def handle_rule_request(handler, method):
    """Handle rule API requests"""
    parsed_path = handler.path.split('?')[0].rstrip('/')  # Remove trailing slash
    
    if method == 'GET':
        # Check for /api/rules/tags before /api/rules (more specific path first)
        if parsed_path == '/api/rules/tags':
            # Get all available tags from enabled rules only
            tags = Rule.get_all_tags(enabled_only=True)
            return {'tags': tags}, 200
        
        elif parsed_path == '/api/rules':
            # Get all rules (including disabled ones for rules management page)
            category = handler.path.split('category=')[1].split('&')[0] if 'category=' in handler.path else None
            if category:
                rules = Rule.get_by_category(category)
            else:
                rules = Rule.get_all(enabled_only=False)  # Show all rules including disabled
            return rules, 200
        
        elif parsed_path.startswith('/api/rules/'):
            # Get rule by ID - check if it's not the tags endpoint
            path_segment = parsed_path.split('/')[-1]
            if path_segment == 'tags':
                # This shouldn't happen due to the check above, but just in case
                tags = Rule.get_all_tags(enabled_only=True)
                return {'tags': tags}, 200
            
            # Try to parse as integer ID
            try:
                rule_id = int(path_segment)
                rule = Rule.get_by_id(rule_id)
                if rule:
                    return rule, 200
                return {'error': 'Rule not found'}, 404
            except ValueError:
                # Path segment is not a number, return 404
                return {'error': 'Invalid rule ID'}, 404
    
    elif method == 'POST':
        try:
            content_length_header = handler.headers.get('Content-Length')
            if not content_length_header:
                return {'error': 'Content-Length header required'}, 400
            
            try:
                content_length = int(content_length_header)
            except ValueError:
                return {'error': 'Invalid Content-Length header'}, 400
            
            if content_length <= 0:
                return {'error': 'Request body required'}, 400
            
            post_data = handler.rfile.read(content_length)
            if not post_data:
                return {'error': 'Empty request body'}, 400
            
            try:
                data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError as e:
                return {'error': f'Invalid JSON: {str(e)}'}, 400
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {'error': f'Error reading request: {str(e)}'}, 500
        
        action = data.get('action')
        
        if action == 'create':
            rule_id = Rule.create(
                name=data['name'],
                description=data.get('description', ''),
                rule_type=data['rule_type'],
                category=data.get('category', ''),
                severity=data.get('severity', 'medium'),
                yaml_content=data.get('yaml_content', '')
            )
            return {'id': rule_id, 'status': 'created'}, 201
        
        elif action == 'update':
            try:
                rule_id = data.get('id')
                if not rule_id:
                    return {'error': 'Rule ID required'}, 400
                
                # Build update parameters, only including non-None values
                update_params = {'rule_id': rule_id}
                if 'name' in data:
                    update_params['name'] = data.get('name')
                if 'description' in data:
                    update_params['description'] = data.get('description')
                if 'category' in data:
                    update_params['category'] = data.get('category')
                if 'severity' in data:
                    update_params['severity'] = data.get('severity')
                if 'yaml_content' in data:
                    update_params['yaml_content'] = data.get('yaml_content')
                if 'tags' in data:
                    update_params['tags'] = data.get('tags')
                if 'enabled' in data:
                    update_params['enabled'] = data.get('enabled')
                if 'remediation_template' in data:
                    update_params['remediation_template'] = data.get('remediation_template')
                if 'compliance_frameworks' in data:
                    update_params['compliance_frameworks'] = data.get('compliance_frameworks')
                
                Rule.update(**update_params)
                return {'status': 'updated', 'id': rule_id}, 200
            except Exception as e:
                import traceback
                traceback.print_exc()
                return {'error': f'Update failed: {str(e)}'}, 500
        
        elif action == 'delete':
            Rule.delete(data['id'])
            return {'status': 'deleted'}, 200
        
        elif action == 'test':
            # Test a rule against sample config
            from services.rule_engine import execute_rules
            
            rule_id = data.get('rule_id')
            config_content = data.get('config_content', '')
            
            if not rule_id or not config_content:
                return {'error': 'rule_id and config_content required'}, 400
            
            rule = Rule.get_by_id(rule_id)
            if not rule:
                return {'error': 'Rule not found'}, 404
            
            # Parse config (basic - just use original text for pattern rules)
            parsed_config = {'original': config_content}
            
            # Execute rule
            findings = execute_rules([rule], parsed_config)
            
            return {
                'rule': rule,
                'findings': findings,
                'finding_count': len(findings)
            }, 200
        
        elif action == 'bulk_update':
            # Bulk update rules
            try:
                rule_ids = data.get('rule_ids', [])
                updates = data.get('updates', {})
                
                if not rule_ids:
                    return {'error': 'rule_ids required'}, 400
                
                updated_count = 0
                for rule_id in rule_ids:
                    update_params = {'rule_id': rule_id, **updates}
                    Rule.update(**update_params)
                    updated_count += 1
                
                return {'status': 'updated', 'count': updated_count}, 200
            except Exception as e:
                import traceback
                traceback.print_exc()
                return {'error': f'Bulk update failed: {str(e)}'}, 500
    
    return {'error': 'Invalid request'}, 400


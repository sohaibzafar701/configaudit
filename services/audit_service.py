"""
Audit processing service
"""

# Use Django models via adapter for compatibility
try:
    from apps.core.model_adapter import Audit, Finding, Rule
except ImportError:
    # Fallback to old models if Django not available
    from models.audit import Audit, Finding
    from models.rule import Rule
from parsers.factory import create_parser
from services.rule_engine import execute_rules
import json

def set_audit_progress(audit_id, status=None, progress_percent=None, current_rule=None,
                       total_rules=None, rules_completed=None, error=None, rule_findings=None, rule_errors=None, rule_execution_details=None):
    """Helper function to set audit progress"""
    Audit.set_progress(audit_id, status=status, progress_percent=progress_percent,
                       current_rule=current_rule, total_rules=total_rules,
                       rules_completed=rules_completed, error=error, 
                       rule_findings=rule_findings, rule_errors=rule_errors,
                       rule_execution_details=rule_execution_details)

def get_audit_progress(audit_id):
    """Helper function to get audit progress"""
    return Audit.get_progress(audit_id)

def process_audit(audit_id, config_content, device_family=None, selected_rule_ids=None, selected_tags=None):
    """Process an audit - parse config and run rules
    
    Args:
        audit_id: ID of the audit to process
        config_content: Configuration file content
        device_family: Device family/vendor
        selected_rule_ids: (deprecated) List of rule IDs to execute
        selected_tags: List of tags - rules matching any of these tags will be executed (only enabled rules)
    """
    # Validate input
    if not config_content or not config_content.strip():
        Audit.update_status(audit_id, Audit.STATUS_FAILED)
        set_audit_progress(audit_id, status='failed', error='Configuration content is empty')
        return
    
    # Update status to processing
    Audit.update_status(audit_id, Audit.STATUS_PROCESSING)
    
    try:
        # Parse configuration
        parser = create_parser(vendor=None, config_text=config_content)
        parsed_config = parser.parse(config_content)
        
        # Update audit with parsed config
        try:
            from apps.core.models import Audit as DjangoAudit
            audit = DjangoAudit.objects.get(id=audit_id)
            audit.parsed_config = parsed_config
            audit.device_family = device_family or parser.detect_device_family(config_content)
            audit.save()
        except ImportError:
            # Fallback to old database method
            from services.database import get_db_connection
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE audit 
                SET parsed_config = ?, device_family = ?
                WHERE id = ?
            """, (json.dumps(parsed_config), device_family or parser.detect_device_family(config_content), audit_id))
            conn.commit()
            conn.close()
        
        # Get device_family from parser or use provided
        device_family = device_family or parser.detect_device_family(config_content)
        
        # Get rules to execute - prioritize tags over rule_ids
        # Always filter by device_family to only include applicable rules
        if selected_tags and len(selected_tags) > 0:
            # Get rules by tags (only enabled rules), but filter by device_family
            all_tagged_rules = Rule.get_by_tags(selected_tags)
            # Filter to only include rules applicable to this device family
            if device_family:
                device_family_rules = Rule.get_by_device_family(device_family)
                device_family_rule_ids = {r['id'] for r in device_family_rules}
                rules = [r for r in all_tagged_rules if r['id'] in device_family_rule_ids]
            else:
                # If no device_family, only include generic/all rules
                rules = [r for r in all_tagged_rules if r.get('tags') and ('generic' in r['tags'].lower() or 'all' in r['tags'].lower())]
        elif selected_rule_ids:
            # Legacy support: get by rule IDs (but still filter by enabled and device_family)
            all_rules = [Rule.get_by_id(rid) for rid in selected_rule_ids if Rule.get_by_id(rid) and Rule.get_by_id(rid).get('enabled') == 1]
            # Filter to only include rules applicable to this device family
            if device_family:
                device_family_rules = Rule.get_by_device_family(device_family)
                device_family_rule_ids = {r['id'] for r in device_family_rules}
                rules = [r for r in all_rules if r and r['id'] in device_family_rule_ids]
            else:
                # If no device_family, only include generic/all rules
                rules = [r for r in all_rules if r and r.get('tags') and ('generic' in r['tags'].lower() or 'all' in r['tags'].lower())]
        else:
            # Default: get rules applicable to device family (includes generic/all + vendor-specific)
            if device_family:
                rules = Rule.get_by_device_family(device_family)
            else:
                # If no device_family, only get generic/all rules
                rules = [r for r in Rule.get_all(enabled_only=True) 
                        if r.get('tags') and ('generic' in r['tags'].lower() or 'all' in r['tags'].lower())]
        
        # Validate at least one rule exists
        if not rules:
            Audit.update_status(audit_id, Audit.STATUS_FAILED)
            set_audit_progress(audit_id, status='failed', error='No rules available to execute')
            return
        
        total_rules = len(rules)
        set_audit_progress(audit_id, status='executing_rules', total_rules=total_rules, rules_completed=0)
        
        # Execute rules with progress tracking
        findings = []
        for idx, rule in enumerate(rules):
            # Check if audit was cancelled
            audit = Audit.get_by_id(audit_id)
            if audit and audit.get('status') == Audit.STATUS_CANCELLED:
                Audit.update_status(audit_id, Audit.STATUS_CANCELLED)
                return
            
            # Calculate progress (use idx for completed rules, idx+1 for current)
            # Progress is based on completed rules, not current rule
            progress_percent = int((idx / total_rules * 100)) if total_rules > 0 else 0
            
            # Execute this rule
            rule_findings_list = []
            rule_errors_list = []
            rule_execution_details = {
                'rule_name': rule.get('name', 'Unknown'),
                'rule_id': rule.get('id'),
                'rule_type': rule.get('rule_type', 'Unknown'),
                'rule_category': rule.get('category', 'Unknown'),
                'rule_description': rule.get('description', ''),
                'rule_severity': rule.get('severity', 'medium'),
                'rule_tags': rule.get('tags', ''),
                'matched': False,
                'findings_count': 0,
                'execution_time_ms': 0,
                'details': [],
                'pattern_info': None,
                'config_sections': [],
                'rule_yaml_preview': rule.get('yaml_content', '')[:200] if rule.get('yaml_content') else None
            }
            
            # Add rule description to details
            if rule_execution_details['rule_description']:
                rule_execution_details['details'].append(f"Rule description: {rule_execution_details['rule_description']}")
            if rule_execution_details['rule_tags']:
                rule_execution_details['details'].append(f"Rule tags: {rule_execution_details['rule_tags']}")
            
            import time
            start_time = time.time()
            
            try:
                # Get rule YAML content for pattern rules to show what's being checked
                if rule.get('rule_type') == 'pattern':
                    try:
                        import yaml
                        rule_yaml = yaml.safe_load(rule.get('yaml_content', ''))
                        if rule_yaml:
                            pattern = rule_yaml.get('pattern', '')
                            rule_execution_details['pattern_info'] = {
                                'pattern': pattern,
                                'message': rule_yaml.get('message', ''),
                                'yaml_content': rule.get('yaml_content', '')
                            }
                            rule_execution_details['details'].append(f"Pattern rule: Searching for pattern '{pattern}'")
                    except:
                        pass
                
                # For Python rules, add more context
                if rule.get('rule_type') == 'python':
                    try:
                        import yaml
                        rule_yaml = yaml.safe_load(rule.get('yaml_content', ''))
                        if rule_yaml:
                            python_code = rule_yaml.get('python_code', '') or rule_yaml.get('python', '')
                            if python_code:
                                # Show preview of Python code being executed
                                code_preview = python_code[:300] + '...' if len(python_code) > 300 else python_code
                                rule_execution_details['details'].append(f"Python rule: Executing custom Python code")
                                rule_execution_details['details'].append(f"  Code preview: {code_preview}")
                    except:
                        pass
                
                rule_findings = execute_rules([rule], parsed_config)
                execution_time = int((time.time() - start_time) * 1000)
                findings.extend(rule_findings)
                
                # Track findings for verbose logging with full details
                if rule_findings:
                    rule_findings_list = [{'message': f.get('message', 'Security issue detected'), 
                                          'severity': f.get('severity', 'medium'),
                                          'config_path': f.get('config_path', ''),
                                          'matched_text': f.get('matched_text', ''),
                                          'line_number': f.get('line_number'),
                                          'context': f.get('context', '')} 
                                         for f in rule_findings]
                    rule_execution_details['matched'] = True
                    rule_execution_details['findings_count'] = len(rule_findings)
                    rule_execution_details['details'].append(f"⚠ MATCHED: Found {len(rule_findings)} security issue(s)")
                    
                    for idx, finding in enumerate(rule_findings[:10], 1):  # Show up to 10 findings
                        findingMsg = finding.get('message', 'Issue detected')
                        configPath = finding.get('config_path', '')
                        matchedText = finding.get('matched_text', '')
                        severity = finding.get('severity', 'medium')
                        lineNumber = finding.get('line_number')
                        context = finding.get('context', '')
                        
                        rule_execution_details['details'].append(f"  ┌─ Finding #{idx} [{severity.upper()}]")
                        rule_execution_details['details'].append(f"  │  Message: {findingMsg}")
                        if lineNumber:
                            rule_execution_details['details'].append(f"  │  Line number: {lineNumber}")
                        if configPath:
                            rule_execution_details['details'].append(f"  │  Location: {configPath}")
                        if matchedText:
                            # Show matched config text (truncate if too long)
                            displayText = matchedText[:300] + '...' if len(matchedText) > 300 else matchedText
                            rule_execution_details['details'].append(f"  │  Matched text: {displayText}")
                        if context:
                            # Show surrounding context (truncate if too long)
                            contextDisplay = context[:400] + '...' if len(context) > 400 else context
                            rule_execution_details['details'].append(f"  │  Context (surrounding lines):")
                            for ctx_line in contextDisplay.split('\n')[:5]:  # Limit to 5 context lines
                                rule_execution_details['details'].append(f"  │    {ctx_line}")
                        remediation = finding.get('remediation', '')
                        if remediation:
                            rule_execution_details['details'].append(f"  │  Remediation: {remediation}")
                        rule_execution_details['details'].append(f"  └─")
                        
                        # Store config section for this finding
                        if configPath or matchedText:
                            rule_execution_details['config_sections'].append({
                                'finding_index': idx,
                                'config_path': configPath,
                                'matched_text': matchedText[:500] if matchedText else '',
                                'context': context[:1000] if context else '',
                                'line_number': lineNumber,
                                'severity': severity
                            })
                else:
                    rule_execution_details['matched'] = False
                    rule_execution_details['details'].append("✓ PASSED: No security issues found")
                    rule_execution_details['details'].append("  Configuration meets security requirements for this rule")
                    if rule_execution_details.get('pattern_info') and rule_execution_details['pattern_info'].get('pattern'):
                        rule_execution_details['details'].append(f"  Pattern '{rule_execution_details['pattern_info']['pattern']}' was not found (which is expected/good)")
                
                rule_execution_details['execution_time_ms'] = execution_time
                rule_execution_details['details'].append(f"Execution completed in {execution_time}ms")
                
            except Exception as e:
                # Log error but continue with other rules
                error_msg = str(e)
                execution_time = int((time.time() - start_time) * 1000)
                print(f"Error executing rule '{rule.get('name')}': {error_msg}")
                import traceback
                traceback.print_exc()
                rule_errors_list = [error_msg]
                rule_execution_details['matched'] = False
                rule_execution_details['details'].append(f"Error during execution: {error_msg}")
                rule_execution_details['execution_time_ms'] = execution_time
                # Continue to next rule instead of failing entire audit
            
            # Update progress with verbose details (single call)
            # Always update execution details, even if empty, so frontend knows rule completed
            set_audit_progress(
                audit_id,
                current_rule=rule.get('name', 'Unknown'),
                rules_completed=idx,
                progress_percent=progress_percent,
                rule_findings=rule_findings_list if rule_findings_list else None,
                rule_errors=rule_errors_list if rule_errors_list else None,
                rule_execution_details=rule_execution_details  # Always include details
            )
            
            # Small delay to ensure progress is written before next rule
            import time
            time.sleep(0.01)  # 10ms delay
        
        # Update progress after all rules executed
        set_audit_progress(audit_id, rules_completed=total_rules, progress_percent=90)
        
        # Store findings - group by rule_id to create parent-child structure
        set_audit_progress(audit_id, status='storing_findings', progress_percent=95)
        
        # Group findings by rule_id
        findings_by_rule = {}
        for finding in findings:
            rule_id = finding.get('rule_id')
            if rule_id not in findings_by_rule:
                findings_by_rule[rule_id] = []
            findings_by_rule[rule_id].append(finding)
        
        # Get rule information for parent findings
        # (Rule is already imported at the top of the file)
        
        # Create parent-child structure for findings
        for rule_id, rule_findings in findings_by_rule.items():
            rule = Rule.get_by_id(rule_id)
            rule_name = rule.get('name', 'Unknown Rule') if rule else 'Unknown Rule'
            rule_remediation = rule.get('remediation_template', '') if rule else ''
            
            if len(rule_findings) == 1:
                # Single finding - create as parent (no children)
                finding = rule_findings[0]
                Finding.create(
                    audit_id=audit_id,
                    rule_id=rule_id,
                    severity=finding.get('severity', 'medium'),
                    message=finding.get('message', ''),
                    config_path=finding.get('config_path'),
                    remediation=finding.get('remediation', '') or rule_remediation,
                    parent_finding_id=None
                )
            else:
                # Multiple findings - create parent with children
                # Determine highest severity
                severities = ['low', 'medium', 'high', 'critical']
                highest_severity = 'low'
                for finding in rule_findings:
                    finding_severity = finding.get('severity', 'low').lower()
                    if finding_severity in severities:
                        if severities.index(finding_severity) > severities.index(highest_severity):
                            highest_severity = finding_severity
                
                # Create parent finding
                parent_message = f"{rule_name} ({len(rule_findings)} instances)"
                parent_config_path = "Multiple locations"
                
                parent_id = Finding.create(
                    audit_id=audit_id,
                    rule_id=rule_id,
                    severity=highest_severity,
                    message=parent_message,
                    config_path=parent_config_path,
                    remediation=rule_remediation,
                    parent_finding_id=None
                )
                
                # Create child findings
                for finding in rule_findings:
                    Finding.create(
                        audit_id=audit_id,
                        rule_id=rule_id,
                        severity=finding.get('severity', 'medium'),
                        message=finding.get('message', ''),
                        config_path=finding.get('config_path'),
                        remediation=finding.get('remediation', ''),
                        parent_finding_id=parent_id
                    )
        
        Audit.update_status(audit_id, Audit.STATUS_COMPLETED)
        set_audit_progress(audit_id, status='completed', progress_percent=100)
        
    except Exception as e:
        Audit.update_status(audit_id, Audit.STATUS_FAILED)
        set_audit_progress(audit_id, status='failed', error=str(e))
        raise


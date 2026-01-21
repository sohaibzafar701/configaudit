"""
Rule execution engine
"""

from models.rule import Rule

def execute_rules(rules, parsed_config):
    """Execute rules against parsed configuration"""
    findings = []
    
    for rule in rules:
        if not rule:
            continue
            
        rule_type = rule.get('rule_type')
        
        if rule_type == 'pattern':
            # Execute pattern rule
            findings.extend(execute_pattern_rule(rule, parsed_config))
        elif rule_type == 'python':
            # Execute Python rule (in subprocess)
            findings.extend(execute_python_rule(rule, parsed_config))
        elif rule_type == 'hybrid':
            # Execute hybrid rule
            findings.extend(execute_hybrid_rule(rule, parsed_config))
    
    return findings

def execute_pattern_rule(rule, parsed_config):
    """Execute pattern-based rule"""
    findings = []
    
    try:
        import yaml
        import re
        
        # Parse YAML content from rule
        rule_yaml = yaml.safe_load(rule.get('yaml_content', ''))
        if not rule_yaml:
            return findings
        
        # Get pattern from YAML
        pattern = rule_yaml.get('pattern', '')
        if not pattern:
            return findings
        
        # Get config text to search
        config_text = parsed_config.get('original', '')
        if not config_text:
            return findings
        
        # Get severity and message from YAML or rule
        severity = rule_yaml.get('severity') or rule.get('severity', 'medium')
        message = rule_yaml.get('message', '') or rule.get('description', '')
        
        # Determine if this is a negative check (should NOT exist)
        rule_name = rule.get('name', '').lower()
        is_negative_check = 'disabled' in rule_name or 'no ' in rule_name.lower()
        
        # For "Required" rules, check for negative patterns (e.g., "no aaa new-model")
        # If rule name contains "Required", also check for "no <pattern>"
        if 'required' in rule_name:
            # Check for negative pattern (e.g., "no aaa new-model" when looking for "aaa new-model")
            negative_pattern = r'no\s+' + pattern.lstrip('^').rstrip('$')
            negative_matches = list(re.finditer(negative_pattern, config_text, re.MULTILINE | re.IGNORECASE))
            
            if negative_matches:
                # Found "no <pattern>" - this is a security issue
                for match in negative_matches:
                    line_start = config_text[:match.start()].count('\n') + 1
                    matched_text = match.group(0)
                    
                    # Get remediation from rule
                    remediation = rule.get('remediation_template', '')
                    if not remediation and rule.get('name'):
                        # Generate basic remediation if none provided
                        remediation = f"Enable the required feature: {rule.get('name')}"
                    
                    # Get surrounding context (3 lines before and after)
                    lines = config_text.split('\n')
                    context_start = max(0, line_start - 4)
                    context_end = min(len(lines), line_start + 2)
                    context_lines = lines[context_start:context_end]
                    context_text = '\n'.join(context_lines)
                    
                    finding = {
                        'rule_id': rule['id'],
                        'severity': severity,
                        'message': message or f"Security issue: {rule.get('name')} - feature is disabled",
                        'config_path': f"Line {line_start}: {matched_text[:100]}",
                        'matched_text': matched_text,
                        'line_number': line_start,
                        'context': context_text,
                        'remediation': remediation
                    }
                    findings.append(finding)
                return findings  # Don't check for positive pattern if negative found
        
        # Search for pattern in config
        matches = list(re.finditer(pattern, config_text, re.MULTILINE | re.IGNORECASE))
        
        if is_negative_check:
            # Negative check: pattern should NOT exist
            # If found, it's a security issue
            for match in matches:
                line_start = config_text[:match.start()].count('\n') + 1
                matched_text = match.group(0)
                
                # Get remediation from rule
                remediation = rule.get('remediation_template', '')
                if not remediation and rule.get('name'):
                    remediation = f"Remove or disable the pattern: {matched_text[:50]}"
                
                # Get surrounding context
                lines = config_text.split('\n')
                context_start = max(0, line_start - 4)
                context_end = min(len(lines), line_start + 2)
                context_lines = lines[context_start:context_end]
                context_text = '\n'.join(context_lines)
                
                finding = {
                    'rule_id': rule['id'],
                    'severity': severity,
                    'message': message or f"Security issue: {rule.get('name')} - pattern found when it should be disabled",
                    'config_path': f"Line {line_start}: {matched_text[:100]}",
                    'matched_text': matched_text,
                    'line_number': line_start,
                    'context': context_text,
                    'remediation': remediation
                }
                findings.append(finding)
        else:
            # Positive check: pattern should exist
            if matches:
                # Pattern found - this is good, report as info
                for match in matches:
                    line_start = config_text[:match.start()].count('\n') + 1
                    matched_text = match.group(0)
                    
                    # Get surrounding context
                    lines = config_text.split('\n')
                    context_start = max(0, line_start - 4)
                    context_end = min(len(lines), line_start + 2)
                    context_lines = lines[context_start:context_end]
                    context_text = '\n'.join(context_lines)
                    
                    finding = {
                        'rule_id': rule['id'],
                        'severity': 'info',  # Lower severity for informational findings
                        'message': message or f"Pattern matched: {matched_text[:50]}",
                        'config_path': f"Line {line_start}: {matched_text[:100]}",
                        'matched_text': matched_text,
                        'line_number': line_start,
                        'context': context_text,
                        'remediation': ''  # No remediation needed for info findings
                    }
                    findings.append(finding)
            else:
                # Pattern not found - might be a missing required feature
                if 'required' in rule_name or 'enabled' in rule_name or 'configured' in rule_name:
                    # Get remediation from rule
                    remediation = rule.get('remediation_template', '')
                    if not remediation and rule.get('name'):
                        remediation = f"Configure the recommended feature: {rule.get('name')}"
                    
                    finding = {
                        'rule_id': rule['id'],
                        'severity': 'low',  # Lower severity for missing optional features
                        'message': message or f"Recommendation: {rule.get('name')} - pattern not found",
                        'config_path': None,
                        'remediation': remediation
                    }
                    findings.append(finding)
    
    except Exception as e:
        print(f"Error executing pattern rule '{rule.get('name')}': {e}")
        import traceback
        traceback.print_exc()
    
    return findings

def execute_python_rule(rule, parsed_config):
    """Execute Python rule in subprocess"""
    from services.python_executor import execute_python_rule_safe
    findings = execute_python_rule_safe(rule, parsed_config)
    # Add rule_id and remediation to each finding
    remediation = rule.get('remediation_template', '')
    for finding in findings:
        finding['rule_id'] = rule['id']
        if 'remediation' not in finding or not finding.get('remediation'):
            finding['remediation'] = remediation
    return findings

def execute_hybrid_rule(rule, parsed_config):
    """Execute hybrid rule - combines pattern and Python execution"""
    findings = []
    
    try:
        import yaml
        
        # Parse YAML content from rule
        rule_yaml = yaml.safe_load(rule.get('yaml_content', ''))
        if not rule_yaml:
            return findings
        
        # Get pattern and python parts from YAML
        pattern = rule_yaml.get('pattern', '')
        python_code = rule_yaml.get('python_code', '')
        
        # Execute pattern part if present
        pattern_findings = []
        if pattern:
            # Create a temporary pattern rule for execution
            pattern_rule = rule.copy()
            pattern_rule['rule_type'] = 'pattern'
            pattern_findings = execute_pattern_rule(pattern_rule, parsed_config)
        
        # Execute Python part if present
        python_findings = []
        if python_code:
            # Create a temporary python rule for execution
            python_rule = rule.copy()
            python_rule['rule_type'] = 'python'
            # Store python code in yaml_content for python executor
            python_rule_yaml = {'python_code': python_code}
            import yaml
            python_rule['yaml_content'] = yaml.dump(python_rule_yaml)
            python_findings = execute_python_rule(python_rule, parsed_config)
        
        # Combine findings from both parts
        # If both pattern and python are present, use intersection logic:
        # - If pattern finds issues AND python confirms, include finding
        # - If only one finds issues, include with lower severity
        if pattern and python_code:
            # Both parts present - use intersection/confirmation logic
            # For now, combine all findings but mark which part found them
            for finding in pattern_findings:
                finding['source'] = 'pattern'
                findings.append(finding)
            for finding in python_findings:
                finding['source'] = 'python'
                # Check if pattern also found similar issue
                pattern_found_similar = any(
                    pf.get('rule_id') == finding.get('rule_id') and
                    pf.get('config_path') == finding.get('config_path')
                    for pf in pattern_findings
                )
                if pattern_found_similar:
                    # Both confirmed - keep original severity
                    finding['confirmed'] = True
                findings.append(finding)
        else:
            # Only one part present - use its findings directly
            findings.extend(pattern_findings)
            findings.extend(python_findings)
    
    except Exception as e:
        print(f"Error executing hybrid rule '{rule.get('name')}': {e}")
        import traceback
        traceback.print_exc()
    
    return findings


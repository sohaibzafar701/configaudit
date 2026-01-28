"""
Baseline configuration document generator service
"""

import json
from datetime import datetime
try:
    from apps.core.models import BaselineConfiguration, Rule
    from apps.core.model_adapter import Rule as RuleAdapter
except ImportError:
    from models.rule import Rule as RuleAdapter
    BaselineConfiguration = None


def get_baseline_rules(baseline_id):
    """Get all rules for a baseline"""
    if BaselineConfiguration is None:
        return []
    
    try:
        baseline = BaselineConfiguration.objects.get(id=baseline_id)
        rule_ids = baseline.rule_ids if baseline.rule_ids else []
        if not rule_ids:
            return []
        
        rules = Rule.objects.filter(id__in=rule_ids, enabled=True).order_by('category', 'name')
        return [rule for rule in rules]
    except BaselineConfiguration.DoesNotExist:
        return []


def generate_baseline_template(baseline_id):
    """Generate example configuration template from baseline rules"""
    rules = get_baseline_rules(baseline_id)
    if not rules:
        return None
    
    if BaselineConfiguration is None:
        return None
    
    try:
        baseline = BaselineConfiguration.objects.get(id=baseline_id)
        vendor = baseline.vendor or 'generic'
        
        template_lines = []
        template_lines.append(f"# Baseline Configuration Template: {baseline.name}")
        template_lines.append(f"# Vendor: {vendor}")
        template_lines.append(f"# Device Type: {baseline.device_type or 'N/A'}")
        template_lines.append(f"# Compliance Frameworks: {baseline.compliance_frameworks or 'N/A'}")
        template_lines.append("")
        template_lines.append("# This template shows example configurations for each security requirement")
        template_lines.append("")
        
        # Group rules by category
        categories = {}
        for rule in rules:
            category = rule.category or 'Other'
            if category not in categories:
                categories[category] = []
            categories[category].append(rule)
        
        # Generate template sections by category
        for category, category_rules in sorted(categories.items()):
            template_lines.append(f"# =========================================")
            template_lines.append(f"# Category: {category}")
            template_lines.append(f"# =========================================")
            template_lines.append("")
            
            for rule in category_rules:
                template_lines.append(f"# Rule: {rule.name}")
                if rule.description:
                    template_lines.append(f"# Description: {rule.description}")
                
                # Add remediation template as example config
                if rule.remediation_template:
                    remediation = rule.remediation_template
                    # Extract example commands from remediation
                    if 'Configure:' in remediation:
                        example = remediation.split('Configure:')[1].strip()
                        template_lines.append(f"# Example: {example}")
                    else:
                        template_lines.append(f"# Example: {remediation}")
                
                # Add compliance frameworks
                if rule.compliance_frameworks:
                    template_lines.append(f"# Compliance: {rule.compliance_frameworks}")
                
                template_lines.append("")
        
        return '\n'.join(template_lines)
    except BaselineConfiguration.DoesNotExist:
        return None


def generate_baseline_document(baseline_id, format='html'):
    """Generate baseline configuration document"""
    if BaselineConfiguration is None:
        return None
    
    try:
        baseline = BaselineConfiguration.objects.get(id=baseline_id)
        rules = get_baseline_rules(baseline_id)
        
        if format == 'html':
            return _generate_html_document(baseline, rules)
        elif format == 'json':
            return _generate_json_document(baseline, rules)
        elif format == 'text':
            return _generate_text_document(baseline, rules)
        else:
            return _generate_html_document(baseline, rules)
    except BaselineConfiguration.DoesNotExist:
        return None


def _generate_html_document(baseline, rules):
    """Generate HTML baseline document"""
    frameworks_list = baseline.get_frameworks_list()
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Baseline Configuration: {baseline.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        .metadata {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .metadata p {{ margin: 5px 0; }}
        .rule {{ border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; background: #f8f9fa; }}
        .rule-name {{ font-weight: bold; color: #2c3e50; }}
        .rule-description {{ color: #555; margin: 10px 0; }}
        .rule-remediation {{ background: #e8f5e9; padding: 10px; border-radius: 3px; margin: 10px 0; }}
        .compliance-badge {{ display: inline-block; background: #3498db; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.85em; margin: 2px; }}
        .category-section {{ margin: 30px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
    </style>
</head>
<body>
    <h1>Baseline Configuration Document</h1>
    
    <div class="metadata">
        <h2>Baseline Information</h2>
        <p><strong>Name:</strong> {baseline.name}</p>
        <p><strong>Description:</strong> {baseline.description or 'N/A'}</p>
        <p><strong>Vendor:</strong> {baseline.vendor or 'N/A'}</p>
        <p><strong>Device Type:</strong> {baseline.device_type or 'N/A'}</p>
        <p><strong>Compliance Frameworks:</strong> 
            {', '.join(['<span class="compliance-badge">' + f + '</span>' for f in frameworks_list]) if frameworks_list else 'N/A'}
        </p>
        <p><strong>Number of Rules:</strong> {len(rules)}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <h2>Security Requirements</h2>
    <p>This baseline defines {len(rules)} security requirements organized by category. Each requirement includes:</p>
    <ul>
        <li>Rule name and description</li>
        <li>Severity level</li>
        <li>Compliance framework mappings</li>
        <li>Remediation guidance</li>
    </ul>
    
    <h2>Requirements by Category</h2>
"""
    
    # Group rules by category
    categories = {}
    for rule in rules:
        category = rule.category or 'Other'
        if category not in categories:
            categories[category] = []
        categories[category].append(rule)
    
    # Generate sections for each category
    for category, category_rules in sorted(categories.items()):
        html += f"""
    <div class="category-section">
        <h3>{category} ({len(category_rules)} rules)</h3>
"""
        for rule in category_rules:
            severity_color = {
                'critical': '#e74c3c',
                'high': '#e67e22',
                'medium': '#f39c12',
                'low': '#3498db',
                'info': '#95a5a6'
            }.get(rule.severity or 'info', '#95a5a6')
            
            rule_frameworks = rule.get_frameworks_list() if hasattr(rule, 'get_frameworks_list') else []
            if rule.compliance_frameworks:
                rule_frameworks = [f.strip() for f in rule.compliance_frameworks.split(',') if f.strip()]
            
            # Build compliance HTML separately to avoid nested f-string issues
            compliance_html = ''
            if rule_frameworks:
                badges = ', '.join([f'<span class="compliance-badge">{framework}</span>' for framework in rule_frameworks])
                compliance_html = f'<div><strong>Compliance:</strong> {badges}</div>'
            
            remediation_html = ''
            if rule.remediation_template:
                remediation_html = f'<div class="rule-remediation"><strong>Remediation:</strong> {rule.remediation_template}</div>'
            
            html += f"""
        <div class="rule">
            <div class="rule-name" style="color: {severity_color};">{rule.name} [{rule.severity or 'N/A'}]</div>
            <div class="rule-description">{rule.description or 'No description'}</div>
            {compliance_html}
            {remediation_html}
        </div>
"""
        html += """
    </div>
"""
    
    html += """
    <h2>Summary</h2>
    <p>This baseline configuration document serves as a reference for secure device configuration. 
    All requirements listed above should be implemented according to the remediation guidance provided.</p>
    
    <p><em>Document generated by NCRT Baseline Configuration System</em></p>
</body>
</html>
"""
    return html


def _generate_json_document(baseline, rules):
    """Generate JSON baseline document"""
    frameworks_list = baseline.get_frameworks_list()
    
    document = {
        'baseline': {
            'id': baseline.id,
            'name': baseline.name,
            'description': baseline.description,
            'vendor': baseline.vendor,
            'device_type': baseline.device_type,
            'compliance_frameworks': frameworks_list,
            'rule_count': len(rules),
            'generated_at': datetime.now().isoformat()
        },
        'rules': []
    }
    
    for rule in rules:
        rule_frameworks = rule.get_frameworks_list() if hasattr(rule, 'get_frameworks_list') else []
        if rule.compliance_frameworks:
            rule_frameworks = [f.strip() for f in rule.compliance_frameworks.split(',') if f.strip()]
        
        document['rules'].append({
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'category': rule.category,
            'severity': rule.severity,
            'compliance_frameworks': rule_frameworks,
            'remediation_template': rule.remediation_template,
            'framework_mappings': rule.framework_mappings if hasattr(rule, 'framework_mappings') else None
        })
    
    return json.dumps(document, indent=2)


def _generate_text_document(baseline, rules):
    """Generate plain text baseline document"""
    frameworks_list = baseline.get_frameworks_list()
    
    text = f"""
BASELINE CONFIGURATION DOCUMENT
{'=' * 80}

Baseline Information:
  Name: {baseline.name}
  Description: {baseline.description or 'N/A'}
  Vendor: {baseline.vendor or 'N/A'}
  Device Type: {baseline.device_type or 'N/A'}
  Compliance Frameworks: {', '.join(frameworks_list) if frameworks_list else 'N/A'}
  Number of Rules: {len(rules)}
  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

{'=' * 80}

SECURITY REQUIREMENTS BY CATEGORY

"""
    
    # Group rules by category
    categories = {}
    for rule in rules:
        category = rule.category or 'Other'
        if category not in categories:
            categories[category] = []
        categories[category].append(rule)
    
    for category, category_rules in sorted(categories.items()):
        text += f"\n{category.upper()} ({len(category_rules)} rules)\n"
        text += "-" * 80 + "\n\n"
        
        for rule in category_rules:
            rule_frameworks = rule.get_frameworks_list() if hasattr(rule, 'get_frameworks_list') else []
            if rule.compliance_frameworks:
                rule_frameworks = [f.strip() for f in rule.compliance_frameworks.split(',') if f.strip()]
            
            text += f"Rule: {rule.name} [{rule.severity or 'N/A'}]\n"
            text += f"Description: {rule.description or 'No description'}\n"
            if rule_frameworks:
                text += f"Compliance: {', '.join(rule_frameworks)}\n"
            if rule.remediation_template:
                text += f"Remediation: {rule.remediation_template}\n"
            text += "\n"
    
    text += "\n" + "=" * 80 + "\n"
    text += "END OF DOCUMENT\n"
    
    return text


def export_baseline_document(baseline_id, format='html'):
    """Export baseline document in specified format"""
    return generate_baseline_document(baseline_id, format)

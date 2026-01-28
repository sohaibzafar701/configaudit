"""
Baseline configuration comparison service
"""

try:
    from apps.core.models import BaselineConfiguration, Audit, Finding, Rule
    from apps.core.model_adapter import Audit as AuditAdapter, Finding as FindingAdapter, Rule as RuleAdapter
except ImportError:
    from models.audit import Audit as AuditAdapter, Finding as FindingAdapter
    from models.rule import Rule as RuleAdapter
    BaselineConfiguration = None


def compare_audit_to_baseline(audit_id, baseline_id):
    """Compare an audit against a baseline configuration"""
    if BaselineConfiguration is None:
        return {'error': 'BaselineConfiguration model not available'}
    
    try:
        audit = Audit.objects.get(id=audit_id)
        baseline = BaselineConfiguration.objects.get(id=baseline_id)
    except Audit.DoesNotExist:
        return {'error': f'Audit {audit_id} not found'}
    except BaselineConfiguration.DoesNotExist:
        return {'error': f'Baseline {baseline_id} not found'}
    
    # Get baseline rules
    baseline_rule_ids = baseline.rule_ids if baseline.rule_ids else []
    if not baseline_rule_ids:
        return {'error': 'Baseline has no rules defined'}
    
    # Get audit findings
    findings = Finding.objects.filter(audit=audit, parent_finding__isnull=True)
    
    # Get findings for baseline rules
    baseline_findings = findings.filter(rule_id__in=baseline_rule_ids)
    
    # Get all baseline rules
    baseline_rules = Rule.objects.filter(id__in=baseline_rule_ids, enabled=True)
    baseline_rule_dict = {rule.id: rule for rule in baseline_rules}
    
    # Analyze compliance
    total_rules = len(baseline_rule_ids)
    rules_with_findings = set()
    failed_rules = []
    passed_rules = []
    missing_rules = []
    
    # Check each baseline rule
    for rule_id in baseline_rule_ids:
        rule = baseline_rule_dict.get(rule_id)
        if not rule:
            missing_rules.append(rule_id)
            continue
        
        # Check if this rule has findings
        rule_findings = baseline_findings.filter(rule_id=rule_id)
        
        # Only count critical, high, and medium severity findings as failures
        critical_findings = rule_findings.filter(severity__in=['critical', 'high', 'medium'])
        
        if critical_findings.exists():
            rules_with_findings.add(rule_id)
            failed_rules.append({
                'rule_id': rule_id,
                'rule_name': rule.name,
                'rule_category': rule.category,
                'severity': rule.severity,
                'findings_count': critical_findings.count(),
                'findings': [
                    {
                        'id': f.id,
                        'severity': f.severity,
                        'message': f.message,
                        'config_path': f.config_path,
                        'remediation': f.remediation
                    }
                    for f in critical_findings[:10]  # Limit to first 10 findings
                ]
            })
        else:
            passed_rules.append({
                'rule_id': rule_id,
                'rule_name': rule.name,
                'rule_category': rule.category,
                'severity': rule.severity
            })
    
    # Calculate compliance score
    passed_count = len(passed_rules)
    failed_count = len(failed_rules)
    compliance_score = (passed_count / total_rules * 100) if total_rules > 0 else 0
    
    # Determine compliance level
    if compliance_score >= 90:
        compliance_level = 'Excellent'
    elif compliance_score >= 75:
        compliance_level = 'Good'
    elif compliance_score >= 50:
        compliance_level = 'Fair'
    else:
        compliance_level = 'Poor'
    
    return {
        'audit_id': audit_id,
        'baseline_id': baseline_id,
        'baseline_name': baseline.name,
        'audit_device': audit.device_identifier,
        'total_rules': total_rules,
        'passed_rules': passed_count,
        'failed_rules': failed_count,
        'missing_rules': len(missing_rules),
        'compliance_score': round(compliance_score, 2),
        'compliance_level': compliance_level,
        'passed_rules_detail': passed_rules,
        'failed_rules_detail': failed_rules,
        'missing_rules_detail': missing_rules,
        'comparison_date': audit.completed_at.isoformat() if audit.completed_at else None
    }


def get_baseline_compliance(audit_id, baseline_id):
    """Get compliance score for audit against baseline"""
    comparison = compare_audit_to_baseline(audit_id, baseline_id)
    if 'error' in comparison:
        return comparison
    
    return {
        'compliance_score': comparison['compliance_score'],
        'compliance_level': comparison['compliance_level'],
        'passed_rules': comparison['passed_rules'],
        'failed_rules': comparison['failed_rules'],
        'total_rules': comparison['total_rules']
    }


def generate_comparison_report(audit_id, baseline_id, format='html'):
    """Generate comparison report between audit and baseline"""
    comparison = compare_audit_to_baseline(audit_id, baseline_id)
    if 'error' in comparison:
        return comparison
    
    if format == 'html':
        return _generate_html_comparison_report(comparison)
    elif format == 'json':
        import json
        return json.dumps(comparison, indent=2)
    else:
        return _generate_html_comparison_report(comparison)


def _generate_html_comparison_report(comparison):
    """Generate HTML comparison report"""
    compliance_color = {
        'Excellent': '#27ae60',
        'Good': '#2ecc71',
        'Fair': '#f39c12',
        'Poor': '#e74c3c'
    }.get(comparison['compliance_level'], '#95a5a6')
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Baseline Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .summary {{ background: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .compliance-score {{ font-size: 2em; font-weight: bold; color: {compliance_color}; }}
        .rule-item {{ border-left: 4px solid #3498db; padding: 15px; margin: 15px 0; background: #f8f9fa; }}
        .rule-passed {{ border-left-color: #27ae60; }}
        .rule-failed {{ border-left-color: #e74c3c; }}
        .finding-item {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .severity-critical {{ color: #e74c3c; font-weight: bold; }}
        .severity-high {{ color: #e67e22; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #3498db; color: white; }}
    </style>
</head>
<body>
    <h1>Baseline Compliance Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Baseline:</strong> {comparison['baseline_name']}</p>
        <p><strong>Device:</strong> {comparison['audit_device']}</p>
        <p><strong>Compliance Score:</strong> <span class="compliance-score">{comparison['compliance_score']}%</span></p>
        <p><strong>Compliance Level:</strong> <span style="color: {compliance_color}; font-weight: bold;">{comparison['compliance_level']}</span></p>
        <p><strong>Total Rules:</strong> {comparison['total_rules']}</p>
        <p><strong>Passed:</strong> {comparison['passed_rules']} | <strong>Failed:</strong> {comparison['failed_rules']}</p>
    </div>
    
    <h2>Failed Requirements ({comparison['failed_rules']})</h2>
"""
    
    for failed_rule in comparison['failed_rules_detail']:
        html += f"""
    <div class="rule-item rule-failed">
        <h3>{failed_rule['rule_name']} [{failed_rule['rule_category']}]</h3>
        <p><strong>Severity:</strong> {failed_rule['severity']}</p>
        <p><strong>Findings:</strong> {failed_rule['findings_count']}</p>
        <h4>Issues Found:</h4>
"""
        for finding in failed_rule['findings']:
            severity_class = f"severity-{finding['severity']}"
            html += f"""
        <div class="finding-item">
            <div class="{severity_class}">[{finding['severity'].upper()}] {finding['message']}</div>
            {f'<div><strong>Location:</strong> {finding["config_path"]}</div>' if finding.get('config_path') else ''}
            {f'<div><strong>Remediation:</strong> {finding["remediation"]}</div>' if finding.get('remediation') else ''}
        </div>
"""
        html += """
    </div>
"""
    
    html += f"""
    <h2>Passed Requirements ({comparison['passed_rules']})</h2>
"""
    
    # Group passed rules by category
    passed_by_category = {}
    for rule in comparison['passed_rules_detail']:
        category = rule['rule_category'] or 'Other'
        if category not in passed_by_category:
            passed_by_category[category] = []
        passed_by_category[category].append(rule)
    
    for category, rules in sorted(passed_by_category.items()):
        html += f"""
    <h3>{category}</h3>
"""
        for rule in rules:
            html += f"""
    <div class="rule-item rule-passed">
        <strong>{rule['rule_name']}</strong> [{rule['severity']}]
    </div>
"""
    
    html += """
    <h2>Remediation Roadmap</h2>
    <p>To achieve full compliance with this baseline, address the following failed requirements:</p>
    <ol>
"""
    
    for failed_rule in comparison['failed_rules_detail']:
        html += f"""
        <li>
            <strong>{failed_rule['rule_name']}</strong> - {failed_rule['findings_count']} issue(s) found
            <ul>
"""
        for finding in failed_rule['findings'][:5]:  # Show first 5 findings
            html += f"""
                <li>{finding['message']} - {finding.get('remediation', 'See rule remediation template')}</li>
"""
        html += """
            </ul>
        </li>
"""
    
    html += """
    </ol>
    
    <p><em>Report generated by NCRT Baseline Comparison System</em></p>
</body>
</html>
"""
    return html

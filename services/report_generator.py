"""
Report generation service
"""

# Use Django models via adapter for compatibility
try:
    from apps.core.model_adapter import Audit, Finding, Rule
except ImportError:
    # Fallback to old models if Django not available
    from models.audit import Audit, Finding
    from models.rule import Rule
from services.database import get_db_connection

def get_filtered_findings(audit_id, filters=None, sort_by='severity', sort_order='desc', group_by=None):
    """Get filtered, sorted, and optionally grouped findings for an audit
    
    Returns findings in parent-child structure (parent findings with children arrays)
    """
    if filters is None:
        filters = {}
    
    # Get findings grouped by parent-child structure
    findings = Finding.get_grouped_by_audit(audit_id)
    
    # Attach rule details to findings for easier filtering
    # Handle parent-child structure: findings is list of parent findings, each with 'children' array
    flat_findings_for_filtering = []
    for parent in findings:
        # Attach rule details to parent
        rule = Rule.get_by_id(parent.get('rule_id'))
        if rule:
            parent['rule_name'] = rule.get('name', 'Unknown')
            parent['rule_category'] = rule.get('category', 'Unknown')
            parent['rule_type'] = rule.get('rule_type', 'Unknown')
        else:
            parent['rule_name'] = 'Unknown'
            parent['rule_category'] = 'Unknown'
            parent['rule_type'] = 'Unknown'
        
        # Attach rule details to children
        for child in parent.get('children', []):
            child_rule = Rule.get_by_id(child.get('rule_id'))
            if child_rule:
                child['rule_name'] = child_rule.get('name', 'Unknown')
                child['rule_category'] = child_rule.get('category', 'Unknown')
                child['rule_type'] = child_rule.get('rule_type', 'Unknown')
            else:
                child['rule_name'] = 'Unknown'
                child['rule_category'] = 'Unknown'
                child['rule_type'] = 'Unknown'
        
        # Add parent and children to flat list for filtering
        flat_findings_for_filtering.append(parent)
        flat_findings_for_filtering.extend(parent.get('children', []))
    
    # Apply filters to parent-child structure
    # Filter at parent level - if parent matches, include it with its children
    # If only children match, we still include the parent with filtered children
    filtered_findings = []
    for parent in findings:
        # Check if parent matches filters
        parent_matches = _finding_matches_filters(parent, filters)
        
        # Filter children
        filtered_children = []
        for child in parent.get('children', []):
            if _finding_matches_filters(child, filters):
                filtered_children.append(child)
        
        # Include parent if it matches filters OR if it has matching children
        if parent_matches or filtered_children:
            # Create a copy of parent with filtered children
            filtered_parent = dict(parent)
            if filtered_children:
                filtered_parent['children'] = filtered_children
            else:
                filtered_parent['children'] = []
            filtered_findings.append(filtered_parent)
    
    # Sort findings (sort parent findings, children are already sorted by creation order)
    severity_order = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
    
    def sort_key(finding):
        if sort_by == 'severity':
            return severity_order.get(finding.get('severity', 'medium').lower(), 0)
        elif sort_by == 'rule_name':
            return finding.get('rule_name', '').lower()
        elif sort_by == 'category':
            rule = Rule.get_by_id(finding.get('rule_id'))
            return rule.get('category', '').lower() if rule else ''
        return 0
    
    filtered_findings.sort(key=sort_key, reverse=(sort_order == 'desc'))
    
    # Sort children within each parent (optional, but good for consistency)
    for parent in filtered_findings:
        if parent.get('children'):
            parent['children'].sort(key=sort_key, reverse=(sort_order == 'desc'))
    
    # Group findings if requested (group parent findings, children stay with their parents)
    if group_by:
        grouped = {}
        for parent in filtered_findings:
            if group_by == 'rule':
                key = parent.get('rule_name', 'Unknown')
            elif group_by == 'category':
                rule = Rule.get_by_id(parent.get('rule_id'))
                key = rule.get('category', 'Unknown') if rule else 'Unknown'
            elif group_by == 'severity':
                key = parent.get('severity', 'medium')
            elif group_by == 'config_path':
                key = parent.get('config_path', 'N/A') or 'N/A'
            else:
                key = 'Other'
            
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(parent)
        
        # Convert to list format with metadata
        result = []
        for key, items in grouped.items():
            result.append({
                'group_key': key,
                'group_count': len(items),
                'findings': items  # Each item is a parent with children
            })
        return result
    
    return filtered_findings

def _finding_matches_filters(finding, filters):
    """Check if a finding matches the given filters"""
    # Severity filter
    if filters.get('severity') and finding.get('severity', '').lower() != filters['severity'].lower():
        return False
    
    # Category filter
    if filters.get('category') and finding.get('rule_category', '').lower() != filters['category'].lower():
        return False
    
    # Rule type filter
    if filters.get('rule_type') and finding.get('rule_type', '').lower() != filters['rule_type'].lower():
        return False
    
    # Rule ID filter
    if filters.get('rule_id') and finding.get('rule_id') != filters['rule_id']:
        return False
    
    # Text search filter (searches in message, rule name, config path)
    if filters.get('search'):
        search_term = filters['search'].lower()
        message_match = search_term in (finding.get('message', '') or '').lower()
        rule_name_match = search_term in (finding.get('rule_name', '') or '').lower()
        config_path_match = search_term in (finding.get('config_path', '') or '').lower()
        if not (message_match or rule_name_match or config_path_match):
            return False
    
    # Rule name filter
    if filters.get('rule_name'):
        rule_name_term = filters['rule_name'].lower()
        if rule_name_term not in (finding.get('rule_name', '') or '').lower():
            return False
    
    # Config path filter
    if filters.get('config_path'):
        config_path_term = filters['config_path'].lower()
        if config_path_term not in (finding.get('config_path', '') or '').lower():
            return False
    
    # Tag filter
    if filters.get('tag'):
        rule = Rule.get_by_id(finding.get('rule_id'))
        if rule:
            tags_str = rule.get('tags', '')
            if tags_str and filters['tag'].lower() not in tags_str.lower():
                return False
        else:
            return False
    
    return True

def generate_statistics(audit_id):
    """Generate statistics for an audit with advanced risk scoring
    Only counts parent findings (not children) for accurate grouping statistics
    """
    # Get only parent findings (children are not counted in statistics)
    findings = Finding.get_parents(audit_id)
    
    if not findings:
        return {
            'total_findings': 0,
            'severity_breakdown': {'counts': {}, 'percentages': {}},
            'category_breakdown': {},
            'rule_type_breakdown': {},
            'risk_score': 0,
            'risk_level': 'Low',
            'compliance_score': 0
        }
    
    # Severity weights for risk calculation
    severity_weights = {
        'critical': 10,
        'high': 7,
        'medium': 4,
        'low': 2,
        'info': 1
    }
    
    # Category weights
    category_weights = {
        'authentication': 1.2,
        'encryption': 1.3,
        'access_control': 1.2,
        'firewall': 1.1,
        'vpn': 1.15,
        'management': 1.5,  # Management interfaces are critical
        'default': 1.0
    }
    
    # Severity breakdown
    severity_counts = {}
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    for severity in severity_order:
        severity_counts[severity] = 0
    
    # Category breakdown
    category_counts = {}
    rule_type_counts = {}
    
    # Risk score calculation
    total_risk_score = 0
    category_risk_scores = {}
    
    for finding in findings:
        sev = finding.get('severity', 'medium').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Category breakdown
        category = finding.get('rule_category', 'Unknown').lower()
        category_counts[category] = category_counts.get(category, 0) + 1
        
        # Rule type breakdown
        rule_type = finding.get('rule_type', 'Unknown').lower()
        rule_type_counts[rule_type] = rule_type_counts.get(rule_type, 0) + 1
        
        # Calculate weighted risk score
        base_weight = severity_weights.get(sev, 1)
        cat_weight = category_weights.get(category, category_weights.get('default', 1.0))
        
        # Check if config path indicates management interface
        config_path = finding.get('config_path') or ''
        config_path_lower = config_path.lower() if config_path else ''
        path_multiplier = 1.5 if any(term in config_path_lower for term in ['management', 'mgmt', 'console', 'vty', 'ssh', 'telnet']) else 1.0
        
        # Get rule-specific risk weight
        rule = Rule.get_by_id(finding.get('rule_id'))
        rule_weight = rule.get('risk_weight', 1.0) if rule else 1.0
        
        finding_risk = base_weight * cat_weight * path_multiplier * rule_weight
        total_risk_score += finding_risk
        
        # Track category risk
        if category not in category_risk_scores:
            category_risk_scores[category] = 0
        category_risk_scores[category] += finding_risk
    
    # Calculate percentages
    total = len(findings)
    severity_percentages = {k: (v / total * 100) if total > 0 else 0 for k, v in severity_counts.items()}
    
    # Normalize risk score (0-100 scale)
    # Max possible score: 10 (critical) * 1.5 (category) * 1.5 (path) * 2.0 (rule weight) = 45 per finding
    # For 100 findings max, that's 4500. Normalize to 0-100.
    max_possible_score = total * 45  # Conservative estimate
    normalized_risk_score = min(100, (total_risk_score / max_possible_score * 100) if max_possible_score > 0 else 0)
    
    # Determine risk level
    if normalized_risk_score >= 70:
        risk_level = 'Critical'
    elif normalized_risk_score >= 50:
        risk_level = 'High'
    elif normalized_risk_score >= 30:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    
    # Calculate compliance score (basic)
    compliance_score = calculate_compliance_score(audit_id).get('score', 0)
    
    return {
        'total_findings': total,
        'severity_breakdown': {
            'counts': severity_counts,
            'percentages': severity_percentages
        },
        'category_breakdown': category_counts,
        'rule_type_breakdown': rule_type_counts,
        'risk_score': round(normalized_risk_score, 2),
        'risk_level': risk_level,
        'risk_breakdown': category_risk_scores,
        'compliance_score': round(compliance_score, 2)
    }

def calculate_compliance_score(audit_id, framework=None):
    """Calculate compliance score for a specific framework with requirement-level detail
    Only counts parent findings (not children) for accurate compliance scoring
    """
    # Get only parent findings (children are not counted in compliance)
    findings = Finding.get_parents(audit_id)
    
    # Get all rules, filtered by framework if specified
    all_rules = Rule.get_all(enabled_only=True)
    
    # Standard compliance frameworks
    standard_frameworks = {
        'PCI-DSS': 'Payment Card Industry Data Security Standard',
        'HIPAA': 'Health Insurance Portability and Accountability Act',
        'ISO27001': 'ISO/IEC 27001 Information Security Management',
        'NIST-CSF': 'NIST Cybersecurity Framework',
        'CIS': 'CIS Benchmarks',
        'SOX': 'Sarbanes-Oxley Act',
        'GDPR': 'General Data Protection Regulation'
    }
    
    if framework and framework.lower() != 'general':
        # Filter rules by framework
        framework_rules = []
        for rule in all_rules:
            frameworks_str = rule.get('compliance_frameworks', '')
            if frameworks_str and framework.lower() in frameworks_str.lower():
                framework_rules.append(rule)
        all_rules = framework_rules
    
    if not all_rules:
        return {
            'framework': framework or 'general',
            'framework_name': standard_frameworks.get(framework or 'general', 'General Compliance'),
            'score': 0,
            'total_rules': 0,
            'passed_rules': 0,
            'failed_rules': 0,
            'failed_rule_ids': [],
            'requirements': {}
        }
    
    # Create a set of rule IDs that are in all_rules for quick lookup
    all_rule_ids = {rule['id'] for rule in all_rules}
    
    # Count rules that have findings vs those that don't
    # Only count critical, high, and medium severity findings as failures
    # Only count findings for rules that are in the current framework's rule set
    rules_with_findings = set()
    failed_rule_ids = []
    requirement_failures = {}  # Track failures by requirement
    
    for f in findings:
        if f.get('severity', '').lower() in ['critical', 'high', 'medium']:
            rule_id = f.get('rule_id')
            # Only count this finding if the rule is in the current framework's rule set
            if rule_id and rule_id in all_rule_ids:
                rules_with_findings.add(rule_id)
                if rule_id not in failed_rule_ids:
                    failed_rule_ids.append(rule_id)
                
                # Extract requirement mappings from rule
                rule = Rule.get_by_id(rule_id)
                if rule:
                    framework_mappings_str = rule.get('framework_mappings', '')
                    if framework_mappings_str:
                        try:
                            import json
                            mappings = json.loads(framework_mappings_str)
                            if framework and framework in mappings:
                                req_id = mappings[framework]
                                if req_id not in requirement_failures:
                                    requirement_failures[req_id] = []
                                requirement_failures[req_id].append({
                                    'rule_id': rule_id,
                                    'rule_name': rule.get('name'),
                                    'severity': f.get('severity')
                                })
                        except:
                            pass
    
    # Calculate score
    total_rules = len(all_rules)
    passed_rules = total_rules - len(rules_with_findings)
    failed_rules = len(rules_with_findings)
    
    score = (passed_rules / total_rules * 100) if total_rules > 0 else 0
    
    # Build requirements map
    requirements_map = {}
    for rule in all_rules:
        framework_mappings_str = rule.get('framework_mappings', '')
        if framework_mappings_str:
            try:
                import json
                mappings = json.loads(framework_mappings_str)
                if framework and framework in mappings:
                    req_id = mappings[framework]
                    if req_id not in requirements_map:
                        requirements_map[req_id] = {
                            'requirement_id': req_id,
                            'total_rules': 0,
                            'passed_rules': 0,
                            'failed_rules': 0,
                            'status': 'pass'
                        }
                    requirements_map[req_id]['total_rules'] += 1
                    if rule['id'] in rules_with_findings:
                        requirements_map[req_id]['failed_rules'] += 1
                        requirements_map[req_id]['status'] = 'fail'
                    else:
                        requirements_map[req_id]['passed_rules'] += 1
            except:
                pass
    
    return {
        'framework': framework or 'general',
        'framework_name': standard_frameworks.get(framework or 'general', 'General Compliance'),
        'score': round(score, 2),
        'total_rules': total_rules,
        'passed_rules': passed_rules,
        'failed_rules': failed_rules,
        'failed_rule_ids': failed_rule_ids,
        'requirements': requirements_map,
        'requirement_failures': requirement_failures
    }

def generate_executive_summary(audit_id):
    """Generate executive summary for an audit"""
    audit = Audit.get_by_id(audit_id)
    if not audit:
        return None
    
    statistics = generate_statistics(audit_id)
    findings = Finding.get_by_audit(audit_id)
    
    # Get top 5 critical findings
    critical_findings = sorted(
        [f for f in findings if f.get('severity', '').lower() in ['critical', 'high']],
        key=lambda x: {'critical': 0, 'high': 1}.get(x.get('severity', '').lower(), 2)
    )[:5]
    
    # Get compliance scores for all frameworks
    compliance_scores = {}
    all_rules = Rule.get_all(enabled_only=True)
    frameworks = set()
    for rule in all_rules:
        frameworks_str = rule.get('compliance_frameworks', '')
        if frameworks_str:
            frameworks.update(frameworks_str.split(','))
    
    for framework in frameworks:
        if framework.strip():
            compliance_scores[framework.strip()] = calculate_compliance_score(audit_id, framework.strip())
    
    # If no frameworks, use general
    if not compliance_scores:
        compliance_scores['General'] = calculate_compliance_score(audit_id)
    
    # Key recommendations
    key_recommendations = []
    if statistics.get('risk_level', 'Low') in ['Critical', 'High']:
        key_recommendations.append("Immediate action required: Address critical and high severity findings")
    if statistics.get('severity_breakdown', {}).get('counts', {}).get('critical', 0) > 0:
        key_recommendations.append(f"Resolve {statistics.get('severity_breakdown', {}).get('counts', {}).get('critical', 0)} critical findings as priority")
    if statistics.get('compliance_score', 100) < 70:
        key_recommendations.append("Compliance score below acceptable threshold - review failed rules")
    
    return {
        'audit_id': audit_id,
        'device_family': audit.get('device_family', 'Unknown'),
        'config_file': audit.get('config_file', 'Unknown'),
        'created_at': audit.get('created_at', ''),
        'risk_assessment': {
            'level': statistics.get('risk_level', 'Low'),
            'score': statistics.get('risk_score', 0),
            'total_findings': statistics.get('total_findings', 0)
        },
        'top_findings': [
            {
                'rule_name': f.get('rule_name', 'Unknown'),
                'severity': f.get('severity', 'medium'),
                'message': (f.get('message', '')[:100] + '...') if len(f.get('message', '')) > 100 else f.get('message', '')
            }
            for f in critical_findings
        ],
        'compliance_status': compliance_scores,
        'key_recommendations': key_recommendations,
        'statistics_summary': {
            'critical': statistics.get('severity_breakdown', {}).get('counts', {}).get('critical', 0),
            'high': statistics.get('severity_breakdown', {}).get('counts', {}).get('high', 0),
            'medium': statistics.get('severity_breakdown', {}).get('counts', {}).get('medium', 0)
        }
    }

def generate_pdf_report(audit_id, filters=None, sort_by='severity', sort_order='desc', group_by=None, sections=None, preset=None, timezone_str='UTC', date_format='%Y-%m-%d %H:%M:%S'):
    """Generate PDF report with customizable sections using ReportLab (pure Python)"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm, inch
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
        from reportlab.pdfgen import canvas
        from io import BytesIO
    except ImportError as e:
        raise ImportError(
            "ReportLab is required for PDF generation. "
            "Install it with: pip install reportlab"
        ) from e
    
    audit = Audit.get_by_id(audit_id)
    if not audit:
        return b''
    
    if sections is None:
        sections = ['statistics', 'findings', 'compliance', 'charts']
    
    findings = get_filtered_findings(audit_id, filters, sort_by, sort_order, group_by)
    statistics = generate_statistics(audit_id) if 'statistics' in sections else None
    compliance = calculate_compliance_score(audit_id) if 'compliance' in sections else None
    executive_summary = generate_executive_summary(audit_id) if 'executive_summary' in sections else None
    
    # Handle parent-child structure: findings is list of parent findings, each with 'children' array
    # Flatten for HTML display: include parent and all children as separate rows
    flat_findings = []
    for parent in findings:
        # Add parent finding
        flat_findings.append(parent)
        # Add children if they exist
        if parent.get('children'):
            flat_findings.extend(parent['children'])
    findings = flat_findings
    
    # Create PDF in memory
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=1.5*cm, leftMargin=1.5*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    
    # Container for the 'Flowable' objects
    story = []
    
    # Define styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading1_style = ParagraphStyle(
        'CustomHeading1',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=12,
        borderWidth=0,
        borderPadding=0
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#475569'),
        spaceAfter=10
    )
    
    normal_style = styles['Normal']
    normal_style.fontSize = 10
    normal_style.leading = 14
    
    # Cover page
    from datetime import datetime
    from services.timezone_utils import format_datetime_now
    story.append(Spacer(1, 3*cm))
    story.append(Paragraph("NCRT Audit Report", title_style))
    story.append(Spacer(1, 1*cm))
    story.append(Paragraph("Network Configuration Security Assessment", 
                          ParagraphStyle('Subtitle', parent=normal_style, fontSize=16, 
                                        textColor=colors.white, alignment=TA_CENTER)))
    story.append(Spacer(1, 2*cm))
    
    # Cover page metadata box
    metadata_data = [
        ['Audit ID:', str(audit.get('id', 'N/A'))],
        ['Device Family:', audit.get('device_family', 'Unknown')],
        ['Config File:', audit.get('config_file', 'Unknown')],
        ['Status:', audit.get('status', 'Unknown')],
        ['Generated:', format_datetime_now(timezone_str, date_format)]
    ]
    metadata_table = Table(metadata_data, colWidths=[4*cm, 8*cm])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#667eea')),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.white),
        ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#1e293b')),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.white)
    ]))
    story.append(metadata_table)
    story.append(PageBreak())
    
    # Executive Summary
    if executive_summary and 'executive_summary' in sections:
        story.append(Paragraph("Executive Summary", heading1_style))
        risk_assessment = executive_summary.get('risk_assessment', {})
        story.append(Paragraph(f"<b>Risk Level:</b> {risk_assessment.get('level', 'Low')}", normal_style))
        story.append(Paragraph(f"<b>Risk Score:</b> {risk_assessment.get('score', 0):.1f}", normal_style))
        story.append(Paragraph(f"<b>Total Findings:</b> {risk_assessment.get('total_findings', 0)}", normal_style))
        story.append(Spacer(1, 0.5*cm))
    
    # Statistics section
    if statistics and 'statistics' in sections:
        story.append(Paragraph("Statistics", heading1_style))
        
        stats_data = [
            ['Metric', 'Value'],
            ['Total Findings', str(statistics.get('total_findings', 0))],
            ['Risk Score', f"{statistics.get('risk_score', 0):.2f}"],
            ['Risk Level', statistics.get('risk_level', 'Low')],
            ['Compliance Score', f"{statistics.get('compliance_score', 0):.2f}%"]
        ]
        
        # Add severity breakdown
        severity_breakdown = statistics.get('severity_breakdown', {}).get('counts', {})
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_breakdown.get(severity, 0)
            if count > 0:
                stats_data.append([f'{severity.capitalize()} Findings', str(count)])
        
        stats_table = Table(stats_data, colWidths=[6*cm, 6*cm])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')])
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.5*cm))
    
    # Findings section
    if findings and 'findings' in sections:
        story.append(Paragraph("Findings", heading1_style))
        
        # Findings table
        findings_data = [['Severity', 'Category', 'Rule', 'Message', 'Path']]
        
        for finding in findings[:100]:  # Limit to first 100 findings for PDF
            severity = (finding.get('severity') or 'info').upper() if finding else 'INFO'
            category = finding.get('category') or 'Unknown' if finding else 'Unknown'
            
            # Safely get and truncate string values
            rule_name = str(finding.get('rule_name') or 'Unknown')[:30] if finding else 'Unknown'
            message = str(finding.get('message') or '')[:50] if finding else ''
            config_path = str(finding.get('config_path') or 'N/A')[:40] if finding else 'N/A'
            
            # Color coding for severity
            severity_color = {
                'CRITICAL': colors.HexColor('#dc2626'),
                'HIGH': colors.HexColor('#ea580c'),
                'MEDIUM': colors.HexColor('#ca8a04'),
                'LOW': colors.HexColor('#16a34a'),
                'INFO': colors.HexColor('#0891b2')
            }.get(severity, colors.black)
            
            findings_data.append([severity, category, rule_name, message, config_path])
        
        if len(findings) > 100:
            findings_data.append(['', '', '', f'... and {len(findings) - 100} more findings', ''])
        
        findings_table = Table(findings_data, colWidths=[1.5*cm, 2*cm, 3*cm, 4*cm, 3.5*cm])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8fafc')]),
            ('TEXTCOLOR', (0, 1), (0, -1), colors.HexColor('#dc2626'))  # Severity column color
        ]))
        story.append(KeepTogether(findings_table))
        story.append(Spacer(1, 0.5*cm))
    
    # Compliance section
    if compliance and 'compliance' in sections:
        story.append(Paragraph("Compliance", heading1_style))
        
        frameworks = compliance.get('frameworks', {})
        for framework_name, framework_data in frameworks.items():
            story.append(Paragraph(f"<b>{framework_name}</b>", heading2_style))
            score = framework_data.get('score', 0)
            story.append(Paragraph(f"Compliance Score: {score:.1f}%", normal_style))
            
            requirements = framework_data.get('requirements', {})
            if requirements:
                req_data = [['Requirement', 'Status']]
                for req_id, req_data_item in list(requirements.items())[:20]:  # Limit to first 20
                    status = req_data_item.get('status', 'N/A')
                    req_data.append([req_id, status])
                
                req_table = Table(req_data, colWidths=[8*cm, 4*cm])
                req_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#e2e8f0'))
                ]))
                story.append(req_table)
            story.append(Spacer(1, 0.3*cm))
    
    # Build PDF
    def add_page_number(canvas_obj, doc):
        """Add page number to each page"""
        canvas_obj.saveState()
        canvas_obj.setFont('Helvetica', 9)
        page_num = canvas_obj.getPageNumber()
        text = f"Page {page_num}"
        canvas_obj.drawCentredString(10.5*cm, 1*cm, text)
        canvas_obj.restoreState()
    
    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
    
    # Get PDF bytes
    pdf_bytes = buffer.getvalue()
    buffer.close()
    
    # Validate PDF
    if not pdf_bytes or len(pdf_bytes) < 100:
        raise ValueError("Generated PDF is empty or too small")
    
    if not pdf_bytes.startswith(b'%PDF'):
        raise ValueError("Generated content is not a valid PDF")
    
    print(f"Successfully generated PDF using ReportLab: {len(pdf_bytes)} bytes")
    return pdf_bytes

def generate_csv_report(audit_id, filters=None, sort_by='severity', sort_order='desc', sections=None, timezone_str='UTC', date_format='%Y-%m-%d %H:%M:%S'):
    """Generate CSV report with customizable sections"""
    import csv
    import io
    from datetime import datetime
    from services.timezone_utils import format_datetime_now
    
    if sections is None:
        sections = ['findings']
    
    audit = Audit.get_by_id(audit_id)
    findings = get_filtered_findings(audit_id, filters, sort_by, sort_order, None)
    
    # Handle parent-child structure: findings is list of parent findings, each with 'children' array
    # Flatten for HTML display: include parent and all children as separate rows
    flat_findings = []
    for parent in findings:
        # Add parent finding
        flat_findings.append(parent)
        # Add children if they exist
        if parent.get('children'):
            flat_findings.extend(parent['children'])
    findings = flat_findings
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write metadata if statistics section is included
    if 'statistics' in sections and audit:
        writer.writerow(['NCRT Audit Report'])
        writer.writerow(['Generated:', format_datetime_now(timezone_str, date_format)])
        writer.writerow(['Audit ID:', audit.get('id', 'N/A')])
        writer.writerow(['Config File:', audit.get('config_file', 'N/A')])
        writer.writerow(['Device Family:', audit.get('device_family', 'N/A')])
        writer.writerow(['Status:', audit.get('status', 'N/A')])
        writer.writerow([])  # Empty row
    
    # Write header
    writer.writerow(['Rule', 'Severity', 'Category', 'Message', 'Config Path', 'Remediation'])
    
    # Write findings - include parent and children
    grouped_findings = Finding.get_grouped_by_audit(audit_id)
    for parent in grouped_findings:
        # Write parent finding
        writer.writerow([
            parent.get('rule_name', 'Unknown'),
            parent.get('severity', 'medium'),
            parent.get('rule_category', 'Unknown'),
            parent.get('message', ''),
            parent.get('config_path', ''),
            parent.get('remediation', '') or parent.get('rule_remediation_template', '')
        ])
        # Write children
        for child in parent.get('children', []):
            writer.writerow([
                '  ' + (child.get('rule_name', 'Unknown') or parent.get('rule_name', 'Unknown')),
                child.get('severity', 'medium'),
                child.get('rule_category', 'Unknown'),
                child.get('message', ''),
                child.get('config_path', ''),
                child.get('remediation', '') or child.get('rule_remediation_template', '')
            ])
    
    return output.getvalue()

def generate_html_standalone_report(audit_id, filters=None, sort_by='severity', sort_order='desc', group_by=None, sections=None, timezone_str='UTC', date_format='%Y-%m-%d %H:%M:%S'):
    """Generate standalone HTML report that can be opened in any browser"""
    if sections is None:
        sections = ['statistics', 'findings', 'compliance']
    findings = get_filtered_findings(audit_id, filters, sort_by, sort_order, group_by)
    statistics = generate_statistics(audit_id) if 'statistics' in sections else None
    compliance = calculate_compliance_score(audit_id) if 'compliance' in sections else None
    return generate_html_report(audit_id, findings, statistics, compliance, sections, None, timezone_str, date_format)

def generate_html_report(audit_id, findings=None, statistics=None, compliance=None, sections=None, preset=None, timezone_str='UTC', date_format='%Y-%m-%d %H:%M:%S'):
    """Generate HTML report for audit with customizable sections"""
    audit = Audit.get_by_id(audit_id)
    if not audit:
        return None
    
    if sections is None:
        sections = ['statistics', 'findings', 'compliance']
    
    if findings is None:
        findings = Finding.get_by_audit(audit_id)
    
    if statistics is None and 'statistics' in sections:
        statistics = generate_statistics(audit_id)
    
    if compliance is None and 'compliance' in sections:
        compliance = calculate_compliance_score(audit_id)
    
    # Handle parent-child structure: findings is list of parent findings, each with 'children' array
    # Flatten for HTML display: include parent and all children as separate rows
    flat_findings = []
    for parent in findings:
        # Add parent finding
        flat_findings.append(parent)
        # Add children if they exist
        if parent.get('children'):
            flat_findings.extend(parent['children'])
    findings = flat_findings
    
    # Ensure config_file has a value (use device_identifier as fallback)
    if not audit.get('config_file'):
        audit['config_file'] = audit.get('device_identifier', 'Unknown')
    
    from datetime import datetime
    from services.timezone_utils import format_datetime_now
    executive_summary = generate_executive_summary(audit_id) if 'executive_summary' in sections else None
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>NCRT Audit Report - {audit.get('config_file', 'Unknown')}</title>
    <style>
        @page {{
            margin: 2cm;
            @top-center {{
                content: "NCRT Audit Report";
                font-size: 10pt;
                color: #666;
            }}
            @bottom-center {{
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10pt;
                color: #666;
            }}
        }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; line-height: 1.6; color: #333; }}
        .cover-page {{
            page-break-after: always;
            text-align: center;
            padding: 100px 50px;
            background-color: #667eea;
            color: white;
            min-height: 80vh;
            display: block;
            text-align: center;
        }}
        .cover-page h1 {{
            font-size: 48px;
            margin-bottom: 20px;
            color: white;
            border: none;
        }}
        .cover-page .subtitle {{
            font-size: 24px;
            margin-bottom: 50px;
            opacity: 0.9;
        }}
        .cover-page .metadata {{
            background-color: rgba(255,255,255,0.2);
            padding: 30px;
            border-radius: 10px;
            margin-top: 50px;
            text-align: left;
            display: inline-block;
        }}
        .toc {{
            page-break-after: always;
            margin: 40px 0;
        }}
        .toc h2 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }}
        .toc ul {{
            list-style: none;
            padding: 0;
        }}
        .toc li {{
            padding: 8px 0;
            border-bottom: 1px solid #ecf0f1;
        }}
        .toc a {{
            text-decoration: none;
            color: #2c3e50;
        }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; page-break-after: avoid; }}
        h2 {{ color: #34495e; margin-top: 30px; border-bottom: 2px solid #ecf0f1; padding-bottom: 5px; page-break-after: avoid; }}
        .report-header {{ background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; page-break-inside: avoid; }}
        .statistics-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background-color: #fff; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stat-card h3 {{ margin: 0 0 10px 0; color: #6c757d; font-size: 14px; }}
        .stat-card .value {{ font-size: 32px; font-weight: bold; color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; page-break-inside: auto; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #2c3e50; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        .severity-info {{ color: #17a2b8; }}
        .parent-finding {{ background-color: #f8f9fa; font-weight: bold; }}
        .child-finding {{ background-color: #ffffff; }}
        .remediation-box {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }}
        .remediation-box strong {{
            color: #856404;
            display: block;
            margin-bottom: 8px;
        }}
        @media print {{
            body {{ margin: 0; }}
            .cover-page {{ page-break-after: always; }}
            .toc {{ page-break-after: always; }}
            .report-header {{ page-break-inside: avoid; }}
            table {{ page-break-inside: auto; }}
            tr {{ page-break-inside: avoid; page-break-after: auto; }}
            thead {{ display: table-header-group; }}
            tfoot {{ display: table-footer-group; }}
        }}
    </style>
</head>
<body>
    <!-- Cover Page -->
    <div class="cover-page">
        <h1>NCRT Audit Report</h1>
        <div class="subtitle">Network Configuration Security Assessment</div>
        <div class="metadata">
            <p><strong>Audit ID:</strong> {audit.get('id', 'N/A')}</p>
            <p><strong>Device Family:</strong> {audit.get('device_family', 'Unknown')}</p>
            <p><strong>Config File:</strong> {audit.get('config_file', 'Unknown')}</p>
            <p><strong>Status:</strong> {audit.get('status', 'Unknown')}</p>
            <p><strong>Generated:</strong> {format_datetime_now(timezone_str, date_format)}</p>
            {f'<p><strong>Risk Level:</strong> {executive_summary.get("risk_assessment", {}).get("level", "N/A")}</p>' if executive_summary else ''}
            {f'<p><strong>Risk Score:</strong> {executive_summary.get("risk_assessment", {}).get("score", 0):.1f}</p>' if executive_summary else ''}
        </div>
    </div>
    
    <!-- Table of Contents -->
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            {f'<li><a href="#executive-summary">Executive Summary</a></li>' if executive_summary and 'executive_summary' in sections else ''}
            {f'<li><a href="#statistics">Statistics</a></li>' if 'statistics' in sections else ''}
            {f'<li><a href="#compliance">Compliance</a></li>' if 'compliance' in sections else ''}
            {f'<li><a href="#findings">Findings</a></li>' if 'findings' in sections else ''}
        </ul>
    </div>
    
    <div class="report-header">
        <h1>NCRT Audit Report</h1>
        <p><strong>Status:</strong> {audit.get('status', 'Unknown')}</p>
        <p><strong>Device Family:</strong> {audit.get('device_family', 'Unknown')}</p>
        <p><strong>Config File:</strong> {audit.get('config_file', 'Unknown')}</p>
        <p><strong>Generated:</strong> {format_datetime_now(timezone_str, date_format)}</p>
    </div>
"""
    
    # Executive Summary section
    if 'executive_summary' in sections and executive_summary:
        html += f"""
    <div id="executive-summary">
    <h2>Executive Summary</h2>
    <div style="background-color: #667eea; color: white; padding: 20px; border-radius: 8px; margin: 20px 0;">
        <h3 style="color: white; margin-top: 0;">Risk Assessment</h3>
        <p style="font-size: 24px; font-weight: bold; margin: 10px 0;">{executive_summary.get('risk_assessment', {}).get('level', 'Low')}</p>
        <p>Risk Score: {executive_summary.get('risk_assessment', {}).get('score', 0):.1f}</p>
        <p>Total Findings: {executive_summary.get('risk_assessment', {}).get('total_findings', 0)}</p>
    </div>
    <h3>Top Critical Findings</h3>
    <ul>
"""
        for finding in executive_summary.get('top_findings', [])[:5]:
            html += f"""
        <li><strong>{finding.get('rule_name', 'Unknown')}</strong> ({finding.get('severity', 'medium')}): {finding.get('message', '')}</li>
"""
        html += """
    </ul>
    <h3>Key Recommendations</h3>
    <ul>
"""
        for rec in executive_summary.get('key_recommendations', []):
            html += f"""
        <li>{rec}</li>
"""
        html += """
    </ul>
    </div>
"""
    
    # Statistics section
    if 'statistics' in sections and statistics:
        html += f"""
    <div id="statistics">
    <h2>Statistics</h2>
    <div class="statistics-grid">
        <div class="stat-card">
            <h3>Total Findings</h3>
            <div class="value">{statistics.get('total_findings', 0)}</div>
        </div>
        <div class="stat-card">
            <h3>Risk Score</h3>
            <div class="value">{statistics.get('risk_score', 0)}</div>
        </div>
"""
        severity_counts = statistics.get('severity_breakdown', {}).get('counts', {})
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                html += f"""
        <div class="stat-card">
            <h3>{severity.capitalize()}</h3>
            <div class="value severity-{severity}">{count}</div>
        </div>
"""
        html += """
    </div>
    </div>
"""
    
    # Compliance section
    if 'compliance' in sections and compliance:
        html += f"""
    <div id="compliance">
    <h2>Compliance</h2>
    <p><strong>Framework:</strong> {compliance.get('framework', 'General')}</p>
    <p><strong>Score:</strong> {compliance.get('score', 0)}%</p>
    <p><strong>Passed Rules:</strong> {compliance.get('passed_rules', 0)} / {compliance.get('total_rules', 0)}</p>
    <p><strong>Failed Rules:</strong> {compliance.get('failed_rules', 0)} / {compliance.get('total_rules', 0)}</p>
    </div>
"""
    
    # Findings section
    if 'findings' in sections:
        findings_count = len(findings) if findings else 0
        html += f"""
    <h2>Findings ({findings_count})</h2>
    <table>
        <thead>
            <tr>
                <th>Rule</th>
                <th>Severity</th>
                <th>Category</th>
                <th>Message</th>
                <th>Config Path</th>
            </tr>
        </thead>
        <tbody>
"""
        # Display parent findings with children
        for parent in grouped_findings:
            children = parent.get('children', [])
            severity = parent.get('severity', 'medium').lower()
            child_count = len(children)
            
            # Parent row
            html += f"""
            <tr class="parent-finding">
                <td><strong>{parent.get('rule_name', 'Unknown')}</strong></td>
                <td class="severity-{severity}"><strong>{parent.get('severity', 'medium')}</strong></td>
                <td>{parent.get('rule_category', 'Unknown')}</td>
                <td><strong>{parent.get('message', '')}</strong>{' (' + str(child_count) + ' sub-issues)' if child_count > 0 else ''}</td>
                <td>{parent.get('config_path', '')}</td>
            </tr>
"""
            # Child rows (indented)
            for child in children:
                child_severity = child.get('severity', 'medium').lower()
                html += f"""
            <tr class="child-finding">
                <td style="padding-left: 30px;">↳ {child.get('rule_name', 'Unknown')}</td>
                <td class="severity-{child_severity}">{child.get('severity', 'medium')}</td>
                <td>{child.get('rule_category', 'Unknown')}</td>
                <td style="padding-left: 30px;">{child.get('message', '')}</td>
                <td>{child.get('config_path', '')}</td>
            </tr>
"""
        
        html += """
        </tbody>
    </table>
"""
    
    html += """
</body>
</html>
"""
    
    return html

def generate_comparison_report(audit_id1, audit_id2):
    """Generate comparison report between two audits"""
    audit1 = Audit.get_by_id(audit_id1)
    audit2 = Audit.get_by_id(audit_id2)
    
    if not audit1 or not audit2:
        return {'error': 'One or both audits not found'}
    
    findings1 = Finding.get_by_audit(audit_id1)
    findings2 = Finding.get_by_audit(audit_id2)
    statistics1 = generate_statistics(audit_id1)
    statistics2 = generate_statistics(audit_id2)
    
    # Create finding maps by rule_id for comparison
    findings1_map = {}
    findings2_map = {}
    
    for f in findings1:
        rule_id = f.get('rule_id')
        if rule_id not in findings1_map:
            findings1_map[rule_id] = []
        findings1_map[rule_id].append(f)
    
    for f in findings2:
        rule_id = f.get('rule_id')
        if rule_id not in findings2_map:
            findings2_map[rule_id] = []
        findings2_map[rule_id].append(f)
    
    # Compare findings
    resolved_findings = []  # In audit1 but not in audit2
    new_findings = []  # In audit2 but not in audit1
    common_findings = []  # In both
    
    all_rule_ids = set(list(findings1_map.keys()) + list(findings2_map.keys()))
    
    for rule_id in all_rule_ids:
        in_audit1 = rule_id in findings1_map
        in_audit2 = rule_id in findings2_map
        
        if in_audit1 and not in_audit2:
            resolved_findings.extend(findings1_map[rule_id])
        elif in_audit2 and not in_audit1:
            new_findings.extend(findings2_map[rule_id])
        elif in_audit1 and in_audit2:
            common_findings.extend(findings1_map[rule_id])
    
    return {
        'audit1': {
            'id': audit_id1,
            'config_file': audit1.get('config_file', 'Unknown'),
            'device_family': audit1.get('device_family', 'Unknown'),
            'created_at': audit1.get('created_at', ''),
            'statistics': statistics1
        },
        'audit2': {
            'id': audit_id2,
            'config_file': audit2.get('config_file', 'Unknown'),
            'device_family': audit2.get('device_family', 'Unknown'),
            'created_at': audit2.get('created_at', ''),
            'statistics': statistics2
        },
        'comparison': {
            'resolved_findings': resolved_findings,
            'new_findings': new_findings,
            'common_findings': common_findings,
            'resolved_count': len(resolved_findings),
            'new_count': len(new_findings),
            'common_count': len(common_findings),
            'risk_score_change': statistics2.get('risk_score', 0) - statistics1.get('risk_score', 0),
            'compliance_score_change': statistics2.get('compliance_score', 0) - statistics1.get('compliance_score', 0)
        }
    }


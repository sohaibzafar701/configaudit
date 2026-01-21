"""
Report API endpoints
"""

import urllib.parse
from datetime import datetime
from models.audit import Audit, Finding
from services.report_generator import get_filtered_findings, generate_statistics, calculate_compliance_score
from services.report_generator import generate_pdf_report, generate_csv_report, generate_executive_summary, generate_comparison_report, generate_html_standalone_report
from services.timezone_utils import format_datetime_now, format_datetime_from_iso, parse_datetime_format

def handle_report_request(handler, method):
    """Handle report API requests"""
    if method == 'GET':
        # Check if this is a comparison request
        parsed_path = urllib.parse.urlparse(handler.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        if query_params.get('compare', [None])[0] == 'true':
            audit_id1 = query_params.get('audit_id1', [None])[0]
            audit_id2 = query_params.get('audit_id2', [None])[0]
            if audit_id1 and audit_id2:
                comparison = generate_comparison_report(int(audit_id1), int(audit_id2))
                return comparison, 200
            return {'error': 'Both audit_id1 and audit_id2 required for comparison'}, 400
        
        # Parse query parameters
        parsed_path = urllib.parse.urlparse(handler.path)
        query_params = urllib.parse.parse_qs(parsed_path.query)
        
        # Get audit_id from query params, or use current audit
        audit_id_param = query_params.get('audit_id', [None])[0]
        
        if audit_id_param:
            audit = Audit.get_by_id(int(audit_id_param))
        else:
            audit = Audit.get_current()
        
        if not audit:
            return {'error': 'No audit found'}, 404
        
        # Check if requesting available frameworks
        if query_params.get('frameworks', [None])[0] == 'list':
            from models.rule import Rule
            all_rules = Rule.get_all(enabled_only=True)
            frameworks = set()
            for rule in all_rules:
                frameworks_str = rule.get('compliance_frameworks', '')
                if frameworks_str:
                    frameworks.update([f.strip() for f in frameworks_str.split(',') if f.strip()])
            return {'frameworks': sorted(list(frameworks))}, 200
        
        # Extract filter parameters
        severity_filter = query_params.get('severity', [None])[0]
        category_filter = query_params.get('category', [None])[0]
        rule_type_filter = query_params.get('rule_type', [None])[0]
        rule_id_filter = query_params.get('rule_id', [None])[0]
        framework_filter = query_params.get('framework', [None])[0]
        sort_by = query_params.get('sort_by', ['severity'])[0] or 'severity'
        sort_order = query_params.get('sort_order', ['desc'])[0] or 'desc'
        group_by = query_params.get('group_by', [None])[0]
        format_type = query_params.get('format', ['html'])[0] or 'html'
        include_statistics = query_params.get('include_statistics', ['false'])[0] == 'true'
        include_compliance = query_params.get('include_compliance', ['false'])[0] == 'true'
        
        # Enhanced export options
        sections_param = query_params.get('sections', [None])[0]
        sections = sections_param.split(',') if sections_param else ['statistics', 'findings', 'compliance', 'charts']
        preset = query_params.get('preset', [None])[0]
        filename = query_params.get('filename', [None])[0]
        search_query = query_params.get('search', [None])[0]
        rule_name_filter = query_params.get('rule_name', [None])[0]
        config_path_filter = query_params.get('config_path', [None])[0]
        tag_filter = query_params.get('tag', [None])[0]
        
        # Get timezone and format preferences
        timezone_str = query_params.get('timezone', ['UTC'])[0] or 'UTC'
        date_format_str = query_params.get('date_format', ['YYYY-MM-DD HH:mm:ss'])[0] or 'YYYY-MM-DD HH:mm:ss'
        date_format_py = parse_datetime_format(date_format_str)
        
        # Build filters dict
        filters = {
            'severity': severity_filter,
            'category': category_filter,
            'rule_type': rule_type_filter,
            'rule_id': int(rule_id_filter) if rule_id_filter else None,
            'search': search_query,
            'rule_name': rule_name_filter,
            'config_path': config_path_filter,
            'tag': tag_filter
        }
        
        # Apply preset configurations
        if preset == 'executive':
            sections = ['statistics', 'compliance']
        elif preset == 'findings_only':
            sections = ['findings']
        elif preset == 'compliance':
            sections = ['statistics', 'compliance']
        elif preset == 'full':
            sections = ['statistics', 'findings', 'compliance', 'charts']
        
        # Generate filename if not provided
        if not filename:
            filename = f'audit_report_{audit["id"]}'
        
        # Handle different export formats - return special response for binary formats
        if format_type == 'pdf':
            try:
                pdf_content = generate_pdf_report(audit['id'], filters, sort_by, sort_order, group_by, sections, preset, timezone_str, date_format_py)
                # Validate PDF content
                if not pdf_content or len(pdf_content) == 0:
                    return {'error': 'PDF generation failed: empty content'}, 500
                if not pdf_content.startswith(b'%PDF'):
                    return {'error': 'PDF generation failed: invalid PDF format'}, 500
                # Return tuple with format type, content, and filename for special response handling
                return ('pdf', pdf_content, f'{filename}.pdf')
            except ImportError as e:
                return {'error': f'PDF generation requires WeasyPrint: {str(e)}. Install with: pip install weasyprint'}, 500
            except RuntimeError as e:
                # RuntimeError from WeasyPrint usually means missing system dependencies
                import traceback
                traceback.print_exc()
                return {'error': str(e)}, 500
            except Exception as e:
                import traceback
                traceback.print_exc()
                return {'error': f'PDF generation failed: {str(e)}'}, 500
        
        elif format_type == 'csv':
            csv_content = generate_csv_report(audit['id'], filters, sort_by, sort_order, sections, timezone_str, date_format_py)
            return ('csv', csv_content, f'{filename}.csv')
        
        elif format_type == 'html_standalone':
            html_content = generate_html_standalone_report(audit['id'], filters, sort_by, sort_order, group_by, sections, timezone_str, date_format_py)
            return ('html', html_content.encode('utf-8'), f'{filename}.html')
        
        elif format_type == 'json':
            findings = get_filtered_findings(audit['id'], filters, sort_by, sort_order, group_by)
            result = {
                'audit': audit,
                'findings': findings,
                'metadata': {
                    'generated_at': format_datetime_now(timezone_str, date_format_py),
                    'generated_at_iso': datetime.now().isoformat(),
                    'filters_applied': filters,
                    'total_findings': len(findings)
                }
            }
            if include_statistics:
                result['statistics'] = generate_statistics(audit['id'])
            if include_compliance:
                framework_filter = query_params.get('framework', [None])[0]
                if framework_filter:
                    result['compliance'] = calculate_compliance_score(audit['id'], framework_filter)
                else:
                    result['compliance'] = calculate_compliance_score(audit['id'])
            return result, 200
        
        else:  # HTML format (default)
            findings = get_filtered_findings(audit['id'], filters, sort_by, sort_order, group_by)
            audit['findings'] = findings
            
            if include_statistics or 'statistics' in sections:
                audit['statistics'] = generate_statistics(audit['id'])
            if include_compliance or 'compliance' in sections:
                # Get compliance for specific framework or all frameworks
                if framework_filter:
                    audit['compliance'] = calculate_compliance_score(audit['id'], framework_filter)
                else:
                    # Get all frameworks
                    from models.rule import Rule
                    all_rules = Rule.get_all(enabled_only=True)
                    frameworks = set()
                    for rule in all_rules:
                        frameworks_str = rule.get('compliance_frameworks', '')
                        if frameworks_str:
                            frameworks.update([f.strip() for f in frameworks_str.split(',') if f.strip()])
                    
                    compliance_scores = {}
                    for framework in frameworks:
                        compliance_scores[framework] = calculate_compliance_score(audit['id'], framework)
                    audit['compliance'] = compliance_scores
                    audit['compliance_general'] = calculate_compliance_score(audit['id'])
            
            # Add available sections info
            audit['available_sections'] = sections
            audit['export_options'] = {
                'preset': preset,
                'filename': filename,
                'sections': sections
            }
            
            return audit, 200
    
    return {'error': 'Invalid request'}, 400


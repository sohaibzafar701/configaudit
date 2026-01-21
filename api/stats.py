"""
Statistics API endpoint
"""

import urllib.parse
import os
from pathlib import Path
from models.audit import Audit, Finding
from models.rule import Rule
from services.report_generator import calculate_compliance_score
from services.timezone_utils import format_datetime_from_iso, parse_datetime_format
from services.database import DB_PATH

def handle_stats_request(handler, method):
    """Handle statistics API requests"""
    if method == 'GET':
        try:
            # Get timezone and format preferences from query params
            parsed_path = urllib.parse.urlparse(handler.path)
            query_params = urllib.parse.parse_qs(parsed_path.query)
            timezone_str = query_params.get('timezone', ['UTC'])[0] or 'UTC'
            date_format_str = query_params.get('date_format', ['YYYY-MM-DD HH:mm:ss'])[0] or 'YYYY-MM-DD HH:mm:ss'
            date_format_py = parse_datetime_format(date_format_str)
            # Get all audits
            all_audits = Audit.get_all()
            total_audits = len(all_audits)
            
            # Count total findings across all audits
            total_findings = 0
            completed_audits = []
            compliance_scores = []
            
            for audit in all_audits:
                try:
                    findings = Finding.get_by_audit(audit['id'])
                    total_findings += len(findings)
                    
                    # Calculate compliance for completed audits
                    if audit.get('status') == Audit.STATUS_COMPLETED:
                        completed_audits.append(audit)
                        try:
                            compliance = calculate_compliance_score(audit['id'])
                            if compliance and compliance.get('score') is not None:
                                compliance_scores.append(compliance['score'])
                        except Exception as e:
                            print(f"Error calculating compliance for audit {audit.get('id')}: {e}")
                except Exception as e:
                    print(f"Error getting findings for audit {audit.get('id')}: {e}")
            
            # Calculate average compliance score
            average_compliance = 0.0
            if compliance_scores:
                average_compliance = sum(compliance_scores) / len(compliance_scores)
            
            # Count active rules
            active_rules = Rule.get_all(enabled_only=True)
            active_rules_count = len(active_rules)
            
            # Get database size
            db_size_bytes = 0
            db_size_formatted = '0 B'
            try:
                db_path_str = str(DB_PATH)
                if DB_PATH.exists():
                    db_size_bytes = os.path.getsize(db_path_str)
                    # Format size in human-readable format
                    if db_size_bytes < 1024:
                        db_size_formatted = f'{db_size_bytes} B'
                    elif db_size_bytes < 1024 * 1024:
                        db_size_formatted = f'{db_size_bytes / 1024:.2f} KB'
                    elif db_size_bytes < 1024 * 1024 * 1024:
                        db_size_formatted = f'{db_size_bytes / (1024 * 1024):.2f} MB'
                    else:
                        db_size_formatted = f'{db_size_bytes / (1024 * 1024 * 1024):.2f} GB'
                else:
                    db_size_formatted = 'Database file not found'
            except Exception as e:
                import traceback
                print(f"Error getting database size: {e}")
                traceback.print_exc()
                db_size_formatted = f'Error: {str(e)}'
            
            # Get recent audits (last 10)
            recent_audits = []
            for audit in all_audits[:10]:  # Already sorted by created_at DESC
                try:
                    findings = Finding.get_by_audit(audit['id'])
                    created_at_iso = audit.get('created_at')
                    created_at_formatted = format_datetime_from_iso(created_at_iso, timezone_str, date_format_py) if created_at_iso else None
                    recent_audits.append({
                        'id': audit.get('id'),
                        'config_file': audit.get('config_file', 'Unknown'),
                        'status': audit.get('status', 'Unknown'),
                        'created_at': created_at_iso,  # Keep ISO for sorting/comparison
                        'created_at_formatted': created_at_formatted,  # Formatted for display
                        'finding_count': len(findings),
                        'device_identifier': audit.get('device_identifier'),  # Include device_identifier
                        'device_hostname': audit.get('device_hostname'),
                        'device_family': audit.get('device_family')
                    })
                except Exception as e:
                    print(f"Error processing recent audit {audit.get('id')}: {e}")
                    created_at_iso = audit.get('created_at')
                    created_at_formatted = format_datetime_from_iso(created_at_iso, timezone_str, date_format_py) if created_at_iso else None
                    recent_audits.append({
                        'id': audit.get('id'),
                        'config_file': audit.get('config_file', 'Unknown'),
                        'status': audit.get('status', 'Unknown'),
                        'created_at': created_at_iso,
                        'created_at_formatted': created_at_formatted,
                        'finding_count': 0,
                        'device_identifier': audit.get('device_identifier'),
                        'device_hostname': audit.get('device_hostname'),
                        'device_family': audit.get('device_family')
                    })
            
            return {
                'total_audits': total_audits,
                'total_findings': total_findings,
                'average_compliance': round(average_compliance, 2),
                'active_rules': active_rules_count,
                'recent_audits': recent_audits,
                'database_size': db_size_formatted,
                'database_size_bytes': db_size_bytes
            }, 200
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {'error': f'Failed to calculate statistics: {str(e)}'}, 500
    
    return {'error': 'Method not allowed'}, 405


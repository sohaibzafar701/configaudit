"""
Audit and Finding models
"""

from services.database import get_db_connection
from datetime import datetime

class Audit:
    """Audit model"""
    
    STATUS_PENDING = "Pending"
    STATUS_PROCESSING = "Processing"
    STATUS_COMPLETED = "Completed"
    STATUS_FAILED = "Failed"
    STATUS_CANCELLED = "Cancelled"
    STATUS_PARTIAL = "Partial"
    
    @staticmethod
    def create(device_identifier, device_family=None, config_file=None, snapshot_name=None, parent_audit_id=None, 
               device_hostname=None, device_model=None, device_firmware=None, device_location=None,
               device_make=None, device_type=None):
        """Create a new audit"""
        if not device_identifier:
            raise ValueError("device_identifier is required")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO audit (status, device_identifier, device_family, config_file, snapshot_name, parent_audit_id,
                              device_hostname, device_model, device_firmware, device_location, device_make, device_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (Audit.STATUS_PENDING, device_identifier, device_family, config_file, snapshot_name, parent_audit_id,
              device_hostname, device_model, device_firmware, device_location, device_make, device_type))
        
        audit_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return audit_id
    
    @staticmethod
    def get_by_id(audit_id):
        """Get audit by ID"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM audit WHERE id = ?", (audit_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    @staticmethod
    def get_current():
        """Get current audit (most recent)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM audit ORDER BY created_at DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    @staticmethod
    def get_all(limit=None):
        """Get all audits (history)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM audit ORDER BY created_at DESC"
        if limit:
            query += " LIMIT ?"
            cursor.execute(query, (limit,))
        else:
            cursor.execute(query)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def delete(audit_id):
        """Delete a specific audit and its findings"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Delete findings first (foreign key constraint)
        cursor.execute("DELETE FROM finding WHERE audit_id = ?", (audit_id,))
        # Delete audit
        cursor.execute("DELETE FROM audit WHERE id = ?", (audit_id,))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def update_status(audit_id, status):
        """Update audit status"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        completed_at = datetime.now().isoformat() if status in [Audit.STATUS_COMPLETED, Audit.STATUS_FAILED] else None
        
        cursor.execute("""
            UPDATE audit 
            SET status = ?, completed_at = ?
            WHERE id = ?
        """, (status, completed_at, audit_id))
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def delete_all():
        """Delete all audits (for single-assessment mode)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM finding")
        cursor.execute("DELETE FROM audit")
        
        conn.commit()
        conn.close()
    
    @staticmethod
    def create_snapshot(audit_id, snapshot_name):
        """Create a snapshot of an existing audit"""
        parent_audit = Audit.get_by_id(audit_id)
        if not parent_audit:
            return None
        
        # Create new audit as snapshot
        snapshot_id = Audit.create(
            device_identifier=parent_audit.get('device_identifier') or parent_audit.get('config_file', 'Unknown'),
            device_family=parent_audit.get('device_family'),
            config_file=parent_audit.get('config_file'),
            snapshot_name=snapshot_name,
            parent_audit_id=audit_id,
            device_hostname=parent_audit.get('device_hostname'),
            device_model=parent_audit.get('device_model'),
            device_firmware=parent_audit.get('device_firmware'),
            device_location=parent_audit.get('device_location')
        )
        
        # Copy parsed config
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE audit SET parsed_config = ?
            WHERE id = ?
        """, (parent_audit.get('parsed_config'), snapshot_id))
        conn.commit()
        conn.close()
        
        # Copy findings from parent audit
        parent_findings = Finding.get_by_audit(audit_id)
        for finding in parent_findings:
            Finding.create(
                audit_id=snapshot_id,
                rule_id=finding.get('rule_id'),
                severity=finding.get('severity', 'medium'),
                message=finding.get('message', ''),
                config_path=finding.get('config_path'),
                remediation=finding.get('remediation'),
                remediation_status=finding.get('remediation_status', 'Not Started'),
                remediation_notes=finding.get('remediation_notes')
            )
        
        return snapshot_id
    
    @staticmethod
    def get_snapshots(audit_id):
        """Get all snapshots for an audit"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM audit 
            WHERE parent_audit_id = ?
            ORDER BY created_at DESC
        """, (audit_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_snapshot_chain(audit_id):
        """Get the full snapshot chain (parent and all snapshots)"""
        audit = Audit.get_by_id(audit_id)
        if not audit:
            return []
        
        # Find root audit (if this is a snapshot, find parent)
        root_id = audit_id
        if audit.get('parent_audit_id'):
            root_id = audit.get('parent_audit_id')
        
        # Get root and all snapshots
        chain = [Audit.get_by_id(root_id)]
        snapshots = Audit.get_snapshots(root_id)
        chain.extend(snapshots)
        
        return [a for a in chain if a]  # Filter out None values
    
    @staticmethod
    def set_progress(audit_id, status=None, progress_percent=None, current_rule=None, 
                     total_rules=None, rules_completed=None, error=None, rule_findings=None, rule_errors=None, rule_execution_details=None):
        """Set audit progress information"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Store progress in a JSON field or separate progress table
        # For simplicity, we'll store it in a progress JSON field in the audit table
        # First check if progress column exists, if not we'll use a simple approach
        try:
            # Try to get existing progress
            cursor.execute("SELECT progress FROM audit WHERE id = ?", (audit_id,))
            row = cursor.fetchone()
            progress = {}
            if row and len(row) > 0 and row[0]:
                import json
                try:
                    progress = json.loads(row[0]) if row[0] else {}
                except:
                    progress = {}
            
            # Update progress fields
            if status is not None:
                progress['status'] = status
            if progress_percent is not None:
                progress['progress_percent'] = progress_percent
            if current_rule is not None:
                progress['current_rule'] = current_rule
            if total_rules is not None:
                progress['total_rules'] = total_rules
            if rules_completed is not None:
                progress['rules_completed'] = rules_completed
            if error is not None:
                progress['error'] = error
            if rule_findings is not None:
                # Store recent rule findings (keep last 10 for verbose logging)
                if 'rule_findings' not in progress:
                    progress['rule_findings'] = []
                progress['rule_findings'].extend(rule_findings)
                # Keep only last 10 findings to avoid bloat
                if len(progress['rule_findings']) > 10:
                    progress['rule_findings'] = progress['rule_findings'][-10:]
            if rule_errors is not None:
                # Store recent rule errors (keep last 10 for verbose logging)
                if 'rule_errors' not in progress:
                    progress['rule_errors'] = []
                progress['rule_errors'].extend(rule_errors)
                # Keep only last 10 errors to avoid bloat
                if len(progress['rule_errors']) > 10:
                    progress['rule_errors'] = progress['rule_errors'][-10:]
            if rule_execution_details is not None:
                # Store detailed execution info for current rule (overwrite previous)
                progress['rule_execution_details'] = rule_execution_details
                # Also keep a history of recent rule executions (last 5)
                if 'rule_execution_history' not in progress:
                    progress['rule_execution_history'] = []
                # Add to history
                progress['rule_execution_history'].append(rule_execution_details)
                # Keep only last 5 executions
                if len(progress['rule_execution_history']) > 5:
                    progress['rule_execution_history'] = progress['rule_execution_history'][-5:]
            
            # Store as JSON string
            import json
            progress_json = json.dumps(progress)
            
            # Try to update progress column, if it doesn't exist, we'll handle it gracefully
            try:
                cursor.execute("UPDATE audit SET progress = ? WHERE id = ?", (progress_json, audit_id))
            except Exception as e:
                error_msg = str(e).lower()
                # Progress column doesn't exist - try to add it
                if 'no such column' in error_msg or 'progress' in error_msg:
                    try:
                        import sqlite3
                        cursor.execute("ALTER TABLE audit ADD COLUMN progress TEXT")
                        cursor.execute("UPDATE audit SET progress = ? WHERE id = ?", (progress_json, audit_id))
                        conn.commit()
                    except Exception as e2:
                        # If we can't add the column, that's okay - progress is optional
                        print(f"Warning: Could not add progress column: {e2}")
                else:
                    # Progress tracking is optional, don't fail if it doesn't work
                    print(f"Warning: Could not update progress: {e}")
            
            conn.commit()
        except Exception as e:
            # Progress tracking is optional, don't fail if it doesn't work
            print(f"Warning: Could not update progress: {e}")
        finally:
            conn.close()
    
    @staticmethod
    def get_progress(audit_id):
        """Get audit progress information"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT progress, status FROM audit WHERE id = ?", (audit_id,))
            row = cursor.fetchone()
            if row:
                progress = {}
                if row[0]:  # progress column
                    import json
                    try:
                        progress = json.loads(row[0])
                    except:
                        pass
                
                # Merge with status from main status field
                progress['status'] = row[1] or progress.get('status', 'Unknown')
                return progress
        except:
            # If progress column doesn't exist, return basic status
            audit = Audit.get_by_id(audit_id)
            if audit:
                return {'status': audit.get('status', 'Unknown')}
        finally:
            conn.close()
        
        return {'status': 'Unknown'}
    
    @staticmethod
    def get_by_device_identifier(device_identifier):
        """Get all audits for a specific device identifier"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM audit 
            WHERE device_identifier = ?
            ORDER BY created_at DESC
        """, (device_identifier,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_latest_by_device_identifier(device_identifier):
        """Get the most recent audit for a device identifier"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM audit 
            WHERE device_identifier = ?
            ORDER BY created_at DESC
            LIMIT 1
        """, (device_identifier,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    @staticmethod
    def get_all_device_identifiers():
        """Get unique list of all device identifiers"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT DISTINCT device_identifier 
            FROM audit 
            WHERE device_identifier IS NOT NULL
            ORDER BY device_identifier
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [row[0] for row in rows]

class Finding:
    """Finding model"""
    
    @staticmethod
    def create(audit_id, rule_id, severity, message, config_path=None, remediation=None, remediation_status='Not Started', remediation_notes=None, parent_finding_id=None):
        """Create a new finding"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO finding (audit_id, rule_id, severity, message, config_path, remediation, remediation_status, remediation_notes, parent_finding_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (audit_id, rule_id, severity, message, config_path, remediation, remediation_status, remediation_notes, parent_finding_id))
        
        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return finding_id
    
    @staticmethod
    def update_remediation(finding_id, status=None, notes=None):
        """Update remediation status and notes for a finding"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        updates = []
        values = []
        
        if status is not None:
            updates.append("remediation_status = ?")
            values.append(status)
        
        if notes is not None:
            updates.append("remediation_notes = ?")
            values.append(notes)
        
        if updates:
            values.append(finding_id)
            query = f"UPDATE finding SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
        
        conn.close()
    
    @staticmethod
    def get_by_audit(audit_id, include_children=True):
        """Get all findings for an audit
        
        Args:
            audit_id: Audit ID
            include_children: If True, includes child findings. If False, only returns parent findings.
        
        Returns:
            List of finding dictionaries
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if include_children:
            cursor.execute("""
                SELECT f.*, r.name as rule_name, r.description as rule_description, 
                       r.remediation_template as rule_remediation_template,
                       r.compliance_frameworks as rule_compliance_frameworks,
                       r.framework_mappings as rule_framework_mappings
                FROM finding f
                JOIN rule r ON f.rule_id = r.id
                WHERE f.audit_id = ?
                ORDER BY COALESCE(f.parent_finding_id, f.id), f.id
            """, (audit_id,))
        else:
            cursor.execute("""
                SELECT f.*, r.name as rule_name, r.description as rule_description, 
                       r.remediation_template as rule_remediation_template,
                       r.compliance_frameworks as rule_compliance_frameworks,
                       r.framework_mappings as rule_framework_mappings
                FROM finding f
                JOIN rule r ON f.rule_id = r.id
                WHERE f.audit_id = ? AND f.parent_finding_id IS NULL
                ORDER BY f.id
            """, (audit_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_children(parent_finding_id):
        """Get child findings for a parent finding"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT f.*, r.name as rule_name, r.description as rule_description, 
                   r.remediation_template as rule_remediation_template,
                   r.compliance_frameworks as rule_compliance_frameworks,
                   r.framework_mappings as rule_framework_mappings
            FROM finding f
            JOIN rule r ON f.rule_id = r.id
            WHERE f.parent_finding_id = ?
            ORDER BY f.id
        """, (parent_finding_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_parents(audit_id):
        """Get only parent findings (where parent_finding_id IS NULL) for an audit"""
        return Finding.get_by_audit(audit_id, include_children=False)
    
    @staticmethod
    def get_grouped_by_audit(audit_id):
        """Get findings grouped by parent-child structure
        
        Returns list of parent findings, each with a 'children' key containing child findings
        """
        parents = Finding.get_parents(audit_id)
        result = []
        
        for parent in parents:
            parent_dict = dict(parent)
            parent_dict['children'] = Finding.get_children(parent['id'])
            result.append(parent_dict)
        
        return result


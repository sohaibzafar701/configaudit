"""
Rule model
"""

from services.database import get_db_connection
import json

class Rule:
    """Rule model"""
    
    TYPE_PATTERN = "pattern"
    TYPE_PYTHON = "python"
    TYPE_HYBRID = "hybrid"
    
    @staticmethod
    def create(name, description, rule_type, category, severity, yaml_content, tags=None, remediation_template=None, compliance_frameworks=None, framework_mappings=None, risk_weight=1.0):
        """Create a new rule"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        tags_str = ','.join(tags) if isinstance(tags, list) else (tags or '')
        frameworks_str = ','.join(compliance_frameworks) if isinstance(compliance_frameworks, list) else (compliance_frameworks or '')
        mappings_str = json.dumps(framework_mappings) if framework_mappings else None
        
        cursor.execute("""
            INSERT INTO rule (name, description, rule_type, category, severity, yaml_content, tags, remediation_template, compliance_frameworks, framework_mappings, risk_weight)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, description, rule_type, category, severity, yaml_content, tags_str, remediation_template, frameworks_str, mappings_str, risk_weight))
        
        rule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return rule_id
    
    @staticmethod
    def get_all(enabled_only=True):
        """Get all rules"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if enabled_only:
            cursor.execute("SELECT * FROM rule WHERE enabled = 1 ORDER BY name")
        else:
            cursor.execute("SELECT * FROM rule ORDER BY name")
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_by_id(rule_id):
        """Get rule by ID"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM rule WHERE id = ?", (rule_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    @staticmethod
    def get_by_category(category):
        """Get rules by category"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM rule 
            WHERE category = ? AND enabled = 1 
            ORDER BY name
        """, (category,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_by_tag(tag):
        """Get rules by tag/vendor"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM rule 
            WHERE tags LIKE ? AND enabled = 1 
            ORDER BY name
        """, (f'%{tag}%',))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_by_device_family(device_family):
        """Get rules applicable to a device family
        
        Returns rules that:
        1. Have 'generic' or 'all' in their tags (applicable to all devices)
        2. Have a tag matching the vendor name extracted from device_family
        
        Args:
            device_family: Device family string (e.g., "Cisco IOS-XE", "Juniper JunOS")
        
        Returns:
            List of rule dictionaries
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Extract vendor name from device_family (first word, lowercase)
        vendor_name = None
        if device_family:
            # Extract vendor name (first word before space)
            vendor_name = device_family.split()[0].lower() if device_family.strip() else None
        
        # Build query to get rules that are generic/all OR match the vendor
        if vendor_name:
            cursor.execute("""
                SELECT * FROM rule 
                WHERE enabled = 1 
                AND (
                    tags LIKE '%generic%' 
                    OR tags LIKE '%all%'
                    OR LOWER(tags) LIKE ?
                )
                ORDER BY name
            """, (f'%{vendor_name}%',))
        else:
            # If no vendor name, only get generic/all rules
            cursor.execute("""
                SELECT * FROM rule 
                WHERE enabled = 1 
                AND (tags LIKE '%generic%' OR tags LIKE '%all%')
                ORDER BY name
            """)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    @staticmethod
    def get_by_tags(tags):
        """Get rules that match any of the provided tags (only enabled rules)"""
        if not tags or len(tags) == 0:
            return []
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Build LIKE conditions for each tag
        conditions = []
        params = []
        for tag in tags:
            conditions.append("tags LIKE ?")
            params.append(f'%{tag}%')
        
        query = f"""
            SELECT DISTINCT * FROM rule 
            WHERE enabled = 1 AND ({' OR '.join(conditions)})
            ORDER BY name
        """
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to dict and deduplicate by ID (in case a rule has multiple matching tags)
        rules_dict = {}
        for row in rows:
            rule = dict(row)
            rules_dict[rule['id']] = rule
        
        return list(rules_dict.values())
    
    @staticmethod
    def get_all_tags(enabled_only=True):
        """Get all unique tags from rules (only from enabled rules if enabled_only=True)
        
        Excludes vendor tags (cisco, juniper, arista, paloalto, fortinet, checkpoint)
        since vendor filtering is handled automatically by device family detection.
        """
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if enabled_only:
            cursor.execute("SELECT DISTINCT tags FROM rule WHERE enabled = 1 AND tags IS NOT NULL AND tags != ''")
        else:
            cursor.execute("SELECT DISTINCT tags FROM rule WHERE tags IS NOT NULL AND tags != ''")
        
        rows = cursor.fetchall()
        conn.close()
        
        # Vendor tags to exclude (vendor filtering is automatic based on device family)
        vendor_tags = {'cisco', 'juniper', 'arista', 'paloalto', 'fortinet', 'checkpoint'}
        
        tags = set()
        for row in rows:
            if row[0]:
                # Split comma-separated tags and strip whitespace
                tag_list = [t.strip() for t in row[0].split(',') if t.strip()]
                # Filter out vendor tags (case-insensitive)
                filtered_tags = [t for t in tag_list if t.lower() not in vendor_tags]
                tags.update(filtered_tags)
        
        return sorted(list(tags))
    
    @staticmethod
    def update(rule_id, name=None, description=None, category=None, severity=None, yaml_content=None, tags=None, enabled=None, remediation_template=None, compliance_frameworks=None, framework_mappings=None, risk_weight=None):
        """Update a rule (in place, no versioning)"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        updates = []
        values = []
        
        if name is not None:
            updates.append("name = ?")
            values.append(name)
        if description is not None:
            updates.append("description = ?")
            values.append(description)
        if category is not None:
            updates.append("category = ?")
            values.append(category)
        if severity is not None:
            updates.append("severity = ?")
            values.append(severity)
        if yaml_content is not None:
            updates.append("yaml_content = ?")
            values.append(yaml_content)
        if tags is not None:
            tags_str = ','.join(tags) if isinstance(tags, list) else tags
            updates.append("tags = ?")
            values.append(tags_str)
        if enabled is not None:
            updates.append("enabled = ?")
            values.append(enabled)
        if remediation_template is not None:
            updates.append("remediation_template = ?")
            values.append(remediation_template)
        if compliance_frameworks is not None:
            frameworks_str = ','.join(compliance_frameworks) if isinstance(compliance_frameworks, list) else compliance_frameworks
            updates.append("compliance_frameworks = ?")
            values.append(frameworks_str)
        if framework_mappings is not None:
            mappings_str = json.dumps(framework_mappings) if framework_mappings else None
            updates.append("framework_mappings = ?")
            values.append(mappings_str)
        if risk_weight is not None:
            updates.append("risk_weight = ?")
            values.append(risk_weight)
        
        if updates:
            values.append(rule_id)
            query = f"UPDATE rule SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
        
        conn.close()
    
    @staticmethod
    def delete(rule_id):
        """Delete a rule"""
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM rule WHERE id = ?", (rule_id,))
        
        conn.commit()
        conn.close()


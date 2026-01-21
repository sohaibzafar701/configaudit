"""
Compatibility adapter to make Django models work with existing service code
This provides a compatibility layer so services can work with both old and new models
"""
from .models import Rule as DjangoRule, Audit as DjangoAudit, Finding as DjangoFinding
import json


class RuleAdapter:
    """Adapter to make Django Rule model compatible with old Rule class interface"""
    
    TYPE_PATTERN = "pattern"
    TYPE_PYTHON = "python"
    TYPE_HYBRID = "hybrid"
    
    @staticmethod
    def create(name, description, rule_type, category, severity, yaml_content, tags=None, remediation_template=None, compliance_frameworks=None, framework_mappings=None, risk_weight=1.0):
        """Create a new rule"""
        rule = DjangoRule.objects.create(
            name=name,
            description=description,
            rule_type=rule_type,
            category=category,
            severity=severity,
            yaml_content=yaml_content,
            tags=','.join(tags) if isinstance(tags, list) else (tags or ''),
            remediation_template=remediation_template,
            compliance_frameworks=','.join(compliance_frameworks) if isinstance(compliance_frameworks, list) else (compliance_frameworks or ''),
            framework_mappings=framework_mappings,
            risk_weight=risk_weight
        )
        return rule.id
    
    @staticmethod
    def get_all(enabled_only=True):
        """Get all rules"""
        if enabled_only:
            rules = DjangoRule.objects.filter(enabled=True).order_by('name')
        else:
            rules = DjangoRule.objects.all().order_by('name')
        return [RuleAdapter._rule_to_dict(rule) for rule in rules]
    
    @staticmethod
    def get_by_id(rule_id):
        """Get rule by ID"""
        try:
            rule = DjangoRule.objects.get(id=rule_id)
            return RuleAdapter._rule_to_dict(rule)
        except DjangoRule.DoesNotExist:
            return None
    
    @staticmethod
    def get_by_category(category):
        """Get rules by category"""
        rules = DjangoRule.objects.filter(category=category, enabled=True).order_by('name')
        return [RuleAdapter._rule_to_dict(rule) for rule in rules]
    
    @staticmethod
    def get_by_tag(tag):
        """Get rules by tag/vendor"""
        rules = DjangoRule.objects.filter(tags__icontains=tag, enabled=True).order_by('name')
        return [RuleAdapter._rule_to_dict(rule) for rule in rules]
    
    @staticmethod
    def get_by_device_family(device_family):
        """Get rules applicable to a device family"""
        from django.db.models import Q
        
        vendor_name = None
        if device_family:
            vendor_name = device_family.split()[0].lower() if device_family.strip() else None
        
        if vendor_name:
            rules = DjangoRule.objects.filter(
                enabled=True
            ).filter(
                Q(tags__icontains='generic') |
                Q(tags__icontains='all') |
                Q(tags__icontains=vendor_name)
            ).order_by('name')
        else:
            rules = DjangoRule.objects.filter(
                enabled=True
            ).filter(
                Q(tags__icontains='generic') |
                Q(tags__icontains='all')
            ).order_by('name')
        
        return [RuleAdapter._rule_to_dict(rule) for rule in rules]
    
    @staticmethod
    def get_by_tags(tags):
        """Get rules that match any of the provided tags"""
        if not tags or len(tags) == 0:
            return []
        
        from django.db.models import Q
        query = Q()
        for tag in tags:
            query |= Q(tags__icontains=tag)
        
        rules = DjangoRule.objects.filter(enabled=True).filter(query).distinct().order_by('name')
        return [RuleAdapter._rule_to_dict(rule) for rule in rules]
    
    @staticmethod
    def get_all_tags(enabled_only=True):
        """Get all unique tags from rules"""
        vendor_tags = {'cisco', 'juniper', 'arista', 'paloalto', 'fortinet', 'checkpoint'}
        
        if enabled_only:
            rules = DjangoRule.objects.filter(enabled=True, tags__isnull=False).exclude(tags='')
        else:
            rules = DjangoRule.objects.filter(tags__isnull=False).exclude(tags='')
        
        tags = set()
        for rule in rules:
            rule_tags = rule.get_tags_list()
            filtered_tags = [t for t in rule_tags if t.lower() not in vendor_tags]
            tags.update(filtered_tags)
        
        return sorted(list(tags))
    
    @staticmethod
    def update(rule_id, **kwargs):
        """Update a rule"""
        try:
            rule = DjangoRule.objects.get(id=rule_id)
            if 'name' in kwargs:
                rule.name = kwargs['name']
            if 'description' in kwargs:
                rule.description = kwargs.get('description')
            if 'category' in kwargs:
                rule.category = kwargs.get('category')
            if 'severity' in kwargs:
                rule.severity = kwargs.get('severity')
            if 'yaml_content' in kwargs:
                rule.yaml_content = kwargs.get('yaml_content')
            if 'tags' in kwargs:
                if isinstance(kwargs['tags'], list):
                    rule.set_tags_list(kwargs['tags'])
                else:
                    rule.tags = kwargs['tags']
            if 'enabled' in kwargs:
                rule.enabled = kwargs['enabled']
            if 'remediation_template' in kwargs:
                rule.remediation_template = kwargs.get('remediation_template')
            if 'compliance_frameworks' in kwargs:
                if isinstance(kwargs['compliance_frameworks'], list):
                    rule.set_frameworks_list(kwargs['compliance_frameworks'])
                else:
                    rule.compliance_frameworks = kwargs['compliance_frameworks']
            if 'framework_mappings' in kwargs:
                rule.framework_mappings = kwargs.get('framework_mappings')
            if 'risk_weight' in kwargs:
                rule.risk_weight = kwargs.get('risk_weight')
            rule.save()
        except DjangoRule.DoesNotExist:
            pass
    
    @staticmethod
    def delete(rule_id):
        """Delete a rule"""
        DjangoRule.objects.filter(id=rule_id).delete()
    
    @staticmethod
    def _rule_to_dict(rule):
        """Convert Django Rule to dict"""
        return {
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'rule_type': rule.rule_type,
            'category': rule.category,
            'severity': rule.severity,
            'yaml_content': rule.yaml_content,
            'tags': rule.tags,
            'enabled': 1 if rule.enabled else 0,
            'remediation_template': rule.remediation_template,
            'compliance_frameworks': rule.compliance_frameworks,
            'framework_mappings': rule.framework_mappings,
            'risk_weight': rule.risk_weight,
            'created_at': rule.created_at.isoformat() if rule.created_at else None
        }


class AuditAdapter:
    """Adapter to make Django Audit model compatible with old Audit class interface"""
    
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
        
        parent_audit = None
        if parent_audit_id:
            try:
                parent_audit = DjangoAudit.objects.get(id=parent_audit_id)
            except DjangoAudit.DoesNotExist:
                pass
        
        audit = DjangoAudit.objects.create(
            device_identifier=device_identifier,
            device_family=device_family,
            config_file=config_file,
            snapshot_name=snapshot_name,
            parent_audit=parent_audit,
            device_hostname=device_hostname,
            device_model=device_model,
            device_firmware=device_firmware,
            device_location=device_location,
            device_make=device_make,
            device_type=device_type,
            status=AuditAdapter.STATUS_PENDING
        )
        return audit.id
    
    @staticmethod
    def get_by_id(audit_id):
        """Get audit by ID"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            return AuditAdapter._audit_to_dict(audit)
        except DjangoAudit.DoesNotExist:
            return None
    
    @staticmethod
    def get_current():
        """Get current audit (most recent)"""
        audit = DjangoAudit.objects.first()
        if audit:
            return AuditAdapter._audit_to_dict(audit)
        return None
    
    @staticmethod
    def get_all(limit=None):
        """Get all audits"""
        audits = DjangoAudit.objects.all()
        if limit:
            audits = audits[:limit]
        return [AuditAdapter._audit_to_dict(audit) for audit in audits]
    
    @staticmethod
    def delete(audit_id):
        """Delete a specific audit"""
        DjangoAudit.objects.filter(id=audit_id).delete()
    
    @staticmethod
    def delete_all():
        """Delete all audits"""
        DjangoAudit.objects.all().delete()
    
    @staticmethod
    def update_status(audit_id, status):
        """Update audit status"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            audit.update_status(status)
        except DjangoAudit.DoesNotExist:
            pass
    
    @staticmethod
    def set_progress(audit_id, **kwargs):
        """Set audit progress"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            audit.set_progress(**kwargs)
        except DjangoAudit.DoesNotExist:
            pass
    
    @staticmethod
    def get_progress(audit_id):
        """Get audit progress"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            return audit.get_progress()
        except DjangoAudit.DoesNotExist:
            return {'status': 'Unknown'}
    
    @staticmethod
    def get_by_device_identifier(device_identifier):
        """Get all audits for a device identifier"""
        audits = DjangoAudit.objects.filter(device_identifier=device_identifier).order_by('-created_at')
        return [AuditAdapter._audit_to_dict(audit) for audit in audits]
    
    @staticmethod
    def get_latest_by_device_identifier(device_identifier):
        """Get the most recent audit for a device identifier"""
        audit = DjangoAudit.objects.filter(device_identifier=device_identifier).order_by('-created_at').first()
        if audit:
            return AuditAdapter._audit_to_dict(audit)
        return None
    
    @staticmethod
    def get_all_device_identifiers():
        """Get unique list of all device identifiers"""
        return list(DjangoAudit.objects.values_list('device_identifier', flat=True).distinct().exclude(device_identifier__isnull=True))
    
    @staticmethod
    def create_snapshot(audit_id, snapshot_name):
        """Create a snapshot of an existing audit"""
        try:
            parent_audit = DjangoAudit.objects.get(id=audit_id)
            if parent_audit.status != AuditAdapter.STATUS_COMPLETED:
                return None
            
            snapshot = DjangoAudit.objects.create(
                device_identifier=parent_audit.device_identifier or parent_audit.config_file or 'Unknown',
                device_family=parent_audit.device_family,
                config_file=parent_audit.config_file,
                snapshot_name=snapshot_name,
                parent_audit=parent_audit,
                device_hostname=parent_audit.device_hostname,
                device_model=parent_audit.device_model,
                device_firmware=parent_audit.device_firmware,
                device_location=parent_audit.device_location,
                parsed_config=parent_audit.parsed_config,
                status=parent_audit.status
            )
            
            # Copy findings
            for finding in parent_audit.findings.all():
                DjangoFinding.objects.create(
                    audit=snapshot,
                    rule=finding.rule,
                    severity=finding.severity,
                    message=finding.message,
                    config_path=finding.config_path,
                    remediation=finding.remediation,
                    remediation_status=finding.remediation_status,
                    remediation_notes=finding.remediation_notes,
                    parent_finding=finding.parent_finding
                )
            
            return snapshot.id
        except DjangoAudit.DoesNotExist:
            return None
    
    @staticmethod
    def get_snapshots(audit_id):
        """Get all snapshots for an audit"""
        snapshots = DjangoAudit.objects.filter(parent_audit_id=audit_id).order_by('-created_at')
        return [AuditAdapter._audit_to_dict(snapshot) for snapshot in snapshots]
    
    @staticmethod
    def get_snapshot_chain(audit_id):
        """Get the full snapshot chain"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            root_id = audit_id
            if audit.parent_audit:
                root_id = audit.parent_audit.id
            
            root = DjangoAudit.objects.get(id=root_id)
            snapshots = DjangoAudit.objects.filter(parent_audit_id=root_id).order_by('-created_at')
            
            chain = [AuditAdapter._audit_to_dict(root)]
            chain.extend([AuditAdapter._audit_to_dict(s) for s in snapshots])
            return chain
        except DjangoAudit.DoesNotExist:
            return []
    
    @staticmethod
    def _audit_to_dict(audit):
        """Convert Django Audit to dict"""
        return {
            'id': audit.id,
            'status': audit.status,
            'device_identifier': audit.device_identifier,
            'device_family': audit.device_family,
            'config_file': audit.config_file,
            'parsed_config': audit.parsed_config,
            'created_at': audit.created_at.isoformat() if audit.created_at else None,
            'completed_at': audit.completed_at.isoformat() if audit.completed_at else None,
            'snapshot_name': audit.snapshot_name,
            'parent_audit_id': audit.parent_audit.id if audit.parent_audit else None,
            'device_hostname': audit.device_hostname,
            'device_model': audit.device_model,
            'device_firmware': audit.device_firmware,
            'device_location': audit.device_location,
            'device_make': audit.device_make,
            'device_type': audit.device_type,
            'progress': audit.progress
        }


class FindingAdapter:
    """Adapter to make Django Finding model compatible with old Finding class interface"""
    
    @staticmethod
    def create(audit_id, rule_id, severity, message, config_path=None, remediation=None, remediation_status='Not Started', remediation_notes=None, parent_finding_id=None):
        """Create a new finding"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            rule = DjangoRule.objects.get(id=rule_id)
            parent_finding = None
            if parent_finding_id:
                try:
                    parent_finding = DjangoFinding.objects.get(id=parent_finding_id)
                except DjangoFinding.DoesNotExist:
                    pass
            
            finding = DjangoFinding.objects.create(
                audit=audit,
                rule=rule,
                severity=severity,
                message=message,
                config_path=config_path,
                remediation=remediation,
                remediation_status=remediation_status,
                remediation_notes=remediation_notes,
                parent_finding=parent_finding
            )
            return finding.id
        except (DjangoAudit.DoesNotExist, DjangoRule.DoesNotExist):
            return None
    
    @staticmethod
    def update_remediation(finding_id, status=None, notes=None):
        """Update remediation status and notes"""
        try:
            finding = DjangoFinding.objects.get(id=finding_id)
            if status:
                finding.remediation_status = status
            if notes is not None:
                finding.remediation_notes = notes
            finding.save()
        except DjangoFinding.DoesNotExist:
            pass
    
    @staticmethod
    def get_by_audit(audit_id, include_children=True):
        """Get all findings for an audit"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            if include_children:
                findings = DjangoFinding.objects.filter(audit=audit).select_related('rule').order_by('parent_finding_id', 'id')
            else:
                findings = DjangoFinding.objects.filter(audit=audit, parent_finding__isnull=True).select_related('rule').order_by('id')
            
            findings_list = []
            for finding in findings:
                finding_dict = FindingAdapter._finding_to_dict(finding)
                finding_dict['rule_name'] = finding.rule.name
                finding_dict['rule_description'] = finding.rule.description
                finding_dict['rule_remediation_template'] = finding.rule.remediation_template
                finding_dict['rule_compliance_frameworks'] = finding.rule.compliance_frameworks
                finding_dict['rule_framework_mappings'] = finding.rule.framework_mappings
                findings_list.append(finding_dict)
            
            return findings_list
        except DjangoAudit.DoesNotExist:
            return []
    
    @staticmethod
    def get_children(parent_finding_id):
        """Get child findings for a parent finding"""
        try:
            parent = DjangoFinding.objects.get(id=parent_finding_id)
            findings = DjangoFinding.objects.filter(parent_finding=parent).select_related('rule').order_by('id')
            findings_list = []
            for finding in findings:
                finding_dict = FindingAdapter._finding_to_dict(finding)
                finding_dict['rule_name'] = finding.rule.name
                finding_dict['rule_description'] = finding.rule.description
                findings_list.append(finding_dict)
            return findings_list
        except DjangoFinding.DoesNotExist:
            return []
    
    @staticmethod
    def get_parents(audit_id):
        """Get only parent findings"""
        return FindingAdapter.get_by_audit(audit_id, include_children=False)
    
    @staticmethod
    def get_grouped_by_audit(audit_id):
        """Get findings grouped by parent-child structure"""
        try:
            audit = DjangoAudit.objects.get(id=audit_id)
            parents = DjangoFinding.objects.filter(audit=audit, parent_finding__isnull=True).select_related('rule').order_by('id')
            
            result = []
            for parent in parents:
                parent_dict = FindingAdapter._finding_to_dict(parent)
                parent_dict['rule_name'] = parent.rule.name
                parent_dict['rule_description'] = parent.rule.description
                parent_dict['rule_category'] = parent.rule.category
                parent_dict['rule_type'] = parent.rule.rule_type
                
                children = DjangoFinding.objects.filter(parent_finding=parent).select_related('rule').order_by('id')
                parent_dict['children'] = []
                for child in children:
                    child_dict = FindingAdapter._finding_to_dict(child)
                    child_dict['rule_name'] = child.rule.name
                    child_dict['rule_description'] = child.rule.description
                    child_dict['rule_category'] = child.rule.category
                    child_dict['rule_type'] = child.rule.rule_type
                    parent_dict['children'].append(child_dict)
                
                result.append(parent_dict)
            
            return result
        except DjangoAudit.DoesNotExist:
            return []
    
    @staticmethod
    def _finding_to_dict(finding):
        """Convert Django Finding to dict"""
        return {
            'id': finding.id,
            'audit_id': finding.audit.id,
            'rule_id': finding.rule.id,
            'severity': finding.severity,
            'message': finding.message,
            'config_path': finding.config_path,
            'remediation': finding.remediation,
            'remediation_status': finding.remediation_status,
            'remediation_notes': finding.remediation_notes,
            'parent_finding_id': finding.parent_finding.id if finding.parent_finding else None
        }


# Create aliases for backward compatibility
Rule = RuleAdapter
Audit = AuditAdapter
Finding = FindingAdapter

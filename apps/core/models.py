"""
Django models for NCRT
"""
from django.db import models
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.utils import timezone
import json
import uuid


class Organization(models.Model):
    """Organization/Tenant model for multi-tenancy"""
    
    STATUS_ACTIVE = "Active"
    STATUS_SUSPENDED = "Suspended"
    STATUS_INACTIVE = "Inactive"
    
    STATUS_CHOICES = [
        (STATUS_ACTIVE, 'Active'),
        (STATUS_SUSPENDED, 'Suspended'),
        (STATUS_INACTIVE, 'Inactive'),
    ]
    
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255, blank=True, null=True, unique=True)
    poc_email = models.EmailField(verbose_name="Point of Contact Email")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_ACTIVE)
    settings = models.JSONField(blank=True, null=True, default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def is_active(self):
        """Check if organization is active"""
        return self.status == self.STATUS_ACTIVE
    
    def get_user_count(self):
        """Get number of users in this organization"""
        from django.contrib.auth.models import User
        return User.objects.filter(userprofile__organization=self).count()
    
    def get_audit_count(self):
        """Get number of audits for this organization"""
        return Audit.objects.filter(organization=self).count()
    
    def copy_platform_rules(self):
        """Copy all platform rules to this organization"""
        platform_rules = Rule.objects.filter(organization__isnull=True)
        for rule in platform_rules:
            Rule.objects.create(
                name=rule.name,
                description=rule.description,
                rule_type=rule.rule_type,
                category=rule.category,
                severity=rule.severity,
                yaml_content=rule.yaml_content,
                tags=rule.tags,
                enabled=rule.enabled,
                remediation_template=rule.remediation_template,
                compliance_frameworks=rule.compliance_frameworks,
                framework_mappings=rule.framework_mappings,
                risk_weight=rule.risk_weight,
                organization=self
            )


class UserProfile(models.Model):
    """User profile extending Django User with organization and role"""
    
    ROLE_SUPER_ADMIN = "super_admin"
    ROLE_ORG_ADMIN = "org_admin"
    ROLE_ORG_USER = "org_user"
    ROLE_ORG_VIEWER = "org_viewer"
    
    ROLE_CHOICES = [
        (ROLE_SUPER_ADMIN, 'Super Admin'),
        (ROLE_ORG_ADMIN, 'Organization Admin'),
        (ROLE_ORG_USER, 'Organization User'),
        (ROLE_ORG_VIEWER, 'Organization Viewer'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='userprofile')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True, related_name='users')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=ROLE_ORG_USER)
    phone = models.CharField(max_length=20, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['user__username']
    
    def __str__(self):
        return f"{self.user.username} - {self.get_role_display()}"
    
    def is_super_admin(self):
        """Check if user is super admin"""
        return self.role == self.ROLE_SUPER_ADMIN
    
    def is_org_admin(self):
        """Check if user is organization admin"""
        return self.role == self.ROLE_ORG_ADMIN
    
    def can_manage_users(self):
        """Check if user can manage other users"""
        return self.role in [self.ROLE_SUPER_ADMIN, self.ROLE_ORG_ADMIN]
    
    def can_edit(self):
        """Check if user can edit content"""
        return self.role in [self.ROLE_SUPER_ADMIN, self.ROLE_ORG_ADMIN, self.ROLE_ORG_USER]
    
    def is_org_viewer(self):
        """Check if user is organization viewer (read-only)"""
        return self.role == self.ROLE_ORG_VIEWER


class Rule(models.Model):
    """Rule model for security audit rules"""
    
    TYPE_PATTERN = "pattern"
    TYPE_PYTHON = "python"
    TYPE_HYBRID = "hybrid"
    
    RULE_TYPE_CHOICES = [
        (TYPE_PATTERN, 'Pattern'),
        (TYPE_PYTHON, 'Python'),
        (TYPE_HYBRID, 'Hybrid'),
    ]
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPE_CHOICES)
    category = models.CharField(max_length=100, blank=True, null=True)
    severity = models.CharField(max_length=20, blank=True, null=True)
    yaml_content = models.TextField(blank=True, null=True)
    tags = models.CharField(max_length=500, blank=True, null=True)
    enabled = models.BooleanField(default=True)
    remediation_template = models.TextField(blank=True, null=True)
    compliance_frameworks = models.CharField(max_length=500, blank=True, null=True)
    framework_mappings = models.JSONField(blank=True, null=True)
    risk_weight = models.FloatField(default=1.0)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True, related_name='rules')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name
    
    def is_platform_rule(self):
        """Check if this is a platform rule"""
        return self.organization is None
    
    def copy_to_organization(self, organization):
        """Create a copy of this rule for an organization"""
        return Rule.objects.create(
            name=self.name,
            description=self.description,
            rule_type=self.rule_type,
            category=self.category,
            severity=self.severity,
            yaml_content=self.yaml_content,
            tags=self.tags,
            enabled=self.enabled,
            remediation_template=self.remediation_template,
            compliance_frameworks=self.compliance_frameworks,
            framework_mappings=self.framework_mappings,
            risk_weight=self.risk_weight,
            organization=organization
        )
    
    def get_tags_list(self):
        """Get tags as a list"""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(',') if t.strip()]
    
    def set_tags_list(self, tags_list):
        """Set tags from a list"""
        if isinstance(tags_list, list):
            self.tags = ','.join(tags_list)
        else:
            self.tags = tags_list or ''
    
    def get_frameworks_list(self):
        """Get compliance frameworks as a list"""
        if not self.compliance_frameworks:
            return []
        return [f.strip() for f in self.compliance_frameworks.split(',') if f.strip()]
    
    def set_frameworks_list(self, frameworks_list):
        """Set compliance frameworks from a list"""
        if isinstance(frameworks_list, list):
            self.compliance_frameworks = ','.join(frameworks_list)
        else:
            self.compliance_frameworks = frameworks_list or ''


class Audit(models.Model):
    """Audit model for configuration audits"""
    
    STATUS_PENDING = "Pending"
    STATUS_PROCESSING = "Processing"
    STATUS_COMPLETED = "Completed"
    STATUS_FAILED = "Failed"
    STATUS_CANCELLED = "Cancelled"
    STATUS_PARTIAL = "Partial"
    
    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_PROCESSING, 'Processing'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_CANCELLED, 'Cancelled'),
        (STATUS_PARTIAL, 'Partial'),
    ]
    
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='audits')
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True, related_name='created_audits')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    device_identifier = models.CharField(max_length=255)
    device_family = models.CharField(max_length=255, blank=True, null=True)
    config_file = models.CharField(max_length=255, blank=True, null=True)
    parsed_config = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    snapshot_name = models.CharField(max_length=255, blank=True, null=True)
    parent_audit = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True, related_name='snapshots')
    device_hostname = models.CharField(max_length=255, blank=True, null=True)
    device_model = models.CharField(max_length=255, blank=True, null=True)
    device_firmware = models.CharField(max_length=255, blank=True, null=True)
    device_location = models.CharField(max_length=255, blank=True, null=True)
    device_make = models.CharField(max_length=100, blank=True, null=True)
    device_type = models.CharField(max_length=100, blank=True, null=True)
    progress = models.JSONField(blank=True, null=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Audit {self.id} - {self.device_identifier}"
    
    def update_status(self, new_status):
        """Update audit status and set completed_at if needed"""
        self.status = new_status
        if new_status in [self.STATUS_COMPLETED, self.STATUS_FAILED]:
            self.completed_at = timezone.now()
        self.save()
    
    def set_progress(self, **kwargs):
        """Update progress information"""
        if not self.progress:
            self.progress = {}
        self.progress.update(kwargs)
        self.save(update_fields=['progress'])
    
    def get_progress(self):
        """Get progress information"""
        progress = self.progress or {}
        progress['status'] = self.status
        return progress


class Finding(models.Model):
    """Finding model for security findings"""
    
    REMEDIATION_STATUS_CHOICES = [
        ('Not Started', 'Not Started'),
        ('In Progress', 'In Progress'),
        ('Completed', 'Completed'),
        ('Verified', 'Verified'),
    ]
    
    audit = models.ForeignKey(Audit, on_delete=models.CASCADE, related_name='findings')
    rule = models.ForeignKey(Rule, on_delete=models.CASCADE, related_name='findings')
    severity = models.CharField(max_length=20)
    message = models.TextField()
    config_path = models.TextField(blank=True, null=True)
    remediation = models.TextField(blank=True, null=True)
    remediation_status = models.CharField(max_length=20, choices=REMEDIATION_STATUS_CHOICES, default='Not Started')
    remediation_notes = models.TextField(blank=True, null=True)
    parent_finding = models.ForeignKey('self', on_delete=models.CASCADE, blank=True, null=True, related_name='children')
    
    class Meta:
        ordering = ['id']
    
    def __str__(self):
        return f"Finding {self.id} - {self.rule.name}"
    
    @property
    def organization(self):
        """Get organization from audit"""
        return self.audit.organization


class UserInvitation(models.Model):
    """User invitation model for inviting users to organizations"""
    
    email = models.EmailField()
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='invitations')
    role = models.CharField(max_length=20, choices=UserProfile.ROLE_CHOICES, default=UserProfile.ROLE_ORG_USER)
    token = models.CharField(max_length=64, unique=True)
    invited_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_invitations')
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Invitation for {self.email} to {self.organization.name}"
    
    def is_expired(self):
        """Check if invitation is expired"""
        return timezone.now() > self.expires_at
    
    def is_accepted(self):
        """Check if invitation has been accepted"""
        return self.accepted_at is not None
    
    def save(self, *args, **kwargs):
        """Generate token if not set"""
        if not self.token:
            self.token = uuid.uuid4().hex
        super().save(*args, **kwargs)


class AuditLog(models.Model):
    """Audit log model for tracking all admin and user actions"""
    
    ACTION_TYPES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('login', 'Login'),
        ('logout', 'Logout'),
        ('invite', 'Invite User'),
        ('accept_invite', 'Accept Invitation'),
    ]
    
    RESOURCE_TYPES = [
        ('organization', 'Organization'),
        ('user', 'User'),
        ('audit', 'Audit'),
        ('rule', 'Rule'),
        ('finding', 'Finding'),
        ('asset', 'Asset'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.SET_NULL, blank=True, null=True, related_name='audit_logs')
    organization = models.ForeignKey(Organization, on_delete=models.SET_NULL, blank=True, null=True, related_name='audit_logs')
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES)
    resource_type = models.CharField(max_length=20, choices=RESOURCE_TYPES)
    resource_id = models.IntegerField(blank=True, null=True)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.action_type} {self.resource_type} by {self.user} at {self.created_at}"


# Signal to copy platform rules when organization is created
@receiver(post_save, sender=Organization)
def copy_platform_rules_to_organization(sender, instance, created, **kwargs):
    """Copy all platform rules to new organization"""
    if created:
        instance.copy_platform_rules()
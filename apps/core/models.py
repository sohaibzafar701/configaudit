"""
Django models for NCRT
"""
from django.db import models
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import json
import uuid
import random
import logging

logger = logging.getLogger(__name__)


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
        try:
            platform_rules = Rule.objects.filter(organization__isnull=True)
            copied_count = 0
            error_count = 0
            
            for rule in platform_rules:
                try:
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
                    copied_count += 1
                except Exception as e:
                    error_count += 1
                    logger.error(
                        f"Error copying rule '{rule.name}' to organization '{self.name}' (ID: {self.id}): {str(e)}",
                        exc_info=True
                    )
            
            if copied_count > 0:
                logger.info(
                    f"Successfully copied {copied_count} platform rules to organization '{self.name}' (ID: {self.id})"
                )
            if error_count > 0:
                logger.warning(
                    f"Failed to copy {error_count} rules to organization '{self.name}' (ID: {self.id})"
                )
            if copied_count == 0 and error_count == 0:
                logger.info(
                    f"No platform rules found to copy to organization '{self.name}' (ID: {self.id})"
                )
        except Exception as e:
            logger.error(
                f"Critical error copying platform rules to organization '{self.name}' (ID: {self.id}): {str(e)}",
                exc_info=True
            )
            raise


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


class BaselineConfiguration(models.Model):
    """Baseline configuration model for defining security baselines"""
    
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    vendor = models.CharField(max_length=100, blank=True, null=True)  # cisco, juniper, fortinet, huawei, sophos, etc.
    device_type = models.CharField(max_length=100, blank=True, null=True)  # router, switch, firewall
    compliance_frameworks = models.CharField(max_length=500, blank=True, null=True)  # comma-separated: PCI-DSS,ISO27001,NIST
    rule_ids = models.JSONField(default=list, blank=True)  # List of rule IDs that define this baseline
    template_config = models.TextField(blank=True, null=True)  # Example/template configuration
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, blank=True, null=True, related_name='baselines')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['name']
        verbose_name = 'Baseline Configuration'
        verbose_name_plural = 'Baseline Configurations'
    
    def __str__(self):
        return self.name
    
    def is_platform_baseline(self):
        """Check if this is a platform baseline"""
        return self.organization is None
    
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
    
    def get_rules(self):
        """Get Rule objects for this baseline"""
        if not self.rule_ids:
            return Rule.objects.none()
        return Rule.objects.filter(id__in=self.rule_ids, enabled=True)
    
    def get_rule_count(self):
        """Get number of rules in this baseline"""
        return len(self.rule_ids) if self.rule_ids else 0


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


class PasswordResetToken(models.Model):
    """Password reset token model for forgot password functionality"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_reset_tokens')
    token = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Password reset token for {self.user.username}"
    
    def is_expired(self):
        """Check if token is expired"""
        return timezone.now() > self.expires_at
    
    def is_used(self):
        """Check if token has been used"""
        return self.used_at is not None
    
    def is_valid(self):
        """Check if token is valid (not expired and not used)"""
        return not self.is_expired() and not self.is_used()
    
    def save(self, *args, **kwargs):
        """Generate token if not set"""
        if not self.token:
            self.token = uuid.uuid4().hex
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(hours=1)
        super().save(*args, **kwargs)


class TwoFactorAuthCode(models.Model):
    """Two-factor authentication code model for email-based 2FA"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='two_factor_codes')
    code = models.CharField(max_length=6)
    session_key = models.CharField(max_length=255, blank=True, null=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"2FA code for {self.user.username}"
    
    def is_expired(self):
        """Check if code is expired"""
        return timezone.now() > self.expires_at
    
    def is_used(self):
        """Check if code has been used"""
        return self.used_at is not None
    
    def is_valid(self):
        """Check if code is valid (not expired and not used)"""
        return not self.is_expired() and not self.is_used()
    
    def save(self, *args, **kwargs):
        """Generate code if not set"""
        if not self.code:
            self.code = f"{random.randint(100000, 999999):06d}"
        if not self.expires_at:
            self.expires_at = timezone.now() + timedelta(minutes=10)
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
        try:
            logger.info(f"Signal triggered: Copying platform rules to new organization '{instance.name}' (ID: {instance.id})")
            instance.copy_platform_rules()
        except Exception as e:
            logger.error(
                f"Error in signal handler when copying rules to organization '{instance.name}' (ID: {instance.id}): {str(e)}",
                exc_info=True
            )
            # Don't re-raise - we don't want to prevent organization creation if rule copying fails


def update_platform_baselines_on_rule_change(rule):
    """
    Update platform baselines when a platform rule changes.
    Only updates baselines that might include this rule based on vendor tags or compliance frameworks.
    """
    # Only process platform rules
    if rule.organization is not None:
        return
    
    # Skip if rule is disabled (will be removed from baselines)
    if not rule.enabled:
        return
    
    try:
        from django.db.models import Q
        
        # Get vendor from rule tags
        vendor = None
        if rule.tags:
            tags_lower = rule.tags.lower()
            for v in ['cisco', 'juniper', 'fortinet', 'huawei', 'sophos']:
                if v in tags_lower:
                    vendor = v
                    break
        
        # Get compliance frameworks from rule
        frameworks = []
        if rule.compliance_frameworks:
            frameworks = [f.strip() for f in rule.compliance_frameworks.split(',') if f.strip()]
        
        # Find platform baselines that might include this rule
        # Match by vendor or compliance framework
        baseline_query = BaselineConfiguration.objects.filter(organization__isnull=True)
        
        matching_baselines = []
        if vendor:
            matching_baselines.extend(baseline_query.filter(vendor=vendor))
        if frameworks:
            for framework in frameworks:
                matching_baselines.extend(baseline_query.filter(compliance_frameworks__icontains=framework))
        
        # Remove duplicates
        matching_baselines = list(set(matching_baselines))
        
        if not matching_baselines:
            return
        
        # Recalculate rule_ids for each matching baseline
        for baseline in matching_baselines:
            try:
                rule_ids = []
                
                # Get rules by vendor if baseline has vendor
                if baseline.vendor:
                    vendor_rules = Rule.objects.filter(
                        enabled=True,
                        organization__isnull=True,
                        tags__icontains=baseline.vendor.lower()
                    )
                    rule_ids.extend(vendor_rules.values_list('id', flat=True))
                
                # Get rules by compliance frameworks
                if baseline.compliance_frameworks:
                    baseline_frameworks = baseline.get_frameworks_list()
                    for framework in baseline_frameworks:
                        framework_rules = Rule.objects.filter(
                            enabled=True,
                            organization__isnull=True,
                            compliance_frameworks__icontains=framework
                        )
                        rule_ids.extend(framework_rules.values_list('id', flat=True))
                
                # Remove duplicates and convert to list
                rule_ids = list(set(rule_ids))
                
                # Update baseline if rule_ids changed
                if set(baseline.rule_ids or []) != set(rule_ids):
                    baseline.rule_ids = rule_ids
                    baseline.save(update_fields=['rule_ids'])
                    logger.info(f"Updated platform baseline '{baseline.name}' with {len(rule_ids)} rules")
                    
            except Exception as e:
                logger.error(f"Error updating baseline '{baseline.name}': {str(e)}", exc_info=True)
                
    except Exception as e:
        logger.error(f"Error in update_platform_baselines_on_rule_change: {str(e)}", exc_info=True)


@receiver(post_save, sender=Rule)
def rule_saved_handler(sender, instance, created, **kwargs):
    """Update platform baselines when a platform rule is saved"""
    # Only update if this is a platform rule
    if instance.organization is None:
        update_platform_baselines_on_rule_change(instance)


@receiver(post_delete, sender=Rule)
def rule_deleted_handler(sender, instance, **kwargs):
    """Update platform baselines when a platform rule is deleted"""
    # Only update if this was a platform rule
    if instance.organization is None:
        update_platform_baselines_on_rule_change(instance)
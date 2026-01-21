"""
Django admin configuration
"""
from django.contrib import admin
from .models import Organization, UserProfile, Rule, Audit, Finding, UserInvitation, AuditLog


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'domain', 'poc_email', 'status', 'created_at']
    list_filter = ['status', 'created_at']
    search_fields = ['name', 'domain', 'poc_email']
    ordering = ['name']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'organization', 'role', 'created_at']
    list_filter = ['role', 'organization', 'created_at']
    search_fields = ['user__username', 'user__email', 'organization__name']
    ordering = ['user__username']
    readonly_fields = ['created_at', 'updated_at']


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ['name', 'rule_type', 'category', 'severity', 'enabled', 'organization', 'created_at']
    list_filter = ['rule_type', 'category', 'severity', 'enabled', 'organization']
    search_fields = ['name', 'description', 'tags']
    ordering = ['name']


@admin.register(Audit)
class AuditAdmin(admin.ModelAdmin):
    list_display = ['id', 'organization', 'device_identifier', 'device_family', 'status', 'created_by', 'created_at']
    list_filter = ['status', 'device_family', 'device_make', 'device_type', 'organization']
    search_fields = ['device_identifier', 'device_hostname', 'config_file']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'completed_at']


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ['id', 'audit', 'rule', 'severity', 'remediation_status']
    list_filter = ['severity', 'remediation_status']
    search_fields = ['message', 'config_path']
    ordering = ['-id']


@admin.register(UserInvitation)
class UserInvitationAdmin(admin.ModelAdmin):
    list_display = ['email', 'organization', 'role', 'invited_by', 'expires_at', 'accepted_at', 'created_at']
    list_filter = ['role', 'organization', 'accepted_at', 'created_at']
    search_fields = ['email', 'organization__name']
    ordering = ['-created_at']
    readonly_fields = ['token', 'created_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'organization', 'action_type', 'resource_type', 'resource_id', 'created_at']
    list_filter = ['action_type', 'resource_type', 'organization', 'created_at']
    search_fields = ['user__username', 'description']
    ordering = ['-created_at']
    readonly_fields = ['created_at']

"""
Core app URL configuration
"""
from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('poc-signup/', views.poc_signup_view, name='poc_signup'),
    path('forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('reset-password/', views.reset_password_view, name='reset_password'),
    path('verify-2fa/', views.verify_2fa_view, name='verify_2fa'),
    
    # Frontend pages
    path('', views.index, name='index'),
    path('audit/', views.audit_page, name='audit_page'),
    path('rules/', views.rules_page, name='rules_page'),
    path('report/', views.report_page, name='report_page'),
    path('report-detail/', views.report_detail_page, name='report_detail_page'),
    path('assets/', views.assets_page, name='assets_page'),
    path('assets/<str:device_identifier>/audits', views.device_audits_page, name='device_audits_page'),
    path('baselines/', views.baselines_page, name='baselines_page'),
    path('analysis/', views.analysis_page, name='analysis_page'),
    path('help/', views.help_page, name='help_page'),
    
    # API endpoints
    path('api/audits', views.audits_api, name='audits_api'),
    path('api/rules/filter-options', views.rules_filter_options_api, name='rules_filter_options_api'),
    path('api/rules/tags', views.rules_api, name='rules_tags_api'),
    path('api/rules/<int:rule_id>', views.rules_api, name='rules_detail_api'),
    path('api/rules', views.rules_api, name='rules_api'),
    path('api/reports', views.reports_api, name='reports_api'),
    path('api/upload', views.upload_api, name='upload_api'),
    path('api/stats', views.stats_api, name='stats_api'),
    path('api/assets/<str:device_identifier>/latest', views.assets_api, name='assets_latest_api'),
    path('api/assets/<str:device_identifier>', views.assets_api, name='assets_detail_api'),
    path('api/assets', views.assets_api, name='assets_api'),
    path('api/settings/backup', views.settings_api, name='settings_backup_api'),
    path('api/settings/optimize', views.settings_api, name='settings_optimize_api'),
    
    # Super Admin routes
    path('super-admin/', views.super_admin_dashboard, name='super_admin_dashboard'),
    path('super-admin/organizations/', views.super_admin_organizations, name='super_admin_organizations'),
    path('super-admin/rules/', views.super_admin_rules, name='super_admin_rules'),
    path('api/super-admin/organizations/', views.super_admin_organization_api, name='super_admin_organizations_api'),
    path('api/super-admin/organizations/<int:org_id>/', views.super_admin_organization_api, name='super_admin_organization_detail_api'),
    path('api/super-admin/rules/', views.super_admin_rules_api, name='super_admin_rules_api'),
    path('api/super-admin/rules/assign/', views.super_admin_assign_rules, name='super_admin_assign_rules'),
    path('api/super-admin/rules/unassign/', views.super_admin_unassign_rules, name='super_admin_unassign_rules'),
    path('api/super-admin/rules/reset/', views.super_admin_reset_rules, name='super_admin_reset_rules'),
    
    # Organization Admin routes
    path('org-admin/users/', views.org_admin_users, name='org_admin_users'),
    path('api/org-admin/invite-user/', views.org_admin_invite_user, name='org_admin_invite_user'),
    path('api/org-admin/invite-user/<int:invitation_id>/resend/', views.org_admin_resend_invite, name='org_admin_resend_invite'),
    path('api/org-admin/invite-user/<int:invitation_id>/cancel/', views.org_admin_cancel_invite, name='org_admin_cancel_invite'),
    path('api/org-admin/users/<int:user_id>/', views.org_admin_user_api, name='org_admin_user_api'),
    
    # Baseline API endpoints
    path('api/baselines/<int:baseline_id>/copy', views.baseline_copy_api, name='baseline_copy_api'),
    path('api/baselines/<int:baseline_id>/compare', views.baseline_compare_api, name='baseline_compare_api'),
    path('api/baselines/<int:baseline_id>/document', views.baseline_document_api, name='baseline_document_api'),
    path('api/baselines/<int:baseline_id>/template', views.baseline_template_api, name='baseline_template_api'),
    path('api/baselines/<int:baseline_id>', views.baselines_api, name='baselines_detail_api'),
    path('api/baselines', views.baselines_api, name='baselines_api'),
]

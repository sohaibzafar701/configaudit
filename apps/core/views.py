"""
Django views for NCRT
"""
import json
import os
import threading
from pathlib import Path
from django.http import JsonResponse, HttpResponse, Http404, FileResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
from django.db import connection

from .models import Organization, UserProfile, Rule, Audit, Finding, UserInvitation, AuditLog
from .decorators import require_authenticated, require_super_admin, require_org_admin, require_org_user, require_org_viewer
from .utils import log_audit_action, get_client_ip
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from services.audit_service import process_audit, get_audit_progress
from services.report_generator import (
    get_filtered_findings, generate_statistics, calculate_compliance_score,
    generate_pdf_report, generate_csv_report, generate_executive_summary,
    generate_comparison_report, generate_html_standalone_report
)
from services.timezone_utils import format_datetime_from_iso, format_datetime_now, parse_datetime_format
from services.metadata_extractor import extract_metadata
from services.config_diff import compare_configs


# Helper function to convert Django model to dict
def model_to_dict(model_instance):
    """Convert Django model instance to dictionary"""
    if model_instance is None:
        return None
    data = {}
    for field in model_instance._meta.fields:
        value = getattr(model_instance, field.name)
        
        # Handle ForeignKey fields - get the ID instead of the object
        if field.many_to_one or field.one_to_one:
            if value is not None:
                # Get the ID of the related object
                data[field.name] = value.pk if hasattr(value, 'pk') else value
                # Also add _id field for ForeignKey fields
                if field.many_to_one:
                    data[f'{field.name}_id'] = value.pk if hasattr(value, 'pk') else value
            else:
                data[field.name] = None
                if field.many_to_one:
                    data[f'{field.name}_id'] = None
        elif hasattr(value, 'isoformat'):  # DateTime field
            data[field.name] = value.isoformat() if value else None
        else:
            data[field.name] = value
    return data


# Authentication Views
@csrf_exempt
@require_http_methods(["GET", "POST"])
def login_view(request):
    """User login view"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return JsonResponse({'error': 'Username and password are required'}, status=400)
            
            user = authenticate(request, username=username, password=password)
            if user is not None:
                auth_login(request, user)
                ip_address = get_client_ip(request)
                log_audit_action(user, 'login', 'user', user.id, f'User {username} logged in', ip_address)
                return JsonResponse({'status': 'success', 'redirect': '/'}, status=200)
            else:
                return JsonResponse({'error': 'Invalid username or password'}, status=401)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # GET request - show login page
    if request.user.is_authenticated:
        return redirect('index')
    return render(request, 'registration/login.html')


@require_http_methods(["POST"])
@require_authenticated
def logout_view(request):
    """User logout view"""
    user = request.user
    ip_address = get_client_ip(request)
    log_audit_action(user, 'logout', 'user', user.id, f'User {user.username} logged out', ip_address)
    auth_logout(request)
    return JsonResponse({'status': 'success', 'redirect': '/login/'}, status=200)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def register_view(request):
    """User registration view (for accepting invitations)"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            token = data.get('token', '').strip()
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            
            if not token:
                return JsonResponse({'error': 'Invitation token is required'}, status=400)
            
            # Get invitation
            try:
                invitation = UserInvitation.objects.get(token=token)
            except UserInvitation.DoesNotExist:
                return JsonResponse({'error': 'Invalid invitation token'}, status=404)
            
            # Check if expired
            if invitation.is_expired():
                return JsonResponse({'error': 'Invitation has expired'}, status=400)
            
            # Check if already accepted
            if invitation.is_accepted():
                return JsonResponse({'error': 'Invitation has already been accepted'}, status=400)
            
            # Validate email matches invitation
            if email.lower() != invitation.email.lower():
                return JsonResponse({'error': 'Email does not match invitation'}, status=400)
            
            # Check if user already exists
            from django.contrib.auth.models import User
            if User.objects.filter(username=username).exists():
                return JsonResponse({'error': 'Username already exists'}, status=400)
            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already registered'}, status=400)
            
            # Create user
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            
            # Create profile
            profile = UserProfile.objects.create(
                user=user,
                organization=invitation.organization,
                role=invitation.role
            )
            
            # Mark invitation as accepted
            invitation.accepted_at = timezone.now()
            invitation.save()
            
            # Log action
            ip_address = get_client_ip(request)
            log_audit_action(user, 'accept_invite', 'user', user.id, 
                           f'User {username} accepted invitation to {invitation.organization.name}', 
                           ip_address, invitation.organization)
            
            # Auto-login
            auth_login(request, user)
            
            return JsonResponse({'status': 'success', 'redirect': '/'}, status=201)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    # GET request - show registration page
    token = request.GET.get('token', '')
    if not token:
        return JsonResponse({'error': 'Invitation token is required'}, status=400)
    
    try:
        invitation = UserInvitation.objects.get(token=token)
        if invitation.is_expired():
            return render(request, 'registration/invite_accept.html', {
                'error': 'Invitation has expired',
                'token': token
            })
        if invitation.is_accepted():
            return render(request, 'registration/invite_accept.html', {
                'error': 'Invitation has already been accepted',
                'token': token
            })
        return render(request, 'registration/invite_accept.html', {
            'invitation': invitation,
            'token': token,
            'email': invitation.email
        })
    except UserInvitation.DoesNotExist:
        return render(request, 'registration/invite_accept.html', {
            'error': 'Invalid invitation token',
            'token': token
        })


# Page views
@require_authenticated
def index(request):
    """Home page"""
    return render(request, 'index.html')


@require_authenticated
def audit_page(request):
    """Audit page"""
    return render(request, 'audit.html')


@require_authenticated
def rules_page(request):
    """Rules management page"""
    return render(request, 'rules.html')


@require_org_viewer  # Org viewer can access reports
def report_page(request):
    """Report page"""
    return render(request, 'report.html')


@require_org_viewer
def report_detail_page(request):
    """Report detail page"""
    return render(request, 'report-detail.html')


@require_authenticated
def assets_page(request):
    """Assets page"""
    return render(request, 'assets.html')


@require_authenticated
def device_audits_page(request, device_identifier):
    """Device audits page - shows all audits for a specific device"""
    return render(request, 'device_audits.html', {'device_identifier': device_identifier})


@require_authenticated
def settings_page(request):
    """Settings page"""
    return render(request, 'settings.html')


@require_authenticated
def analysis_page(request):
    """Analysis page"""
    return render(request, 'analysis.html')


@require_authenticated
def help_page(request):
    """Help page"""
    return render(request, 'help.html')


# API Views
@csrf_exempt
@require_http_methods(["GET", "POST"])
@require_authenticated
def audits_api(request):
    """Handle audit API requests"""
    if request.method == 'GET':
        # Get timezone and format preferences
        timezone_str = request.GET.get('timezone', 'UTC') or 'UTC'
        date_format_str = request.GET.get('date_format', 'YYYY-MM-DD HH:mm:ss') or 'YYYY-MM-DD HH:mm:ss'
        date_format_py = parse_datetime_format(date_format_str)
        
        history_param = request.GET.get('history')
        if history_param == 'true':
            # Return audit history
            try:
                from django.db.models import Q
                from datetime import datetime, timedelta
                
                # Filter by organization (unless super admin)
                if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                    # Super Admin: Can see aggregated data but not individual audits
                    audits = Audit.objects.none()  # Return empty for super admin
                else:
                    # Regular users: Filter by their organization
                    if hasattr(request, 'organization') and request.organization:
                        audits = Audit.objects.filter(organization=request.organization)
                    else:
                        audits = Audit.objects.none()
                
                # Apply search filter
                search_query = request.GET.get('search', '').strip()
                if search_query:
                    search_lower = search_query.lower()
                    audits = audits.filter(
                        Q(device_identifier__icontains=search_query) |
                        Q(config_file__icontains=search_query) |
                        Q(device_hostname__icontains=search_query) |
                        Q(status__icontains=search_query)
                    )
                
                # Apply status filter
                status_filter = request.GET.get('status', '').strip()
                if status_filter:
                    audits = audits.filter(status=status_filter)
                
                # Apply date range filter
                date_range = request.GET.get('date_range', '').strip()
                if date_range and date_range.isdigit():
                    days = int(date_range)
                    cutoff_date = datetime.now() - timedelta(days=days)
                    audits = audits.filter(created_at__gte=cutoff_date)
                
                audits = audits.order_by('-created_at')
                audits_list = []
                for audit in audits:
                    audit_dict = model_to_dict(audit)
                    # Count only parent findings
                    findings = Finding.objects.filter(audit=audit, parent_finding__isnull=True)
                    audit_dict['finding_count'] = findings.count()
                    # Format dates
                    if audit_dict.get('created_at'):
                        audit_dict['created_at_formatted'] = format_datetime_from_iso(
                            audit_dict['created_at'], timezone_str, date_format_py
                        )
                    if audit_dict.get('completed_at'):
                        audit_dict['completed_at_formatted'] = format_datetime_from_iso(
                            audit_dict['completed_at'], timezone_str, date_format_py
                        )
                    audits_list.append(audit_dict)
                return JsonResponse({'audits': audits_list}, status=200)
            except Exception as e:
                import traceback
                traceback.print_exc()
                return JsonResponse({'error': f'Failed to load audit history: {str(e)}', 'audits': []}, status=500)
        
        # Check if requesting specific audit by ID
        audit_id_param = request.GET.get('audit_id')
        if audit_id_param:
            try:
                audit_id = int(audit_id_param)
                try:
                    # Filter by organization (unless super admin)
                    if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                        return JsonResponse({'error': 'Super Admin cannot access individual audits'}, status=403)
                    
                    if hasattr(request, 'organization') and request.organization:
                        audit = Audit.objects.get(id=audit_id, organization=request.organization)
                    else:
                        return JsonResponse({'error': 'No organization found'}, status=403)
                    audit_dict = model_to_dict(audit)
                    findings = Finding.objects.filter(audit=audit).select_related('rule')
                    findings_list = []
                    for finding in findings:
                        finding_dict = model_to_dict(finding)
                        finding_dict['rule_name'] = finding.rule.name
                        finding_dict['rule_description'] = finding.rule.description
                        finding_dict['rule_remediation_template'] = finding.rule.remediation_template
                        finding_dict['rule_compliance_frameworks'] = finding.rule.compliance_frameworks
                        finding_dict['rule_framework_mappings'] = finding.rule.framework_mappings
                        findings_list.append(finding_dict)
                    audit_dict['findings'] = findings_list
                    # Format dates
                    if audit_dict.get('created_at'):
                        audit_dict['created_at_formatted'] = format_datetime_from_iso(
                            audit_dict['created_at'], timezone_str, date_format_py
                        )
                    if audit_dict.get('completed_at'):
                        audit_dict['completed_at_formatted'] = format_datetime_from_iso(
                            audit_dict['completed_at'], timezone_str, date_format_py
                        )
                    return JsonResponse(audit_dict, status=200)
                except Audit.DoesNotExist:
                    return JsonResponse({'error': 'Audit not found'}, status=404)
            except ValueError:
                return JsonResponse({'error': 'Invalid audit_id'}, status=400)
        
        # Get current audit (most recent) - filtered by organization
        if hasattr(request, 'user_role') and request.user_role == 'super_admin':
            audit = None  # Super Admin cannot access individual audits
        else:
            if hasattr(request, 'organization') and request.organization:
                audit = Audit.objects.filter(organization=request.organization).first()
            else:
                audit = None
        
        if audit:
            audit_dict = model_to_dict(audit)
            findings = Finding.objects.filter(audit=audit).select_related('rule')
            findings_list = []
            for finding in findings:
                finding_dict = model_to_dict(finding)
                finding_dict['rule_name'] = finding.rule.name
                finding_dict['rule_description'] = finding.rule.description
                findings_list.append(finding_dict)
            audit_dict['findings'] = findings_list
            # Format dates
            if audit_dict.get('created_at'):
                audit_dict['created_at_formatted'] = format_datetime_from_iso(
                    audit_dict['created_at'], timezone_str, date_format_py
                )
            return JsonResponse(audit_dict, status=200)
        return JsonResponse({}, status=200)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
        
        action = data.get('action')
        
        if action == 'create':
            # Validate config_content
            config_content = data.get('config_content', '')
            if not config_content or not config_content.strip():
                return JsonResponse({'error': 'Configuration content is required and cannot be empty'}, status=400)
            
            # Validate file size (default 10MB limit)
            MAX_CONFIG_SIZE = 10 * 1024 * 1024  # 10MB
            if len(config_content.encode('utf-8')) > MAX_CONFIG_SIZE:
                return JsonResponse({'error': f'Configuration file exceeds maximum size of {MAX_CONFIG_SIZE / (1024*1024):.0f}MB'}, status=400)
            
            # Validate rule tags selection
            selected_tags = data.get('rule_tags', [])
            if isinstance(selected_tags, str):
                selected_tags = [selected_tags] if selected_tags else []
            elif not isinstance(selected_tags, list):
                selected_tags = []
            
            selected_tags = [tag.strip() for tag in selected_tags if tag and tag.strip()]
            
            if not selected_tags:
                return JsonResponse({'error': 'Please select at least one rule tag.'}, status=400)
            
            # Validate that rules exist for selected tags
            rules = Rule.objects.filter(enabled=True)
            matching_rules = []
            for rule in rules:
                rule_tags = rule.get_tags_list()
                if any(tag in rule_tags for tag in selected_tags):
                    matching_rules.append(rule)
            
            if not matching_rules:
                return JsonResponse({'error': f'No enabled rules found for selected tags: {", ".join(selected_tags)}'}, status=400)
            
            # Check permissions - Org Viewer cannot create audits
            if hasattr(request, 'user_role') and request.user_role == 'org_viewer':
                return JsonResponse({'error': 'Read-only access. Cannot create audits.'}, status=403)
            
            # Get user's organization
            if not hasattr(request, 'organization') or not request.organization:
                return JsonResponse({'error': 'No organization found'}, status=403)
            
            # Validate device_identifier
            device_identifier = data.get('device_identifier')
            if not device_identifier or not device_identifier.strip():
                return JsonResponse({'error': 'device_identifier is required and cannot be empty'}, status=400)
            
            # Extract metadata from config
            metadata = extract_metadata(config_content, data.get('device_family'))
            
            # Get device make, model, type from request
            device_make = data.get('device_make')
            device_type = data.get('device_type')
            device_model_user = data.get('device_model', '')
            device_model = device_model_user.strip() if device_model_user else metadata.get('model')
            
            # Build device_family
            if not data.get('device_family') and device_make and device_type:
                device_family = f"{device_make} {device_type}"
                if device_model:
                    device_family += f" {device_model}"
            else:
                device_family = data.get('device_family')
            
            # Get config_file from data or use device_identifier as fallback
            config_file = data.get('config_file')
            if not config_file:
                # Use device_identifier as fallback
                config_file = device_identifier.strip()
            
            # Create new audit
            audit = Audit.objects.create(
                organization=request.organization,
                created_by=request.user,
                device_identifier=device_identifier.strip(),
                device_family=device_family,
                config_file=config_file,
                device_hostname=metadata.get('hostname'),
                device_model=device_model,
                device_firmware=metadata.get('firmware'),
                device_location=metadata.get('location'),
                device_make=device_make,
                device_type=device_type,
                status=Audit.STATUS_PENDING
            )
            
            # Log audit creation
            ip_address = get_client_ip(request)
            log_audit_action(request.user, 'create', 'audit', audit.id, 
                           f'Created audit for {device_identifier}', ip_address, request.organization)
            
            # Start processing in background thread
            if config_content:
                thread = threading.Thread(
                    target=process_audit,
                    args=(audit.id, config_content, device_family, None, selected_tags),
                    daemon=True
                )
                thread.start()
            
            return JsonResponse({'id': audit.id, 'status': 'created'}, status=201)
        
        elif action == 'delete':
            # Check permissions - Org Viewer cannot delete
            if hasattr(request, 'user_role') and request.user_role == 'org_viewer':
                return JsonResponse({'error': 'Read-only access. Cannot delete audits.'}, status=403)
            
            audit_id = data.get('audit_id')
            device_identifier = data.get('device_identifier')
            
            if audit_id:
                try:
                    # Filter by organization
                    if hasattr(request, 'organization') and request.organization:
                        audit = Audit.objects.get(id=audit_id, organization=request.organization)
                    else:
                        return JsonResponse({'error': 'Audit not found'}, status=404)
                    
                    audit_id_val = audit.id
                    audit.delete()  # Django CASCADE will delete findings
                    
                    # Log deletion
                    ip_address = get_client_ip(request)
                    log_audit_action(request.user, 'delete', 'audit', audit_id_val, 
                                   f'Deleted audit {audit_id_val}', ip_address, request.organization)
                    
                    return JsonResponse({'status': 'deleted', 'audit_id': audit_id}, status=200)
                except Audit.DoesNotExist:
                    return JsonResponse({'error': 'Audit not found'}, status=404)
            elif device_identifier:
                # Delete all audits for a device (delete asset) - filter by organization
                if hasattr(request, 'organization') and request.organization:
                    deleted_count = Audit.objects.filter(
                        device_identifier=device_identifier,
                        organization=request.organization
                    ).delete()[0]
                    
                    # Log deletion
                    ip_address = get_client_ip(request)
                    log_audit_action(request.user, 'delete', 'asset', None, 
                                   f'Deleted all audits for device {device_identifier}', 
                                   ip_address, request.organization)
                    
                    return JsonResponse({'status': 'deleted', 'device_identifier': device_identifier, 'deleted_count': deleted_count}, status=200)
                else:
                    return JsonResponse({'error': 'No organization found'}, status=403)
            else:
                # Delete all audits for organization (not all audits in system)
                if hasattr(request, 'organization') and request.organization:
                    deleted_count = Audit.objects.filter(organization=request.organization).delete()[0]
                    
                    # Log deletion
                    ip_address = get_client_ip(request)
                    log_audit_action(request.user, 'delete', 'audit', None, 
                                   f'Deleted all audits for organization', 
                                   ip_address, request.organization)
                    
                    return JsonResponse({'status': 'deleted', 'all': True, 'deleted_count': deleted_count}, status=200)
                else:
                    return JsonResponse({'error': 'No organization found'}, status=403)
        
        elif action == 'get_progress':
            audit_id = data.get('audit_id')
            if audit_id:
                try:
                    audit = Audit.objects.get(id=audit_id)
                    progress = audit.get_progress()
                    progress['audit_id'] = audit_id
                    return JsonResponse(progress, status=200)
                except Audit.DoesNotExist:
                    return JsonResponse({'error': 'Audit not found'}, status=404)
            return JsonResponse({'error': 'audit_id required'}, status=400)
        
        elif action == 'cancel':
            audit_id = data.get('audit_id')
            if audit_id:
                try:
                    audit = Audit.objects.get(id=audit_id)
                    audit.update_status(Audit.STATUS_CANCELLED)
                    return JsonResponse({'status': 'cancelled'}, status=200)
                except Audit.DoesNotExist:
                    return JsonResponse({'error': 'Audit not found'}, status=404)
            return JsonResponse({'error': 'audit_id required'}, status=400)
        
        elif action == 'update_remediation':
            finding_id = data.get('finding_id')
            status = data.get('status')
            notes = data.get('notes')
            
            if not finding_id:
                return JsonResponse({'error': 'finding_id required'}, status=400)
            
            valid_statuses = ['Not Started', 'In Progress', 'Completed', 'Verified']
            if status and status not in valid_statuses:
                return JsonResponse({'error': f'Invalid remediation status. Must be one of: {", ".join(valid_statuses)}'}, status=400)
            
            try:
                finding = Finding.objects.get(id=finding_id)
                if status:
                    finding.remediation_status = status
                if notes is not None:
                    finding.remediation_notes = notes
                finding.save()
                return JsonResponse({'status': 'updated'}, status=200)
            except Finding.DoesNotExist:
                return JsonResponse({'error': 'Finding not found'}, status=404)
        
        elif action == 'create_snapshot':
            audit_id = data.get('audit_id')
            snapshot_name = data.get('snapshot_name', 'Snapshot')
            if not audit_id:
                return JsonResponse({'error': 'audit_id required'}, status=400)
            
            try:
                parent_audit = Audit.objects.get(id=audit_id)
                if parent_audit.status != Audit.STATUS_COMPLETED:
                    return JsonResponse({'error': 'Can only create snapshots of completed audits'}, status=400)
                
                # Create snapshot
                snapshot = Audit.objects.create(
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
                    Finding.objects.create(
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
                
                return JsonResponse({'status': 'created', 'snapshot_id': snapshot.id}, status=201)
            except Audit.DoesNotExist:
                return JsonResponse({'error': 'Audit not found'}, status=404)
        
        elif action == 'compare_configs':
            audit_id1 = data.get('audit_id1')
            audit_id2 = data.get('audit_id2')
            if not audit_id1 or not audit_id2:
                return JsonResponse({'error': 'audit_id1 and audit_id2 required'}, status=400)
            
            diff_result = compare_configs(audit_id1, audit_id2)
            if diff_result:
                return JsonResponse(diff_result, status=200)
            return JsonResponse({'error': 'Failed to compare configs'}, status=400)
        
        return JsonResponse({'error': 'Invalid request'}, status=400)


@require_http_methods(["GET"])
def rules_filter_options_api(request):
    """Get filter options for rules (vendors, categories, severities, types, statuses)"""
    # Get unique vendors from tags
    vendor_tags = {'cisco', 'juniper', 'arista', 'paloalto', 'fortinet', 'checkpoint'}
    vendors_found = set()
    rules = Rule.objects.filter(tags__isnull=False).exclude(tags='')
    for rule in rules:
        rule_tags = rule.get_tags_list()
        for tag in rule_tags:
            tag_lower = tag.lower()
            if tag_lower in vendor_tags:
                # Capitalize vendor names properly
                vendor_name = tag.capitalize()
                if tag_lower == 'paloalto':
                    vendor_name = 'Palo Alto'
                elif tag_lower == 'checkpoint':
                    vendor_name = 'Check Point'
                vendors_found.add(vendor_name)
    
    vendors = ['All Vendors'] + sorted(list(vendors_found))
    
    # Get unique categories - filter by organization
    if hasattr(request, 'user_role') and request.user_role == 'super_admin':
        categories_query = Rule.objects.exclude(category__isnull=True).exclude(category='').filter(organization__isnull=True)
        severity_query = Rule.objects.exclude(severity__isnull=True).exclude(severity='').filter(organization__isnull=True)
        types_query = Rule.objects.filter(organization__isnull=True)
    else:
        if hasattr(request, 'organization') and request.organization:
            categories_query = Rule.objects.exclude(category__isnull=True).exclude(category='').filter(organization=request.organization)
            severity_query = Rule.objects.exclude(severity__isnull=True).exclude(severity='').filter(organization=request.organization)
            types_query = Rule.objects.filter(organization=request.organization)
        else:
            categories_query = Rule.objects.none()
            severity_query = Rule.objects.none()
            types_query = Rule.objects.none()
    
    categories = ['All Categories'] + sorted(list(categories_query.values_list('category', flat=True).distinct()))
    
    # Get unique severities (capitalize first letter)
    severity_list = list(severity_query.values_list('severity', flat=True).distinct())
    severities = ['All Severities'] + sorted([s.capitalize() if s else s for s in severity_list])
    
    # Get unique rule types
    types = ['All Types'] + sorted(list(types_query.values_list('rule_type', flat=True).distinct()))
    
    # Status options
    statuses = ['All Status', 'Enabled', 'Disabled']
    
    return JsonResponse({
        'vendors': vendors,
        'categories': categories,
        'severities': severities,
        'types': types,
        'statuses': statuses
    }, status=200)


@csrf_exempt
@require_http_methods(["GET", "POST"])
@require_authenticated
def rules_api(request, rule_id=None):
    """Handle rule API requests"""
    if request.method == 'GET':
        # Check if requesting filter options
        if request.path.endswith('/filter-options') or 'filter-options' in request.path:
            return rules_filter_options_api(request)
        
        # Check if requesting tags
        if request.path.endswith('/tags') or 'tags' in request.path:
            # Get all available tags - filter by organization
            tags = set()
            vendor_tags = {'cisco', 'juniper', 'arista', 'paloalto', 'fortinet', 'checkpoint'}
            
            # Filter rules by organization (unless super admin)
            if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                # Super Admin sees platform rules only
                rules = Rule.objects.filter(enabled=True, organization__isnull=True, tags__isnull=False).exclude(tags='')
            else:
                # Regular users see their organization's rules
                if hasattr(request, 'organization') and request.organization:
                    rules = Rule.objects.filter(enabled=True, organization=request.organization, tags__isnull=False).exclude(tags='')
                else:
                    rules = Rule.objects.none()
            
            for rule in rules:
                rule_tags = rule.get_tags_list()
                filtered_tags = [t for t in rule_tags if t.lower() not in vendor_tags]
                tags.update(filtered_tags)
            return JsonResponse({'tags': sorted(list(tags))}, status=200)
        
        # Check if requesting specific rule by ID
        if rule_id:
            try:
                # Filter by organization (unless super admin)
                if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                    # Super Admin can only access platform rules
                    rule = Rule.objects.get(id=rule_id, organization__isnull=True)
                else:
                    # Regular users can only access their organization's rules
                    if hasattr(request, 'organization') and request.organization:
                        rule = Rule.objects.get(id=rule_id, organization=request.organization)
                    else:
                        return JsonResponse({'error': 'Rule not found'}, status=404)
                
                rule_dict = model_to_dict(rule)
                return JsonResponse(rule_dict, status=200)
            except Rule.DoesNotExist:
                return JsonResponse({'error': 'Rule not found'}, status=404)
        
        # Get all rules with filtering support - filter by organization
        from django.db.models import Q
        
        # Filter by organization (unless super admin)
        if hasattr(request, 'user_role') and request.user_role == 'super_admin':
            # Super Admin sees platform rules only
            rules = Rule.objects.filter(organization__isnull=True)
        else:
            # Regular users see their organization's rules
            if hasattr(request, 'organization') and request.organization:
                rules = Rule.objects.filter(organization=request.organization)
            else:
                rules = Rule.objects.none()
        
        # Apply filters
        vendor = request.GET.get('vendor')
        category = request.GET.get('category')
        severity = request.GET.get('severity')
        rule_type = request.GET.get('type')
        status = request.GET.get('status')
        
        # Vendor filter (check tags for vendor keywords)
        if vendor and vendor.lower() != 'all vendors':
            vendor_lower = vendor.lower()
            vendor_tags_map = {
                'cisco': 'cisco',
                'juniper': 'juniper',
                'arista': 'arista',
                'palo alto': 'paloalto',
                'paloalto': 'paloalto',
                'fortinet': 'fortinet',
                'check point': 'checkpoint',
                'checkpoint': 'checkpoint'
            }
            vendor_tag = vendor_tags_map.get(vendor_lower, vendor_lower)
            rules = rules.filter(tags__icontains=vendor_tag)
        
        # Category filter
        if category and category.lower() != 'all categories':
            rules = rules.filter(category=category)
        
        # Severity filter (case-insensitive)
        if severity and severity.lower() != 'all severities':
            rules = rules.filter(severity__iexact=severity.lower())
        
        # Type filter
        if rule_type and rule_type.lower() != 'all types':
            rules = rules.filter(rule_type=rule_type.lower())
        
        # Status filter
        if status and status.lower() != 'all status':
            if status.lower() == 'enabled':
                rules = rules.filter(enabled=True)
            elif status.lower() == 'disabled':
                rules = rules.filter(enabled=False)
        
        rules = rules.order_by('name')
        rules_list = [model_to_dict(rule) for rule in rules]
        return JsonResponse(rules_list, safe=False, status=200)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError as e:
            return JsonResponse({'error': f'Invalid JSON: {str(e)}'}, status=400)
        
        action = data.get('action')
        
        if action == 'create':
            # Check permissions - Org Viewer cannot create rules
            if hasattr(request, 'user_role') and request.user_role == 'org_viewer':
                return JsonResponse({'error': 'Read-only access. Cannot create rules.'}, status=403)
            
            # Super Admin creates platform rules, others create org rules
            if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                organization = None  # Platform rule
            else:
                if not hasattr(request, 'organization') or not request.organization:
                    return JsonResponse({'error': 'No organization found'}, status=403)
                organization = request.organization
            
            rule = Rule.objects.create(
                name=data['name'],
                description=data.get('description', ''),
                rule_type=data['rule_type'],
                category=data.get('category', ''),
                severity=data.get('severity', 'medium'),
                yaml_content=data.get('yaml_content', ''),
                tags=','.join(data.get('tags', [])) if isinstance(data.get('tags'), list) else data.get('tags', ''),
                enabled=data.get('enabled', True),
                remediation_template=data.get('remediation_template', ''),
                compliance_frameworks=','.join(data.get('compliance_frameworks', [])) if isinstance(data.get('compliance_frameworks'), list) else data.get('compliance_frameworks', ''),
                framework_mappings=data.get('framework_mappings'),
                risk_weight=data.get('risk_weight', 1.0),
                organization=organization
            )
            
            # Log creation
            ip_address = get_client_ip(request)
            log_audit_action(request.user, 'create', 'rule', rule.id, 
                           f'Created rule: {data["name"]}', ip_address, organization)
            
            return JsonResponse({'id': rule.id, 'status': 'created'}, status=201)
        
        elif action == 'update':
            # Check permissions - Org Viewer cannot update rules
            if hasattr(request, 'user_role') and request.user_role == 'org_viewer':
                return JsonResponse({'error': 'Read-only access. Cannot update rules.'}, status=403)
            
            rule_id = data.get('id')
            if not rule_id:
                return JsonResponse({'error': 'Rule ID required'}, status=400)
            
            try:
                # Filter by organization (unless super admin)
                if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                    # Super Admin can only update platform rules
                    rule = Rule.objects.get(id=rule_id, organization__isnull=True)
                else:
                    # Regular users can only update their organization's rules
                    if hasattr(request, 'organization') and request.organization:
                        rule = Rule.objects.get(id=rule_id, organization=request.organization)
                    else:
                        return JsonResponse({'error': 'Rule not found'}, status=404)
                if 'name' in data:
                    rule.name = data['name']
                if 'description' in data:
                    rule.description = data.get('description')
                if 'rule_type' in data:
                    rule.rule_type = data.get('rule_type')
                if 'category' in data:
                    rule.category = data.get('category')
                if 'severity' in data:
                    rule.severity = data.get('severity')
                if 'yaml_content' in data:
                    rule.yaml_content = data.get('yaml_content')
                if 'tags' in data:
                    if isinstance(data['tags'], list):
                        rule.set_tags_list(data['tags'])
                    else:
                        rule.tags = data['tags']
                if 'enabled' in data:
                    rule.enabled = data['enabled']
                if 'remediation_template' in data:
                    rule.remediation_template = data.get('remediation_template')
                if 'compliance_frameworks' in data:
                    if isinstance(data['compliance_frameworks'], list):
                        rule.set_frameworks_list(data['compliance_frameworks'])
                    else:
                        rule.compliance_frameworks = data['compliance_frameworks']
                if 'framework_mappings' in data:
                    rule.framework_mappings = data.get('framework_mappings')
                if 'risk_weight' in data:
                    rule.risk_weight = data.get('risk_weight')
                rule.save()
                return JsonResponse({'status': 'updated', 'id': rule_id}, status=200)
            except Rule.DoesNotExist:
                return JsonResponse({'error': 'Rule not found'}, status=404)
            except Exception as e:
                import traceback
                traceback.print_exc()
                return JsonResponse({'error': f'Update failed: {str(e)}'}, status=500)
        
        elif action == 'delete':
            # Check permissions - Org Viewer cannot delete rules
            if hasattr(request, 'user_role') and request.user_role == 'org_viewer':
                return JsonResponse({'error': 'Read-only access. Cannot delete rules.'}, status=403)
            
            rule_id = data.get('id')
            if rule_id:
                try:
                    # Filter by organization (unless super admin)
                    if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                        # Super Admin can only delete platform rules
                        rule = Rule.objects.get(id=rule_id, organization__isnull=True)
                    else:
                        # Regular users can only delete their organization's rules
                        if hasattr(request, 'organization') and request.organization:
                            rule = Rule.objects.get(id=rule_id, organization=request.organization)
                        else:
                            return JsonResponse({'error': 'Rule not found'}, status=404)
                    
                    rule_id_val = rule.id
                    rule_name = rule.name
                    rule.delete()
                    
                    # Log deletion
                    ip_address = get_client_ip(request)
                    org = None if hasattr(request, 'user_role') and request.user_role == 'super_admin' else request.organization
                    log_audit_action(request.user, 'delete', 'rule', rule_id_val, 
                                   f'Deleted rule: {rule_name}', ip_address, org)
                    
                    return JsonResponse({'status': 'deleted'}, status=200)
                except Rule.DoesNotExist:
                    return JsonResponse({'error': 'Rule not found'}, status=404)
            return JsonResponse({'error': 'Rule ID required'}, status=400)
        
        elif action == 'test':
            # Test a rule against sample config
            from services.rule_engine import execute_rules
            
            rule_id = data.get('rule_id')
            config_content = data.get('config_content', '')
            
            if not config_content:
                return JsonResponse({'error': 'config_content is required'}, status=400)
            
            # Build rule dict - either from database or from provided data
            if rule_id:
                # Test existing rule from database - filter by organization
                try:
                    # Filter by organization (unless super admin)
                    if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                        # Super Admin can test platform rules
                        rule = Rule.objects.get(id=rule_id, organization__isnull=True)
                    else:
                        # Regular users can test their organization's rules
                        if hasattr(request, 'organization') and request.organization:
                            rule = Rule.objects.get(id=rule_id, organization=request.organization)
                        else:
                            return JsonResponse({'error': 'Rule not found'}, status=404)
                    rule_dict = model_to_dict(rule)
                except Rule.DoesNotExist:
                    return JsonResponse({'error': 'Rule not found'}, status=404)
            else:
                # Test rule from form data (unsaved rule)
                rule_dict = {
                    'id': None,
                    'name': data.get('name', 'Test Rule'),
                    'description': data.get('description', ''),
                    'rule_type': data.get('rule_type', 'pattern'),
                    'category': data.get('category', ''),
                    'severity': data.get('severity', 'medium'),
                    'yaml_content': data.get('yaml_content', ''),
                    'tags': data.get('tags', ''),
                    'remediation_template': data.get('remediation_template', ''),
                    'compliance_frameworks': data.get('compliance_frameworks', ''),
                    'enabled': data.get('enabled', True)
                }
            
            if not rule_dict.get('yaml_content'):
                return JsonResponse({'error': 'YAML content is required to test the rule'}, status=400)
            
            try:
                # Parse config (basic - just use original text for pattern rules)
                parsed_config = {'original': config_content}
                # Execute rule
                findings = execute_rules([rule_dict], parsed_config)
                return JsonResponse({
                    'rule': rule_dict,
                    'findings': findings,
                    'finding_count': len(findings),
                    'config_preview': config_content[:500] + ('...' if len(config_content) > 500 else '')
                }, status=200)
            except Exception as e:
                import traceback
                traceback.print_exc()
                return JsonResponse({'error': f'Rule execution failed: {str(e)}'}, status=500)
        
        elif action == 'bulk_update':
            rule_ids = data.get('rule_ids', [])
            updates = data.get('updates', {})
            
            if not rule_ids:
                return JsonResponse({'error': 'rule_ids required'}, status=400)
            
            updated_count = 0
            for rule_id in rule_ids:
                try:
                    rule = Rule.objects.get(id=rule_id)
                    for key, value in updates.items():
                        setattr(rule, key, value)
                    rule.save()
                    updated_count += 1
                except Rule.DoesNotExist:
                    continue
            
            return JsonResponse({'status': 'updated', 'count': updated_count}, status=200)
        
        return JsonResponse({'error': 'Invalid request'}, status=400)


@csrf_exempt
@require_http_methods(["GET"])
@require_org_viewer  # Org viewer can access reports
def reports_api(request):
    """Handle report API requests"""
    # Check if this is a comparison request
    if request.GET.get('compare') == 'true':
        audit_id1 = request.GET.get('audit_id1')
        audit_id2 = request.GET.get('audit_id2')
        if audit_id1 and audit_id2:
            # Filter by organization
            if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                return JsonResponse({'error': 'Super Admin cannot access individual audits'}, status=403)
            
            if hasattr(request, 'organization') and request.organization:
                try:
                    audit1 = Audit.objects.get(id=int(audit_id1), organization=request.organization)
                    audit2 = Audit.objects.get(id=int(audit_id2), organization=request.organization)
                    comparison = generate_comparison_report(int(audit_id1), int(audit_id2))
                    return JsonResponse(comparison, status=200)
                except Audit.DoesNotExist:
                    return JsonResponse({'error': 'One or both audits not found'}, status=404)
            else:
                return JsonResponse({'error': 'No organization found'}, status=403)
        return JsonResponse({'error': 'Both audit_id1 and audit_id2 required for comparison'}, status=400)
    
    # Get audit_id from query params, or use current audit
    audit_id_param = request.GET.get('audit_id')
    
    if audit_id_param:
        try:
            # Filter by organization (unless super admin)
            if hasattr(request, 'user_role') and request.user_role == 'super_admin':
                return JsonResponse({'error': 'Super Admin cannot access individual audits'}, status=403)
            
            if hasattr(request, 'organization') and request.organization:
                audit = Audit.objects.get(id=int(audit_id_param), organization=request.organization)
            else:
                return JsonResponse({'error': 'No organization found'}, status=403)
        except (Audit.DoesNotExist, ValueError):
            return JsonResponse({'error': 'No audit found'}, status=404)
    else:
        # Get most recent audit for organization
        if hasattr(request, 'user_role') and request.user_role == 'super_admin':
            audit = None  # Super Admin cannot access individual audits
        else:
            if hasattr(request, 'organization') and request.organization:
                audit = Audit.objects.filter(organization=request.organization).first()
            else:
                audit = None
    
    if not audit:
        return JsonResponse({'error': 'No audit found'}, status=404)
    
    # Check if requesting available frameworks
    if request.GET.get('frameworks') == 'list':
        frameworks = set()
        # Filter rules by organization
        if hasattr(request, 'user_role') and request.user_role == 'super_admin':
            rules = Rule.objects.filter(enabled=True, organization__isnull=True)
        else:
            if hasattr(request, 'organization') and request.organization:
                rules = Rule.objects.filter(enabled=True, organization=request.organization)
            else:
                rules = Rule.objects.none()
        for rule in rules:
            frameworks_list = rule.get_frameworks_list()
            frameworks.update(frameworks_list)
        return JsonResponse({'frameworks': sorted(list(frameworks))}, status=200)
    
    # Extract filter parameters
    severity_filter = request.GET.get('severity')
    category_filter = request.GET.get('category')
    rule_type_filter = request.GET.get('rule_type')
    rule_id_filter = request.GET.get('rule_id')
    framework_filter = request.GET.get('framework')
    sort_by = request.GET.get('sort_by', 'severity')
    sort_order = request.GET.get('sort_order', 'desc')
    group_by = request.GET.get('group_by')
    format_type = request.GET.get('format', 'html')
    include_statistics = request.GET.get('include_statistics', 'false') == 'true'
    include_compliance = request.GET.get('include_compliance', 'false') == 'true'
    
    # Enhanced export options
    sections_param = request.GET.get('sections')
    sections = sections_param.split(',') if sections_param else ['statistics', 'findings', 'compliance', 'charts']
    preset = request.GET.get('preset')
    filename = request.GET.get('filename')
    search_query = request.GET.get('search')
    rule_name_filter = request.GET.get('rule_name')
    config_path_filter = request.GET.get('config_path')
    tag_filter = request.GET.get('tag')
    
    # Get timezone and format preferences
    timezone_str = request.GET.get('timezone', 'UTC') or 'UTC'
    date_format_str = request.GET.get('date_format', 'YYYY-MM-DD HH:mm:ss') or 'YYYY-MM-DD HH:mm:ss'
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
        filename = f'audit_report_{audit.id}'
    
    # Handle different export formats
    if format_type == 'pdf':
        try:
            pdf_content = generate_pdf_report(audit.id, filters, sort_by, sort_order, group_by, sections, preset, timezone_str, date_format_py)
            if not pdf_content or len(pdf_content) == 0:
                return JsonResponse({'error': 'PDF generation failed: empty content'}, status=500)
            if not pdf_content.startswith(b'%PDF'):
                return JsonResponse({'error': 'PDF generation failed: invalid PDF format'}, status=500)
            response = HttpResponse(pdf_content, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="{filename}.pdf"'
            return response
        except Exception as e:
            import traceback
            traceback.print_exc()
            return JsonResponse({'error': f'PDF generation failed: {str(e)}'}, status=500)
    
    elif format_type == 'csv':
        csv_content = generate_csv_report(audit.id, filters, sort_by, sort_order, sections, timezone_str, date_format_py)
        response = HttpResponse(csv_content, content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}.csv"'
        return response
    
    elif format_type == 'html_standalone':
        html_content = generate_html_standalone_report(audit.id, filters, sort_by, sort_order, group_by, sections, timezone_str, date_format_py)
        response = HttpResponse(html_content, content_type='text/html')
        response['Content-Disposition'] = f'attachment; filename="{filename}.html"'
        return response
    
    elif format_type == 'json':
        findings = get_filtered_findings(audit.id, filters, sort_by, sort_order, group_by)
        audit_dict = model_to_dict(audit)
        result = {
            'audit': audit_dict,
            'findings': findings,
            'metadata': {
                'generated_at': format_datetime_now(timezone_str, date_format_py),
                'generated_at_iso': format_datetime_now('UTC', '%Y-%m-%dT%H:%M:%S'),
                'filters_applied': filters,
                'total_findings': len(findings)
            }
        }
        if include_statistics:
            result['statistics'] = generate_statistics(audit.id)
        if include_compliance:
            if framework_filter:
                result['compliance'] = calculate_compliance_score(audit.id, framework_filter)
            else:
                result['compliance'] = calculate_compliance_score(audit.id)
        return JsonResponse(result, status=200)
    
    else:  # HTML format (default)
        findings = get_filtered_findings(audit.id, filters, sort_by, sort_order, group_by)
        audit_dict = model_to_dict(audit)
        audit_dict['findings'] = findings
        
        if include_statistics or 'statistics' in sections:
            audit_dict['statistics'] = generate_statistics(audit.id)
        if include_compliance or 'compliance' in sections:
            if framework_filter:
                audit_dict['compliance'] = calculate_compliance_score(audit.id, framework_filter)
            else:
                # Get all frameworks
                frameworks = set()
                rules = Rule.objects.filter(enabled=True)
                for rule in rules:
                    frameworks_list = rule.get_frameworks_list()
                    frameworks.update(frameworks_list)
                
                compliance_scores = {}
                for framework in frameworks:
                    compliance_scores[framework] = calculate_compliance_score(audit.id, framework)
                audit_dict['compliance'] = compliance_scores
                audit_dict['compliance_general'] = calculate_compliance_score(audit.id)
        
        audit_dict['available_sections'] = sections
        audit_dict['export_options'] = {
            'preset': preset,
            'filename': filename,
            'sections': sections
        }
        
        return JsonResponse(audit_dict, status=200)


@csrf_exempt
@require_http_methods(["POST"])
def upload_api(request):
    """Handle file upload requests"""
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = ['.txt', '.cfg', '.conf']
    
    uploaded_files = []
    
    for file_key, uploaded_file in request.FILES.items():
        filename = uploaded_file.name
        
        # Validate file extension
        file_ext = Path(filename).suffix.lower()
        if file_ext not in ALLOWED_EXTENSIONS:
            uploaded_files.append({
                'status': 'error',
                'filename': filename,
                'error': f'Invalid file extension. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'
            })
            continue
        
        # Validate file size
        if uploaded_file.size > MAX_FILE_SIZE:
            uploaded_files.append({
                'status': 'error',
                'filename': filename,
                'error': f'File exceeds maximum size of {MAX_FILE_SIZE / (1024*1024):.0f}MB'
            })
            continue
        
        # Read file content once
        uploaded_file.seek(0)  # Reset file pointer
        try:
            file_bytes = uploaded_file.read()
            config_content = file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            uploaded_file.seek(0)
            file_bytes = uploaded_file.read()
            config_content = file_bytes.decode('utf-8', errors='ignore')
        
        # Validate file is not empty
        if not config_content.strip():
            uploaded_files.append({
                'status': 'error',
                'filename': filename,
                'error': 'File is empty'
            })
            continue
        
        # Save file to media directory (use the bytes we already read)
        file_path = default_storage.save(f'uploads/{filename}', ContentFile(file_bytes))
        
        # Extract device metadata
        metadata = extract_metadata(config_content)
        
        # Detect device family from parser
        device_family = None
        try:
            from parsers.factory import create_parser
            parser = create_parser(config_text=config_content)
            if parser:
                vendor_name = parser.__class__.__name__.lower().replace('parser', '')
                device_family = vendor_name.capitalize()
        except:
            pass
        
        uploaded_files.append({
            'status': 'uploaded',
            'filename': filename,
            'path': file_path,
            'content': config_content,
            'device_family': device_family,
            'device_metadata': metadata
        })
    
    # Check if any files were successfully uploaded
    successful_files = [f for f in uploaded_files if f.get('status') == 'uploaded']
    error_files = [f for f in uploaded_files if f.get('status') == 'error']
    
    # Return single file or batch
    if len(uploaded_files) == 1:
        file_result = uploaded_files[0]
        if file_result.get('status') == 'error':
            return JsonResponse({
                'error': file_result.get('error', 'Upload failed'),
                'filename': file_result.get('filename')
            }, status=400)
        return JsonResponse(file_result, status=200)
    else:
        if not successful_files:
            return JsonResponse({
                'error': 'All files failed to upload',
                'files': uploaded_files
            }, status=400)
        return JsonResponse({
            'status': 'uploaded',
            'files': uploaded_files,
            'count': len(successful_files),
            'success_count': len(successful_files),
            'error_count': len(error_files),
            'errors': error_files
        }, status=200)


@require_http_methods(["GET"])
@require_authenticated
def stats_api(request):
    """Handle statistics API requests"""
    try:
        # Get timezone and format preferences
        timezone_str = request.GET.get('timezone', 'UTC') or 'UTC'
        date_format_str = request.GET.get('date_format', 'YYYY-MM-DD HH:mm:ss') or 'YYYY-MM-DD HH:mm:ss'
        date_format_py = parse_datetime_format(date_format_str)
        
        # Filter by organization (unless super admin - aggregated stats only)
        if hasattr(request, 'user_role') and request.user_role == 'super_admin':
            # Super Admin: Aggregated stats only (counts, not individual data)
            all_audits = Audit.objects.all()  # For counting only
            total_audits = all_audits.count()
            total_findings = Finding.objects.count()
            active_rules_count = Rule.objects.filter(enabled=True).count()
            completed_audits = all_audits.filter(status=Audit.STATUS_COMPLETED)
        else:
            # Regular users: Filter by organization
            if hasattr(request, 'organization') and request.organization:
                all_audits = Audit.objects.filter(organization=request.organization)
                total_audits = all_audits.count()
                # Count findings for organization's audits only
                total_findings = Finding.objects.filter(audit__organization=request.organization).count()
                # Count organization's rules only
                active_rules_count = Rule.objects.filter(enabled=True, organization=request.organization).count()
                completed_audits = all_audits.filter(status=Audit.STATUS_COMPLETED)
            else:
                return JsonResponse({'error': 'No organization found'}, status=403)
        
        # Calculate compliance for completed audits
        compliance_scores = []
        
        for audit in completed_audits:
            try:
                compliance = calculate_compliance_score(audit.id)
                if compliance and compliance.get('score') is not None:
                    compliance_scores.append(compliance['score'])
            except Exception as e:
                print(f"Error calculating compliance for audit {audit.id}: {e}")
        
        # Calculate average compliance score
        average_compliance = 0.0
        if compliance_scores:
            average_compliance = sum(compliance_scores) / len(compliance_scores)
        
        # active_rules_count already set above based on user role
        
        # Get database size
        db_size_bytes = 0
        db_size_formatted = '0 B'
        try:
            db_path = settings.DATABASES['default']['NAME']
            if os.path.exists(db_path):
                db_size_bytes = os.path.getsize(db_path)
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
            traceback.print_exc()
            db_size_formatted = f'Error: {str(e)}'
        
        # Get recent audits (last 10) - filter by organization
        recent_audits = []
        if hasattr(request, 'user_role') and request.user_role == 'super_admin':
            # Super Admin: No individual audits
            recent_audits_query = []
        else:
            if hasattr(request, 'organization') and request.organization:
                recent_audits_query = Audit.objects.filter(organization=request.organization).order_by('-created_at')[:10]
            else:
                recent_audits_query = []
        
        for audit in recent_audits_query:
            try:
                findings_count = Finding.objects.filter(audit=audit).count()
                created_at_iso = audit.created_at.isoformat() if audit.created_at else None
                created_at_formatted = format_datetime_from_iso(created_at_iso, timezone_str, date_format_py) if created_at_iso else None
                recent_audits.append({
                    'id': audit.id,
                    'config_file': audit.config_file or 'Unknown',
                    'status': audit.status,
                    'created_at': created_at_iso,
                    'created_at_formatted': created_at_formatted,
                    'finding_count': findings_count,
                    'device_identifier': audit.device_identifier,
                    'device_hostname': audit.device_hostname,
                    'device_family': audit.device_family
                })
            except Exception as e:
                print(f"Error processing recent audit {audit.id}: {e}")
                created_at_iso = audit.created_at.isoformat() if audit.created_at else None
                created_at_formatted = format_datetime_from_iso(created_at_iso, timezone_str, date_format_py) if created_at_iso else None
                recent_audits.append({
                    'id': audit.id,
                    'config_file': audit.config_file or 'Unknown',
                    'status': audit.status,
                    'created_at': created_at_iso,
                    'created_at_formatted': created_at_formatted,
                    'finding_count': 0,
                    'device_identifier': audit.device_identifier,
                    'device_hostname': audit.device_hostname,
                    'device_family': audit.device_family
                })
        
        return JsonResponse({
            'total_audits': total_audits,
            'total_findings': total_findings,
            'average_compliance': round(average_compliance, 2),
            'active_rules': active_rules_count,
            'recent_audits': recent_audits,
            'database_size': db_size_formatted,
            'database_size_bytes': db_size_bytes
        }, status=200)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': f'Failed to calculate statistics: {str(e)}'}, status=500)


@require_http_methods(["GET"])
@require_authenticated
def assets_api(request, device_identifier=None):
    """Handle assets API requests"""
    # Get timezone and format preferences
    timezone_str = request.GET.get('timezone', 'UTC') or 'UTC'
    date_format_str = request.GET.get('date_format', 'YYYY-MM-DD HH:mm:ss') or 'YYYY-MM-DD HH:mm:ss'
    date_format_py = parse_datetime_format(date_format_str)
    
    # Filter by organization (unless super admin)
    if hasattr(request, 'user_role') and request.user_role == 'super_admin':
        return JsonResponse({'error': 'Super Admin cannot access individual assets'}, status=403)
    
    if not hasattr(request, 'organization') or not request.organization:
        return JsonResponse({'error': 'No organization found'}, status=403)
    
    # Check if requesting specific device
    if device_identifier:
        # Check if requesting latest audit
        if 'latest' in request.path:
            try:
                latest_audit = Audit.objects.filter(
                    device_identifier=device_identifier,
                    organization=request.organization
                ).order_by('-created_at').first()
                if latest_audit:
                    findings_count = Finding.objects.filter(audit=latest_audit).count()
                    audit_dict = model_to_dict(latest_audit)
                    audit_dict['findings'] = []
                    audit_dict['finding_count'] = findings_count
                    return JsonResponse(audit_dict, status=200)
                return JsonResponse({'error': 'Device not found'}, status=404)
            except Exception as e:
                return JsonResponse({'error': str(e)}, status=500)
        
        # Get all audits for device - filter by organization
        audits = Audit.objects.filter(
            device_identifier=device_identifier,
            organization=request.organization
        ).order_by('-created_at')
        audits_list = []
        for audit in audits:
            audit_dict = model_to_dict(audit)
            findings_count = Finding.objects.filter(audit=audit).count()
            audit_dict['finding_count'] = findings_count
            # Format dates
            if audit_dict.get('created_at'):
                audit_dict['created_at_formatted'] = format_datetime_from_iso(
                    audit_dict['created_at'], timezone_str, date_format_py
                )
            if audit_dict.get('completed_at'):
                audit_dict['completed_at_formatted'] = format_datetime_from_iso(
                    audit_dict['completed_at'], timezone_str, date_format_py
                )
            audits_list.append(audit_dict)
        return JsonResponse({'device_identifier': device_identifier, 'audits': audits_list}, status=200)
    
    # Get list of all assets
    search_query = request.GET.get('search', '').strip()
    date_range = request.GET.get('date_range', '').strip()
    
    from django.db.models import Q
    from datetime import datetime, timedelta
    
    # Get all unique device identifiers with search filter - filter by organization
    if search_query:
        # Search across multiple fields - filter by organization
        audits_query = Audit.objects.filter(
            organization=request.organization
        ).filter(
            Q(device_identifier__icontains=search_query) |
            Q(device_hostname__icontains=search_query) |
            Q(device_model__icontains=search_query) |
            Q(device_make__icontains=search_query) |
            Q(device_type__icontains=search_query)
        )
        device_identifiers = audits_query.values_list('device_identifier', flat=True).distinct().exclude(device_identifier__isnull=True)
    else:
        device_identifiers = Audit.objects.filter(
            organization=request.organization
        ).values_list('device_identifier', flat=True).distinct().exclude(device_identifier__isnull=True)
    
    # Convert to list and ensure uniqueness (in case of any edge cases)
    device_identifiers = list(set(device_identifiers))
    
    # Build asset list with metadata - use a dict to ensure no duplicates
    assets_dict = {}
    for device_id in device_identifiers:
        # Get all audits for this device
        audits = Audit.objects.filter(
            device_identifier=device_id,
            organization=request.organization
        ).order_by('-created_at')
        if not audits.exists():
            continue
        
        # Get latest audit
        latest_audit = audits.first()
        
        # Apply date range filter
        if date_range == 'never':
            # Skip assets that have been audited
            continue
        elif date_range and date_range.isdigit():
            days = int(date_range)
            cutoff_date = datetime.now() - timedelta(days=days)
            if not latest_audit.created_at or latest_audit.created_at < cutoff_date:
                continue
        
        # Get finding count for latest audit
        findings_count = Finding.objects.filter(audit=latest_audit).count()
        
        # Calculate total audit count
        total_audits = audits.count()
        
        last_audit_date_iso = latest_audit.created_at.isoformat() if latest_audit.created_at else None
        last_audit_date_formatted = format_datetime_from_iso(last_audit_date_iso, timezone_str, date_format_py) if last_audit_date_iso else None
        
        # Use device_identifier as key to ensure uniqueness
        assets_dict[device_id] = {
            'device_identifier': device_id,
            'last_audit_date': last_audit_date_iso,
            'last_audit_date_formatted': last_audit_date_formatted,
            'total_audits': total_audits,
            'latest_audit_status': latest_audit.status,
            'latest_findings_count': findings_count,
            'latest_audit_id': latest_audit.id,
            'device_hostname': latest_audit.device_hostname,
            'device_model': latest_audit.device_model,
            'device_firmware': latest_audit.device_firmware,
            'device_location': latest_audit.device_location,
            'device_make': latest_audit.device_make,
            'device_type': latest_audit.device_type
        }
    
    # Convert dict to list and sort by last audit date (most recent first)
    assets = list(assets_dict.values())
    assets.sort(key=lambda x: x['last_audit_date'] or '', reverse=True)
    
    return JsonResponse({'assets': assets, 'count': len(assets)}, status=200)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def settings_api(request):
    """Handle settings API requests"""
    path = request.path.rstrip('/')
    
    if path.endswith('/backup'):
        return handle_backup_request(request)
    elif path.endswith('/optimize'):
        return handle_optimize_request(request)
    else:
        return JsonResponse({'error': 'Not found'}, status=404)


def handle_backup_request(request):
    """Handle database backup request"""
    try:
        db_path = settings.DATABASES['default']['NAME']
        if not os.path.exists(db_path):
            return JsonResponse({'error': 'Database file not found'}, status=404)
        
        # Read database file
        with open(db_path, 'rb') as f:
            db_content = f.read()
        
        # Generate filename with timestamp
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'ncrt_backup_{timestamp}.db'
        
        # Send file response
        response = HttpResponse(db_content, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Cache-Control'] = 'no-cache'
        return response
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': f'Failed to create backup: {str(e)}'}, status=500)


def handle_optimize_request(request):
    """Handle database optimization request"""
    try:
        with connection.cursor() as cursor:
            cursor.execute("VACUUM;")
        return JsonResponse({'status': 'optimized'}, status=200)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Super Admin Views
@require_super_admin
def super_admin_dashboard(request):
    """Super Admin dashboard - aggregated statistics only"""
    # Get aggregated stats (no individual org data)
    total_orgs = Organization.objects.count()
    total_users = UserProfile.objects.exclude(role=UserProfile.ROLE_SUPER_ADMIN).count()
    total_audits = Audit.objects.count()  # Total count only
    total_findings = Finding.objects.count()  # Total count only
    active_rules = Rule.objects.filter(enabled=True, organization__isnull=True).count()  # Platform rules only
    
    return render(request, 'super_admin/dashboard.html', {
        'total_orgs': total_orgs,
        'total_users': total_users,
        'total_audits': total_audits,
        'total_findings': total_findings,
        'active_rules': active_rules,
    })


@require_super_admin
def super_admin_organizations(request):
    """List all organizations"""
    organizations = Organization.objects.all().order_by('name')
    orgs_list = []
    for org in organizations:
        orgs_list.append({
            'id': org.id,
            'name': org.name,
            'domain': org.domain,
            'poc_email': org.poc_email,
            'status': org.status,
            'user_count': org.get_user_count(),
            'audit_count': org.get_audit_count(),
            'created_at': org.created_at,
        })
    return render(request, 'super_admin/organizations.html', {'organizations': orgs_list})


@require_super_admin
@csrf_exempt
@require_http_methods(["GET", "POST"])
def super_admin_organization_api(request, org_id=None):
    """Super Admin organization API"""
    if request.method == 'GET':
        if org_id:
            try:
                org = Organization.objects.get(id=org_id)
                return JsonResponse({
                    'id': org.id,
                    'name': org.name,
                    'domain': org.domain,
                    'poc_email': org.poc_email,
                    'status': org.status,
                    'user_count': org.get_user_count(),
                    'audit_count': org.get_audit_count(),
                }, status=200)
            except Organization.DoesNotExist:
                return JsonResponse({'error': 'Organization not found'}, status=404)
        else:
            orgs = Organization.objects.all().order_by('name')
            orgs_list = []
            for org in orgs:
                orgs_list.append({
                    'id': org.id,
                    'name': org.name,
                    'domain': org.domain,
                    'poc_email': org.poc_email,
                    'status': org.status,
                    'user_count': org.get_user_count(),
                    'audit_count': org.get_audit_count(),
                })
            return JsonResponse({'organizations': orgs_list}, status=200)
    
    elif request.method == 'POST':
        try:
            data = json.loads(request.body)
            action = data.get('action')
            
            if action == 'create':
                name = data.get('name', '').strip()
                domain = data.get('domain', '').strip() or None
                poc_email = data.get('poc_email', '').strip()
                status = data.get('status', Organization.STATUS_ACTIVE)
                
                if not name or not poc_email:
                    return JsonResponse({'error': 'Name and POC email are required'}, status=400)
                
                org = Organization.objects.create(
                    name=name,
                    domain=domain,
                    poc_email=poc_email,
                    status=status
                )
                
                # Log creation
                ip_address = get_client_ip(request)
                log_audit_action(request.user, 'create', 'organization', org.id, 
                               f'Created organization: {name}', ip_address, None)
                
                return JsonResponse({'id': org.id, 'status': 'created'}, status=201)
            
            elif action == 'update':
                if not org_id:
                    return JsonResponse({'error': 'Organization ID required'}, status=400)
                
                try:
                    org = Organization.objects.get(id=org_id)
                    if 'name' in data:
                        org.name = data['name'].strip()
                    if 'domain' in data:
                        org.domain = data['domain'].strip() or None
                    if 'poc_email' in data:
                        org.poc_email = data['poc_email'].strip()
                    if 'status' in data:
                        org.status = data['status']
                    org.save()
                    
                    # Log update
                    ip_address = get_client_ip(request)
                    log_audit_action(request.user, 'update', 'organization', org.id, 
                                   f'Updated organization: {org.name}', ip_address, None)
                    
                    return JsonResponse({'status': 'updated'}, status=200)
                except Organization.DoesNotExist:
                    return JsonResponse({'error': 'Organization not found'}, status=404)
            
            elif action == 'delete':
                if not org_id:
                    return JsonResponse({'error': 'Organization ID required'}, status=400)
                
                try:
                    org = Organization.objects.get(id=org_id)
                    org_name = org.name
                    org_id_val = org.id
                    org.delete()
                    
                    # Log deletion
                    ip_address = get_client_ip(request)
                    log_audit_action(request.user, 'delete', 'organization', org_id_val, 
                                   f'Deleted organization: {org_name}', ip_address, None)
                    
                    return JsonResponse({'status': 'deleted'}, status=200)
                except Organization.DoesNotExist:
                    return JsonResponse({'error': 'Organization not found'}, status=404)
            
            return JsonResponse({'error': 'Invalid action'}, status=400)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)


# Organization Admin Views
@require_org_admin
def org_admin_users(request):
    """Organization Admin - User management page"""
    if not hasattr(request, 'organization') or not request.organization:
        return HttpResponse('No organization found', status=403)
    
    users = UserProfile.objects.filter(organization=request.organization).select_related('user')
    users_list = []
    for profile in users:
        users_list.append({
            'id': profile.user.id,
            'username': profile.user.username,
            'email': profile.user.email,
            'role': profile.role,
            'role_display': profile.get_role_display(),
            'created_at': profile.created_at,
        })
    
    return render(request, 'org_admin/users.html', {'users': users_list})


@require_org_admin
@csrf_exempt
@require_http_methods(["POST"])
def org_admin_invite_user(request):
    """Organization Admin - Send user invitation"""
    if not hasattr(request, 'organization') or not request.organization:
        return JsonResponse({'error': 'No organization found'}, status=403)
    
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip().lower()
        role = data.get('role', UserProfile.ROLE_ORG_USER)
        
        if not email:
            return JsonResponse({'error': 'Email is required'}, status=400)
        
        # Check if user already exists
        from django.contrib.auth.models import User
        if User.objects.filter(email=email).exists():
            return JsonResponse({'error': 'User with this email already exists'}, status=400)
        
        # Check if invitation already exists and not expired
        existing_invitation = UserInvitation.objects.filter(
            email=email,
            organization=request.organization,
            accepted_at__isnull=True
        ).first()
        
        if existing_invitation and not existing_invitation.is_expired():
            return JsonResponse({'error': 'Invitation already sent and not expired'}, status=400)
        
        # Create invitation
        invitation = UserInvitation.objects.create(
            email=email,
            organization=request.organization,
            role=role,
            invited_by=request.user,
            expires_at=timezone.now() + timedelta(days=7)  # 7 days expiry
        )
        
        # Log invitation
        ip_address = get_client_ip(request)
        log_audit_action(request.user, 'invite', 'user', None, 
                       f'Invited user {email} to {request.organization.name}', 
                       ip_address, request.organization)
        
        # TODO: Send email with invitation link
        # For now, return the invitation token
        invite_url = request.build_absolute_uri(f'/register/?token={invitation.token}')
        
        return JsonResponse({
            'status': 'invited',
            'invitation_id': invitation.id,
            'invite_url': invite_url,
            'message': f'Invitation sent to {email}. Share this link: {invite_url}'
        }, status=201)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    """Handle database optimization request (VACUUM)"""
    try:
        with connection.cursor() as cursor:
            cursor.execute('VACUUM')
        return JsonResponse({'message': 'Database optimized successfully'}, status=200)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JsonResponse({'error': f'Failed to optimize database: {str(e)}'}, status=500)

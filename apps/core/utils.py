"""
Utility functions for multi-tenancy
"""
import logging
from .models import AuditLog

logger = logging.getLogger(__name__)


def log_audit_action(user, action_type, resource_type, resource_id=None, description="", ip_address=None, organization=None):
    """Log an audit action"""
    try:
        # Get organization from user profile if not provided
        if organization is None and user.is_authenticated:
            try:
                profile = user.userprofile
                if not profile.is_super_admin():
                    organization = profile.organization
            except AttributeError:
                pass
        
        AuditLog.objects.create(
            user=user if user.is_authenticated else None,
            organization=organization,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            ip_address=ip_address
        )
        
        # Log to Django logger for visibility
        username = user.username if user.is_authenticated else 'Anonymous'
        org_name = organization.name if organization else 'N/A'
        logger.info(f"{action_type.upper()}: {description} | User: {username} | Org: {org_name} | IP: {ip_address}")
    except Exception as e:
        logger.error(f"Failed to log audit action: {action_type} - {description} | Error: {str(e)}")


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

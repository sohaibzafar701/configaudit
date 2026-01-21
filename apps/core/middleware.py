"""
Organization filtering middleware for multi-tenancy
"""
from django.utils.deprecation import MiddlewareMixin
from django.shortcuts import redirect
from django.urls import reverse


class OrganizationMiddleware(MiddlewareMixin):
    """Middleware to set organization context for all requests"""
    
    def process_request(self, request):
        """Set organization on request object"""
        if request.user.is_authenticated:
            try:
                profile = request.user.userprofile
                # Super Admin has no organization
                if profile.is_super_admin():
                    request.organization = None
                    request.user_role = 'super_admin'
                else:
                    request.organization = profile.organization
                    request.user_role = profile.role
            except AttributeError:
                # User has no profile - check if Django superuser
                if request.user.is_superuser:
                    # Django superuser without profile - treat as super_admin
                    request.organization = None
                    request.user_role = 'super_admin'
                else:
                    # Regular user without profile - no organization
                    request.organization = None
                    request.user_role = None
        else:
            request.organization = None
            request.user_role = None
        
        return None

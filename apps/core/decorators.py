"""
Permission decorators for views
"""
from functools import wraps
from django.http import JsonResponse, HttpResponseForbidden
from django.shortcuts import redirect


def require_super_admin(view_func):
    """Decorator to require super admin role"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            profile = request.user.userprofile
            if not profile.is_super_admin():
                return HttpResponseForbidden("Super Admin access required")
        except AttributeError:
            return HttpResponseForbidden("User profile not found")
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def require_org_admin(view_func):
    """Decorator to require org admin or super admin role"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            profile = request.user.userprofile
            if not (profile.is_super_admin() or profile.is_org_admin()):
                return HttpResponseForbidden("Organization Admin access required")
        except AttributeError:
            return HttpResponseForbidden("User profile not found")
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def require_org_user(view_func):
    """Decorator to require org user or above (not viewer)"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        try:
            profile = request.user.userprofile
            if profile.is_org_viewer():
                return HttpResponseForbidden("Read-only access. Editing not allowed.")
            if not profile.can_edit():
                return HttpResponseForbidden("Insufficient permissions")
        except AttributeError:
            return HttpResponseForbidden("User profile not found")
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def require_org_viewer(view_func):
    """Decorator to require any authenticated user (including viewer)"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login')
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def require_authenticated(view_func):
    """Decorator to require authentication"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            # For API requests, return JSON error instead of redirect
            if request.path.startswith('/api/'):
                return JsonResponse({'error': 'Authentication required'}, status=401)
            return redirect('login')
        
        # Redirect org_viewer to reports page if they try to access other pages
        try:
            profile = request.user.userprofile
            if profile.is_org_viewer():
                # Allow access to reports pages and related API endpoints
                allowed_paths = ['/report/', '/report-detail/', '/api/reports', '/api/audits']
                if not any(request.path.startswith(path) for path in allowed_paths):
                    # For API requests, return JSON error instead of redirect
                    if request.path.startswith('/api/'):
                        return JsonResponse({'error': 'Access denied. Organization viewers can only access reports.'}, status=403)
                    # Redirect to reports page for page requests
                    return redirect('report_page')
        except AttributeError:
            pass  # No profile, continue normally
        
        return view_func(request, *args, **kwargs)
    return _wrapped_view

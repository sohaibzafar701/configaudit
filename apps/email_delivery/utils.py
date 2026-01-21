"""
Utility functions for sending specific email types.
"""
import logging

from django.core.mail import EmailMultiAlternatives
from django.conf import settings

from .services.template_service import TemplateService

logger = logging.getLogger(__name__)


def send_invitation_email(invitation, request):
    """
    Send user invitation email.
    
    Args:
        invitation: UserInvitation model instance
        request: HttpRequest object for building absolute URLs
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Build invitation URL
        invite_url = request.build_absolute_uri(f'/register/?token={invitation.token}')
        
        # Prepare template context
        context = {
            'invitation': invitation,
            'invite_url': invite_url,
            'organization': invitation.organization,
            'expires_at': invitation.expires_at,
            'invited_by': invitation.invited_by,
        }
        
        # Render email templates
        template_service = TemplateService()
        html_content, text_content = template_service.render_email_template(
            'invitation_email',
            context,
            request
        )
        
        # Get sender email from settings
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@pdsconfigaudit.com')
        
        # Create email message
        subject = f'Invitation to join {invitation.organization.name}'
        
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=[invitation.email]
        )
        email.attach_alternative(html_content, 'text/html')
        
        # Send email
        email.send()
        
        logger.info(f"Invitation email sent to {invitation.email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending invitation email to {invitation.email}: {str(e)}")
        return False


def send_organization_created_email(organization, request):
    """
    Send email notification when a new organization is created.
    
    Args:
        organization: Organization model instance
        request: HttpRequest object for building absolute URLs
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Generate signed signup token
        from django.core.signing import Signer
        signer = Signer()
        token_data = f"{organization.id}|{organization.poc_email}"
        signed_token = signer.sign(token_data)
        
        # Build signup URL
        signup_url = request.build_absolute_uri(f'/poc-signup/?token={signed_token}')
        
        # Prepare template context
        context = {
            'organization': organization,
            'created_at': organization.created_at,
            'signup_url': signup_url,
            'poc_email': organization.poc_email,
        }
        
        # Render email templates
        template_service = TemplateService()
        html_content, text_content = template_service.render_email_template(
            'organization_created',
            context,
            request
        )
        
        # Get sender email from settings
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@pdsconfigaudit.com')
        
        # Create email message
        subject = f'Welcome to ConfigAudit - Organization Created: {organization.name}'
        
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=[organization.poc_email]
        )
        email.attach_alternative(html_content, 'text/html')
        
        # Send email
        email.send()
        
        logger.info(f"Organization creation email sent to {organization.poc_email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending organization creation email to {organization.poc_email}: {str(e)}")
        return False


def send_password_reset_email(user, request):
    """
    Send password reset email.
    
    Args:
        user: User model instance
        request: HttpRequest object for building absolute URLs
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        from apps.core.models import PasswordResetToken
        from django.utils import timezone
        from datetime import timedelta
        
        # Create or get existing valid token
        # Invalidate any existing unused tokens for this user
        PasswordResetToken.objects.filter(user=user, used_at__isnull=True).update(used_at=timezone.now())
        
        # Create new reset token
        reset_token = PasswordResetToken.objects.create(
            user=user,
            expires_at=timezone.now() + timedelta(hours=1)
        )
        
        # Build reset URL
        reset_url = request.build_absolute_uri(f'/reset-password/?token={reset_token.token}')
        
        # Prepare template context
        context = {
            'user': user,
            'reset_url': reset_url,
            'expires_at': reset_token.expires_at,
        }
        
        # Render email templates
        template_service = TemplateService()
        html_content, text_content = template_service.render_email_template(
            'password_reset_email',
            context,
            request
        )
        
        # Get sender email from settings
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@pdsconfigaudit.com')
        
        # Create email message
        subject = 'Password Reset Request - NCRT'
        
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=[user.email]
        )
        email.attach_alternative(html_content, 'text/html')
        
        # Send email
        email.send()
        
        logger.info(f"Password reset email sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending password reset email to {user.email}: {str(e)}")
        return False


def send_2fa_code_email(user, code_instance, request):
    """
    Send 2FA code email.
    
    Args:
        user: User model instance
        code_instance: TwoFactorAuthCode model instance
        request: HttpRequest object for building absolute URLs
        
    Returns:
        True if email was sent successfully, False otherwise
    """
    try:
        # Prepare template context
        context = {
            'user': user,
            'code': code_instance.code,
            'created_at': code_instance.created_at,
            'expires_at': code_instance.expires_at,
        }
        
        # Render email templates
        template_service = TemplateService()
        html_content, text_content = template_service.render_email_template(
            '2fa_code_email',
            context,
            request
        )
        
        # Get sender email from settings
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@pdsconfigaudit.com')
        
        # Create email message
        subject = 'Two-Factor Authentication Code - NCRT'
        
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=from_email,
            to=[user.email]
        )
        email.attach_alternative(html_content, 'text/html')
        
        # Send email
        email.send()
        
        logger.info(f"2FA code email sent to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending 2FA code email to {user.email}: {str(e)}")
        return False

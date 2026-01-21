"""
Custom Django email backend for direct MX-to-MX delivery.
"""
import logging

from django.core.mail.backends.base import BaseEmailBackend
from django.core.mail import EmailMessage

from .services.email_service import EmailService

logger = logging.getLogger(__name__)


class MXDirectBackend(BaseEmailBackend):
    """
    Custom email backend that sends emails directly to recipient MX servers.
    Bypasses traditional SMTP relays.
    """
    
    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently, **kwargs)
        self.email_service = EmailService()
    
    def send_messages(self, email_messages):
        """
        Send one or more EmailMessage objects.
        
        Args:
            email_messages: List of EmailMessage objects
            
        Returns:
            Number of successfully sent messages
        """
        if not email_messages:
            return 0
        
        num_sent = 0
        for message in email_messages:
            try:
                if self.email_service.send_email_direct(message):
                    num_sent += 1
                elif not self.fail_silently:
                    logger.error(f"Failed to send email to {message.to}")
            except Exception as e:
                if not self.fail_silently:
                    logger.error(f"Error sending email: {str(e)}")
                else:
                    logger.warning(f"Error sending email (silent): {str(e)}")
        
        return num_sent

"""
Template Service for rendering email templates.
"""
import logging
from typing import Dict, Optional

from django.template.loader import render_to_string
from django.http import HttpRequest

logger = logging.getLogger(__name__)


class TemplateService:
    """
    Service for rendering email templates.
    """
    
    @staticmethod
    def render_email_template(
        template_name: str,
        context: Dict,
        request: Optional[HttpRequest] = None
    ) -> tuple[str, str]:
        """
        Render email template and return both HTML and text versions.
        
        Args:
            template_name: Base name of template (without extension)
            context: Template context dictionary
            request: Optional HttpRequest for context
            
        Returns:
            Tuple of (html_content, text_content)
        """
        try:
            # Render HTML version
            html_template = f'email_delivery/{template_name}.html'
            html_content = render_to_string(html_template, context, request=request)
            
            # Render text version
            text_template = f'email_delivery/{template_name}.txt'
            text_content = render_to_string(text_template, context, request=request)
            
            return html_content, text_content
            
        except Exception as e:
            logger.error(f"Error rendering email template {template_name}: {str(e)}")
            raise

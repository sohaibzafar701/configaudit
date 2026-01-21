"""
Email Service for composing and sending emails via direct MX-to-MX delivery.
"""
import logging
import smtplib
import uuid
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate, make_msgid
from typing import Optional

from django.conf import settings
from django.core.mail import EmailMessage

from .dns_service import DNSService

logger = logging.getLogger(__name__)


class EmailService:
    """
    Service for email composition and SMTP delivery.
    """
    
    def __init__(self):
        self.dns_service = DNSService()
        self.timeout = getattr(settings, 'EMAIL_MX_TIMEOUT', 30)
        self.max_retry_attempts = getattr(settings, 'EMAIL_MX_RETRY_ATTEMPTS', 3)
    
    def compose_mime_message(self, email_message: EmailMessage) -> MIMEMultipart:
        """
        Convert Django EmailMessage to MIME message.
        
        Args:
            email_message: Django EmailMessage object
            
        Returns:
            MIMEMultipart message ready for sending
        """
        # Create multipart message
        msg = MIMEMultipart('alternative')
        
        # Set headers
        msg['From'] = email_message.from_email
        msg['To'] = ', '.join(email_message.to)
        if email_message.cc:
            msg['Cc'] = ', '.join(email_message.cc)
        if email_message.bcc:
            msg['Bcc'] = ', '.join(email_message.bcc)
        msg['Subject'] = email_message.subject
        msg['Date'] = formatdate()
        msg['Message-ID'] = make_msgid()
        
        # Add Reply-To if specified
        if hasattr(email_message, 'reply_to') and email_message.reply_to:
            msg['Reply-To'] = ', '.join(email_message.reply_to)
        
        # Add text part
        if email_message.body:
            text_part = MIMEText(email_message.body, 'plain', 'utf-8')
            msg.attach(text_part)
        
        # Add HTML part if provided
        if hasattr(email_message, 'alternatives') and email_message.alternatives:
            for content, mimetype in email_message.alternatives:
                if mimetype == 'text/html':
                    html_part = MIMEText(content, 'html', 'utf-8')
                    msg.attach(html_part)
        
        # Add attachments
        if email_message.attachments:
            for attachment in email_message.attachments:
                if isinstance(attachment, tuple):
                    filename, content, mimetype = attachment
                    part = MIMEBase(*mimetype.split('/', 1))
                    part.set_payload(content)
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {filename}'
                    )
                    msg.attach(part)
        
        return msg
    
    def send_to_mx_server(
        self,
        mx_host: str,
        mx_priority: int,
        email_message: EmailMessage,
        mime_message: MIMEMultipart
    ) -> bool:
        """
        Send email to a specific MX server.
        
        Args:
            mx_host: MX server hostname
            mx_priority: MX server priority
            email_message: Django EmailMessage object
            mime_message: Composed MIME message
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Attempting to send email to MX server: {mx_host} (priority: {mx_priority})")
            
            # Connect to MX server
            smtp = smtplib.SMTP(mx_host, 25, timeout=self.timeout)
            
            try:
                # Send EHLO
                code, response = smtp.ehlo()
                logger.debug(f"EHLO response from {mx_host}: {code} {response}")
                
                # Send MAIL FROM
                code, response = smtp.mail(email_message.from_email)
                logger.debug(f"MAIL FROM response from {mx_host}: {code} {response}")
                if code != 250:
                    raise smtplib.SMTPException(f"MAIL FROM failed: {code} {response}")
                
                # Send RCPT TO for each recipient
                all_recipients = list(email_message.to)
                if email_message.cc:
                    all_recipients.extend(email_message.cc)
                if email_message.bcc:
                    all_recipients.extend(email_message.bcc)
                
                for recipient in all_recipients:
                    code, response = smtp.rcpt(recipient)
                    logger.debug(f"RCPT TO {recipient} response from {mx_host}: {code} {response}")
                    if code not in (250, 251):
                        raise smtplib.SMTPException(f"RCPT TO {recipient} failed: {code} {response}")
                
                # Send DATA
                code, response = smtp.data(mime_message.as_string())
                logger.debug(f"DATA response from {mx_host}: {code} {response}")
                if code != 250:
                    raise smtplib.SMTPException(f"DATA failed: {code} {response}")
                
                logger.info(f"Successfully sent email via MX server: {mx_host}")
                return True
                
            finally:
                try:
                    smtp.quit()
                except:
                    pass
                    
        except smtplib.SMTPException as e:
            logger.warning(f"SMTP error sending to {mx_host}: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending to {mx_host}: {str(e)}")
            return False
    
    def send_email_direct(self, email_message: EmailMessage) -> bool:
        """
        Send email directly to recipient MX servers.
        
        Args:
            email_message: Django EmailMessage object
            
        Returns:
            True if email was sent successfully, False otherwise
        """
        # Get all recipients
        all_recipients = list(email_message.to)
        if email_message.cc:
            all_recipients.extend(email_message.cc)
        if email_message.bcc:
            all_recipients.extend(email_message.bcc)
        
        if not all_recipients:
            logger.error("No recipients specified in email message")
            return False
        
        # Group recipients by domain
        domains = {}
        for recipient in all_recipients:
            try:
                domain = self.dns_service.extract_domain_from_email(recipient)
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append(recipient)
            except ValueError as e:
                logger.error(f"Invalid email address {recipient}: {str(e)}")
                return False
        
        # Compose MIME message once
        try:
            mime_message = self.compose_mime_message(email_message)
        except Exception as e:
            logger.error(f"Error composing email message: {str(e)}")
            return False
        
        # Send to each domain
        success = True
        for domain, recipients in domains.items():
            try:
                # Get MX records
                mx_records = self.dns_service.get_mx_records(domain)
                
                if not mx_records:
                    logger.error(f"No MX records found for domain: {domain}")
                    success = False
                    continue
                
                # Try each MX server in priority order
                sent = False
                attempts = 0
                for priority, mx_host in mx_records[:self.max_retry_attempts]:
                    attempts += 1
                    if self.send_to_mx_server(mx_host, priority, email_message, mime_message):
                        sent = True
                        break
                
                if not sent:
                    logger.error(f"Failed to send email to domain {domain} after {attempts} MX server attempts")
                    success = False
                else:
                    logger.info(f"Successfully sent email to domain {domain} via MX server")
                    
            except ValueError as e:
                logger.error(f"DNS error for domain {domain}: {str(e)}")
                success = False
            except Exception as e:
                logger.error(f"Unexpected error sending to domain {domain}: {str(e)}")
                success = False
        
        return success

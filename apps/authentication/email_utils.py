"""
SCRUM-117: Email utilities for password operations
Handles sending formatted password reset and change emails
"""
from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.template.loader import render_to_string
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger('django.security.auth')


def send_password_reset_email(user, reset_token_string):
    """
    Send password reset email with secure token.
    
    Args:
        user: User requesting password reset
        reset_token_string: The reset token to include in the link
    
    Security:
    - Token expires in 1 hour
    - Link points to frontend for security
    - Email contains security notice
    """
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={reset_token_string}"
    expiry_time = timezone.now() + timedelta(hours=1)
    
    subject = 'Password Reset Request - PSS System'
    
    # Create plain text version
    text_content = f"""
Hello {user.first_name or user.email},

You have requested to reset your password for the PSS System.

Password Reset Instructions:
1. Click the link below or copy it into your browser
2. Enter your new password
3. Click "Reset Password"

Reset Link:
{reset_url}

IMPORTANT SECURITY INFORMATION:
- This link will expire at {expiry_time.strftime('%Y-%m-%d %H:%M:%S')} (in 1 hour)
- This link can only be used once
- If you did not request this password reset, please ignore this email
- Your password will remain unchanged if you do not complete the reset

If the link doesn't work, copy and paste the following token into the password reset form:
{reset_token_string}

Need help?
If you're having trouble resetting your password, contact support at {settings.DEFAULT_FROM_EMAIL}

---
PSS Support Team
This is an automated message, please do not reply.
    """.strip()

    # Create HTML version
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
        .content {{ background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd; }}
        .button {{ display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
        .security-notice {{ background-color: #fff3cd; border: 1px solid #ffc107; color: #856404; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .footer {{ background-color: #f0f0f0; color: #666; font-size: 12px; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; }}
        .token-box {{ background-color: #f5f5f5; border: 1px solid #ddd; padding: 10px; word-break: break-all; font-family: monospace; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        
        <div class="content">
            <p>Hello {user.first_name or user.email},</p>
            
            <p>You have requested to reset your password for the <strong>PSS System</strong>.</p>
            
            <h3>Password Reset Instructions:</h3>
            <ol>
                <li>Click the button below to reset your password</li>
                <li>Enter your new password (minimum 8 characters)</li>
                <li>Click "Reset Password" to confirm</li>
            </ol>
            
            <center>
                <a href="{reset_url}" class="button">Reset Your Password</a>
            </center>
            
            <div class="security-notice">
                <strong>⚠️ Security Information:</strong>
                <ul style="margin: 10px 0;">
                    <li>This link expires: <strong>{expiry_time.strftime('%Y-%m-%d %H:%M:%S UTC')}</strong> (in 1 hour)</li>
                    <li>This link can only be used once</li>
                    <li>If you didn't request this reset, ignore this email</li>
                    <li>Your password will remain unchanged if you don't complete the reset</li>
                </ul>
            </div>
            
            <h3>Can't click the button?</h3>
            <p>Copy and paste this token into the password reset form:</p>
            <div class="token-box">{reset_token_string}</div>
            
            <h3>Need Help?</h3>
            <p>If you're having trouble resetting your password, contact support at <a href="mailto:{settings.DEFAULT_FROM_EMAIL}">{settings.DEFAULT_FROM_EMAIL}</a></p>
        </div>
        
        <div class="footer">
            <p>PSS Support Team</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
    """

    try:
        # Send using EmailMultiAlternatives for HTML support
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        
        logger.info(f"Password reset email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
        return False


def send_password_change_confirmation_email(user):
    """
    Send confirmation email after successful password change.
    
    Args:
        user: User who changed their password
    
    Security:
    - Notifies user of password change
    - Alerts to contact support if unauthorized
    - Informs about session invalidation
    """
    subject = 'Password Changed - PSS System'
    
    # Create plain text version
    text_content = f"""
Hello {user.first_name or user.email},

Your password for the PSS System has been successfully changed.

WHAT HAPPENED:
- Your password was updated at {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}
- You were logged out of all other sessions for security
- You may need to log in again on other devices

IMPORTANT:
If you did NOT make this change, please contact support immediately!
Contact: {settings.DEFAULT_FROM_EMAIL}

For Security:
- Never share your password with anyone
- Always use a strong, unique password
- Be wary of emails asking for your password

---
PSS Support Team
This is an automated message, please do not reply.
    """.strip()

    # Create HTML version
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #28a745; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }}
        .content {{ background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd; }}
        .alert {{ background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .success {{ background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .footer {{ background-color: #f0f0f0; color: #666; font-size: 12px; padding: 15px; text-align: center; border-radius: 0 0 5px 5px; }}
        .contact {{ font-weight: bold; color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>✓ Password Changed Successfully</h1>
        </div>
        
        <div class="content">
            <p>Hello {user.first_name or user.email},</p>
            
            <div class="success">
                <strong>✓ Success!</strong> Your password for the PSS System has been successfully changed at {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}.
            </div>
            
            <h3>What Happened:</h3>
            <ul>
                <li>Your password was updated</li>
                <li>You were logged out of all other sessions (for your security)</li>
                <li>You may need to log in again on other devices</li>
            </ul>
            
            <div class="alert">
                <strong>⚠️ Important:</strong> If you did NOT make this change, please contact support <span class="contact">immediately!</span>
                <br><br>
                Contact: <a href="mailto:{settings.DEFAULT_FROM_EMAIL}">{settings.DEFAULT_FROM_EMAIL}</a>
            </div>
            
            <h3>Security Tips:</h3>
            <ul>
                <li>Never share your password with anyone</li>
                <li>Use a strong, unique password with letters, numbers, and symbols</li>
                <li>Be wary of emails asking for your password</li>
                <li>Check your account activity regularly</li>
            </ul>
            
            <h3>Need Help?</h3>
            <p>If you have questions, contact support at <a href="mailto:{settings.DEFAULT_FROM_EMAIL}">{settings.DEFAULT_FROM_EMAIL}</a></p>
        </div>
        
        <div class="footer">
            <p>PSS Support Team</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
    """

    try:
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user.email]
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()
        
        logger.info(f"Password change confirmation email sent to {user.email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password change confirmation email to {user.email}: {str(e)}")
        return False

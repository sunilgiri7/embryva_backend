from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.pagination import PageNumberPagination
from functools import wraps

def send_verification_email(user, request=None):
    # Get domain - you can customize this based on your setup
    domain = request.get_host() if request else 'your-domain.com'
    protocol = 'https' if request and request.is_secure() else 'http'
    
    verification_url = f"{protocol}://{domain}/api/v1/verify-email/{user.email_verification_token}/"
    
    subject = 'Verify Your Email - Embryva'
    
    # HTML email template
    html_message = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>Email Verification</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
            .content {{ padding: 30px; background-color: #f9f9f9; }}
            .button {{ display: inline-block; padding: 12px 30px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }}
            .footer {{ padding: 20px; text-align: center; color: #666; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Welcome to Embryva!</h1>
            </div>
            <div class="content">
                <h2>Hello {user.get_full_name() or user.email},</h2>
                <p>Thank you for signing up as a {user.get_user_type_display()}. To complete your registration and start using your account, please verify your email address.</p>
                <p>Click the button below to verify your email:</p>
                <a href="{verification_url}" class="button">Verify Email Address</a>
                <p>Or copy and paste this link into your browser:</p>
                <p><a href="{verification_url}">{verification_url}</a></p>
                <p><strong>Note:</strong> This verification link will expire in 24 hours.</p>
                <p>If you didn't create an account with us, please ignore this email.</p>
            </div>
            <div class="footer">
                <p>Best regards,<br>The Embryva Team</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Plain text version
    plain_message = f"""
    Hello {user.get_full_name() or user.email},

    Thank you for signing up as a {user.get_user_type_display()}. To complete your registration and start using your account, please verify your email address.

    Click the link below to verify your email:
    {verification_url}

    Note: This verification link will expire in 24 hours.

    If you didn't create an account with us, please ignore this email.

    Best regards,
    The Embryva Team
    """
    
    try:
        send_mail(
            subject=subject,
            message=plain_message,
            html_message=html_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        print(f"Failed to send verification email: {e}")
        return False
    
def require_permission(section):
    """Decorator to check if user has permission for a specific section"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {"detail": "Authentication required."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            
            if not request.user.has_permission(section):
                return Response(
                    {"detail": f"You don't have permission to access {section} section."},
                    status=status.HTTP_403_FORBIDDEN,
                )
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

class CustomPageNumberPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100
    
    def get_paginated_response(self, data):
        return Response({
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'page_size': self.page.paginator.per_page,
            'next': self.page.next_page_number() if self.page.has_next() else None,
            'previous': self.page.previous_page_number() if self.page.has_previous() else None,
            'results': data
        })
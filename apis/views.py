from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
import io
import logging
import threading
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.auth import login
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
import urllib
from apis.email_service import EmailService
from apis.services.donor_service import DonorImportService, DonorMatchingService
from apis.services.embeddingsMatching import DonorMatchingEngine, EmbeddingService, MatchResult
from apis.services.signals import generate_and_store_embedding
from apis.services.stripe_service import create_stripe_customer
from apis.utils import CustomPageNumberPagination, generate_unique_donor_id, process_donor_data, validate_donor_row
from .models import Appointment, MatchingResult, Meeting, User
from django.db.models import Count, Sum, Q, Avg
from .serializers import *
from django.shortcuts import get_object_or_404, render
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
import pandas as pd
import json
from django.db import transaction
from django.http import HttpResponse
from django.db import models
import stripe
from django.core.paginator import Paginator
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework import filters
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

@swagger_auto_schema(
    method='post',
    request_body=ParentSignupSerializer,
    responses={
        201: openapi.Response(
            description="Parent registered successfully. Verification email sent.",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'email_sent': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )
        ),
        400: "Bad Request"
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def parent_signup(request):
    """
    Register a new parent user and send verification email
    """
    serializer = ParentSignupSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        user = serializer.save()
        
        return Response({
            'message': 'Parent registered successfully. Please check your email to verify your account.',
            'user': UserSerializer(user).data,
            'email_sent': True
        }, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    request_body=LoginSerializer,
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'tokens': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'access': openapi.Schema(type=openapi.TYPE_STRING),
                            'refresh': openapi.Schema(type=openapi.TYPE_STRING)
                        }
                    ),
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )
        ),
        400: openapi.Response(
            description="Bad Request - Invalid credentials or email not verified",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'email': openapi.Schema(
                        type=openapi.TYPE_ARRAY, 
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'password': openapi.Schema(
                        type=openapi.TYPE_ARRAY, 
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'non_field_errors': openapi.Schema(
                        type=openapi.TYPE_ARRAY, 
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'email_verification': openapi.Schema(type=openapi.TYPE_STRING),
                    'verification_required': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )
        )
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def user_login(request):
    """
    Login user - supports all user types (parent, clinic, admin, subadmin)
    Email verification required only for clinic and parent users
    """
    serializer = LoginSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Double check verification status for clinic and parent users (extra safety)
        if user.user_type in ['clinic', 'parent'] and not user.is_verified:
            return Response({
                'message': 'Please verify your email address before logging in.',
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # User is verified or admin/subadmin, proceed with login
        login(request, user)
        tokens = get_tokens_for_user(user)
        
        return Response({
            'message': 'Login successful',
            'user': UserSerializer(user).data,
            'tokens': tokens,
            'success': True
        }, status=status.HTTP_200_OK)
    
    # Handle validation errors
    errors = serializer.errors
    
    if 'email_verification' in errors:
        return Response({
            'message': 'Please verify your email address before logging in.',
            'success': False
        }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response({
        'message': 'Invalid credentials or missing fields.',
        'success': False
    }, status=status.HTTP_400_BAD_REQUEST)

# ----------------------- CREATE  CLINIC -------------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_clinic(request):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub‑admins can create clinic accounts."},
            status=status.HTTP_403_FORBIDDEN,
        )

    serializer = ClinicCreateSerializer(
        data=request.data, context={"request": request}
    )
    if serializer.is_valid():
        clinic = serializer.save()
        return Response(
            {
                "message": "Clinic created successfully. Verification email sent to the clinic.",
                "clinic": UserSerializer(clinic).data,
                "email_sent": True
            },
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

##########################EMAIL VERIFICATION FOR CLINIC AND PARENT##########################
@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="Email verified successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'verified': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )
        ),
        400: "Invalid or expired verification token",
        404: "User not found"
    }
)
@api_view(['GET'])
@permission_classes([AllowAny])
def verify_email(request, token):
    try:
        user = get_object_or_404(User, email_verification_token=token)
        
        if user.is_email_verification_expired():
            return render(request, 'email_verification_failed.html', {
                'message': 'This verification link has expired.'
            })

        user.is_verified = True
        user.save(update_fields=['is_verified'])

        return render(request, 'email_verification_success.html')
    
    except User.DoesNotExist:
        return render(request, 'email_verification_failed.html', {
            'message': 'Invalid or expired verification link.'
        })


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'email': openapi.Schema(type=openapi.TYPE_STRING, format='email')
        },
        required=['email']
    ),
    responses={
        200: openapi.Response(
            description="Verification email sent successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'email_sent': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )
        ),
        400: "Bad Request",
        404: "User not found"
    }
)
@api_view(['POST'])
@permission_classes([AllowAny])
def resend_verification_email(request):
    """
    Resend verification email to user
    """
    email = request.data.get('email')
    if not email:
        return Response({
            'message': 'Email is required.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(email=email)
        
        if user.is_verified:
            return Response({
                'message': 'Email is already verified.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Generate new token and send email
        user.regenerate_verification_token()
        email_sent = send_verification_email(user, request)
        
        if email_sent:
            return Response({
                'message': 'Verification email sent successfully.',
                'email_sent': True
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'message': 'Failed to send verification email. Please try again.',
                'email_sent': False
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except User.DoesNotExist:
        return Response({
            'message': 'User with this email does not exist.'
        }, status=status.HTTP_404_NOT_FOUND)

# --------------------- CREATE  SUB‑ADMIN ------------------------------
@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
            'email': openapi.Schema(type=openapi.TYPE_STRING),
            'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
            'password': openapi.Schema(type=openapi.TYPE_STRING),
            'password_confirm': openapi.Schema(type=openapi.TYPE_STRING),
            'permissions': openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'clinic': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'parent': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'subscription': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'appointment': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'transaction': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'profile': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                },
                description="Permissions for different sections"
            )
        },
        required=['first_name', 'last_name', 'email', 'password', 'password_confirm']
    ),
    responses={
        201: openapi.Response(
            description="SubAdmin created successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )
        ),
        400: openapi.Response(description="Bad Request"),
        403: openapi.Response(description="Permission denied")
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_subadmin(request):
    """Create a new subadmin with specified permissions"""
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can create subadmin accounts."},
            status=status.HTTP_403_FORBIDDEN,
        )

    serializer = SubAdminCreateSerializer(
        data=request.data, 
        context={"request": request}
    )
    
    if serializer.is_valid():
        subadmin = serializer.save()
        return Response(
            {
                "message": "SubAdmin created successfully.",
                "user": UserSerializer(subadmin, context={'request': request}).data,
                "success": True
            },
            status=status.HTTP_201_CREATED,
        )
    
    return Response(
        {
            "message": "Failed to create subadmin.",
            "errors": serializer.errors,
            "success": False
        }, 
        status=status.HTTP_400_BAD_REQUEST
    )

@swagger_auto_schema(
    method='patch',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'permissions': openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'clinic': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'parent': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'subscription': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'appointment': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'transaction': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'profile': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                },
                description="Updated permissions for the subadmin"
            )
        },
        required=['permissions']
    ),
    responses={
        200: openapi.Response(description="Permissions updated successfully"),
        400: openapi.Response(description="Bad Request"),
        403: openapi.Response(description="Permission denied"),
        404: openapi.Response(description="SubAdmin not found")
    }
)
@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_subadmin_permissions(request, subadmin_id):
    """Update permissions for a specific subadmin"""
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can update subadmin permissions."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    try:
        subadmin = User.objects.get(id=subadmin_id, user_type='subadmin')
    except User.DoesNotExist:
        return Response(
            {"detail": "SubAdmin not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    
    permissions = request.data.get('permissions', {})
    
    # Validate permissions
    if not isinstance(permissions, dict):
        return Response(
            {"detail": "Permissions must be a dictionary."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    
    valid_sections = User.PERMISSION_SECTIONS
    invalid_sections = set(permissions.keys()) - set(valid_sections)
    
    if invalid_sections:
        return Response(
            {
                "detail": f"Invalid permission sections: {list(invalid_sections)}. "
                         f"Valid sections are: {valid_sections}"
            },
            status=status.HTTP_400_BAD_REQUEST,
        )
    
    # Update permissions
    subadmin.set_permissions(permissions)
    
    return Response(
        {
            "message": "Permissions updated successfully.",
            "user": UserSerializer(subadmin, context={'request': request}).data,
            "success": True
        },
        status=status.HTTP_200_OK,
    )


@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="SubAdmin permissions retrieved successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'permissions': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'clinic': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            'parent': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            'subscription': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            'appointment': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            'transaction': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            'profile': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        }
                    )
                }
            )
        ),
        403: openapi.Response(description="Permission denied"),
        404: openapi.Response(description="SubAdmin not found")
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_subadmin_permissions(request, subadmin_id):
    """Get permissions for a specific subadmin"""
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can view subadmin permissions."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    try:
        subadmin = User.objects.get(id=subadmin_id, user_type='subadmin')
    except User.DoesNotExist:
        return Response(
            {"detail": "SubAdmin not found."},
            status=status.HTTP_404_NOT_FOUND,
        )
    
    return Response(
        {
            "permissions": subadmin.get_permissions(),
            "success": True
        },
        status=status.HTTP_200_OK,
    )

class UserListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user

        # Allow access only if user is admin or subadmin
        if not (user.user_type in ['admin', 'subadmin']):
            return User.objects.none()

        # Optional filter by user_type
        user_type = self.request.query_params.get('user_type')
        queryset = User.objects.all().order_by('-created_at')

        if user_type:
            queryset = queryset.filter(user_type=user_type)

        return queryset

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="User profile",
            schema=UserSerializer
        ),
        401: "Unauthorized"
    }
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def user_profile(request):
    """
    Get current user profile for all user types (admin, parent, clinic, subadmin)
    """
    serializer = UserSerializer(request.user, context={'request': request})
    return Response({
        'success': True,
        'user': serializer.data
    })

@swagger_auto_schema(
    method='put',
    request_body=AdminProfileUpdateSerializer,
    responses={
        200: openapi.Response(
            description="Profile updated successfully",
            schema=UserSerializer
        ),
        400: "Bad Request - Validation errors",
        403: "Forbidden - Only admins can update profiles"
    },
    operation_description="Update admin profile (admin only)",
    tags=['Profile']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def admin_profile_update(request):
    """
    Update admin profile - only accessible by admin users
    """
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can update profiles."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    serializer = AdminProfileUpdateSerializer(
        request.user, 
        data=request.data, 
        partial=True,
        context={'request': request}
    )
    
    if serializer.is_valid():
        user = serializer.save()
        response_serializer = UserSerializer(user, context={'request': request})
        return Response({
            'success': True,
            'message': 'Profile updated successfully',
            'user': response_serializer.data
        }, status=status.HTTP_200_OK)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

# New profile_image_upload view for handling image upload separately
@swagger_auto_schema(
    method='post',
    manual_parameters=[
        openapi.Parameter(
            'profile_image',
            openapi.IN_FORM,
            description="Profile image file",
            type=openapi.TYPE_FILE,
            required=True
        )
    ],
    responses={
        200: openapi.Response(
            description="Profile image uploaded successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'profile_image_url': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: "Bad Request - Invalid image file",
        403: "Forbidden - Only admins can upload images"
    },
    operation_description="Upload profile image (admin only)",
    tags=['Profile']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def profile_image_upload(request):
    """
    Upload profile image - only accessible by admin users
    """
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can upload profile images."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    if 'profile_image' not in request.FILES:
        return Response({
            'success': False,
            'message': 'No image file provided'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    profile_image = request.FILES['profile_image']
    
    # Validate image file
    if not profile_image.content_type.startswith('image/'):
        return Response({
            'success': False,
            'message': 'Invalid image file'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Delete old image if exists
    if request.user.profile_image:
        request.user.profile_image.delete()
    
    # Save new image
    request.user.profile_image = profile_image
    request.user.save()
    
    profile_image_url = request.build_absolute_uri(request.user.profile_image.url)
    
    return Response({
        'success': True,
        'message': 'Profile image uploaded successfully',
        'profile_image_url': profile_image_url
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_email(request):
    serializer = ForgotPasswordEmailSerializer(data=request.data)
    if serializer.is_valid():
        otp_instance, token = serializer.save()  # Now returns both OTP instance and token
        
        return Response({
            'message': 'OTP sent to your email successfully',
            'email': serializer.validated_data['email'],
            'token': token  # Return token in response
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    request_body=VerifyOTPSerializer,
    manual_parameters=[
        openapi.Parameter(
            'token',
            in_=openapi.IN_QUERY,
            description='Signed OTP token from password reset email',
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={
        200: openapi.Response(
            description="OTP verified successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: "Bad Request",
    },
    operation_description="Verify the OTP sent to user's email via password reset link",
    tags=['Password Reset']
)
@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp(request):
    token = request.query_params.get("token")
    serializer = VerifyOTPSerializer(data=request.data, context={"token": token})
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"message": "OTP verified"}, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    request_body=ResetPasswordSerializer,
    manual_parameters=[
        openapi.Parameter(
            'token',
            in_=openapi.IN_QUERY,
            description='Signed OTP token from verified reset flow',
            type=openapi.TYPE_STRING,
            required=True
        )
    ],
    responses={
        200: openapi.Response(
            description="Password reset successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING)
                }
            )
        ),
        400: "Bad Request",
    },
    operation_description="Reset password using previously verified OTP token",
    tags=['Password Reset']
)
@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request):
    token = request.query_params.get("token")
    serializer = ResetPasswordSerializer(data=request.data, context={"token": token})
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return Response({"message": "Password reset successful"}, status=status.HTTP_200_OK)

@swagger_auto_schema(
    method='post',
    request_body=ChangePasswordSerializer,
    responses={
        200: openapi.Response(
            description="Password changed successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                }
            )
        ),
        400: openapi.Response(
            description="Validation errors",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'old_password': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'new_password': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'confirm_new_password': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(type=openapi.TYPE_STRING)
                    ),
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                }
            )
        )
    }
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """
    Change password for logged-in user (requires authentication)
    """
    serializer = ChangePasswordSerializer(data=request.data, context={'request': request})

    if serializer.is_valid():
        user = request.user
        user.set_password(serializer.validated_data['new_password'])
        user.save()

        return Response({
            'message': 'Password changed successfully.',
            'success': True
        }, status=status.HTTP_200_OK)

    return Response({
        **serializer.errors,
        'success': False
    }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page (default: 10, max: 100)", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name or email", type=openapi.TYPE_STRING),
    ],
    responses={200: openapi.Response(
        description="Paginated list of subadmins",
        schema=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'count': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of records"),
                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of pages"),
                'current_page': openapi.Schema(type=openapi.TYPE_INTEGER, description="Current page number"),
                'page_size': openapi.Schema(type=openapi.TYPE_INTEGER, description="Number of records per page"),
                'next': openapi.Schema(type=openapi.TYPE_STRING, description="URL for next page"),
                'previous': openapi.Schema(type=openapi.TYPE_STRING, description="URL for previous page"),
                'results': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT))
            }
        )
    )},
    operation_description="Get paginated list of all subadmins (Admin only)",
    tags=['User Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def subadmin_list(request):
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can view subadmin list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = User.objects.filter(user_type='subadmin').order_by('-created_at')
    
    # Search functionality
    search = request.query_params.get('search', None)
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | 
            Q(last_name__icontains=search) | 
            Q(email__icontains=search)
        )
    
    paginator = CustomPageNumberPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = UserSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page (default: 10, max: 100)", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name or email", type=openapi.TYPE_STRING),
    ],
    responses={200: openapi.Response(
        description="Paginated list of clinics",
        schema=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'count': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of records"),
                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of pages"),
                'current_page': openapi.Schema(type=openapi.TYPE_INTEGER, description="Current page number"),
                'page_size': openapi.Schema(type=openapi.TYPE_INTEGER, description="Number of records per page"),
                'next': openapi.Schema(type=openapi.TYPE_STRING, description="URL for next page"),
                'previous': openapi.Schema(type=openapi.TYPE_STRING, description="URL for previous page"),
                'results': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT))
            }
        )
    )},
    operation_description="Get paginated list of all clinics (Admin/SubAdmin only)",
    tags=['User Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def clinic_list(request):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view clinic list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    # Check if subadmin has clinic permission
    if request.user.is_subadmin and not request.user.has_permission('clinic'):
        return Response(
            {"detail": "You don't have permission to view clinic list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = User.objects.filter(user_type='clinic').order_by('-created_at')
    
    # Search functionality
    search = request.query_params.get('search', None)
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | 
            Q(last_name__icontains=search) | 
            Q(email__icontains=search) |
            Q(specialization__icontains=search)
        )
    
    paginator = CustomPageNumberPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = UserSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page (default: 10, max: 100)", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name or email", type=openapi.TYPE_STRING),
    ],
    responses={200: openapi.Response(
        description="Paginated list of parents",
        schema=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'count': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of records"),
                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER, description="Total number of pages"),
                'current_page': openapi.Schema(type=openapi.TYPE_INTEGER, description="Current page number"),
                'page_size': openapi.Schema(type=openapi.TYPE_INTEGER, description="Number of records per page"),
                'next': openapi.Schema(type=openapi.TYPE_STRING, description="URL for next page"),
                'previous': openapi.Schema(type=openapi.TYPE_STRING, description="URL for previous page"),
                'results': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Schema(type=openapi.TYPE_OBJECT))
            }
        )
    )},
    operation_description="Get paginated list of all parents (Admin/SubAdmin only - Read only)",
    tags=['User Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def parent_list(request):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view parent list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    # Check if subadmin has parent permission
    if request.user.is_subadmin and not request.user.has_permission('parent'):
        return Response(
            {"detail": "You don't have permission to view parent list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = User.objects.filter(user_type='parent').order_by('-created_at')
    
    # Search functionality
    search = request.query_params.get('search', None)
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | 
            Q(last_name__icontains=search) | 
            Q(email__icontains=search) |
            Q(relationship_to_child__icontains=search)
        )
    
    paginator = CustomPageNumberPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = UserSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

# ====================== SUBADMIN CRUD ======================

@swagger_auto_schema(
    method='get',
    responses={200: UserSerializer()},
    operation_description="Get subadmin details (Admin only)",
    tags=['SubAdmin Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def subadmin_detail(request, user_id):
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can view subadmin details."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    subadmin = get_object_or_404(User, id=user_id, user_type='subadmin')
    serializer = UserSerializer(subadmin)
    return Response(serializer.data)

@swagger_auto_schema(
    method='put',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'first_name': openapi.Schema(type=openapi.TYPE_STRING),
            'last_name': openapi.Schema(type=openapi.TYPE_STRING),
            'email': openapi.Schema(type=openapi.TYPE_STRING),
            'phone_number': openapi.Schema(type=openapi.TYPE_STRING),
            'is_active': openapi.Schema(type=openapi.TYPE_BOOLEAN),
        }
    ),
    responses={200: UserSerializer()},
    operation_description="Update subadmin details (Admin only)",
    tags=['SubAdmin Management']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def subadmin_update(request, user_id):
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can update subadmin details."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    subadmin = get_object_or_404(User, id=user_id, user_type='subadmin')
    
    # Check if email is being changed and if it already exists
    email = request.data.get('email')
    if email and email != subadmin.email:
        if User.objects.filter(email=email).exists():
            return Response(
                {"email": ["User with this email already exists"]},
                status=status.HTTP_400_BAD_REQUEST
            )
    
    serializer = UserUpdateSerializer(subadmin, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'SubAdmin updated successfully',
            'user': UserSerializer(subadmin).data
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='delete',
    responses={204: "SubAdmin deleted successfully"},
    operation_description="Delete subadmin (Admin only)",
    tags=['SubAdmin Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def subadmin_delete(request, user_id):
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can delete subadmin."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    subadmin = get_object_or_404(User, id=user_id, user_type='subadmin')
    subadmin.delete()
    return Response(
        {"message": "SubAdmin deleted successfully"},
        status=status.HTTP_204_NO_CONTENT
    )

# ====================== CLINIC CRUD ======================

@swagger_auto_schema(
    method='get',
    responses={200: UserSerializer()},
    operation_description="Get clinic details (Admin, SubAdmin, or the clinic itself)",
    tags=['Clinic Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def clinic_detail(request, user_id):
    is_owner = request.user.is_clinic and str(request.user.id) == str(user_id)
    if not (request.user.is_admin or request.user.is_subadmin or is_owner):
        return Response(
            {"detail": "You do not have permission to view these details."},
            status=status.HTTP_403_FORBIDDEN,
        )

    clinic = get_object_or_404(User, id=user_id, user_type='clinic')
    return Response(UserSerializer(clinic).data)

@swagger_auto_schema(
    method='put',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'first_name':        openapi.Schema(type=openapi.TYPE_STRING),
            'last_name':         openapi.Schema(type=openapi.TYPE_STRING),
            'email':             openapi.Schema(type=openapi.TYPE_STRING),   # admin/sub‑admin only
            'phone_number':      openapi.Schema(type=openapi.TYPE_STRING),
            'specialization':    openapi.Schema(type=openapi.TYPE_STRING),
            'years_of_experience': openapi.Schema(type=openapi.TYPE_INTEGER),
            'is_active':         openapi.Schema(type=openapi.TYPE_BOOLEAN),  # admin/sub‑admin only
        }
    ),
    responses={200: UserSerializer()},
    operation_description="Update clinic details (Admin, SubAdmin, or the clinic itself)",
    tags=['Clinic Management']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def clinic_update(request, user_id):
    is_owner = request.user.is_clinic and str(request.user.id) == str(user_id)
    if not (request.user.is_admin or request.user.is_subadmin or is_owner):
        return Response(
            {"detail": "You do not have permission to update these details."},
            status=status.HTTP_403_FORBIDDEN,
        )

    clinic = get_object_or_404(User, id=user_id, user_type='clinic')

    serializer = UserUpdateSerializer(
        clinic,
        data=request.data,
        partial=True,
        context={'request': request}
    )
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Clinic updated successfully',
            'user': UserSerializer(clinic).data
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='delete',
    responses={204: "Clinic deleted successfully"},
    operation_description="Delete clinic (Admin/SubAdmin only)",
    tags=['Clinic Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def clinic_delete(request, user_id):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can delete clinic."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    clinic = get_object_or_404(User, id=user_id, user_type='clinic')
    clinic.delete()
    return Response(
        {"message": "Clinic deleted successfully"},
        status=status.HTTP_204_NO_CONTENT
    )

# ====================== PARENT MANAGEMENT (RUD only) ======================

@swagger_auto_schema(
    method='get',
    responses={200: UserSerializer()},
    operation_description="Get parent details (Admin or the parent herself)",
    tags=['Parent Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def parent_detail(request, user_id):
    # ▸ NEW: permission check for parent’s own record
    if not (request.user.is_admin or request.user.is_subadmin or (request.user.is_parent and str(request.user.id) == str(user_id))):
        return Response(
            {"detail": "You do not have permission to view these details."},
            status=status.HTTP_403_FORBIDDEN,
        )

    parent = get_object_or_404(User, id=user_id, user_type='parent')
    serializer = UserSerializer(parent)
    return Response(serializer.data)


# ---------- 2.  UPDATE  ----------
@swagger_auto_schema(
    method='put',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'first_name':           openapi.Schema(type=openapi.TYPE_STRING),
            'last_name':            openapi.Schema(type=openapi.TYPE_STRING),
            'email':                openapi.Schema(type=openapi.TYPE_STRING),   # admin‑only
            'phone_number':         openapi.Schema(type=openapi.TYPE_STRING),
            'relationship_to_child':openapi.Schema(type=openapi.TYPE_STRING),
            'is_active':            openapi.Schema(type=openapi.TYPE_BOOLEAN),  # admin‑only
        }
    ),
    responses={200: UserSerializer()},
    operation_description="Update parent details (Admin or the parent herself)",
    tags=['Parent Management']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def parent_update(request, user_id):
    if not (request.user.is_admin or request.user.is_subadmin or (request.user.is_parent and str(request.user.id) == str(user_id))):
        return Response(
            {"detail": "You do not have permission to update these details."},
            status=status.HTTP_403_FORBIDDEN,
        )

    parent = get_object_or_404(User, id=user_id, user_type='parent')

    # ▸ Pass request into serializer for per‑field validation
    serializer = UserUpdateSerializer(
        parent,
        data=request.data,
        partial=True,
        context={'request': request}
    )

    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'Parent updated successfully',
            'user': UserSerializer(parent).data
        })
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='delete',
    responses={204: "Parent deleted successfully"},
    operation_description="Delete parent (Admin only)",
    tags=['Parent Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def parent_delete(request, user_id):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view clinic list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    parent = get_object_or_404(User, id=user_id, user_type='parent')
    parent.delete()
    return Response(
        {"message": "Parent deleted successfully"},
        status=status.HTTP_204_NO_CONTENT
    )

# ====================== APPOINTMENT MANAGEMENT ======================

@swagger_auto_schema(
    method='post',
    request_body=AppointmentCreateSerializer,
    responses={
        201: openapi.Response(
            description="Appointment created successfully",
            schema=AppointmentDetailSerializer
        ),
        400: "Bad Request"
    },
    operation_description="Create appointment - Public endpoint for donor form submission",
    tags=['Appointments']
)
@api_view(['POST'])
@permission_classes([AllowAny])  # Public endpoint for appointment booking
def create_appointment(request):
    serializer = AppointmentCreateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        appointment = serializer.save()
        return Response({
            'success': True,
            'message': 'Appointment created successfully. You will be contacted soon.',
            'appointment': AppointmentDetailSerializer(appointment).data
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'message': 'Please check the form data',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Results per page", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name, email, or reason", type=openapi.TYPE_STRING),
        openapi.Parameter('status', openapi.IN_QUERY, description="Filter by status", type=openapi.TYPE_STRING),
        openapi.Parameter('clinic_id', openapi.IN_QUERY, description="Filter by clinic", type=openapi.TYPE_STRING),
        openapi.Parameter('has_meeting', openapi.IN_QUERY, description="Filter by meeting status (true/false)", type=openapi.TYPE_BOOLEAN),
        openapi.Parameter('reason', openapi.IN_QUERY, description="Filter by consultation reason", type=openapi.TYPE_STRING),
    ],
    responses={200: AppointmentDetailSerializer(many=True)},
    operation_description="Get all appointments with filters (Admin/SubAdmin only)",
    tags=['Appointment Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def appointment_list(request):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view appointments."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = Appointment.objects.select_related(
        'clinic', 'parent', 'reviewed_by'
    ).prefetch_related('meeting').order_by('-created_at')
    
    # Search functionality
    search = request.query_params.get('search', None)
    if search:
        queryset = queryset.filter(
            Q(name__icontains=search) | 
            Q(email__icontains=search) | 
            Q(reason_for_consultation__icontains=search) |
            Q(clinic__first_name__icontains=search) |
            Q(clinic__last_name__icontains=search) |
            Q(phone_number__icontains=search)
        )
    
    # Status filter
    status_filter = request.query_params.get('status', None)
    if status_filter:
        queryset = queryset.filter(status=status_filter)
    
    # Clinic filter
    clinic_id = request.query_params.get('clinic_id', None)
    if clinic_id:
        queryset = queryset.filter(clinic_id=clinic_id)
    
    # Consultation reason filter
    reason = request.query_params.get('reason', None)
    if reason:
        queryset = queryset.filter(reason_for_consultation=reason)
    
    # Meeting filter
    has_meeting = request.query_params.get('has_meeting', None)
    if has_meeting is not None:
        if has_meeting.lower() == 'true':
            queryset = queryset.filter(meeting__isnull=False)
        elif has_meeting.lower() == 'false':
            queryset = queryset.filter(meeting__isnull=True)
    
    paginator = StandardResultsSetPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = AppointmentDetailSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def parent_appointments_list(request):
    # Check if user is a parent
    if not request.user.is_parent:
        return Response({
            'success': False,
            'message': 'Access denied. Only parents can view their appointments.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Get appointments for the logged-in parent
    appointments = Appointment.objects.filter(
        Q(parent=request.user) | Q(email=request.user.email)
    ).select_related('clinic', 'donor').order_by('-created_at')
    
    # Apply filters if provided
    status_filter = request.GET.get('status')
    if status_filter:
        appointments = appointments.filter(status=status_filter)
    
    reason_filter = request.GET.get('reason')
    if reason_filter:
        appointments = appointments.filter(reason_for_consultation=reason_filter)
    
    # Serialize the appointments
    serializer = ParentAppointmentListSerializer(appointments, many=True)
    
    return Response({
        'success': True,
        'message': 'Appointments retrieved successfully',
        'total_appointments': appointments.count(),
        'appointments': serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def parent_appointment_stats(request):
    if not request.user.is_parent:
        return Response({
            'success': False,
            'message': 'Access denied. Only parents can view their appointment statistics.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    appointments = Appointment.objects.filter(
        Q(parent=request.user) | Q(email=request.user.email)
    )
    
    stats = {
        'total_appointments': appointments.count(),
        'pending_appointments': appointments.filter(status='pending').count(),
        'confirmed_appointments': appointments.filter(status='confirmed').count(),
        'completed_appointments': appointments.filter(status='completed').count(),
        'cancelled_appointments': appointments.filter(status='cancelled').count(),
        'consultation_types': {
            'sperm': appointments.filter(reason_for_consultation='sperm').count(),
            'egg': appointments.filter(reason_for_consultation='egg').count(),
            'surrogate': appointments.filter(reason_for_consultation='surrogate').count(),
        }
    }
    
    return Response({
        'success': True,
        'message': 'Appointment statistics retrieved successfully',
        'stats': stats
    }, status=status.HTTP_200_OK)


@swagger_auto_schema(
    method='get',
    responses={200: AppointmentDetailSerializer()},
    operation_description="Get appointment details (Admin/SubAdmin only)",
    tags=['Appointment Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def appointment_detail(request, appointment_id):
    """
    Admin/SubAdmin: Get specific appointment details
    """
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view appointment details."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    appointment = get_object_or_404(
        Appointment.objects.select_related('clinic', 'parent', 'reviewed_by').prefetch_related('meeting'),
        id=appointment_id
    )
    serializer = AppointmentDetailSerializer(appointment)
    return Response({
        'success': True,
        'appointment': serializer.data
    })

@swagger_auto_schema(
    method='put',
    request_body=AppointmentUpdateSerializer,
    responses={200: AppointmentDetailSerializer()},
    operation_description="Update appointment status and notes (Admin/SubAdmin only)",
    tags=['Appointment Management']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def appointment_update(request, appointment_id):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can update appointments."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    appointment = get_object_or_404(Appointment, id=appointment_id)
    
    serializer = AppointmentUpdateSerializer(appointment, data=request.data, partial=True)
    if serializer.is_valid():
        appointment = serializer.save()
        appointment.reviewed_by = request.user
        appointment.save()
        
        return Response({
            'success': True,
            'message': 'Appointment updated successfully',
            'appointment': AppointmentDetailSerializer(appointment).data
        })
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='delete',
    responses={204: "Appointment deleted successfully"},
    operation_description="Delete appointment (Admin only)",
    tags=['Appointment Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def appointment_delete(request, appointment_id):
    """
    Admin only: Delete appointment
    """
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view clinic list."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    appointment = get_object_or_404(Appointment, id=appointment_id)
    
    # Check if appointment has a meeting
    if hasattr(appointment, 'meeting'):
        return Response({
            'success': False,
            'message': 'Cannot delete appointment with scheduled meeting. Cancel meeting first.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    appointment.delete()
    return Response({
        'success': True,
        'message': 'Appointment deleted successfully'
    }, status=status.HTTP_204_NO_CONTENT)

# ====================== MEETING MANAGEMENT ======================

@swagger_auto_schema(
    method='post',
    request_body=MeetingCreateSerializer,
    responses={
        201: openapi.Response(
            description="Meeting created successfully",
            schema=MeetingDetailSerializer
        ),
        400: "Bad Request"
    },
    operation_description="Create meeting for appointment (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_meeting(request):
    """
    Admin/SubAdmin: Create instant or scheduled meeting for appointment
    Emails are sent to admin/subadmin, parent, and clinic
    """
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can create meetings."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    serializer = MeetingCreateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        meeting = serializer.save()
        
        # Send email notifications
        email_sent = EmailService.send_meeting_creation_emails(meeting)
        
        return Response({
            'success': True,
            'message': 'Meeting created successfully',
            'meeting': MeetingDetailSerializer(meeting).data,
            'email_sent': email_sent
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'appointment_id': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_UUID),
            'meeting_link': openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_URI),
            'meeting_id': openapi.Schema(type=openapi.TYPE_STRING),
            'passcode': openapi.Schema(type=openapi.TYPE_STRING),
        },
        required=['appointment_id', 'meeting_link', 'meeting_id']
    ),
    responses={201: MeetingDetailSerializer()},
    operation_description="Create instant meeting (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_instant_meeting(request):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can create meetings."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    # Set scheduled time to current time for instant meeting
    meeting_data = request.data.copy()
    meeting_data['meeting_type'] = 'instant'
    meeting_data['scheduled_datetime'] = timezone.now().isoformat()
    meeting_data['duration_minutes'] = meeting_data.get('duration_minutes', 30)
    
    serializer = MeetingCreateSerializer(data=meeting_data, context={'request': request})
    if serializer.is_valid():
        meeting = serializer.save()
        
        # Update meeting status to ongoing for instant meetings
        meeting.status = 'ongoing'
        meeting.save()
        
        # Send email notifications
        email_sent = EmailService.send_meeting_creation_emails(meeting)
        
        return Response({
            'success': True,
            'message': 'Instant meeting created successfully',
            'meeting': MeetingDetailSerializer(meeting).data,
            'email_sent': email_sent
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Results per page", type=openapi.TYPE_INTEGER),
        openapi.Parameter('status', openapi.IN_QUERY, description="Filter by meeting status", type=openapi.TYPE_STRING),
        openapi.Parameter('meeting_type', openapi.IN_QUERY, description="Filter by meeting type", type=openapi.TYPE_STRING),
        openapi.Parameter('clinic_id', openapi.IN_QUERY, description="Filter by clinic", type=openapi.TYPE_STRING),
    ],
    responses={200: MeetingDetailSerializer(many=True)},
    operation_description="Get all meetings with filters (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def meeting_list(request):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view meetings."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = Meeting.objects.select_related(
        'appointment', 'appointment__clinic', 'appointment__parent', 'created_by'
    ).prefetch_related('participants').order_by('-created_at')
    
    # Status filter
    status_filter = request.query_params.get('status', None)
    if status_filter:
        queryset = queryset.filter(status=status_filter)
    
    # Meeting type filter
    meeting_type = request.query_params.get('meeting_type', None)
    if meeting_type:
        queryset = queryset.filter(meeting_type=meeting_type)
    
    # Clinic filter
    clinic_id = request.query_params.get('clinic_id', None)
    if clinic_id:
        queryset = queryset.filter(appointment__clinic_id=clinic_id)
    
    paginator = StandardResultsSetPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = MeetingDetailSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

@swagger_auto_schema(
    method='get',
    responses={200: MeetingDetailSerializer()},
    operation_description="Get meeting details (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def meeting_detail(request, meeting_id):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view meeting details."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    meeting = get_object_or_404(
        Meeting.objects.select_related(
            'appointment', 'appointment__clinic', 'appointment__parent', 'created_by'
        ).prefetch_related('participants'),
        id=meeting_id
    )
    serializer = MeetingDetailSerializer(meeting)
    return Response({
        'success': True,
        'meeting': serializer.data
    })

@swagger_auto_schema(
    method='put',
    request_body=MeetingUpdateSerializer,
    responses={200: MeetingDetailSerializer()},
    operation_description="Update meeting details (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def meeting_update(request, meeting_id):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can update meetings."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    meeting = get_object_or_404(Meeting, id=meeting_id)
    
    serializer = MeetingUpdateSerializer(meeting, data=request.data, partial=True)
    if serializer.is_valid():
        meeting = serializer.save()
        
        return Response({
            'success': True,
            'message': 'Meeting updated successfully',
            'meeting': MeetingDetailSerializer(meeting).data
        })
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    responses={200: "Meeting status updated"},
    operation_description="Update meeting status (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def meeting_status_update(request, meeting_id, new_status):
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can update meeting status."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    meeting = get_object_or_404(Meeting, id=meeting_id)
    
    # Validate status
    valid_statuses = ['scheduled', 'ongoing', 'completed', 'cancelled']
    if new_status not in valid_statuses:
        return Response({
            'success': False,
            'message': f'Invalid status. Valid options: {", ".join(valid_statuses)}'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    meeting.status = new_status
    meeting.save()
    
    # Update appointment status based on meeting status
    if new_status == 'completed':
        meeting.appointment.status = 'completed'
        meeting.appointment.save()
    elif new_status == 'cancelled':
        meeting.appointment.status = 'pending'  # Reset to pending if meeting cancelled
        meeting.appointment.save()
    
    return Response({
        'success': True,
        'message': f'Meeting status updated to {new_status}',
        'meeting': MeetingDetailSerializer(meeting).data
    })

@swagger_auto_schema(
    method='post',
    responses={200: "Reminder emails sent"},
    operation_description="Send reminder emails manually (Admin/SubAdmin only)",
    tags=['Meeting Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_meeting_reminders(request, meeting_id):
    """
    Admin/SubAdmin: Manually send meeting reminder emails
    """
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can send reminders."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    meeting = get_object_or_404(Meeting, id=meeting_id)
    
    # Send reminder emails
    email_sent = EmailService.send_meeting_reminder_emails(meeting)
    
    return Response({
        'success': True,
        'message': 'Reminder emails sent successfully' if email_sent else 'Failed to send reminder emails',
        'email_sent': email_sent
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def clinic_donor_booking_stats(request):
    if not request.user.is_clinic:
        return Response({
            'success': False,
            'message': 'Access denied. Only clinics can view donor statistics.'
        }, status=status.HTTP_403_FORBIDDEN)
    
    # Get all donors belonging to this clinic
    donors = Donor.objects.filter(clinic=request.user, is_active=True)
    
    # Apply date filter if provided
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    
    appointment_filter = Q(clinic=request.user)
    if date_from:
        try:
            date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
            appointment_filter &= Q(created_at__date__gte=date_from)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
            appointment_filter &= Q(created_at__date__lte=date_to)
        except ValueError:
            pass
    
    # Get donor statistics
    donor_stats = []
    for donor in donors:
        # Get appointments for this donor
        appointments = Appointment.objects.filter(
            appointment_filter & Q(donor=donor)
        )
        
        # Get meetings for these appointments
        meetings = Meeting.objects.filter(appointment__in=appointments)
        
        donor_data = {
            'donor_id': donor.donor_id,
            'donor_name': donor.full_name,
            'donor_type': donor.donor_type,
            'donor_age': donor.age,
            'total_bookings': appointments.count(),
            'booking_by_status': {
                'pending': appointments.filter(status='pending').count(),
                'confirmed': appointments.filter(status='confirmed').count(),
                'completed': appointments.filter(status='completed').count(),
                'cancelled': appointments.filter(status='cancelled').count(),
            },
            'total_meetings': meetings.count(),
            'meeting_by_status': {
                'scheduled': meetings.filter(status='scheduled').count(),
                'completed': meetings.filter(status='completed').count(),
                'cancelled': meetings.filter(status='cancelled').count(),
                'in_progress': meetings.filter(status='in_progress').count(),
            },
            'meeting_by_type': {
                'instant': meetings.filter(meeting_type='instant').count(),
                'scheduled': meetings.filter(meeting_type='scheduled').count(),
            },
            'latest_booking_date': appointments.order_by('-created_at').first().created_at if appointments.exists() else None,
            'recent_bookings': appointments.order_by('-created_at')[:3].values(
                'id', 'name', 'email', 'status', 'created_at', 'reason_for_consultation'
            )
        }
        donor_stats.append(donor_data)
    
    # Sort by total bookings (descending)
    donor_stats.sort(key=lambda x: x['total_bookings'], reverse=True)
    
    # Overall clinic statistics
    total_appointments = Appointment.objects.filter(appointment_filter).count()
    total_meetings = Meeting.objects.filter(
        appointment__clinic=request.user
    ).count()
    
    overall_stats = {
        'total_active_donors': donors.count(),
        'total_appointments': total_appointments,
        'total_meetings': total_meetings,
        'appointments_by_status': {
            'pending': Appointment.objects.filter(appointment_filter & Q(status='pending')).count(),
            'confirmed': Appointment.objects.filter(appointment_filter & Q(status='confirmed')).count(),
            'completed': Appointment.objects.filter(appointment_filter & Q(status='completed')).count(),
            'cancelled': Appointment.objects.filter(appointment_filter & Q(status='cancelled')).count(),
        },
        'appointments_by_consultation': {
            'sperm': Appointment.objects.filter(appointment_filter & Q(reason_for_consultation='sperm')).count(),
            'egg': Appointment.objects.filter(appointment_filter & Q(reason_for_consultation='egg')).count(),
            'surrogate': Appointment.objects.filter(appointment_filter & Q(reason_for_consultation='surrogate')).count(),
        }
    }
    
    return Response({
        'success': True,
        'message': 'Donor statistics retrieved successfully',
        'overall_stats': overall_stats,
        'donor_stats': donor_stats,
        'filters_applied': {
            'date_from': date_from.isoformat() if date_from else None,
            'date_to': date_to.isoformat() if date_to else None,
        }
    }, status=status.HTTP_200_OK)

# ====================== DASHBOARD STATISTICS ======================

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(
        description="Dashboard statistics",
        schema=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'total_appointments': openapi.Schema(type=openapi.TYPE_INTEGER),
                'pending_appointments': openapi.Schema(type=openapi.TYPE_INTEGER),
                'confirmed_appointments': openapi.Schema(type=openapi.TYPE_INTEGER),
                'completed_appointments': openapi.Schema(type=openapi.TYPE_INTEGER),
                'total_meetings': openapi.Schema(type=openapi.TYPE_INTEGER),
                'scheduled_meetings': openapi.Schema(type=openapi.TYPE_INTEGER),
                'ongoing_meetings': openapi.Schema(type=openapi.TYPE_INTEGER),
                'completed_meetings': openapi.Schema(type=openapi.TYPE_INTEGER),
                'total_users': openapi.Schema(type=openapi.TYPE_INTEGER),
                'total_active_users': openapi.Schema(type=openapi.TYPE_INTEGER),
                'total_clinics': openapi.Schema(type=openapi.TYPE_INTEGER),
                'subscriber_users': openapi.Schema(type=openapi.TYPE_INTEGER),
                'total_subadmins': openapi.Schema(type=openapi.TYPE_INTEGER),
                'total_parents': openapi.Schema(type=openapi.TYPE_INTEGER)
            }
        )
    )},
    operation_description="Get appointment, meeting, and user statistics for dashboard",
    tags=['Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """
    Admin/SubAdmin: Get dashboard statistics for appointment management and user stats
    """
    if not (request.user.is_admin or request.user.is_subadmin):
        return Response(
            {"detail": "Only admins or sub-admins can view dashboard stats."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    # Appointment statistics
    appointment_stats = Appointment.objects.aggregate(
        total=Count('id'),
        pending=Count('id', filter=Q(status='pending')),
        confirmed=Count('id', filter=Q(status='confirmed')),
        completed=Count('id', filter=Q(status='completed')),
        cancelled=Count('id', filter=Q(status='cancelled')),
    )
    
    # Meeting statistics
    meeting_stats = Meeting.objects.aggregate(
        total=Count('id'),
        scheduled=Count('id', filter=Q(status='scheduled')),
        ongoing=Count('id', filter=Q(status='ongoing')),
        completed=Count('id', filter=Q(status='completed')),
        cancelled=Count('id', filter=Q(status='cancelled')),
    )
    
    # User statistics
    user_stats = User.objects.aggregate(
        total_users=Count('id'),
        total_active_users=Count('id', filter=Q(is_active=True)),
        total_clinics=Count('id', filter=Q(user_type='clinic')),
        total_subadmins=Count('id', filter=Q(user_type='subadmin')),
        total_parents=Count('id', filter=Q(user_type='parent')),
    )
    
    # Subscriber users (users with active subscriptions)
    subscriber_users = UserSubscription.objects.filter(
        status='active',
        start_date__lte=timezone.now(),
        end_date__gte=timezone.now()
    ).values('user').distinct().count()
    
    # Recent appointments
    recent_appointments = Appointment.objects.select_related('clinic').order_by('-created_at')[:5]
    recent_appointments_data = AppointmentDetailSerializer(recent_appointments, many=True).data
    
    # Upcoming meetings
    upcoming_meetings = Meeting.objects.filter(
        status='scheduled',
        scheduled_datetime__gt=timezone.now()
    ).select_related('appointment').order_by('scheduled_datetime')[:5]
    upcoming_meetings_data = MeetingDetailSerializer(upcoming_meetings, many=True).data
    
    return Response({
        'success': True,
        'statistics': {
            'appointments': appointment_stats,
            'meetings': meeting_stats,
            'users': {
                'total_users': user_stats['total_users'],
                'total_active_users': user_stats['total_active_users'],
                'total_parents': user_stats['total_parents'],
                'total_clinics': user_stats['total_clinics'],
                'subscriber_users': subscriber_users,
                'total_subadmins': user_stats['total_subadmins'],
            }
        },
        'recent_appointments': recent_appointments_data,
        'upcoming_meetings': upcoming_meetings_data
    })

# ====================== CLINIC LIST FOR APPOINTMENTS ======================

@swagger_auto_schema(
    method='get',
    responses={200: openapi.Response(
        description="List of active clinics",
        schema=openapi.Schema(
            type=openapi.TYPE_ARRAY,
            items=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'id': openapi.Schema(type=openapi.TYPE_STRING),
                    'name': openapi.Schema(type=openapi.TYPE_STRING),
                    'email': openapi.Schema(type=openapi.TYPE_STRING),
                    'specialization': openapi.Schema(type=openapi.TYPE_STRING),
                    'years_of_experience': openapi.Schema(type=openapi.TYPE_INTEGER),
                }
            )
        )
    )},
    operation_description="Get list of active clinics for appointment booking",
    tags=['Appointments']
)
@api_view(['GET'])
@permission_classes([AllowAny])  # Public endpoint for clinic selection
def clinic_list_for_appointments(request):
    """
    Public endpoint: Get list of active clinics for appointment booking
    Used in donor form for clinic selection
    """
    clinics = User.objects.filter(
        user_type='clinic',
        is_active=True
        # is_verified=True
    ).values('id', 'first_name', 'last_name', 'email', 'specialization', 'years_of_experience')
    
    clinic_data = []
    for clinic in clinics:
        clinic_data.append({
            'id': clinic['id'],
            'name': f"{clinic['first_name']} {clinic['last_name']}".strip(),
            'email': clinic['email'],
            'specialization': clinic['specialization'] or 'General',
            'years_of_experience': clinic['years_of_experience'] or 0
        })
    
    return Response({
        'success': True,
        'clinics': clinic_data
    })

#################################SUBSCRIPTION MANAGEMENT#################################
class SubscriptionPlanViewSet(viewsets.ModelViewSet):
    queryset = SubscriptionPlan.objects.all()
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['name', 'billing_cycle', 'is_active']
    search_fields = ['name', 'description']
    ordering_fields = ['created_at', 'price', 'name']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        if self.action in ['update', 'partial_update']:
            return SubscriptionPlanUpdateSerializer
        return SubscriptionPlanSerializer
    
    def list(self, request, *args, **kwargs):
        """List all subscription plans"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'status': 'success',
            'message': 'Subscription plans retrieved successfully',
            'data': serializer.data
        })
    
    def create(self, request, *args, **kwargs):
        """Create a new subscription plan"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': 'success',
                'message': 'Subscription plan created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'status': 'error',
            'message': 'Failed to create subscription plan',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def retrieve(self, request, *args, **kwargs):
        """Get a specific subscription plan"""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            'status': 'success',
            'message': 'Subscription plan retrieved successfully',
            'data': serializer.data
        })
    
    def update(self, request, *args, **kwargs):
        """Update a subscription plan"""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        
        if serializer.is_valid():
            serializer.save()
            return Response({
                'status': 'success',
                'message': 'Subscription plan updated successfully',
                'data': serializer.data
            })
        
        return Response({
            'status': 'error',
            'message': 'Failed to update subscription plan',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    def destroy(self, request, *args, **kwargs):
        """Delete a subscription plan"""
        instance = self.get_object()
        
        # Check if any active subscriptions are using this plan
        active_subscriptions = UserSubscription.objects.filter(
            plan=instance, 
            status='active'
        ).count()
        
        if active_subscriptions > 0:
            return Response({
                'status': 'error',
                'message': f'Cannot delete plan. {active_subscriptions} active subscriptions are using this plan.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        instance.delete()
        return Response({
            'status': 'success',
            'message': 'Subscription plan deleted successfully'
        }, status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=True, methods=['post'])
    def toggle_status(self, request, pk=None):
        """Toggle active status of a subscription plan"""
        plan = self.get_object()
        plan.is_active = not plan.is_active
        plan.save()
        
        status_text = 'activated' if plan.is_active else 'deactivated'
        return Response({
            'status': 'success',
            'message': f'Subscription plan {status_text} successfully',
            'data': {'is_active': plan.is_active}
        })

    @action(detail=False, methods=['get'])
    def billing_cycles(self, request):
        """Get available billing cycles"""
        cycles = [{'value': cycle[0], 'label': cycle[1]} for cycle in SubscriptionPlan.BILLING_CYCLES]
        return Response({
            'status': 'success',
            'message': 'Billing cycles retrieved successfully',
            'data': cycles
        })


class UserSubscriptionViewSet(viewsets.ModelViewSet):
    queryset = UserSubscription.objects.select_related('user', 'plan').all()
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'payment_status', 'plan__name', 'plan__billing_cycle']
    search_fields = ['user__first_name', 'user__last_name', 'user__email']
    ordering_fields = ['created_at', 'start_date', 'end_date']
    ordering = ['-created_at']
    
    def get_serializer_class(self):
        if self.action == 'create':
            return UserSubscriptionCreateSerializer
        return UserSubscriptionSerializer
    
    def list(self, request, *args, **kwargs):
        """List all user subscriptions"""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'status': 'success',
            'message': 'User subscriptions retrieved successfully',
            'data': serializer.data
        })
    
    def create(self, request, *args, **kwargs):
        """Create a new user subscription"""
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            subscription = serializer.save()
            response_serializer = UserSubscriptionSerializer(subscription)
            return Response({
                'status': 'success',
                'message': 'User subscription created successfully',
                'data': response_serializer.data
            }, status=status.HTTP_201_CREATED)
        
        return Response({
            'status': 'error',
            'message': 'Failed to create user subscription',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['patch'])
    def update_status(self, request, pk=None):
        """Update subscription status"""
        subscription = self.get_object()
        new_status = request.data.get('status')
        
        if new_status not in ['active', 'inactive', 'expired', 'cancelled']:
            return Response({
                'status': 'error',
                'message': 'Invalid status. Must be one of: active, inactive, expired, cancelled'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        subscription.status = new_status
        subscription.save()
        
        return Response({
            'status': 'success',
            'message': f'Subscription status updated to {new_status}',
            'data': {'status': new_status}
        })
    
    @action(detail=True, methods=['post'])
    def activate(self, request, pk=None):
        """Activate a subscription"""
        subscription = self.get_object()
        subscription.activate()
        
        return Response({
            'status': 'success',
            'message': 'Subscription activated successfully',
            'data': UserSubscriptionSerializer(subscription).data
        })
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a subscription"""
        subscription = self.get_object()
        subscription.cancel()
        
        return Response({
            'status': 'success',
            'message': 'Subscription cancelled successfully',
            'data': UserSubscriptionSerializer(subscription).data
        })
    
    @action(detail=True, methods=['post'])
    def renew(self, request, pk=None):
        """Renew a subscription"""
        subscription = self.get_object()
        subscription.renew()
        
        return Response({
            'status': 'success',
            'message': 'Subscription renewed successfully',
            'data': UserSubscriptionSerializer(subscription).data
        })
    
    @action(detail=False, methods=['get'])
    def parent_users(self, request):
        """Get list of parent users for subscription assignment"""
        parent_users = User.objects.filter(user_type='parent')
        serializer = ParentUserSerializer(parent_users, many=True)
        
        return Response({
            'status': 'success',
            'message': 'Parent users retrieved successfully',
            'data': serializer.data
        })
    
    @action(detail=False, methods=['get'])
    def subscription_stats(self, request):
        """Get flat-format subscription statistics"""

        # Basic counts
        total_subscriptions = UserSubscription.objects.count()
        active_subscriptions = UserSubscription.objects.filter(status='active').count()
        expired_subscriptions = UserSubscription.objects.filter(status='expired').count()
        cancelled_subscriptions = UserSubscription.objects.filter(status='cancelled').count()

        # Plan-wise statistics
        plan_stats = {}
        for plan in SubscriptionPlan.objects.all():
            plan_subs = UserSubscription.objects.filter(plan=plan)
            plan_stats[f"{plan.name}_{plan.billing_cycle}"] = {
                'total': plan_subs.count(),
                'active': plan_subs.filter(status='active').count()
            }

        # Billing cycle statistics
        billing_cycle_stats = {}
        for cycle in ['month', 'year']:
            cycle_subs = UserSubscription.objects.filter(plan__billing_cycle=cycle)
            billing_cycle_stats[cycle] = {
                'total': cycle_subs.count(),
                'active': cycle_subs.filter(status='active').count()
            }

        # Revenue metrics
        total_revenue = UserSubscription.objects.filter(
            payment_status='completed'
        ).aggregate(total=Sum('plan__price'))['total'] or 0

        # Growth metrics
        current_month = timezone.now().replace(day=1)
        last_month = (current_month - timedelta(days=1)).replace(day=1)

        current_month_subs = UserSubscription.objects.filter(
            created_at__gte=current_month
        ).count()

        last_month_subs = UserSubscription.objects.filter(
            created_at__gte=last_month,
            created_at__lt=current_month
        ).count()

        growth_rate = 0
        if last_month_subs > 0:
            growth_rate = ((current_month_subs - last_month_subs) / last_month_subs) * 100

        # Churn rate
        thirty_days_ago = timezone.now() - timedelta(days=30)
        cancelled_last_30 = UserSubscription.objects.filter(
            status='cancelled',
            updated_at__gte=thirty_days_ago
        ).count()

        active_30_days_ago = UserSubscription.objects.filter(
            created_at__lt=thirty_days_ago,
            status='active'
        ).count()

        churn_rate = 0
        if active_30_days_ago > 0:
            churn_rate = (cancelled_last_30 / active_30_days_ago) * 100

        # Top plans
        top_plans = list(UserSubscription.objects.values(
            'plan__name', 'plan__billing_cycle'
        ).annotate(
            count=Count('id')
        ).order_by('-count')[:5])

        # Return everything flat under `data`
        return Response({
            'status': 'success',
            'message': 'Subscription statistics retrieved successfully',
            'data': {
                'total_subscriptions': total_subscriptions,
                'active_subscriptions': active_subscriptions,
                'expired_subscriptions': expired_subscriptions,
                'cancelled_subscriptions': cancelled_subscriptions,
                'total_revenue': float(total_revenue),
                'current_month_subscriptions': current_month_subs,
                'last_month_subscriptions': last_month_subs,
                'growth_rate': round(growth_rate, 2),
                'churn_rate': round(churn_rate, 2),
                'plan_statistics': plan_stats,
                'billing_cycle_statistics': billing_cycle_stats,
                'top_plans': top_plans
            }
        })

# ====================== DONOR IMPORT/EXPORT ======================

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="Template file downloaded successfully",
            schema=openapi.Schema(type=openapi.TYPE_FILE)
        )
    },
    operation_description="Download template file for donor import (CSV/Excel format)",
    tags=['Donor Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_donor_template(request):
    """Download template file for donor import - Clinic only"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can download donor templates."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    file_format = request.GET.get('format', 'csv').lower()
    
    # Define template columns with proper headers
    template_columns = {
        'title': 'Mr/Ms/Dr',
        'first_name': 'John',
        'last_name': 'Doe',
        'gender': 'male/female',
        'date_of_birth': '1990-01-15',
        'phone_number': '+1234567890',
        'email': 'john.doe@example.com',
        'location': 'City Center',
        'address': '123 Main Street',
        'city': 'Mumbai',
        'state': 'Maharashtra',
        'country': 'India',
        'postal_code': '400001',
        'donor_type': 'sperm/egg/surrogate',
        'blood_group': 'A+/A-/B+/B-/AB+/AB-/O+/O-',
        'height': '175.5',
        'weight': '70.0',
        'eye_color': 'Brown',
        'hair_color': 'Black',
        'skin_tone': 'Fair',
        'education_level': 'bachelor/master/phd/high_school/professional',
        'occupation': 'Software Engineer',
        'marital_status': 'single/married/divorced/widowed',
        'religion': 'Hindu',
        'ethnicity': 'Asian',
        'medical_history': 'No major health issues',
        'genetic_conditions': 'None',
        'medications': 'None',
        'allergies': 'None',
        'smoking_status': 'FALSE/TRUE',
        'alcohol_consumption': 'Occasional',
        'exercise_frequency': 'Regular',
        'number_of_children': '0',
        'family_medical_history': 'No hereditary diseases',
        'personality_traits': '{"outgoing": true, "creative": false}',
        'interests_hobbies': '["reading", "sports", "music"]',
        'notes': 'Additional notes about donor'
    }
    
    # Create DataFrame with template data
    df = pd.DataFrame([template_columns])
    
    if file_format == 'excel' or file_format == 'xlsx':
        # Create Excel file
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Donor_Template', index=False)
            
            # Add instructions sheet
            instructions = pd.DataFrame({
                'Field': list(template_columns.keys()),
                'Description': [
                    'Title (Mr, Ms, Dr)',
                    'First name of donor',
                    'Last name of donor',
                    'Gender (male/female)',
                    'Date of birth (YYYY-MM-DD format)',
                    'Phone number with country code',
                    'Email address',
                    'Location/Area',
                    'Full address',
                    'City name',
                    'State/Province',
                    'Country name',
                    'Postal/ZIP code',
                    'Type of donation (sperm/egg/surrogate)',
                    'Blood group (A+, A-, B+, B-, AB+, AB-, O+, O-)',
                    'Height in centimeters',
                    'Weight in kilograms',
                    'Eye color',
                    'Hair color',
                    'Skin tone',
                    'Education level',
                    'Current occupation',
                    'Marital status',
                    'Religion',
                    'Ethnicity',
                    'Medical history details',
                    'Genetic conditions if any',
                    'Current medications',
                    'Known allergies',
                    'Smoking status (TRUE/FALSE)',
                    'Alcohol consumption frequency',
                    'Exercise frequency',
                    'Number of children',
                    'Family medical history',
                    'Personality traits (JSON format)',
                    'Interests and hobbies (JSON array)',
                    'Additional notes'
                ]
            })
            instructions.to_excel(writer, sheet_name='Instructions', index=False)
        
        output.seek(0)
        response = HttpResponse(
            output.getvalue(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = 'attachment; filename="donor_import_template.xlsx"'
        
    else:  # CSV format
        output = io.StringIO()
        df.to_csv(output, index=False)
        
        response = HttpResponse(output.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="donor_import_template.csv"'
    
    return response

@swagger_auto_schema(
    method='post',
    request_body=DonorImportPreviewSerializer,
    responses={200: openapi.Response("File preview generated successfully")},
    operation_description="Preview imported donor data before final import. Reads donor_type from file.",
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def preview_donor_import(request):
    """Preview donor data from uploaded file - Clinic only"""
    if not request.user.is_clinic:
        return Response({"detail": "Only clinics can preview donor imports."}, status=status.HTTP_403_FORBIDDEN)
    
    serializer = DonorImportPreviewSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({'success': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    file = serializer.validated_data['file']
    rows_limit = serializer.validated_data['rows_limit']
    
    try:
        file_ext = os.path.splitext(file.name)[1].lower()
        file.seek(0)
        if file_ext == '.csv':
            content = file.read().decode('utf-8-sig')
            df = pd.read_csv(io.StringIO(urllib.parse.unquote_plus(content)))
        elif file_ext in ['.xlsx', '.xls']:
            df = pd.read_excel(file)
        elif file_ext == '.json':
            df = pd.DataFrame(json.loads(file.read().decode('utf-8-sig')))
        else:
            return Response({'success': False, 'message': 'Unsupported file format'}, status=status.HTTP_400_BAD_REQUEST)
        
        df.columns = df.columns.str.strip()
        if df.empty:
            return Response({'success': False, 'message': 'The uploaded file is empty'}, status=status.HTTP_400_BAD_REQUEST)
        
        preview_df = df.head(rows_limit)
        preview_data = []
        
        for index, row in preview_df.iterrows():
            row_number = index + 2  # Header is row 1
            row_data = {col: None if pd.isna(val) else val for col, val in row.items()}
            
            validation_result = validate_donor_row(row_data, row_number)
            
            preview_data.append({
                'row_number': row_number,
                'data': {k: str(v) if pd.notna(v) else None for k, v in row_data.items()},
                'errors': validation_result['errors'],
                'is_valid': not bool(validation_result['errors'])
            })
            
        valid_rows_count = sum(1 for item in preview_data if item['is_valid'])
        
        return Response({
            'success': True,
            'preview_data': preview_data,
            'total_rows': len(df),
            'preview_rows': len(preview_data),
            'columns': list(df.columns),
            'valid_rows': valid_rows_count,
            'invalid_rows': len(preview_data) - valid_rows_count,
        })
    
    except Exception as e:
        return Response({'success': False, 'message': f'Error processing file: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

# ====================== DONOR STATISTICS ======================

@swagger_auto_schema(
    method='get',
    responses={
        200: openapi.Response(
            description="Donor statistics",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'total_donors': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'by_type': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'by_status': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'by_blood_group': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'by_location': openapi.Schema(type=openapi.TYPE_OBJECT),
                }
            )
        )
    },
    operation_description="Get donor statistics (Clinic sees only their donors)",
    tags=['Donor Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def donor_statistics(request):
    """Get donor statistics"""
    if not (request.user.is_admin or request.user.is_subadmin or request.user.is_clinic):
        return Response(
            {"detail": "Access denied."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = Donor.objects.all()
    
    # Clinic can only see their own donors
    if request.user.is_clinic:
        queryset = queryset.filter(clinic=request.user)
    
    # Calculate statistics
    total_donors = queryset.count()
    
    # By donor type
    by_type = {}
    for choice in Donor.DONOR_TYPES:
        count = queryset.filter(donor_type=choice[0]).count()
        by_type[choice[1]] = count
    
    # By availability status
    by_status = {}
    for choice in Donor.AVAILABILITY_STATUS:
        count = queryset.filter(availability_status=choice[0]).count()
        by_status[choice[1]] = count
    
    # By blood group
    by_blood_group = {}
    for choice in Donor.BLOOD_GROUPS:
        count = queryset.filter(blood_group=choice[0]).count()
        if count > 0:
            by_blood_group[choice[1]] = count
    
    # By location (top 10)
    locations = queryset.values('location').annotate(count=models.Count('id')).order_by('-count')[:10]
    by_location = {item['location']: item['count'] for item in locations}
    
    # Recent additions (last 30 days)
    from datetime import timedelta
    thirty_days_ago = timezone.now() - timedelta(days=30)
    recent_additions = queryset.filter(created_at__gte=thirty_days_ago).count()
    
    return Response({
        'success': True,
        'statistics': {
            'total_donors': total_donors,
            'by_type': by_type,
            'by_status': by_status,
            'by_blood_group': by_blood_group,
            'by_location': by_location,
            'recent_additions': recent_additions,
            'active_donors': queryset.filter(is_active=True).count(),
            'inactive_donors': queryset.filter(is_active=False).count(),
        }
    })

# Bulk Delete Donors API
@swagger_auto_schema(
    method='post',
    request_body=DonorBulkDeleteSerializer,
    operation_description="Delete multiple donors at once and remove their embeddings from Pinecone",
    responses={
        200: openapi.Response("Donors deleted successfully"),
        400: openapi.Response("Invalid request data")
    },
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def bulk_delete_donors(request):
    """Delete multiple donors at once and remove their embeddings from Pinecone"""
    if not request.user.is_clinic:
        return Response({"detail": "Only clinics can delete donors."}, status=status.HTTP_403_FORBIDDEN)
    
    serializer = DonorBulkDeleteSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    donor_ids = serializer.validated_data['donor_ids']
    
    try:
        with transaction.atomic():
            # Get donors that exist and belong to the clinic
            existing_donors = Donor.objects.filter(
                donor_id__in=donor_ids,
                clinic=request.user,
                is_active=True
            )
            
            if not existing_donors.exists():
                return Response({
                    'success': False,
                    'message': 'No valid donors found to delete'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Store donor info for embedding deletion
            donors_info = []
            deleted_donors = []
            
            for donor in existing_donors:
                donors_info.append({
                    'donor_id': donor.donor_id,
                    'clinic_id': str(request.user.id)
                })
                deleted_donors.append({
                    'donor_id': donor.donor_id,
                    'name': donor.full_name
                })
            
            # Soft delete donors
            existing_donors.update(is_active=False)
            
            # Delete embeddings in background thread
            if donors_info:
                embedding_service = EmbeddingService()
                thread = threading.Thread(
                    target=embedding_service.bulk_delete_embeddings,
                    args=(donors_info,)
                )
                thread.daemon = True
                thread.start()
            
            # Check for donors that were not found
            found_ids = [donor.donor_id for donor in existing_donors]
            not_found_ids = [donor_id for donor_id in donor_ids if donor_id not in found_ids]
            
            response_data = {
                'success': True,
                'message': f'Successfully deleted {len(deleted_donors)} donors',
                'deleted_donors': deleted_donors,
                'deleted_count': len(deleted_donors)
            }
            
            if not_found_ids:
                response_data['not_found_donors'] = not_found_ids
                response_data['message'] += f'. {len(not_found_ids)} donors were not found.'
            
            return Response(response_data)
    
    except Exception as e:
        logger.error(f"Error in bulk_delete_donors: {str(e)}")
        return Response({
            'success': False,
            'message': f'An error occurred while deleting donors: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

###############################AI MATCHING ENDPOINTS####################################
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_fertility_profile(request):
    """Create or update fertility profile for parent"""
    if not request.user.is_parent:
        return Response(
            {"detail": "Only parents can create fertility profiles."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    donor_type = request.data.get('donor_type_preference')
    
    # Check if profile already exists for this parent and donor type
    try:
        existing_profile = FertilityProfile.objects.get(
            parent=request.user,
            donor_type_preference=donor_type
        )
        # Update existing profile
        serializer = FertilityProfileSerializer(
            existing_profile, 
            data=request.data, 
            context={'request': request}
        )
        action = 'updated'
    except FertilityProfile.DoesNotExist:
        # Create new profile
        serializer = FertilityProfileSerializer(
            data=request.data, 
            context={'request': request}
        )
        action = 'created'
    
    if serializer.is_valid():
        profile = serializer.save()
        return Response({
            'success': True,
            'message': f'Fertility profile {action} successfully',
            'profile_id': str(profile.id),
            'action': action
        }, status=status.HTTP_201_CREATED if action == 'created' else status.HTTP_200_OK)
    
    return Response({
        'success': False,
        'message': 'Please check the form data',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PATCH', 'PUT'])
@permission_classes([IsAuthenticated])
def update_fertility_profile(request, donor_type_preference):
    """Update fertility profile for parent by donor type"""
    if not request.user.is_parent:
        return Response(
            {"detail": "Only parents can update fertility profiles."},
            status=status.HTTP_403_FORBIDDEN,
        )

    try:
        profile = FertilityProfile.objects.get(parent=request.user, donor_type_preference=donor_type_preference)
    except FertilityProfile.DoesNotExist:
        return Response(
            {"detail": "Fertility profile not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    serializer = FertilityProfileSerializer(profile, data=request.data, partial=True, context={'request': request})
    if serializer.is_valid():
        serializer.save()
        return Response({
            'success': True,
            'message': 'Fertility profile updated successfully',
            'profile_id': str(profile.id)
        }, status=status.HTTP_200_OK)

    return Response({
        'success': False,
        'message': 'Validation error',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_fertility_profiles(request):
    """Get fertility profiles for the authenticated parent"""
    if not request.user.is_parent:
        return Response(
            {"detail": "Only parents can view fertility profiles."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    profiles = FertilityProfile.objects.filter(parent=request.user).order_by('-created_at')
    
    profile_data = []
    for profile in profiles:
        profile_data.append({
            'id': str(profile.id),
            'donor_type_preference': profile.donor_type_preference,
            'location': profile.location,
            'created_at': profile.created_at.isoformat(),
            'has_matches': MatchingResult.objects.filter(fertility_profile=profile).exists()
        })
    
    return Response({
        'success': True,
        'profiles': profile_data
    })

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def trigger_donor_embedding_on_create(request):
    """Trigger embedding generation when donor is created/updated"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can trigger donor embeddings."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    donor_id = request.data.get('donor_id')
    if not donor_id:
        return Response({
            'success': False,
            'message': 'Donor ID is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        donor = Donor.objects.get(donor_id=donor_id, clinic=request.user)
        
        # Initialize embedding service
        embedding_service = EmbeddingService()
        
        # Create donor data
        donor_data = {
            'gender': donor.gender,
            'donor_type': donor.donor_type,
            'height': donor.height,
            'eye_color': donor.eye_color,
            'hair_color': donor.hair_color,
            'ethnicity': donor.ethnicity,
            'skin_tone': donor.skin_tone,
            'education_level': donor.education_level,
            'occupation': donor.occupation,
            'blood_group': donor.blood_group,
            'smoking_status': donor.smoking_status,
            'alcohol_consumption': donor.alcohol_consumption,
            'religion': donor.religion,
            'marital_status': donor.marital_status,
            'personality_traits': donor.personality_traits,
            'interests_hobbies': donor.interests_hobbies,
            'date_of_birth': donor.date_of_birth,
            'genetic_conditions': donor.genetic_conditions,
            'medical_history': donor.medical_history,
        }
        
        # Generate and store embedding
        donor_text = embedding_service.create_donor_text(donor_data)
        embedding = embedding_service.generate_embedding(donor_text)
        
        metadata = {
            'donor_type': donor.donor_type,
            'gender': donor.gender,
            'education_level': donor.education_level,
            'ethnicity': donor.ethnicity,
            'location': donor.location,
        }
        
        embedding_service.store_donor_embedding(
            donor_id=donor.donor_id,
            clinic_id=str(donor.clinic.id),
            embedding=embedding,
            metadata=metadata
        )
        
        return Response({
            'success': True,
            'message': f'Embedding generated successfully for donor {donor_id}'
        })
        
    except Donor.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Donor not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Failed to generate embedding for donor {donor_id}: {e}")
        return Response({
            'success': False,
            'message': f'Failed to generate embedding: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ==============================================================================
# STRIPE PAYMENT FLOW VIEWS
# ==============================================================================

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={'plan_id': openapi.Schema(type=openapi.TYPE_STRING, description='ID of the SubscriptionPlan')}
    ),
    operation_description="Create a Stripe Checkout Session for a parent to subscribe to a plan.",
    tags=['Payments']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_checkout_session(request):
    user = request.user
    if user.user_type != 'parent':
        return Response({"error": "Only parents can subscribe to plans."}, status=status.HTTP_403_FORBIDDEN)

    plan_id = request.data.get('plan_id')
    try:
        plan = SubscriptionPlan.objects.get(id=plan_id)
        if not plan.stripe_price_id:
            return Response({"error": "This plan is not configured for payment."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if user already has an active subscription
        existing_subscription = UserSubscription.objects.filter(
            user=user,
            status='active'
        ).first()
        
        if existing_subscription:
            return Response({
                "error": "You already have an active subscription. Please cancel it first."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get or create a Stripe Customer for the user
        customer_id = create_stripe_customer(user)

        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{'price': plan.stripe_price_id, 'quantity': 1}],
            mode='subscription',
            success_url=settings.STRIPE_REDIRECT_DOMAIN + '/payment-success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=settings.STRIPE_REDIRECT_DOMAIN + '/payment-cancelled',
            metadata={
                'user_id': str(user.id), 
                'plan_id': str(plan.id),
                'user_email': user.email,
                'plan_name': plan.name,
                'billing_cycle': plan.billing_cycle
            }
        )
        
        return Response({
            'sessionId': checkout_session.id, 
            'url': checkout_session.url,
            'plan_name': plan.get_name_display(),
            'plan_price': str(plan.price),
            'billing_cycle': plan.get_billing_cycle_display()
        })

    except SubscriptionPlan.DoesNotExist:
        return Response({"error": "Subscription plan not found."}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        print(f"Error creating checkout session: {e}")
        return Response({'error': 'Failed to create checkout session'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@swagger_auto_schema(
    method='post',
    operation_description="Create a Stripe Customer Portal session for a parent to manage their subscription.",
    tags=['Payments']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_customer_portal_session(request):
    """
    Generates a one-time link for the parent to manage their billing information.
    """
    user = request.user
    if not user.stripe_customer_id:
         return Response({"error": "User is not a Stripe customer."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        print("stripe customer id", user.stripe_customer_id)
        portal_session = stripe.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=settings.STRIPE_REDIRECT_DOMAIN + '/profile',
        )
        return Response({'url': portal_session.url})
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@api_view(['POST'])
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        print(f"Invalid payload: {e}")
        return Response(status=status.HTTP_400_BAD_REQUEST)
    except stripe.error.SignatureVerificationError as e:
        print(f"Invalid signature: {e}")
        return Response(status=status.HTTP_400_BAD_REQUEST)

    print(f"Received webhook event: {event['type']}")

    # Handle the checkout.session.completed event
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        user_id = session.get('metadata', {}).get('user_id')
        plan_id = session.get('metadata', {}).get('plan_id')
        stripe_customer_id = session.get('customer')
        stripe_subscription_id = session.get('subscription')

        try:
            user = User.objects.get(id=user_id)
            plan = SubscriptionPlan.objects.get(id=plan_id)

            # Get subscription details from Stripe
            stripe_subscription = stripe.Subscription.retrieve(stripe_subscription_id)
            
            # Calculate end date based on current period
            start_date = timezone.make_aware(datetime.fromtimestamp(stripe_subscription.current_period_start))
            end_date = timezone.make_aware(datetime.fromtimestamp(stripe_subscription.current_period_end))

            # Create or update the UserSubscription record
            subscription, created = UserSubscription.objects.update_or_create(
                user=user,
                stripe_subscription_id=stripe_subscription_id,
                defaults={
                    'plan': plan,
                    'status': 'active',
                    'start_date': start_date,
                    'end_date': end_date,
                    'payment_status': 'completed',
                    'transaction_id': session.get('payment_intent', ''),
                }
            )

            # Cancel any other active subscriptions for this user
            UserSubscription.objects.filter(
                user=user,
                status='active'
            ).exclude(id=subscription.id).update(status='cancelled')

            # Ensure the user's stripe_customer_id is saved
            if not user.stripe_customer_id:
                user.stripe_customer_id = stripe_customer_id
                user.save(update_fields=['stripe_customer_id'])

            print(f"Subscription {'created' if created else 'updated'} for user {user.email}")

        except (User.DoesNotExist, SubscriptionPlan.DoesNotExist) as e:
            print(f"Webhook Error (checkout.session.completed): {e}")
            return Response(status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(f"Unexpected error in checkout.session.completed: {e}")
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # Handle recurring payment success
    elif event['type'] == 'invoice.paid':
        invoice = event['data']['object']
        stripe_subscription_id = invoice.get('subscription')
        
        if stripe_subscription_id:
            try:
                subscription = UserSubscription.objects.get(stripe_subscription_id=stripe_subscription_id)
                stripe_sub = stripe.Subscription.retrieve(stripe_subscription_id)
                
                # Update subscription with new period
                subscription.end_date = timezone.make_aware(
                    datetime.fromtimestamp(stripe_sub.current_period_end)
                )
                subscription.status = 'active'
                subscription.payment_status = 'completed'
                subscription.save()
                
                print(f"Subscription renewed for user {subscription.user.email}")
                
            except UserSubscription.DoesNotExist:
                print(f"Subscription not found for stripe_subscription_id: {stripe_subscription_id}")
            except Exception as e:
                print(f"Error handling invoice.paid: {e}")

    # Handle subscription cancellation
    elif event['type'] == 'customer.subscription.deleted':
        sub_event = event['data']['object']
        stripe_subscription_id = sub_event.get('id')
        
        try:
            subscription = UserSubscription.objects.get(stripe_subscription_id=stripe_subscription_id)
            subscription.status = 'cancelled'
            subscription.save()
            
            print(f"Subscription cancelled for user {subscription.user.email}")
            
        except UserSubscription.DoesNotExist:
            print(f"Subscription not found for cancellation: {stripe_subscription_id}")
        except Exception as e:
            print(f"Error handling subscription deletion: {e}")

    # Handle payment failure
    elif event['type'] == 'invoice.payment_failed':
        invoice = event['data']['object']
        stripe_subscription_id = invoice.get('subscription')
        
        if stripe_subscription_id:
            try:
                subscription = UserSubscription.objects.get(stripe_subscription_id=stripe_subscription_id)
                subscription.payment_status = 'failed'
                subscription.save()
                
                print(f"Payment failed for user {subscription.user.email}")
                
            except UserSubscription.DoesNotExist:
                print(f"Subscription not found for payment failure: {stripe_subscription_id}")
            except Exception as e:
                print(f"Error handling payment failure: {e}")

    return Response(status=status.HTTP_200_OK)

def payment_success(request):
    """Handle successful payment redirect"""
    session_id = request.GET.get('session_id')
    
    try:
        # Retrieve session from Stripe to get details
        session = stripe.checkout.Session.retrieve(session_id)
        user_id = session.get('metadata', {}).get('user_id')
        plan_id = session.get('metadata', {}).get('plan_id')
        
        # Get subscription details
        subscription = None
        if user_id and plan_id:
            try:
                user = User.objects.get(id=user_id)
                subscription = UserSubscription.objects.filter(
                    user=user,
                    status='active'
                ).first()
            except User.DoesNotExist:
                pass
        
        context = {
            'session_id': session_id,
            'message': 'Payment successful! Your subscription is now active.',
            'subscription': subscription,
            'plan_name': session.get('metadata', {}).get('plan_name', ''),
            'billing_cycle': session.get('metadata', {}).get('billing_cycle', '')
        }
        
    except Exception as e:
        print(f"Error retrieving session: {e}")
        context = {
            'session_id': session_id,
            'message': 'Payment successful! Your subscription is now active.',
            'error': 'Could not retrieve subscription details'
        }
    
    return render(request, 'payment_success.html', context)

def payment_cancelled(request):
    """Handle cancelled payment redirect"""
    context = {
        'message': 'Payment was cancelled. You can try again anytime.'
    }
    return render(request, 'payment_cancelled.html', context)


################################################REFACTORED AI MATCHING AND DONER UPLOAD################################
class DonorViewSet(viewsets.ModelViewSet):
    serializer_class = DonorDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    lookup_field = 'donor_id'

    def get_queryset(self):
        user = self.request.user
        if user.is_clinic:
            return Donor.objects.filter(clinic=user, is_active=True).order_by('-created_at')
        return Donor.objects.none()

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return DonorUpdateSerializer
        return DonorDetailSerializer

    def create(self, request, *args, **kwargs):
        # We must inject the clinic and created_by from the request user
        request.data['clinic'] = request.user.id
        request.data['created_by'] = request.user.id
        
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        
        # After creation, serialize with the detail serializer for the response
        response_data = DonorDetailSerializer(serializer.instance).data
        
        headers = self.get_success_headers(response_data)
        return Response({
            "success": True,
            "message": "Donor profile created successfully.",
            "data": response_data
        }, status=status.HTTP_201_CREATED, headers=headers)

    def list(self, request, *args, **kwargs):
        user = request.user
        if not user.is_clinic:
            return Response({"success": False, "message": "Only clinics can view donors."}, status=status.HTTP_403_FORBIDDEN)

        try:
            # Get base queryset
            queryset = Donor.objects.filter(clinic=user, is_active=True)

            # Apply search filter
            search = request.GET.get('search', '').strip()
            if search:
                queryset = queryset.filter(
                    Q(first_name__icontains=search) |
                    Q(last_name__icontains=search) |
                    Q(donor_id__icontains=search) |
                    Q(location__icontains=search)
                )

            # Apply additional filters
            donor_type = request.GET.get('donor_type')
            if donor_type:
                queryset = queryset.filter(donor_type=donor_type)

            availability_status = request.GET.get('availability_status')
            if availability_status:
                queryset = queryset.filter(availability_status=availability_status)

            gender = request.GET.get('gender')
            if gender:
                queryset = queryset.filter(gender=gender)

            blood_group = request.GET.get('blood_group')
            if blood_group:
                queryset = queryset.filter(blood_group=blood_group)

            # Apply ordering
            ordering = request.GET.get('ordering', '-created_at')
            valid_ordering_fields = [
                'created_at', '-created_at', 'updated_at', '-updated_at',
                'first_name', '-first_name', 'last_name', '-last_name',
                'donor_id', '-donor_id', 'age', '-age', 'donor_type', '-donor_type'
            ]
            if ordering in valid_ordering_fields:
                if ordering in ['age', '-age']:
                    ordering = '-date_of_birth' if ordering == 'age' else 'date_of_birth'
                queryset = queryset.order_by(ordering)

            # Pagination
            page = request.GET.get('page', 1)
            page_size = min(int(request.GET.get('page_size', 20)), 100)  # Cap at 100
            paginator = Paginator(queryset, page_size)
            page_obj = paginator.get_page(page)

            serializer = self.get_serializer(page_obj, many=True)

            return Response({
                'success': True,
                'message': "Donors retrieved successfully.",
                'data': serializer.data,
                'pagination': {
                    'current_page': page_obj.number,
                    'total_pages': paginator.num_pages,
                    'total_items': paginator.count,
                    'page_size': page_size,
                    'has_next': page_obj.has_next(),
                    'has_previous': page_obj.has_previous(),
                },
                'filters_applied': {
                    'search': search,
                    'donor_type': donor_type,
                    'availability_status': availability_status,
                    'gender': gender,
                    'blood_group': blood_group,
                    'ordering': ordering
                }
            })

        except Exception as e:
            logger.error(f"Error in DonorViewSet.list: {str(e)}")
            return Response({
                'success': False,
                'message': f"An error occurred while fetching donors: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        return Response({
            "success": True,
            "message": "Donor details retrieved successfully.",
            "data": response.data
        })

    def perform_update(self, serializer):
        updated_fields = list(serializer.validated_data.keys())
        if 'updated_at' not in updated_fields:
            updated_fields.append('updated_at')
        serializer.save(update_fields=updated_fields)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        return Response({
            "success": True,
            "message": "Donor profile updated successfully.",
            "data": response.data
        })

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        return Response({
            "success": True,
            "message": "Donor profile partially updated successfully.",
            "data": response.data
        })

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        donor_id_for_message = instance.donor_id
        
        # The pre_delete signal will fire here, triggering the Pinecone deletion.
        self.perform_destroy(instance)
        
        return Response({
            "success": True,
            "message": f"Donor {donor_id_for_message} and all associated data have been successfully deleted."
        }, status=status.HTTP_200_OK)
    
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def import_donors_view(request):
    """Import donor data from a file - Clinic only."""
    if not request.user.is_clinic:
        return Response({"detail": "Only clinics can import donors."}, status=status.HTTP_403_FORBIDDEN)

    serializer = DonorImportSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({'success': False, 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    service = DonorImportService(file=serializer.validated_data['file'], clinic_user=request.user)
    result = service.process_import()
    
    return Response(result, status=result.get('status', 200))

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def find_matching_donors_view(request):
    if not request.user.is_parent:
        return Response({"detail": "Only parents can search for matches."}, status=status.HTTP_403_FORBIDDEN)

    profile_id = request.data.get('profile_id')
    try:
        profile = FertilityProfile.objects.get(id=profile_id, parent=request.user)
        service = DonorMatchingService(fertility_profile=profile)
        result = service.find_matches()
        return Response(result)
    except FertilityProfile.DoesNotExist:
        return Response({'success': False, 'message': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error in find_matching_donors_view: {e}", exc_info=True)
        return Response({'success': False, 'message': 'An unexpected error occurred.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
@permission_classes([AllowAny])
def contact_us_view(request):
    serializer = ContactUsSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({
            "message": "Your query has been submitted successfully."
        }, status=status.HTTP_201_CREATED)
    return Response({
        "error": serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)
    
class AdminBlogViewSet(viewsets.ModelViewSet):
    """
    Admin CRUD operations for blogs
    """
    queryset = BlogMaster.objects.all()
    serializer_class = BlogSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'is_featured', 'created_by']
    search_fields = ['title', 'content', 'excerpt']
    ordering_fields = ['created_at', 'updated_at', 'published_at', 'view_count']
    ordering = ['-created_at']
    
    def get_queryset(self):
        user = self.request.user
        queryset = BlogMaster.objects.all()
        # If subadmin, only show their own blogs
        if not (user.user_type in ['admin', 'subadmin']):
            return User.objects.none()
        return queryset
    
    @action(detail=True, methods=['post'])
    def publish(self, request, pk=None):
        """Publish a blog post"""
        blog = self.get_object()
        blog.status = 'published'
        blog.save()
        return Response({'status': 'Blog published successfully'})
    
    @action(detail=True, methods=['post'])
    def unpublish(self, request, pk=None):
        """Unpublish a blog post"""
        blog = self.get_object()
        blog.status = 'draft'
        blog.save()
        return Response({'status': 'Blog unpublished successfully'})
    
    @action(detail=True, methods=['post'])
    def feature(self, request, pk=None):
        """Feature/unfeature a blog post"""
        blog = self.get_object()
        blog.is_featured = not blog.is_featured
        blog.save()
        status_text = 'featured' if blog.is_featured else 'unfeatured'
        return Response({'status': f'Blog {status_text} successfully'})


class PublicBlogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public API to view published blogs
    """
    queryset = BlogMaster.objects.filter(status='published')
    serializer_class = PublicBlogSerializer
    permission_classes = [AllowAny]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['is_featured']
    search_fields = ['title', 'content', 'excerpt']
    ordering_fields = ['published_at', 'view_count']
    ordering = ['-published_at']
    
    def retrieve(self, request, *args, **kwargs):
        """Override retrieve to increment view count"""
        instance = self.get_object()
        # Increment view count
        BlogMaster.objects.filter(pk=instance.pk).update(view_count=instance.view_count + 1)
        # Refresh instance to get updated view count
        instance.refresh_from_db()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def featured(self, request):
        """Get featured blogs"""
        featured_blogs = self.get_queryset().filter(is_featured=True)
        page = self.paginate_queryset(featured_blogs)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(featured_blogs, many=True)
        return Response(serializer.data)
    
    @action(detail=False, methods=['get'])
    def recent(self, request):
        """Get recent blogs (last 10)"""
        recent_blogs = self.get_queryset()[:10]
        serializer = self.get_serializer(recent_blogs, many=True)
        return Response(serializer.data)
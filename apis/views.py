from datetime import date
from decimal import Decimal
import io
import logging
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
from apis.email_service import EmailService
from apis.services.embeddingsMatching import DonorMatchingEngine, EmbeddingService, MatchResult
from .models import Appointment, MatchingResult, Meeting, User
from django.db.models import Q, Count
from .serializers import *
from django.shortcuts import get_object_or_404, render
from django.db.models import Q
from rest_framework.pagination import PageNumberPagination
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser
import pandas as pd
import json
import csv
from io import StringIO
from django.db import transaction
from django.http import HttpResponse
from django.db import models
from rest_framework.decorators import api_view, permission_classes, parser_classes
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
    Login user - requires verified email address
    """
    serializer = LoginSerializer(data=request.data, context={'request': request})
    
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Double check verification status (extra safety)
        if not user.is_verified:
            return Response({
                'message': 'Please verify your email address before logging in.',
                'success': False
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # User is verified, proceed with login
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

@swagger_auto_schema(
    method='post',
    request_body=AdminLoginSerializer,
    responses={
        200: openapi.Response(
            description="Login successful",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'access': openapi.Schema(type=openapi.TYPE_STRING),
                    'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'email': openapi.Schema(type=openapi.TYPE_STRING),
                            'user_type': openapi.Schema(type=openapi.TYPE_STRING),
                            'full_name': openapi.Schema(type=openapi.TYPE_STRING)
                        }
                    )
                }
            )
        ),
        400: "Invalid credentials"
    },
    operation_description="Login for Admin or SubAdmin",
    tags=['Authentication']
)
@api_view(['POST'])
@permission_classes([AllowAny])
def admin_login_view(request):
    serializer = AdminLoginSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        return Response(serializer.validated_data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
@api_view(["POST"])
@permission_classes([IsAuthenticated])         # only need to be logged in
def create_subadmin(request):
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can create sub‑admin accounts."},
            status=status.HTTP_403_FORBIDDEN,
        )

    serializer = SubAdminCreateSerializer(
        data=request.data, context={"request": request}
    )
    if serializer.is_valid():
        subadmin = serializer.save()
        return Response(
            {
                "message": "Sub‑admin created successfully",
                "subadmin": UserSerializer(subadmin).data,
            },
            status=status.HTTP_201_CREATED,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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
    Get current user profile
    """
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_email(request):
    serializer = ForgotPasswordEmailSerializer(data=request.data)
    if serializer.is_valid():
        otp_instance = serializer.save()
        
        return Response({
            'message': 'OTP sent to your email successfully',
            'email': serializer.validated_data['email']
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
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name or email", type=openapi.TYPE_STRING),
    ],
    responses={200: UserSerializer(many=True)},
    operation_description="Get list of all subadmins (Admin only)",
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
    
    paginator = StandardResultsSetPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = UserSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name or email", type=openapi.TYPE_STRING),
    ],
    responses={200: UserSerializer(many=True)},
    operation_description="Get list of all clinics (Admin/SubAdmin only)",
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
    
    paginator = StandardResultsSetPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = UserSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)

@swagger_auto_schema(
    method='get',
    manual_parameters=[
        openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
        openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page", type=openapi.TYPE_INTEGER),
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name or email", type=openapi.TYPE_STRING),
    ],
    responses={200: UserSerializer(many=True)},
    operation_description="Get list of all parents (Admin only - Read only)",
    tags=['User Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def parent_list(request):
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can view parent list."},
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
    
    paginator = StandardResultsSetPagination()
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
    if not (request.user.is_admin or (request.user.is_parent and str(request.user.id) == str(user_id))):
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
    if not (request.user.is_admin or (request.user.is_parent and str(request.user.id) == str(user_id))):
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
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can delete parent."},
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
    if not request.user.is_admin:
        return Response(
            {"detail": "Only admins can delete appointments."},
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
            }
        )
    )},
    operation_description="Get appointment and meeting statistics for dashboard",
    tags=['Dashboard']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard_stats(request):
    """
    Admin/SubAdmin: Get dashboard statistics for appointment management
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
        """Get subscription statistics"""
        total_subscriptions = UserSubscription.objects.count()
        active_subscriptions = UserSubscription.objects.filter(status='active').count()
        expired_subscriptions = UserSubscription.objects.filter(status='expired').count()
        cancelled_subscriptions = UserSubscription.objects.filter(status='cancelled').count()
        
        # Plan wise statistics
        plan_stats = {}
        for plan in SubscriptionPlan.objects.all():
            plan_subs = UserSubscription.objects.filter(plan=plan)
            plan_stats[f"{plan.name}_{plan.billing_cycle}"] = {
                'total': plan_subs.count(),
                'active': plan_subs.filter(status='active').count()
            }
        
        # Billing cycle statistics
        billing_cycle_stats = {}
        for cycle in ['monthly', 'quarterly', 'yearly']:
            cycle_subs = UserSubscription.objects.filter(plan__billing_cycle=cycle)
            billing_cycle_stats[cycle] = {
                'total': cycle_subs.count(),
                'active': cycle_subs.filter(status='active').count()
            }
        
        return Response({
            'status': 'success',
            'message': 'Subscription statistics retrieved successfully',
            'data': {
                'total_subscriptions': total_subscriptions,
                'active_subscriptions': active_subscriptions,
                'expired_subscriptions': expired_subscriptions,
                'cancelled_subscriptions': cancelled_subscriptions,
                'plan_statistics': plan_stats,
                'billing_cycle_statistics': billing_cycle_stats
            }
        })
    
# ====================== DONOR MANAGEMENT ======================

@swagger_auto_schema(
    method='post',
    request_body=DonorCreateSerializer,
    responses={
        201: openapi.Response(
            description="Donor created successfully",
            schema=DonorDetailSerializer
        ),
        400: "Bad Request",
        403: "Forbidden - Clinic access only"
    },
    operation_description="Create new donor (Clinic only)",
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_donor(request):
    """Create new donor - Clinic only"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can create donors."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    serializer = DonorCreateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        donor = serializer.save()
        return Response({
            'success': True,
            'message': 'Donor created successfully',
            'donor': DonorDetailSerializer(donor).data
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
        openapi.Parameter('search', openapi.IN_QUERY, description="Search by name, donor_id, or location", type=openapi.TYPE_STRING),
        openapi.Parameter('donor_type', openapi.IN_QUERY, description="Filter by donor type", type=openapi.TYPE_STRING),
        openapi.Parameter('availability_status', openapi.IN_QUERY, description="Filter by availability", type=openapi.TYPE_STRING),
        openapi.Parameter('blood_group', openapi.IN_QUERY, description="Filter by blood group", type=openapi.TYPE_STRING),
        openapi.Parameter('location', openapi.IN_QUERY, description="Filter by location", type=openapi.TYPE_STRING),
        openapi.Parameter('min_age', openapi.IN_QUERY, description="Minimum age filter", type=openapi.TYPE_INTEGER),
        openapi.Parameter('max_age', openapi.IN_QUERY, description="Maximum age filter", type=openapi.TYPE_INTEGER),
        openapi.Parameter('gender', openapi.IN_QUERY, description="Filter by gender", type=openapi.TYPE_STRING),
        openapi.Parameter('education_level', openapi.IN_QUERY, description="Filter by education level", type=openapi.TYPE_STRING),
        openapi.Parameter('is_active', openapi.IN_QUERY, description="Filter by active status", type=openapi.TYPE_BOOLEAN),
    ],
    responses={200: DonorListSerializer(many=True)},
    operation_description="Get all donors with filters (Clinic sees only their donors, Admin/SubAdmin see all)",
    tags=['Donor Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def donor_list(request):
    """Get all donors with filters"""
    if not (request.user.is_admin or request.user.is_subadmin or request.user.is_clinic):
        return Response(
            {"detail": "Access denied."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    # Base queryset
    queryset = Donor.objects.select_related('clinic', 'created_by').prefetch_related('images')
    
    # Clinic can only see their own donors
    if request.user.is_clinic:
        queryset = queryset.filter(clinic=request.user)
    
    # Search functionality
    search = request.query_params.get('search', None)
    if search:
        queryset = queryset.filter(
            Q(first_name__icontains=search) | 
            Q(last_name__icontains=search) | 
            Q(donor_id__icontains=search) |
            Q(location__icontains=search) |
            Q(email__icontains=search) |
            Q(phone_number__icontains=search)
        )
    
    # Filter by donor type
    donor_type = request.query_params.get('donor_type', None)
    if donor_type:
        queryset = queryset.filter(donor_type=donor_type)
    
    # Filter by availability status
    availability_status = request.query_params.get('availability_status', None)
    if availability_status:
        queryset = queryset.filter(availability_status=availability_status)
    
    # Filter by blood group
    blood_group = request.query_params.get('blood_group', None)
    if blood_group:
        queryset = queryset.filter(blood_group=blood_group)
    
    # Filter by location
    location = request.query_params.get('location', None)
    if location:
        queryset = queryset.filter(location__icontains=location)
    
    # Filter by gender
    gender = request.query_params.get('gender', None)
    if gender:
        queryset = queryset.filter(gender=gender)
    
    # Filter by education level
    education_level = request.query_params.get('education_level', None)
    if education_level:
        queryset = queryset.filter(education_level=education_level)
    
    # Age filtering
    min_age = request.query_params.get('min_age', None)
    max_age = request.query_params.get('max_age', None)
    
    if min_age or max_age:
        from datetime import date, timedelta
        today = date.today()
        
        if min_age:
            max_birth_date = today - timedelta(days=int(min_age) * 365)
            queryset = queryset.filter(date_of_birth__lte=max_birth_date)
        
        if max_age:
            min_birth_date = today - timedelta(days=int(max_age) * 365)
            queryset = queryset.filter(date_of_birth__gte=min_birth_date)
    
    # Active status filter
    is_active = request.query_params.get('is_active', None)
    if is_active is not None:
        queryset = queryset.filter(is_active=is_active.lower() == 'true')
    
    # Order by
    queryset = queryset.order_by('-created_at')
    
    # Pagination
    paginator = StandardResultsSetPagination()
    paginated_queryset = paginator.paginate_queryset(queryset, request)
    serializer = DonorListSerializer(paginated_queryset, many=True)
    
    return paginator.get_paginated_response(serializer.data)


@swagger_auto_schema(
    method='get',
    responses={200: DonorDetailSerializer()},
    operation_description="Get donor details",
    tags=['Donor Management']
)
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def donor_detail(request, donor_id):
    """Get specific donor details"""
    if not (request.user.is_admin or request.user.is_subadmin or request.user.is_clinic):
        return Response(
            {"detail": "Access denied."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = Donor.objects.select_related('clinic', 'created_by').prefetch_related('images', 'documents_files')
    
    # Clinic can only see their own donors
    if request.user.is_clinic:
        queryset = queryset.filter(clinic=request.user)
    
    donor = get_object_or_404(queryset, id=donor_id)
    serializer = DonorDetailSerializer(donor)
    
    return Response({
        'success': True,
        'donor': serializer.data
    })


@swagger_auto_schema(
    method='put',
    request_body=DonorUpdateSerializer,
    responses={200: DonorDetailSerializer()},
    operation_description="Update donor information (Clinic can update only their donors)",
    tags=['Donor Management']
)
@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def donor_update(request, donor_id):
    """Update donor information"""
    if not (request.user.is_admin or request.user.is_subadmin or request.user.is_clinic):
        return Response(
            {"detail": "Access denied."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = Donor.objects.all()
    
    # Clinic can only update their own donors
    if request.user.is_clinic:
        queryset = queryset.filter(clinic=request.user)
    
    donor = get_object_or_404(queryset, id=donor_id)
    
    serializer = DonorUpdateSerializer(donor, data=request.data, partial=True)
    if serializer.is_valid():
        donor = serializer.save()
        return Response({
            'success': True,
            'message': 'Donor updated successfully',
            'donor': DonorDetailSerializer(donor).data
        })
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='delete',
    responses={204: "Donor deleted successfully"},
    operation_description="Delete donor (Clinic can delete only their donors)",
    tags=['Donor Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def donor_delete(request, donor_id):
    """Delete donor"""
    if not (request.user.is_admin or request.user.is_subadmin or request.user.is_clinic):
        return Response(
            {"detail": "Access denied."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    queryset = Donor.objects.all()
    
    # Clinic can only delete their own donors
    if request.user.is_clinic:
        queryset = queryset.filter(clinic=request.user)
    
    donor = get_object_or_404(queryset, id=donor_id)
    print("donor:", donor)
    print("doner appointment",Appointment.objects.filter(
        Q(reason_for_consultation__icontains='donor') |
        Q(additional_notes__icontains=donor.donor_id)
    ))
    # Check if donor has any appointments
    if Appointment.objects.filter(
        Q(reason_for_consultation__icontains='donor') |
        Q(additional_notes__icontains=donor.donor_id)
    ).exists():
        return Response({
            'success': False,
            'message': 'Cannot delete donor with existing appointments.'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    donor.delete()
    return Response({
        'success': True,
        'message': 'Donor deleted successfully'
    }, status=status.HTTP_204_NO_CONTENT)


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
        'donor_type': 'sperm/egg/embryo',
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
                    'Type of donation (sperm/egg/embryo)',
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
    responses={
        200: openapi.Response(
            description="File preview generated successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'preview_data': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_STRING)
                    ),
                    'total_rows': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'columns': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_STRING)
                    ),
                    'validation_errors': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_STRING)
                    ),
                    'valid_rows': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'invalid_rows': openapi.Schema(type=openapi.TYPE_INTEGER)
                }
            )
        ),
        400: "Bad Request"
    },
    operation_description="Preview imported donor data before final import",
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def preview_donor_import(request):
    """Preview donor data from uploaded file - Clinic only"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can preview donor imports."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    serializer = DonorImportPreviewSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    file = serializer.validated_data['file']
    donor_type = serializer.validated_data['donor_type']
    rows_limit = serializer.validated_data['rows_limit']
    
    try:
        # Parse file based on extension
        file_ext = os.path.splitext(file.name)[1].lower()
        
        if file_ext == '.csv':
            # Reset file pointer and read with proper encoding
            file.seek(0)
            content = file.read().decode('utf-8')
            # URL decode the content
            import urllib.parse
            content = urllib.parse.unquote_plus(content)
            df = pd.read_csv(io.StringIO(content))
        elif file_ext in ['.xlsx', '.xls']:
            df = pd.read_excel(file)
        elif file_ext == '.json':
            file.seek(0)
            json_data = json.loads(file.read().decode('utf-8'))
            df = pd.DataFrame(json_data)
        else:
            return Response({
                'success': False,
                'message': 'Unsupported file format'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Clean column names (remove extra spaces)
        df.columns = df.columns.str.strip()
        
        # Check if DataFrame is empty
        if df.empty:
            return Response({
                'success': False,
                'message': 'The uploaded file is empty or contains no valid data'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Get preview data (limited rows)
        preview_df = df.head(rows_limit)
        
        # Convert DataFrame to list of dictionaries for JSON response
        preview_data = []
        validation_errors = []
        
        for index, row in preview_df.iterrows():
            row_data = {}
            row_errors = []
            
            for col in df.columns:
                value = row[col]
                # Handle NaN values
                if pd.isna(value):
                    row_data[col] = None
                else:
                    # Clean and decode the value
                    if isinstance(value, str):
                        # URL decode and clean
                        import urllib.parse
                        cleaned_value = urllib.parse.unquote_plus(str(value)).strip()
                        row_data[col] = cleaned_value
                    else:
                        row_data[col] = str(value)
            
            # Basic validation for preview
            row_validation = validate_donor_row(row_data, donor_type, index + 1)
            if row_validation['errors']:
                row_errors = row_validation['errors']
            
            preview_data.append({
                'row_number': index + 1,
                'data': row_data,
                'errors': row_errors,
                'is_valid': len(row_errors) == 0
            })
            
            if row_errors:
                validation_errors.extend(row_errors)
        
        # Count valid/invalid rows
        valid_rows = sum(1 for row in preview_data if row['is_valid'])
        invalid_rows = len(preview_data) - valid_rows
        
        return Response({
            'success': True,
            'preview_data': preview_data,
            'total_rows': len(df),
            'preview_rows': len(preview_data),
            'columns': list(df.columns),
            'validation_errors': validation_errors,
            'valid_rows': valid_rows,
            'invalid_rows': invalid_rows,
            'donor_type': donor_type
        })
    
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Error processing file: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)

@swagger_auto_schema(
    method='post',
    request_body=DonorImportSerializer,
    responses={
        200: openapi.Response(
            description="Donors imported successfully",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                    'message': openapi.Schema(type=openapi.TYPE_STRING),
                    'imported_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'failed_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'errors': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_STRING)
                    ),
                    'imported_donors': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'name': openapi.Schema(type=openapi.TYPE_STRING),
                                'email': openapi.Schema(type=openapi.TYPE_STRING),
                                'phone': openapi.Schema(type=openapi.TYPE_STRING),
                                # add more fields if needed
                            }
                        )
                    )
                }
            )
        ),
        400: "Bad Request"
    },
    operation_description="Import donor data from CSV/Excel/JSON file (Clinic only)",
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def import_donors(request):
    """Import donor data from file - Clinic only (Complete Implementation)"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can import donors."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    serializer = DonorImportSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False,
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    file = serializer.validated_data['file']
    donor_type = serializer.validated_data['donor_type']
    
    try:
        # Parse file based on extension
        file_ext = os.path.splitext(file.name)[1].lower()
        
        if file_ext == '.csv':
            # Reset file pointer and read with proper encoding
            file.seek(0)
            content = file.read().decode('utf-8')
            # URL decode the content
            import urllib.parse
            content = urllib.parse.unquote_plus(content)
            df = pd.read_csv(io.StringIO(content))
        elif file_ext in ['.xlsx', '.xls']:
            df = pd.read_excel(file)
        elif file_ext == '.json':
            file.seek(0)
            json_data = json.loads(file.read().decode('utf-8'))
            df = pd.DataFrame(json_data)
        else:
            return Response({
                'success': False,
                'message': 'Unsupported file format'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Clean column names and decode them
        df.columns = df.columns.str.strip()
        
        # Check if DataFrame is empty
        if df.empty:
            return Response({
                'success': False,
                'message': 'The uploaded file is empty or contains no valid data'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        imported_count = 0
        failed_count = 0
        errors = []
        imported_donors = []
        
        # Process each row
        for index, row in df.iterrows():
            row_number = index + 1
            try:
                with transaction.atomic():
                    # Convert row to dictionary and clean data
                    row_data = {}
                    for col in df.columns:
                        value = row[col]
                        if pd.isna(value):
                            row_data[col] = None
                        else:
                            # Clean and decode the value
                            if isinstance(value, str):
                                # URL decode and clean
                                cleaned_value = urllib.parse.unquote_plus(str(value)).strip()
                                row_data[col] = cleaned_value
                            else:
                                row_data[col] = value
                    
                    # Skip empty rows
                    if all(v is None or str(v).strip() == '' for v in row_data.values()):
                        continue
                    
                    # Validate row data
                    validation_result = validate_donor_row(row_data, donor_type, row_number)
                    if validation_result['errors']:
                        failed_count += 1
                        errors.extend(validation_result['errors'])
                        continue
                    
                    # Process and create donor
                    processed_data = process_donor_data(row_data, donor_type, request.user)
                    
                    # Create donor with error handling
                    try:
                        donor = Donor.objects.create(**processed_data)
                        imported_count += 1
                        imported_donors.append({
                            'donor_id': donor.donor_id,
                            'name': donor.full_name,
                            'donor_type': donor.donor_type,
                            'row_number': row_number
                        })
                    except Exception as create_error:
                        failed_count += 1
                        errors.append({
                            'row': row_number,
                            'error': f'Database error: {str(create_error)}'
                        })
            
            except Exception as e:
                failed_count += 1
                errors.append({
                    'row': row_number,
                    'error': f'Processing error: {str(e)}'
                })
        
        # Prepare response message
        if imported_count > 0:
            message = f'Import completed. {imported_count} donors imported successfully'
            if failed_count > 0:
                message += f', {failed_count} rows failed'
        else:
            message = f'Import failed. {failed_count} rows had errors'
        
        return Response({
            'success': imported_count > 0,
            'message': message,
            'imported_count': imported_count,
            'failed_count': failed_count,
            'errors': errors,
            'imported_donors': imported_donors
        })
    
    except Exception as e:
        return Response({
            'success': False,
            'message': f'Import failed: {str(e)}'
        }, status=status.HTTP_400_BAD_REQUEST)

# Helper Functions
def validate_donor_row(row_data, donor_type, row_number):
    """Validate individual donor row data"""
    errors = []
    
    # Required fields validation
    required_fields = [
        'first_name', 'last_name', 'gender', 'date_of_birth', 
        'phone_number', 'donor_type', 'blood_group'
    ]
    
    # for field in required_fields:
    #     value = row_data.get(field)
    #     # Check if field is empty, None, or contains template example data
    #     if not value or str(value).strip() == '' or str(value).strip() in ['John', 'Doe', 'male/female', '1990-01-15', '+1234567890', 'sperm/egg/embryo', 'A+/A-/B+/B-/AB+/AB-/O+/O-']:
    #         errors.append({
    #             'row': row_number,
    #             'field': field,
    #             'error': f'{field} is required and cannot be template example data'
    #         })
    
    # Skip further validation if required fields are missing
    if errors:
        return {'errors': errors}
    
    # Validate gender
    gender_value = str(row_data.get('gender', '')).strip().lower()
    if gender_value and gender_value not in ['male', 'female']:
        errors.append({
            'row': row_number,
            'field': 'gender',
            'error': 'Gender must be "male" or "female"'
        })
    
    # Validate donor_type
    donor_type_value = str(row_data.get('donor_type', '')).strip().lower()
    if donor_type_value and donor_type_value != donor_type.lower():
        errors.append({
            'row': row_number,
            'field': 'donor_type',
            'error': f'Donor type must be "{donor_type}"'
        })
    
    # Validate blood group
    valid_blood_groups = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-']
    blood_group_value = str(row_data.get('blood_group', '')).strip()
    # if blood_group_value and blood_group_value not in valid_blood_groups:
    #     errors.append({
    #         'row': row_number,
    #         'field': 'blood_group',
    #         'error': f'Blood group must be one of: {", ".join(valid_blood_groups)}'
    #     })
    
    # Validate date of birth
    dob_value = row_data.get('date_of_birth')
    if dob_value:
        try:
            # Handle different date formats
            dob_str = str(dob_value).strip()
            if dob_str:
                dob = pd.to_datetime(dob_str).date()
                today = date.today()
                age = today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))
                if age < 18:
                    errors.append({
                        'row': row_number,
                        'field': 'date_of_birth',
                        'error': 'Donor must be at least 18 years old'
                    })
                elif age > 65:
                    errors.append({
                        'row': row_number,
                        'field': 'date_of_birth',
                        'error': 'Donor age cannot exceed 65 years'
                    })
        except Exception as e:
            errors.append({
                'row': row_number,
                'field': 'date_of_birth',
                'error': f'Invalid date format. Use YYYY-MM-DD. Error: {str(e)}'
            })
    
    # Validate numeric fields
    numeric_fields = {'height': 'Height', 'weight': 'Weight', 'number_of_children': 'Number of children'}
    for field, display_name in numeric_fields.items():
        value = row_data.get(field)
        if value is not None and str(value).strip() != '':
            try:
                num_value = float(str(value).strip())
                if field in ['height', 'weight'] and num_value <= 0:
                    errors.append({
                        'row': row_number,
                        'field': field,
                        'error': f'{display_name} must be greater than 0'
                    })
                elif field == 'number_of_children' and num_value < 0:
                    errors.append({
                        'row': row_number,
                        'field': field,
                        'error': f'{display_name} cannot be negative'
                    })
            except (ValueError, TypeError):
                errors.append({
                    'row': row_number,
                    'field': field,
                    'error': f'{display_name} must be a valid number'
                })
    
    # Validate boolean fields
    smoking_status = row_data.get('smoking_status')
    if smoking_status is not None and str(smoking_status).strip() != '':
        smoking_str = str(smoking_status).strip().lower()
        if smoking_str not in ['true', 'false', '1', '0', 'yes', 'no']:
            errors.append({
                'row': row_number,
                'field': 'smoking_status',
                'error': 'Smoking status must be TRUE/FALSE, YES/NO, or 1/0'
            })
    
    return {'errors': errors}

def process_donor_data(row_data, donor_type, clinic_user):
    """Process and convert row data to Donor model format"""
    import urllib.parse
    processed_data = {}
    
    # Map and process each field
    field_mapping = {
        'title': 'title',
        'first_name': 'first_name',
        'last_name': 'last_name',
        'gender': 'gender',
        'date_of_birth': 'date_of_birth',
        'phone_number': 'phone_number',
        'email': 'email',
        'location': 'location',
        'address': 'address',
        'city': 'city',
        'state': 'state',
        'country': 'country',
        'postal_code': 'postal_code',
        'donor_type': 'donor_type',
        'blood_group': 'blood_group',
        'height': 'height',
        'weight': 'weight',
        'eye_color': 'eye_color',
        'hair_color': 'hair_color',
        'skin_tone': 'skin_tone',
        'education_level': 'education_level',
        'occupation': 'occupation',
        'marital_status': 'marital_status',
        'religion': 'religion',
        'ethnicity': 'ethnicity',
        'medical_history': 'medical_history',
        'genetic_conditions': 'genetic_conditions',
        'medications': 'medications',
        'allergies': 'allergies',
        'smoking_status': 'smoking_status',
        'alcohol_consumption': 'alcohol_consumption',
        'exercise_frequency': 'exercise_frequency',
        'number_of_children': 'number_of_children',
        'family_medical_history': 'family_medical_history',
        'personality_traits': 'personality_traits',
        'interests_hobbies': 'interests_hobbies',
        'notes': 'notes'
    }
    
    for csv_field, model_field in field_mapping.items():
        if csv_field in row_data and row_data[csv_field] is not None:
            value = row_data[csv_field]
            
            # Skip empty values
            if str(value).strip() == '':
                continue
                
            # URL decode the value if it's a string
            if isinstance(value, str):
                value = urllib.parse.unquote_plus(value.strip())
            
            # Special processing for specific fields
            try:
                if model_field == 'date_of_birth':
                    processed_data[model_field] = pd.to_datetime(str(value)).date()
                elif model_field in ['height', 'weight']:
                    if str(value).strip():
                        processed_data[model_field] = Decimal(str(value).strip())
                elif model_field == 'number_of_children':
                    if str(value).strip():
                        processed_data[model_field] = int(float(str(value).strip()))
                elif model_field == 'smoking_status':
                    smoking_str = str(value).strip().lower()
                    processed_data[model_field] = smoking_str in ['true', '1', 'yes']
                elif model_field == 'gender':
                    processed_data[model_field] = str(value).strip().lower()
                elif model_field == 'donor_type':
                    processed_data[model_field] = str(value).strip().lower()
                elif model_field in ['personality_traits', 'interests_hobbies']:
                    try:
                        # Clean up JSON strings
                        json_str = str(value).strip()
                        if json_str and json_str not in ['{}', '[]', 'null', 'None']:
                            # Handle malformed JSON strings from URL encoding
                            json_str = json_str.replace('"{', '{').replace('}"', '}')
                            json_str = json_str.replace('"[', '[').replace(']"', ']')
                            parsed_value = json.loads(json_str)
                            processed_data[model_field] = parsed_value
                        else:
                            processed_data[model_field] = {} if model_field == 'personality_traits' else []
                    except (json.JSONDecodeError, ValueError) as e:
                        # If JSON parsing fails, set default values
                        processed_data[model_field] = {} if model_field == 'personality_traits' else []
                else:
                    # For all other string fields
                    processed_data[model_field] = str(value).strip()
            except (ValueError, TypeError, pd.errors.OutOfBoundsDatetime) as e:
                # Skip fields that can't be processed correctly
                print(f"Warning: Could not process field {model_field} with value {value}: {str(e)}")
                continue
    
    # Set required fields
    processed_data['clinic'] = clinic_user
    processed_data['created_by'] = clinic_user
    processed_data['availability_status'] = 'pending'
    processed_data['is_active'] = True
    
    # Set default values if not provided
    if 'country' not in processed_data or not processed_data['country']:
        processed_data['country'] = 'India'
    
    # Ensure donor_type matches the expected type
    processed_data['donor_type'] = donor_type
    
    return processed_data


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


# ====================== DONOR IMAGE/DOCUMENT MANAGEMENT ======================

@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'image': openapi.Schema(type=openapi.TYPE_FILE),
            'caption': openapi.Schema(type=openapi.TYPE_STRING),
            'is_primary': openapi.Schema(type=openapi.TYPE_BOOLEAN)
        }
    ),
    responses={201: DonorImageSerializer()},
    operation_description="Add image to donor",
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def add_donor_image(request, donor_id):
    """Add image to donor"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can add donor images."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    donor = get_object_or_404(Donor, id=donor_id, clinic=request.user)
    
    serializer = DonorImageSerializer(data=request.data)
    if serializer.is_valid():
        image = serializer.save(donor=donor)
        
        # If this is set as primary, unset others
        if image.is_primary:
            DonorImage.objects.filter(donor=donor).exclude(id=image.id).update(is_primary=False)
        
        return Response({
            'success': True,
            'message': 'Image added successfully',
            'image': DonorImageSerializer(image).data
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='delete',
    responses={204: "Image deleted successfully"},
    operation_description="Delete donor image",
    tags=['Donor Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_donor_image(request, donor_id, image_id):
    """Delete donor image"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can delete donor images."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    donor = get_object_or_404(Donor, id=donor_id, clinic=request.user)
    image = get_object_or_404(DonorImage, id=image_id, donor=donor)
    
    image.delete()
    return Response({
        'success': True,
        'message': 'Image deleted successfully'
    }, status=status.HTTP_204_NO_CONTENT)


@swagger_auto_schema(
    method='post',
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'document_type': openapi.Schema(type=openapi.TYPE_STRING),
            'document': openapi.Schema(type=openapi.TYPE_FILE),
            'document_name': openapi.Schema(type=openapi.TYPE_STRING),
            'description': openapi.Schema(type=openapi.TYPE_STRING)
        }
    ),
    responses={201: DonorDocumentSerializer()},
    operation_description="Add document to donor",
    tags=['Donor Management']
)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
@parser_classes([MultiPartParser, FormParser])
def add_donor_document(request, donor_id):
    """Add document to donor"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can add donor documents."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    donor = get_object_or_404(Donor, id=donor_id, clinic=request.user)
    
    serializer = DonorDocumentSerializer(data=request.data)
    if serializer.is_valid():
        document = serializer.save(donor=donor)
        return Response({
            'success': True,
            'message': 'Document added successfully',
            'document': DonorDocumentSerializer(document).data
        }, status=status.HTTP_201_CREATED)
    
    return Response({
        'success': False,
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@swagger_auto_schema(
    method='delete',
    responses={204: "Document deleted successfully"},
    operation_description="Delete donor document",
    tags=['Donor Management']
)
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def delete_donor_document(request, donor_id, document_id):
    """Delete donor document"""
    if not request.user.is_clinic:
        return Response(
            {"detail": "Only clinics can delete donor documents."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    donor = get_object_or_404(Donor, id=donor_id, clinic=request.user)
    document = get_object_or_404(DonorDocument, id=document_id, donor=donor)
    
    document.delete()
    return Response({
        'success': True,
        'message': 'Document deleted successfully'
    }, status=status.HTTP_204_NO_CONTENT)

###############################AI MATCHING ENDPOINTS####################################
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def create_fertility_profile(request):
    """Create fertility profile for parent"""
    if not request.user.is_parent:
        return Response(
            {"detail": "Only parents can create fertility profiles."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    serializer = FertilityProfileSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        profile = serializer.save()
        return Response({
            'success': True,
            'message': 'Fertility profile created successfully',
            'profile_id': str(profile.id)
        }, status=status.HTTP_201_CREATED)
    
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

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_donor_embeddings(request):
    """Generate embeddings for all donors (Admin/Clinic only)"""
    if not (request.user.is_admin or request.user.is_clinic):
        return Response(
            {"detail": "Unauthorized."},
            status=status.HTTP_403_FORBIDDEN,
        )
    try:
        embedding_service = EmbeddingService()
        if request.user.is_clinic:
            donors = Donor.objects.filter(clinic=request.user)
            print("donors", donors)
        else:
            donors = Donor.objects.all()
        
        success_count = 0
        error_count = 0
        errors = []
        
        for donor in donors:
            try:
                # Create donor data dictionary
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
                
                # Generate text representation
                donor_text = embedding_service.create_donor_text(donor_data)
                
                # Generate embedding
                embedding = embedding_service.generate_embedding(donor_text)
                
                # Store in Pinecone
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
                
                success_count += 1
                
            except Exception as e:
                error_count += 1
                errors.append({
                    'donor_id': donor.donor_id,
                    'error': str(e)
                })
                logger.error(f"Failed to process donor {donor.donor_id}: {e}")
        
        return Response({
            'success': True,
            'message': f'Embedding generation completed. {success_count} successful, {error_count} failed.',
            'success_count': success_count,
            'error_count': error_count,
            'errors': errors[:10]  # Limit error details
        })
        
    except Exception as e:
        logger.error(f"Failed to generate donor embeddings: {e}")
        return Response({
            'success': False,
            'message': f'Failed to generate embeddings: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def find_matching_donors(request):
    """Find matching donors for parent's fertility profile"""
    if not request.user.is_parent:
        return Response(
            {"detail": "Only parents can search for matching donors."},
            status=status.HTTP_403_FORBIDDEN,
        )
    
    # Get or validate profile_id
    profile_id = request.data.get('profile_id')
    if not profile_id:
        return Response({
            'success': False,
            'message': 'Profile ID is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Get fertility profile
        fertility_profile = FertilityProfile.objects.get(
            id=profile_id,
            parent=request.user
        )
    except FertilityProfile.DoesNotExist:
        return Response({
            'success': False,
            'message': 'Fertility profile not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    try:
        # Initialize services
        embedding_service = EmbeddingService()
        matching_engine = DonorMatchingEngine()
        
        # Create profile data dictionary
        profile_data = {
            'donor_type_preference': fertility_profile.donor_type_preference,
            'location': fertility_profile.location,
            'preferred_height_min': fertility_profile.preferred_height_min,
            'preferred_height_max': fertility_profile.preferred_height_max,
            'preferred_ethnicity': fertility_profile.preferred_ethnicity,
            'preferred_eye_color': fertility_profile.preferred_eye_color,
            'preferred_hair_color': fertility_profile.preferred_hair_color,
            'preferred_education_level': fertility_profile.preferred_education_level,
            'genetic_screening_required': fertility_profile.genetic_screening_required,
            'preferred_age_min': fertility_profile.preferred_age_min,
            'preferred_age_max': fertility_profile.preferred_age_max,
            'preferred_occupation': fertility_profile.preferred_occupation,
            'preferred_religion': fertility_profile.preferred_religion,
            'importance_physical': fertility_profile.importance_physical,
            'importance_education': fertility_profile.importance_education,
            'importance_medical': fertility_profile.importance_medical,
            'importance_personality': fertility_profile.importance_personality,
            'special_requirements': fertility_profile.special_requirements,
        }
        
        # Generate profile text and embedding
        profile_text = embedding_service.create_profile_text(profile_data)
        profile_embedding = embedding_service.generate_embedding(profile_text)
        
        # Search for similar donors
        similar_donors = embedding_service.search_similar_donors(
            profile_embedding=profile_embedding,
            top_k=50,  # Get more candidates for detailed filtering
            donor_type_filter=fertility_profile.donor_type_preference
        )
        
        # Get detailed donor information and calculate precise matches
        match_results = []
        
        for similar_donor in similar_donors:
            try:
                # Get full donor information
                donor = Donor.objects.get(
                    donor_id=similar_donor['donor_id'],
                    clinic_id=similar_donor['clinic_id']
                )
                
                # Create detailed donor data
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
                    'location': donor.location,
                }
                
                # Calculate detailed match score
                detailed_score, matched_attributes = matching_engine.calculate_detailed_match_score(
                    donor_data, profile_data
                )
                
                # Combine semantic similarity with detailed matching
                # Weighted combination: 70% detailed matching + 30% semantic similarity
                final_score = (detailed_score * 0.7) + (similar_donor['similarity_score'] * 0.3)
                
                # Generate AI explanation
                ai_explanation = matching_engine.generate_ai_explanation(
                    donor_data, profile_data, matched_attributes, final_score
                )
                
                # Create match result
                match_result = MatchResult(
                    donor_id=donor.donor_id,
                    clinic_id=str(donor.clinic.id),
                    match_score=final_score,
                    matched_attributes=matched_attributes,
                    ai_explanation=ai_explanation
                )
                
                match_results.append(match_result)
                
                # Store result for analytics (optional)
                MatchingResult.objects.update_or_create(
                    fertility_profile=fertility_profile,
                    donor_id=donor.donor_id,
                    defaults={
                        'clinic_id': donor.clinic.id,
                        'match_score': final_score,
                        'matched_attributes': matched_attributes,
                        'ai_explanation': ai_explanation
                    }
                )
                
            except Donor.DoesNotExist:
                logger.warning(f"Donor {similar_donor['donor_id']} not found in database")
                continue
            except Exception as e:
                logger.error(f"Error processing donor {similar_donor['donor_id']}: {e}")
                continue
        
        # Sort by match score and limit results
        match_results.sort(key=lambda x: x.match_score, reverse=True)
        top_matches = match_results[:20]  # Return top 20 matches
        
        # Format response (privacy-safe)
        formatted_matches = []
        for match in top_matches:
            formatted_matches.append({
                'donor_reference_id': match.donor_id,  # Safe reference ID
                'clinic_reference_id': match.clinic_id,  # Safe clinic reference
                'match_percentage': round(match.match_score * 100, 1),
                'matched_attributes': match.matched_attributes,
                'ai_explanation': match.ai_explanation,
                'compatibility_score': {
                    'overall': round(match.match_score * 100, 1),
                    'physical': round(len([k for k in match.matched_attributes.keys() 
                                        if k in ['height', 'ethnicity', 'eye_color', 'hair_color']]) / 4 * 100, 1),
                    'educational': 100 if 'education' in match.matched_attributes else 0,
                    'medical': round(len([k for k in match.matched_attributes.keys() 
                                       if k in ['genetic_screening', 'smoking']]) / 2 * 100, 1),
                }
            })
        
        return Response({
            'success': True,
            'message': f'Found {len(formatted_matches)} matching donors',
            'total_matches': len(formatted_matches),
            'matches': formatted_matches,
            'search_criteria': {
                'donor_type': fertility_profile.donor_type_preference,
                'location': fertility_profile.location,
                'key_preferences': [
                    k for k, v in profile_data.items() 
                    if v and k.startswith('preferred_') and k != 'preferred_occupation'
                ]
            }
        })
        
    except Exception as e:
        logger.error(f"Failed to find matching donors: {e}")
        return Response({
            'success': False,
            'message': f'Failed to find matching donors: {str(e)}'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
import os
import re
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from rest_framework.authentication import _
from django.contrib.auth import password_validation
from apis.utils import send_verification_email
from .models import Appointment, Donor, DonorDocument, DonorImage, Meeting, PasswordResetOTP, SubscriptionPlan, User, UserSubscription
from django.conf import settings
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core import signing
from rest_framework_simplejwt.tokens import RefreshToken
import uuid


User = get_user_model()

class ParentSignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'relationship_to_child', 'password', 'password_confirm'
        ]
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Check if email already exists
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError("User with this email already exists")
            
        return attrs
    
    def validate_phone_number(self, value):
        if not re.fullmatch(r'\+?\d{10,15}', value):
            raise serializers.ValidationError("Enter a valid phone number (10–15 digits, optional leading '+').")

        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("User with this phone number already exists.")
        
        return value
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        user = User.objects.create(
            user_type='parent',
            username=validated_data['email'],
            is_verified=False,  # Set to False initially
            **validated_data
        )
        user.set_password(password)
        user.email_verification_sent_at = timezone.now()
        user.save()
        
        # Send verification email
        request = self.context.get('request')
        send_verification_email(user, request)
        
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        
        # Debug: Check what user exists with this email
        try:
            user_by_email = User.objects.get(email=email)
            print(f"User found by email {email}: {user_by_email} (ID: {user_by_email.id})")
        except User.DoesNotExist:
            print(f"No user found with email: {email}")
        
        # Debug: Check what authenticate returns
        print(f"Trying to authenticate with email: {email}")
        user = authenticate(request=self.context.get('request'), username=email, password=password)
        print(f"Authenticate returned: {user} (ID: {user.id if user else 'None'})")
        
        if not user:
            raise serializers.ValidationError('Invalid email or password')

        if not user.is_active:
            raise serializers.ValidationError('User account is disabled')

        # Only check email verification for clinic and parent users
        if user.user_type in ['clinic', 'parent'] and not user.is_verified:
            raise serializers.ValidationError({
                'email_verification': 'Please verify your email address before logging in.',
                'verification_required': True,
                'email': email
            })

        attrs['user'] = user
        return attrs

class ClinicCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'specialization', 'years_of_experience', 'id_proof',
            'password', 'password_confirm'
        ]
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Check if email already exists
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError("User with this email already exists")
            
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        user = User.objects.create(
            user_type='clinic',
            username=validated_data['email'],
            created_by=self.context['request'].user,
            is_verified=False,  # Set to False initially
            **validated_data
        )
        user.set_password(password)
        user.email_verification_sent_at = timezone.now()
        user.save()
        
        # Send verification email
        request = self.context.get('request')
        send_verification_email(user, request)
        
        return user

class SubAdminCreateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password_confirm = serializers.CharField(write_only=True)
    permissions = serializers.JSONField(required=False, default=dict)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'password', 'password_confirm', 'permissions'
        ]
    
    def validate_permissions(self, value):
        """Validate permissions format"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Permissions must be a dictionary")
        
        valid_sections = User.PERMISSION_SECTIONS
        invalid_sections = set(value.keys()) - set(valid_sections)
        
        if invalid_sections:
            raise serializers.ValidationError(
                f"Invalid permission sections: {list(invalid_sections)}. "
                f"Valid sections are: {valid_sections}"
            )
        
        # Ensure all values are boolean
        for section, permission in value.items():
            if not isinstance(permission, bool):
                raise serializers.ValidationError(
                    f"Permission for '{section}' must be a boolean value"
                )
        
        return value
        
    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        
        # Check if email already exists
        if User.objects.filter(email=attrs['email']).exists():
            raise serializers.ValidationError("User with this email already exists")
            
        return attrs
    
    def create(self, validated_data):
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        permissions = validated_data.pop('permissions', {})
        
        user = User.objects.create(
            user_type='subadmin',
            username=validated_data['email'],
            created_by=self.context['request'].user,
            permissions=permissions,
            **validated_data
        )
        user.set_password(password)
        user.save()
        return user

class UserSerializer(serializers.ModelSerializer):
    is_admin = serializers.SerializerMethodField()
    is_subadmin = serializers.SerializerMethodField()
    is_clinic = serializers.SerializerMethodField()
    is_parent = serializers.SerializerMethodField()
    profile_image_url = serializers.SerializerMethodField()
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "first_name", "last_name", "email", "phone_number",
            "user_type", "is_verified", "created_at", "profile_image",
            "relationship_to_child", "specialization", "years_of_experience",
            "is_admin", "is_subadmin", "is_clinic", "is_parent", "profile_image_url",
            "permissions"
        ]
        read_only_fields = ["id", "user_type", "created_at"]

    def get_is_admin(self, obj):
        return obj.is_admin
    
    def get_is_subadmin(self, obj):
        return obj.is_subadmin
    
    def get_is_clinic(self, obj):
        return obj.is_clinic
    
    def get_is_parent(self, obj):
        return obj.is_parent
    
    def get_profile_image_url(self, obj):
        if obj.profile_image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.profile_image.url)
            return obj.profile_image.url
        return None
    
    def get_permissions(self, obj):
        """Return permissions for admin/subadmin users"""
        return obj.get_permissions()
    
class AdminProfileUpdateSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=False)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'profile_image'
        ]
    
    def validate_email(self, value):
        user = self.instance
        if User.objects.filter(email=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("User with this email already exists")
        return value
    
    def update(self, instance, validated_data):
        # Handle profile image update
        profile_image = validated_data.pop('profile_image', None)
        if profile_image:
            # Delete old image if exists
            if instance.profile_image:
                instance.profile_image.delete()
            instance.profile_image = profile_image
        
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        instance.save()
        return instance

# ---------------------------- SEND OTP -------------------------------
class ForgotPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)

    def validate_email(self, value):
        try:
            user = User.objects.get(
                email=value.strip().lower(),      # normalise
                user_type__in=["parent", "clinic", "admin", "subadmin"]
            )
        except User.DoesNotExist:
            raise serializers.ValidationError("No account found with this email address")

        if not user.is_active:
            raise serializers.ValidationError("User account is disabled")

        self.user = user
        return value

    def save(self):
        otp_obj = PasswordResetOTP.create_for_user(self.user)
        
        # Generate the signed token
        token = otp_obj.signed_token()

        # Send email with OTP only (no token link)
        send_mail(
            "Password Reset OTP – Embryva",
            f"Your OTP is {otp_obj.otp}. It expires in 10 minutes.",
            getattr(settings, "DEFAULT_FROM_EMAIL", "noreply@embryva.com"),
            [self.user.email],
        )
        
        return otp_obj, token

# --------------------------- VERIFY OTP ------------------------------
class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length=6, max_length=6, write_only=True)

    def validate(self, attrs):
        token = self.context.get("token")
        if not token:
            raise serializers.ValidationError("Missing token")

        try:
            payload = signing.loads(token, salt="password-reset", max_age=60*60)  # 1 h
            otp_obj = PasswordResetOTP.objects.get(pk=payload["otp_id"], is_used=False)
        except (signing.BadSignature, signing.SignatureExpired, PasswordResetOTP.DoesNotExist):
            raise serializers.ValidationError("Invalid or expired token")

        if attrs["otp"] != otp_obj.otp:
            raise serializers.ValidationError({"otp": "Incorrect OTP"})

        if otp_obj.is_expired():
            raise serializers.ValidationError({"otp": "OTP has expired"})

        self.otp_obj = otp_obj
        return attrs

    def save(self):
        self.otp_obj.is_used = True
        self.otp_obj.save()
        return self.otp_obj


# ----------------------- RESET PASSWORD ------------------------------
class ResetPasswordSerializer(serializers.Serializer):
    new_password     = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords don't match")

        token = self.context.get("token")
        if not token:
            raise serializers.ValidationError("Missing token")

        try:
            payload = signing.loads(token, salt="password-reset", max_age=60*60)  # 1 h
            otp_obj = PasswordResetOTP.objects.get(pk=payload["otp_id"], is_used=True)
        except (signing.BadSignature, signing.SignatureExpired, PasswordResetOTP.DoesNotExist):
            raise serializers.ValidationError("Invalid or unverified token")

        # still within 30‑minute post‑verify window?
        if timezone.now() > otp_obj.expires_at + timezone.timedelta(minutes=30):
            raise serializers.ValidationError("Token session expired; request a new OTP")

        self.user = otp_obj.user
        return attrs

    def save(self):
        self.user.set_password(self.validated_data["new_password"])
        self.user.save()
        PasswordResetOTP.objects.filter(user=self.user).update(is_used=True)
        return self.user
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    confirm_new_password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = self.context['request'].user
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_new_password = attrs.get('confirm_new_password')

        # Check old password
        if not user.check_password(old_password):
            raise serializers.ValidationError({"old_password": "Old password is incorrect."})

        # Check new and confirm match
        if new_password != confirm_new_password:
            raise serializers.ValidationError({"confirm_new_password": "New passwords do not match."})

        # Check if new password is same as old
        if old_password == new_password:
            raise serializers.ValidationError({"new_password": "New password cannot be same as old password."})

        # Django's built-in password validators
        # password_validation.validate_password(new_password, user)

        return attrs
    
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model  = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'is_active', 'relationship_to_child',
            'specialization', 'years_of_experience'
        ]

    # email uniqueness stays unchanged
    def validate_email(self, value):
        user = self.instance
        if User.objects.filter(email=value).exclude(id=user.id).exists():
            raise serializers.ValidationError("User with this email already exists")
        return value

    def validate(self, attrs):
        request_user = self.context['request'].user

        # ❗ Only Admin or SubAdmin may touch admin‑only fields
        if not (request_user.is_admin or request_user.is_subadmin):
            forbidden = set(attrs.keys()) & {'email', 'is_active'}
            if forbidden:
                raise serializers.ValidationError({
                    field: ["Only admins or sub‑admins can change this field."]  # message matches rule
                    for field in forbidden
                })
        return attrs

    def update(self, instance, validated_data):
        # keep username in sync when e‑mail is changed by admin/sub‑admin
        if 'email' in validated_data:
            instance.username = validated_data['email']
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
    
#############################APPOINTENTS AND CREATE MEETING SERIALIZERS####################################
class AppointmentCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating appointments by parents/users"""
    
    class Meta:
        model = Appointment
        fields = [
            'name', 'email', 'phone_number', 'reason_for_consultation',
            'additional_notes', 'clinic', 'donor', 'preferred_date', 'preferred_time'
        ]
    
    def validate_clinic(self, value):
        """Ensure the selected clinic exists and is active"""
        if not value.is_clinic or not value.is_active:
            raise serializers.ValidationError("Selected clinic is not available")
        return value
    
    def validate_donor(self, value):
        """Ensure the selected donor exists and is active"""
        if value and not value.is_active:
            raise serializers.ValidationError("Selected donor is not available")
        return value
    
    def validate_preferred_date(self, value):
        """Ensure preferred date is not in the past"""
        if value and value < timezone.now().date():
            raise serializers.ValidationError("Preferred date cannot be in the past")
        return value
    
    def validate(self, data):
        """Cross-field validation to ensure donor belongs to the selected clinic"""
        clinic = data.get('clinic')
        donor = data.get('donor')
        
        if donor and clinic:
            if donor.clinic != clinic:
                raise serializers.ValidationError({
                    'donor': 'Selected donor does not belong to the selected clinic'
                })
        
        return data
    
    def create(self, validated_data):
        # If user is authenticated and is a parent, link the appointment
        request = self.context.get('request')
        if request and request.user.is_authenticated and request.user.is_parent:
            validated_data['parent'] = request.user
        
        return super().create(validated_data)


class AppointmentDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for appointment with all relationships"""
    clinic_name = serializers.CharField(source='clinic.get_full_name', read_only=True)
    clinic_email = serializers.CharField(source='clinic.email', read_only=True)
    clinic_specialization = serializers.CharField(source='clinic.specialization', read_only=True)
    
    donor_name = serializers.CharField(source='donor.full_name', read_only=True)
    donor_id = serializers.CharField(source='donor.donor_id', read_only=True)
    donor_type = serializers.CharField(source='donor.donor_type', read_only=True)
    
    parent_name = serializers.CharField(source='parent.get_full_name', read_only=True)
    parent_email = serializers.CharField(source='parent.email', read_only=True)
    
    reviewed_by_name = serializers.CharField(source='reviewed_by.get_full_name', read_only=True)
    
    has_meeting = serializers.SerializerMethodField()
    meeting_details = serializers.SerializerMethodField()
    
    class Meta:
        model = Appointment
        fields = [
            'id', 'name', 'email', 'phone_number', 'reason_for_consultation',
            'additional_notes', 'status', 'preferred_date', 'preferred_time',
            'created_at', 'updated_at', 'admin_notes',
            'clinic_name', 'clinic_email', 'clinic_specialization',
            'donor_name', 'donor_id', 'donor_type',
            'parent_name', 'parent_email', 'reviewed_by_name',
            'has_meeting', 'meeting_details'
        ]
    
    def get_has_meeting(self, obj):
        return hasattr(obj, 'meeting')
    
    def get_meeting_details(self, obj):
        if hasattr(obj, 'meeting'):
            return {
                'id': obj.meeting.id,
                'meeting_type': obj.meeting.meeting_type,
                'scheduled_datetime': obj.meeting.scheduled_datetime,
                'status': obj.meeting.status,
                'meeting_link': obj.meeting.meeting_link,
                'duration_minutes': obj.meeting.duration_minutes
            }
        return None


class AppointmentUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = ['status', 'admin_notes']


class MeetingCreateSerializer(serializers.Serializer):
    """Serializer for creating meetings by admin"""
    appointment_id = serializers.UUIDField()
    meeting_type = serializers.ChoiceField(choices=Meeting.MEETING_TYPES)
    scheduled_datetime = serializers.DateTimeField()
    duration_minutes = serializers.IntegerField(default=30, min_value=15, max_value=180)
    meeting_link = serializers.URLField(required=True)  # Made mandatory
    meeting_id = serializers.CharField(max_length=100, required=False, allow_blank=True)  # Made optional
    passcode = serializers.CharField(max_length=50, required=False, allow_blank=True)
    
    def validate_appointment_id(self, value):
        """Ensure appointment exists and doesn't already have a meeting"""
        try:
            appointment = Appointment.objects.get(id=value)
            if hasattr(appointment, 'meeting'):
                raise serializers.ValidationError("This appointment already has a meeting scheduled")
            return value
        except Appointment.DoesNotExist:
            raise serializers.ValidationError("Appointment not found")
    
    def validate_scheduled_datetime(self, value):
        meeting_type = self.initial_data.get("meeting_type")

        # Allow “now” (or even a hair in the past) for instant meetings
        if meeting_type == "instant":
            return value

        # Scheduled meetings must still be in the future
        if value <= timezone.now():
            raise serializers.ValidationError("Meeting cannot be scheduled in the past")
        return value
    
    def validate_meeting_id(self, value):
        """Ensure meeting ID is unique if provided"""
        if value and Meeting.objects.filter(meeting_id=value).exists():
            raise serializers.ValidationError("Meeting ID already exists")
        return value
    
    def create(self, validated_data):
        appointment = Appointment.objects.get(id=validated_data['appointment_id'])
        
        # Generate meeting_id if not provided
        meeting_id = validated_data.get('meeting_id')
        if not meeting_id:
            meeting_id = str(uuid.uuid4())[:8].upper()  # Generate 8-character ID
            # Ensure uniqueness
            while Meeting.objects.filter(meeting_id=meeting_id).exists():
                meeting_id = str(uuid.uuid4())[:8].upper()
        
        meeting = Meeting.objects.create(
            appointment=appointment,
            meeting_type=validated_data['meeting_type'],
            scheduled_datetime=validated_data['scheduled_datetime'],
            duration_minutes=validated_data['duration_minutes'],
            meeting_link=validated_data['meeting_link'],
            meeting_id=meeting_id,
            passcode=validated_data.get('passcode', ''),
            created_by=self.context['request'].user
        )
        
        # Update appointment status to confirmed
        appointment.status = 'confirmed'
        appointment.reviewed_by = self.context['request'].user
        appointment.save()
        
        return meeting


class MeetingDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for meeting with appointment and participant details"""
    appointment = serializers.SerializerMethodField()  # Adjust based on your AppointmentDetailSerializer
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    participants = serializers.SerializerMethodField()
    is_reminder_due = serializers.ReadOnlyField()
    
    class Meta:
        model = Meeting
        fields = [
            'id', 'meeting_type', 'meeting_link', 'meeting_id', 'passcode',
            'scheduled_datetime', 'duration_minutes', 'status',
            'creation_email_sent', 'reminder_email_sent',
            'created_at', 'updated_at', 'created_by_name',
            'appointment', 'participants', 'is_reminder_due'
        ]
    
    def get_appointment(self, obj):
        return {
            'id': obj.appointment.id,
            'name': obj.appointment.name,
            # Add other fields as needed
        }
    
    def get_participants(self, obj):
        participants = obj.participants.all()
        return [
            {
                'id': p.id,
                'user_name': p.user.get_full_name(),
                'user_email': p.user.email,
                'participant_type': p.participant_type,
                'creation_email_sent': p.creation_email_sent,
                'reminder_email_sent': p.reminder_email_sent,
                'joined_at': p.joined_at,
                'left_at': p.left_at
            }
            for p in participants
        ]


class MeetingUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Meeting
        fields = [
            'scheduled_datetime', 'duration_minutes', 'meeting_link',
            'meeting_id', 'passcode', 'status'
        ]
    
    def validate_scheduled_datetime(self, value):
        """Ensure new scheduled time is in the future"""
        if value <= timezone.now():
            raise serializers.ValidationError("Meeting cannot be scheduled in the past")
        return value
    
    def validate_meeting_id(self, value):
        """Ensure meeting ID is unique (excluding current meeting)"""
        if Meeting.objects.filter(meeting_id=value).exclude(id=self.instance.id).exists():
            raise serializers.ValidationError("Meeting ID already exists")
        return value
    
class SubscriptionPlanSerializer(serializers.ModelSerializer):
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    
    class Meta:
        model = SubscriptionPlan
        fields = [
            'id', 'name', 'billing_cycle', 'price', 'description', 
            'features', 'is_active', 'created_at', 'updated_at', 
            'created_by', 'created_by_name', 'duration_days'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'duration_days']
    
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            validated_data['created_by'] = request.user
        return super().create(validated_data)


class SubscriptionPlanUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriptionPlan
        fields = ['name', 'billing_cycle', 'price', 'description', 'features', 'is_active']
    
    def validate(self, data):
        name = data.get('name', self.instance.name)
        billing_cycle = data.get('billing_cycle', self.instance.billing_cycle)
        
        existing_plan = SubscriptionPlan.objects.filter(
            name=name, 
            billing_cycle=billing_cycle
        ).exclude(id=self.instance.id).first()
        
        if existing_plan:
            raise serializers.ValidationError(
                "A plan with this name and billing cycle already exists."
            )
        
        return data


class UserSubscriptionSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.get_full_name', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)
    plan_name = serializers.CharField(source='plan.get_name_display', read_only=True)
    plan_billing_cycle = serializers.CharField(source='plan.get_billing_cycle_display', read_only=True)
    plan_price = serializers.DecimalField(source='plan.price', max_digits=10, decimal_places=2, read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    
    class Meta:
        model = UserSubscription
        fields = [
            'id', 'user', 'user_name', 'user_email', 'plan', 'plan_name', 
            'plan_billing_cycle', 'plan_price', 'status', 'start_date', 
            'end_date', 'payment_status', 'transaction_id', 'created_at', 
            'updated_at', 'is_active', 'days_remaining'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserSubscriptionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserSubscription
        fields = ['user', 'plan', 'payment_status', 'transaction_id']
    
    def validate_user(self, value):
        if value.user_type != 'parent':
            raise serializers.ValidationError("Only parent users can have subscriptions.")
        return value
    
    def create(self, validated_data):
        subscription = UserSubscription.objects.create(**validated_data)
        if validated_data.get('payment_status') == 'completed':
            subscription.activate()
        return subscription


class ParentUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'first_name', 'last_name', 'email', 'phone_number']
        
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['full_name'] = instance.get_full_name()
        return data
    
################DONER SERIALIZER##########################
class DonorImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = DonorImage
        fields = ['id', 'image', 'caption', 'is_primary', 'uploaded_at']


class DonorDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = DonorDocument
        fields = ['id', 'document_type', 'document', 'document_name', 'description', 'uploaded_at']


class DonorCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating donors (Clinic only)"""
    images = DonorImageSerializer(many=True, required=False)
    documents_files = DonorDocumentSerializer(many=True, required=False)
    
    class Meta:
        model = Donor
        fields = [
            'title', 'first_name', 'last_name', 'gender', 'date_of_birth',
            'phone_number', 'email', 'location', 'address', 'city', 'state', 
            'country', 'postal_code', 'donor_type', 'blood_group', 'height', 
            'weight', 'eye_color', 'hair_color', 'skin_tone', 'education_level',
            'occupation', 'marital_status', 'religion', 'ethnicity',
            'medical_history', 'genetic_conditions', 'medications', 'allergies',
            'smoking_status', 'alcohol_consumption', 'exercise_frequency',
            'number_of_children', 'family_medical_history', 'profile_image',
            'documents', 'personality_traits', 'interests_hobbies', 'notes',
            'images', 'documents_files'
        ]
    
    def validate_date_of_birth(self, value):
        """Ensure donor is at least 18 years old"""
        from datetime import date
        today = date.today()
        age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))
        if age < 18:
            raise serializers.ValidationError("Donor must be at least 18 years old")
        if age > 65:
            raise serializers.ValidationError("Donor age cannot exceed 65 years")
        return value
    
    def create(self, validated_data):
        images_data = validated_data.pop('images', [])
        documents_data = validated_data.pop('documents_files', [])
        
        # Set clinic from authenticated user
        request = self.context.get('request')
        if request and request.user.is_authenticated and request.user.is_clinic:
            validated_data['clinic'] = request.user
            validated_data['created_by'] = request.user
        
        donor = Donor.objects.create(**validated_data)
        
        # Create images
        for image_data in images_data:
            DonorImage.objects.create(donor=donor, **image_data)
        
        # Create documents
        for document_data in documents_data:
            DonorDocument.objects.create(donor=donor, **document_data)
        
        return donor


class DonorDetailSerializer(serializers.ModelSerializer):
    """Detailed serializer for donor with all relationships"""
    clinic_name = serializers.CharField(source='clinic.get_full_name', read_only=True)
    clinic_email = serializers.CharField(source='clinic.email', read_only=True)
    created_by_name = serializers.CharField(source='created_by.get_full_name', read_only=True)
    age = serializers.ReadOnlyField()
    full_name = serializers.ReadOnlyField()
    images = DonorImageSerializer(many=True, read_only=True)
    documents_files = DonorDocumentSerializer(many=True, read_only=True)
    
    class Meta:
        model = Donor
        fields = [
            'id', 'donor_id', 'title', 'first_name', 'last_name', 'full_name',
            'gender', 'date_of_birth', 'age', 'phone_number', 'email', 
            'location', 'address', 'city', 'state', 'country', 'postal_code',
            'donor_type', 'availability_status', 'blood_group', 'height', 
            'weight', 'eye_color', 'hair_color', 'skin_tone', 'education_level',
            'occupation', 'marital_status', 'religion', 'ethnicity',
            'medical_history', 'genetic_conditions', 'medications', 'allergies',
            'smoking_status', 'alcohol_consumption', 'exercise_frequency',
            'number_of_children', 'family_medical_history', 'profile_image',
            'documents', 'personality_traits', 'interests_hobbies', 
            'ai_matching_score', 'clinic_name', 'clinic_email', 'created_by_name',
            'created_at', 'updated_at', 'verified_at', 'notes', 'is_active',
            'images', 'documents_files'
        ]


class DonorUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating donor information"""
    class Meta:
        model = Donor
        fields = [
            'title', 'first_name', 'last_name', 'gender', 'date_of_birth',
            'phone_number', 'email', 'location', 'address', 'city', 'state', 
            'country', 'postal_code', 'availability_status', 'blood_group', 
            'height', 'weight', 'eye_color', 'hair_color', 'skin_tone', 
            'education_level', 'occupation', 'marital_status', 'religion', 
            'ethnicity', 'medical_history', 'genetic_conditions', 'medications', 
            'allergies', 'smoking_status', 'alcohol_consumption', 'exercise_frequency',
            'number_of_children', 'family_medical_history', 'profile_image',
            'documents', 'personality_traits', 'interests_hobbies', 'notes', 'is_active'
        ]
    
    def validate_date_of_birth(self, value):
        """Ensure donor is at least 18 years old"""
        from datetime import date
        today = date.today()
        age = today.year - value.year - ((today.month, today.day) < (value.month, value.day))
        if age < 18:
            raise serializers.ValidationError("Donor must be at least 18 years old")
        if age > 65:
            raise serializers.ValidationError("Donor age cannot exceed 65 years")
        return value


class DonorListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for donor listing"""
    clinic_name = serializers.CharField(source='clinic.get_full_name', read_only=True)
    age = serializers.ReadOnlyField()
    full_name = serializers.ReadOnlyField()
    primary_image = serializers.SerializerMethodField()
    
    class Meta:
        model = Donor
        fields = [
            'id', 'donor_id', 'full_name', 'age', 'gender', 'donor_type',
            'availability_status', 'blood_group', 'location', 'education_level',
            'occupation', 'ai_matching_score', 'clinic_name', 'created_at',
            'primary_image', 'is_active'
        ]
    
    def get_primary_image(self, obj):
        primary_image = obj.images.filter(is_primary=True).first()
        if primary_image:
            return primary_image.image.url
        elif obj.profile_image:
            return obj.profile_image.url
        return None


class DonorImportSerializer(serializers.Serializer):
    """Serializer for importing donor data from files"""
    file = serializers.FileField()
    donor_type = serializers.ChoiceField(choices=[
        ('sperm', 'Sperm Donor'),
        ('egg', 'Egg Donor'),
        ('embryo', 'Embryo Donor'),
    ])
    
    def validate_file(self, value):
        """Validate file type and size"""
        ext = os.path.splitext(value.name)[1].lower()
        valid_extensions = ['.csv', '.xlsx', '.xls', '.json']
        
        if ext not in valid_extensions:
            raise serializers.ValidationError(
                f"Invalid file type. Supported formats: {', '.join(valid_extensions)}"
            )
        
        # Check file size (max 10MB)
        if value.size > 10 * 1024 * 1024:
            raise serializers.ValidationError("File size cannot exceed 10MB")
        
        return value

class DonorImportPreviewSerializer(serializers.Serializer):
    """Serializer for donor import preview data"""
    file = serializers.FileField()
    donor_type = serializers.ChoiceField(choices=[
        ('sperm', 'Sperm Donor'),
        ('egg', 'Egg Donor'),
        ('embryo', 'Embryo Donor'),
    ])
    rows_limit = serializers.IntegerField(default=10, min_value=1, max_value=100)
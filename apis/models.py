from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator
import uuid
import random, string
from django.db import models, transaction
from django.core import signing
from django.conf import settings
from django.utils import timezone
from django.core.validators import EmailValidator
from apis.custom_manager import CustomUserManager
from datetime import timedelta

class User(AbstractUser):
    objects = CustomUserManager()
    USER_TYPES = (
        ('admin', 'Admin'),
        ('subadmin', 'Sub Admin'),
        ('clinic', 'Clinic'),
        ('parent', 'Parent'),
    )
    
    RELATIONSHIP_CHOICES = (
        ('mother', 'Mother'),
        ('father', 'Father'),
        ('guardian', 'Guardian'),
        ('partner', 'Partner'),
    )
    
    # Available permission sections
    PERMISSION_SECTIONS = [
        'clinic', 'parent', 'subscription', 
        'appointment', 'transaction', 'profile'
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_type = models.CharField(max_length=20, choices=USER_TYPES)
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    phone_number = models.CharField(validators=[phone_regex], max_length=17, blank=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True)

    # Email verification fields
    email_verification_token = models.UUIDField(default=uuid.uuid4, editable=False)
    email_verification_sent_at = models.DateTimeField(null=True, blank=True)

    stripe_customer_id = models.CharField(max_length=255, blank=True, null=True, unique=True, help_text="Stripe customer ID for this user.")
    
    # Parent specific fields
    relationship_to_child = models.CharField(
        max_length=20, 
        choices=RELATIONSHIP_CHOICES, 
        blank=True, 
        null=True
    )
    
    # Clinic specific fields
    specialization = models.CharField(max_length=255, blank=True, null=True)
    years_of_experience = models.PositiveIntegerField(blank=True, null=True)
    id_proof = models.FileField(upload_to='clinic_documents/', blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    
    permissions = models.JSONField(
        default=dict, 
        blank=True, 
        help_text="Permissions for subadmin users. Format: {'clinic': True, 'parent': False, ...}"
    )

    @property
    def is_admin(self):
        return self.is_superuser or self.user_type == "admin"

    @property
    def is_subadmin(self):
        return self.user_type == "subadmin"

    @property
    def is_clinic(self):
        return self.user_type == "clinic"

    @property
    def is_parent(self):
        return self.user_type == "parent"
    
    def get_permissions(self):
        """Get permissions for subadmin users"""
        if self.user_type == 'admin':
            # Admin has all permissions
            return {section: True for section in self.PERMISSION_SECTIONS}
        elif self.user_type == 'subadmin':
            # Return stored permissions or default to no permissions
            return self.permissions if self.permissions else {section: False for section in self.PERMISSION_SECTIONS}
        else:
            # Other user types don't have section permissions
            return {}
    
    def set_permissions(self, permissions_dict):
        """Set permissions for subadmin users"""
        if self.user_type == 'subadmin':
            # Only allow valid permission sections
            valid_permissions = {
                key: value for key, value in permissions_dict.items() 
                if key in self.PERMISSION_SECTIONS
            }
            self.permissions = valid_permissions
            self.save(update_fields=['permissions'])
    
    def has_permission(self, section):
        """Check if user has permission for a specific section"""
        if self.user_type == 'admin':
            return True
        elif self.user_type == 'subadmin':
            return self.permissions.get(section, False)
        return False
    
    def is_email_verification_expired(self):
        """Check if email verification token is expired (24 hours)"""
        if not self.email_verification_sent_at:
            return True
        return timezone.now() > self.email_verification_sent_at + timedelta(hours=24)
    
    def regenerate_verification_token(self):
        """Generate new verification token"""
        self.email_verification_token = uuid.uuid4()
        self.email_verification_sent_at = timezone.now()
        self.save(update_fields=['email_verification_token', 'email_verification_sent_at'])

    def save(self, *args, **kwargs):
        if not self.profile_image and not self.pk:
            self.profile_image = 'media/profile_images/default_avatar.png'
        if not self.username:
            self.username = self.email
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.user_type})"
    
    class Meta:
        db_table = 'users'


class Meeting(models.Model):
    MEETING_TYPES = (
        ('instant', 'Instant Meeting'),
        ('scheduled', 'Scheduled Meeting'),
    )
    
    MEETING_STATUS = (
        ('scheduled', 'Scheduled'),
        ('ongoing', 'Ongoing'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    appointment = models.OneToOneField(
        'Appointment',  # Use string reference to avoid import issues
        on_delete=models.CASCADE, 
        related_name='meeting'
    )
    
    # Meeting details
    meeting_type = models.CharField(max_length=20, choices=MEETING_TYPES)
    meeting_link = models.URLField(max_length=500)  # Required
    meeting_id = models.CharField(max_length=100, blank=True, null=True)  # Made optional
    passcode = models.CharField(max_length=50, blank=True, null=True)
    
    # Scheduling
    scheduled_datetime = models.DateTimeField()
    duration_minutes = models.PositiveIntegerField(default=30)
    
    # Status and management
    status = models.CharField(max_length=20, choices=MEETING_STATUS, default='scheduled')
    created_by = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='created_meetings',
        limit_choices_to={'user_type__in': ['admin', 'subadmin']}
    )
    
    # Email tracking
    creation_email_sent = models.BooleanField(default=False)
    reminder_email_sent = models.BooleanField(default=False)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'meetings'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Meeting for {self.appointment.name} - {self.get_meeting_type_display()}"
    
    def save(self, *args, **kwargs):
        # Auto-generate meeting_id if not provided
        if not self.meeting_id:
            self.meeting_id = str(uuid.uuid4())[:8].upper()
            # Ensure uniqueness
            while Meeting.objects.filter(meeting_id=self.meeting_id).exists():
                self.meeting_id = str(uuid.uuid4())[:8].upper()
        super().save(*args, **kwargs)
    
    @property
    def reminder_time(self):
        """Calculate reminder time (5 minutes before meeting)"""
        return self.scheduled_datetime - timezone.timedelta(minutes=5)
    
    @property
    def is_reminder_due(self):
        """Check if reminder should be sent"""
        now = timezone.now()
        return (
            not self.reminder_email_sent and 
            now >= self.reminder_time and 
            now < self.scheduled_datetime and
            self.status == 'scheduled'
        )


class MeetingParticipant(models.Model):
    PARTICIPANT_TYPES = (
        ('admin', 'Admin'),
        ('subadmin', 'SubAdmin'),
        ('parent', 'Parent'),
        ('clinic', 'Clinic'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    meeting = models.ForeignKey(Meeting, on_delete=models.CASCADE, related_name='participants')
    user = models.ForeignKey('User', on_delete=models.CASCADE)
    participant_type = models.CharField(max_length=20, choices=PARTICIPANT_TYPES)
    
    # Email tracking
    creation_email_sent = models.BooleanField(default=False)
    creation_email_sent_at = models.DateTimeField(null=True, blank=True)
    reminder_email_sent = models.BooleanField(default=False)
    reminder_email_sent_at = models.DateTimeField(null=True, blank=True)
    
    # Participation tracking
    joined_at = models.DateTimeField(null=True, blank=True)
    left_at = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'meeting_participants'
        unique_together = ['meeting', 'user']
    
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.meeting.appointment.name}"
    
class SubscriptionPlan(models.Model):
    PLAN_TYPES = (
        ('basic', 'Basic'),
        ('standard', 'Standard'),
        ('pro', 'Pro'),
    )
    
    BILLING_CYCLES = (
        ('month', 'Monthly'),
        ('year', 'Yearly'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=50, choices=PLAN_TYPES)
    billing_cycle = models.CharField(max_length=20, choices=BILLING_CYCLES)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    description = models.TextField(blank=True, null=True)
    features = models.JSONField(default=dict, blank=True)  # Store plan features as JSON
    is_active = models.BooleanField(default=True)

    stripe_price_id = models.CharField(max_length=255, blank=True, null=True, help_text="The ID of the corresponding price object in Stripe.")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey('User', on_delete=models.SET_NULL, null=True, blank=True)
    
    class Meta:
        db_table = 'subscription_plans'
        unique_together = ('name', 'billing_cycle')
        
    def __str__(self):
        return f"{self.get_name_display()} - {self.get_billing_cycle_display()}"
    
    @property
    def duration_days(self):
        """Returns the duration of the plan in days"""
        if self.billing_cycle == 'monthly':
            return 30
        elif self.billing_cycle == 'quarterly':
            return 90  # 3 months
        elif self.billing_cycle == 'yearly':  # Updated from 'annually'
            return 365
        return 0


class UserSubscription(models.Model):
    STATUS_CHOICES = (
        ('active', 'Active'),
        ('inactive', 'Inactive'),
        ('expired', 'Expired'),
        ('cancelled', 'Cancelled'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('User', on_delete=models.CASCADE, limit_choices_to={'user_type': 'parent'})
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='inactive')
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    payment_status = models.CharField(max_length=20, default='pending')
    transaction_id = models.CharField(max_length=255, blank=True, null=True)
    stripe_subscription_id = models.CharField(max_length=255, blank=True, null=True, unique=True, help_text="The ID of the subscription in Stripe.")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_subscriptions'
        
    def __str__(self):
        return f"{self.user.get_full_name()} - {self.plan.name}"
    
    @property
    def is_active(self):
        """Check if subscription is currently active"""
        now = timezone.now()
        return self.status == 'active' and self.start_date <= now <= self.end_date
    
    @property
    def days_remaining(self):
        """Get remaining days in subscription"""
        if self.is_active:
            return (self.end_date - timezone.now()).days
        return 0
    
    def activate(self):
        """Activate the subscription"""
        self.status = 'active'
        self.start_date = timezone.now()
        self.end_date = self.start_date + timedelta(days=self.plan.duration_days)
        self.save()
    
    def cancel(self):
        """Cancel the subscription"""
        self.status = 'cancelled'
        self.save()
    
    def renew(self):
        """Renew the subscription"""
        if self.status in ['active', 'expired']:
            self.start_date = timezone.now()
            self.end_date = self.start_date + timedelta(days=self.plan.duration_days)
            self.status = 'active'
            self.save()

class PasswordResetOTP(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_otps")
    otp         = models.CharField(max_length=6)
    created_at  = models.DateTimeField(auto_now_add=True)
    expires_at  = models.DateTimeField()
    is_used     = models.BooleanField(default=False)

    class Meta:
        db_table            = "password_reset_otps"
        ordering            = ["-created_at"]
        verbose_name_plural = "Password Reset OTPs"

    def __str__(self):
        return f"OTP for {self.user.email} ({'used' if self.is_used else 'unused'})"

    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at
    
    def signed_token(self) -> str:
        """
        Return a URL‑safe signed token that encodes this OTP’s PK.
        Front‑end will carry this token as a query string (?token=…).
        """
        return signing.dumps({"otp_id": str(self.pk)}, salt="password-reset")

    @classmethod
    def create_for_user(cls, user) -> "PasswordResetOTP":
        with transaction.atomic():
            cls.objects.filter(user=user, is_used=False).update(is_used=True)

            otp_code = "".join(random.choices(string.digits, k=6))
            return cls.objects.create(
                user       = user,
                otp        = otp_code,
                expires_at = timezone.now() + timezone.timedelta(minutes=10),
            )
        
class Donor(models.Model):
    DONOR_TYPES = (
        ('sperm', 'Sperm Donor'),
        ('egg', 'Egg Donor'),
        ('embryo', 'Embryo Donor'),
    )
    
    AVAILABILITY_STATUS = (
        ('available', 'Available'),
        ('unavailable', 'Unavailable'),
        ('pending', 'Pending Verification'),
        ('suspended', 'Suspended'),
    )
    
    BLOOD_GROUPS = (
        ('A+', 'A Positive'),
        ('A-', 'A Negative'),
        ('B+', 'B Positive'),
        ('B-', 'B Negative'),
        ('AB+', 'AB Positive'),
        ('AB-', 'AB Negative'),
        ('O+', 'O Positive'),
        ('O-', 'O Negative'),
    )
    
    GENDER_CHOICES = (
        ('male', 'Male'),
        ('female', 'Female'),
    )
    
    EDUCATION_LEVELS = (
        ('high_school', 'High School'),
        ('bachelor', 'Bachelor\'s Degree'),
        ('masters', 'Master\'s Degree'),
        ('phd', 'PhD'),
        ('professional', 'Professional Degree'),
    )
    
    MARITAL_STATUS = (
        ('single', 'Single'),
        ('married', 'Married'),
        ('divorced', 'Divorced'),
        ('widowed', 'Widowed'),
    )
    
    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    donor_id = models.CharField(max_length=50, unique=True, blank=True)  # Auto-generated
    
    # Basic Information
    title = models.CharField(max_length=100)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES)
    date_of_birth = models.DateField()
    
    # Contact Information
    phone_number = models.CharField(max_length=25)
    email = models.EmailField(blank=True, null=True)
    location = models.CharField(max_length=255)
    address = models.TextField(blank=True, null=True)
    city = models.CharField(max_length=100)
    state = models.CharField(max_length=100)
    country = models.CharField(max_length=100, default='India')
    postal_code = models.CharField(max_length=50, blank=True, null=True)  # Increased from 20 to 50
    
    # Donor Specific Information
    donor_type = models.CharField(max_length=50, choices=DONOR_TYPES)  # Increased from 20 to 50
    availability_status = models.CharField(max_length=50, choices=AVAILABILITY_STATUS, default='pending')  # Increased from 20 to 50
    blood_group = models.CharField(max_length=5, choices=BLOOD_GROUPS)
    
    # Physical Characteristics
    height = models.DecimalField(max_digits=5, decimal_places=2, help_text="Height in cm")
    weight = models.DecimalField(max_digits=5, decimal_places=2, help_text="Weight in kg")
    eye_color = models.CharField(max_length=50, blank=True, null=True)
    hair_color = models.CharField(max_length=50, blank=True, null=True)
    skin_tone = models.CharField(max_length=50, blank=True, null=True)
    
    # Personal Information
    education_level = models.CharField(max_length=50, choices=EDUCATION_LEVELS, blank=True, null=True)  # Increased from 20 to 50
    occupation = models.CharField(max_length=100, blank=True, null=True)
    marital_status = models.CharField(max_length=50, choices=MARITAL_STATUS, blank=True, null=True)  # Increased from 20 to 50
    religion = models.CharField(max_length=50, blank=True, null=True)
    ethnicity = models.CharField(max_length=50, blank=True, null=True)
    
    # Medical Information
    medical_history = models.TextField(blank=True, null=True)
    genetic_conditions = models.TextField(blank=True, null=True)
    medications = models.TextField(blank=True, null=True)
    allergies = models.TextField(blank=True, null=True)
    
    # Lifestyle Information
    smoking_status = models.BooleanField(default=False)
    alcohol_consumption = models.CharField(max_length=50, blank=True, null=True)
    exercise_frequency = models.CharField(max_length=50, blank=True, null=True)
    
    # Family Information
    number_of_children = models.PositiveIntegerField(default=0)
    family_medical_history = models.TextField(blank=True, null=True)
    
    # Profile and Documents
    profile_image = models.ImageField(upload_to='donor_profiles/', blank=True, null=True)
    documents = models.FileField(upload_to='donor_documents/', blank=True, null=True)
    
    # AI Matching Fields
    personality_traits = models.JSONField(default=dict, blank=True)
    interests_hobbies = models.JSONField(default=list, blank=True)
    ai_matching_score = models.DecimalField(max_digits=5, decimal_places=2, default=0.00)
    
    # Clinic and Management
    clinic = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='donors',
        limit_choices_to={'user_type': 'clinic'}
    )
    created_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_donors'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Additional Notes
    notes = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'donors'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['donor_type', 'availability_status']),
            models.Index(fields=['clinic', 'is_active']),
            models.Index(fields=['blood_group']),
            models.Index(fields=['location']),
        ]
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} - {self.get_donor_type_display()}"
    
    def save(self, *args, **kwargs):
        # Auto-generate donor_id if not provided
        if not self.donor_id:
            prefix = 'EMB'
            donor_type_prefix = {
                'sperm': 'SP',
                'egg': 'EG',
                'embryo': 'EM'
            }.get(self.donor_type, 'DN')
            
            # Generate unique donor ID
            import random
            import string
            while True:
                random_suffix = ''.join(random.choices(string.digits, k=6))
                potential_id = f"{prefix}{donor_type_prefix}{random_suffix}"
                if not Donor.objects.filter(donor_id=potential_id).exists():
                    self.donor_id = potential_id
                    break
        
        super().save(*args, **kwargs)
    
    @property
    def age(self):
        """Calculate age from date of birth"""
        from datetime import date
        today = date.today()
        return today.year - self.date_of_birth.year - ((today.month, today.day) < (self.date_of_birth.month, self.date_of_birth.day))
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"


class DonorImage(models.Model):
    """Model to store multiple images for a donor"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    donor = models.ForeignKey(Donor, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='donor_images/')
    caption = models.CharField(max_length=255, blank=True, null=True)
    is_primary = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'donor_images'
        ordering = ['-is_primary', '-uploaded_at']
    
    def __str__(self):
        return f"Image for {self.donor.full_name}"


class DonorDocument(models.Model):
    """Model to store multiple documents for a donor"""
    DOCUMENT_TYPES = (
        ('identity', 'Identity Document'),
        ('medical', 'Medical Report'),
        ('education', 'Education Certificate'),
        ('screening', 'Screening Report'),
        ('consent', 'Consent Form'),
        ('other', 'Other'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    donor = models.ForeignKey(Donor, on_delete=models.CASCADE, related_name='documents_files')
    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES)
    document = models.FileField(upload_to='donor_documents/')
    document_name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'donor_documents'
        ordering = ['-uploaded_at']
    
    def __str__(self):
        return f"{self.document_name} - {self.donor.full_name}"
    
class Appointment(models.Model):
    APPOINTMENT_STATUS = (
        ('pending', 'Pending'),
        ('confirmed', 'Confirmed'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    )
    
    CONSULTATION_REASONS = (
        ('sperm_donor', 'Sperm Donor Consultation'),
        ('egg_donor', 'Egg Donor Consultation'),
        ('surrogate', 'Surrogate Consultation'),
        ('ivf_treatment', 'IVF Treatment'),
        ('fertility_assessment', 'Fertility Assessment'),
        ('genetic_counseling', 'Genetic Counseling'),
        ('other', 'Other'),
    )
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    donor = models.ForeignKey(Donor, on_delete=models.CASCADE, null=True, blank=True)
    # Appointment details filled by parent/user
    name = models.CharField(max_length=255)
    email = models.EmailField(validators=[EmailValidator()])
    phone_number = models.CharField(max_length=17)
    reason_for_consultation = models.CharField(
        max_length=50, 
        choices=CONSULTATION_REASONS,
        default='other'
    )
    additional_notes = models.TextField(blank=True, null=True)
    
    # Clinic and Parent references
    clinic = models.ForeignKey(
        'User', 
        on_delete=models.CASCADE, 
        related_name='clinic_appointments',
        limit_choices_to={'user_type': 'clinic'}
    )
    parent = models.ForeignKey(
        'User', 
        on_delete=models.CASCADE, 
        related_name='parent_appointments',
        limit_choices_to={'user_type': 'parent'},
        null=True,
        blank=True
    )
    
    # Appointment status and management
    status = models.CharField(max_length=20, choices=APPOINTMENT_STATUS, default='pending')
    preferred_date = models.DateField(null=True, blank=True)
    preferred_time = models.TimeField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Admin management
    reviewed_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_appointments',
        limit_choices_to={'user_type__in': ['admin', 'subadmin']}
    )
    admin_notes = models.TextField(blank=True, null=True)
    
    class Meta:
        db_table = 'appointments'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.name} - {self.clinic.get_full_name()} - {self.get_reason_for_consultation_display()}"

class FertilityProfile(models.Model):
    """Parent's fertility matching profile"""
    DONOR_TYPE_CHOICES = [
        ('sperm', 'Sperm Donor'),
        ('egg', 'Egg Donor'),
        ('both', 'Both'),
    ]
    
    EDUCATION_CHOICES = [
        ('high_school', 'High School'),
        ('bachelors', 'Bachelor\'s Degree'),
        ('masters', 'Master\'s Degree'),
        ('doctorate', 'Doctorate'),
        ('professional', 'Professional Degree'),
    ]
    
    ETHNICITY_CHOICES = [
        ('caucasian', 'Caucasian'),
        ('african', 'African'),
        ('asian', 'Asian'),
        ('hispanic', 'Hispanic'),
        ('middle_eastern', 'Middle Eastern'),
        ('mixed', 'Mixed'),
        ('other', 'Other'),
    ]
    
    EYE_COLOR_CHOICES = [
        ('brown', 'Brown'),
        ('blue', 'Blue'),
        ('green', 'Green'),
        ('hazel', 'Hazel'),
        ('gray', 'Gray'),
    ]
    
    # Basic Info
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    parent = models.ForeignKey('User', on_delete=models.CASCADE, related_name='fertility_profiles')
    donor_type_preference = models.CharField(max_length=20, choices=DONOR_TYPE_CHOICES)
    location = models.CharField(max_length=255)
    
    # Physical Attributes Preferences
    preferred_height_min = models.IntegerField(help_text="Height in cm", null=True, blank=True)
    preferred_height_max = models.IntegerField(help_text="Height in cm", null=True, blank=True)
    preferred_ethnicity = models.CharField(max_length=50, choices=ETHNICITY_CHOICES, blank=True)
    preferred_eye_color = models.CharField(max_length=20, choices=EYE_COLOR_CHOICES, blank=True)
    preferred_hair_color = models.CharField(max_length=50, blank=True)
    
    # Education & Background
    preferred_education_level = models.CharField(max_length=50, choices=EDUCATION_CHOICES, blank=True)
    genetic_screening_required = models.BooleanField(default=True)
    
    # Demographic Preferences
    preferred_age_min = models.IntegerField(null=True, blank=True)
    preferred_age_max = models.IntegerField(null=True, blank=True)
    preferred_occupation = models.CharField(max_length=255, blank=True)
    preferred_religion = models.CharField(max_length=100, blank=True)
    
    # Additional Preferences
    importance_physical = models.IntegerField(default=5, help_text="1-10 scale")
    importance_education = models.IntegerField(default=5, help_text="1-10 scale")
    importance_medical = models.IntegerField(default=5, help_text="1-10 scale")
    importance_personality = models.IntegerField(default=5, help_text="1-10 scale")
    
    # Special Requirements
    special_requirements = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'fertility_profiles'
        unique_together = ['parent', 'donor_type_preference']

class MatchingResult(models.Model):
    """Store matching results for analytics and caching"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    fertility_profile = models.ForeignKey(FertilityProfile, on_delete=models.CASCADE)
    donor_id = models.CharField(max_length=255)  # Reference to Donor.donor_id
    clinic_id = models.UUIDField()  # Reference to clinic User.id
    match_score = models.FloatField()
    matched_attributes = models.JSONField()
    ai_explanation = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'matching_results'
        unique_together = ['fertility_profile', 'donor_id']
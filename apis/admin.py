from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import User

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name', 'user_type')

class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = '__all__'

@admin.register(User)
class UserAdmin(BaseUserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = User
    
    list_display = [
        'email', 'first_name', 'last_name', 'user_type', 
        'is_verified', 'is_active', 'created_at'
    ]
    list_filter = ['user_type', 'is_active', 'is_verified', 'created_at']
    search_fields = ['email', 'first_name', 'last_name', 'phone_number']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal Info', {
            'fields': (
                'first_name', 'last_name', 'phone_number', 'user_type'
            )
        }),
        ('Parent Specific', {
            'fields': ('relationship_to_child',),
            'classes': ('collapse',)
        }),
        ('Clinic Specific', {
            'fields': ('specialization', 'years_of_experience', 'id_proof'),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': (
                'is_active', 'is_staff', 'is_superuser', 'is_verified',
                'groups', 'user_permissions'
            ),
            'classes': ('collapse',)
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
        ('Relations', {
            'fields': ('created_by',),
            'classes': ('collapse',)
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'email', 'first_name', 'last_name', 'user_type',
                'password1', 'password2'
            ),
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at', 'date_joined', 'last_login']
    
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        is_superuser = request.user.is_superuser
        
        if not is_superuser:
            # Non-superuser admins can't edit superuser fields
            if 'is_superuser' in form.base_fields:
                form.base_fields['is_superuser'].disabled = True
                
        return form
        
    def save_model(self, request, obj, form, change):
        if not change:  # If creating new user
            obj.created_by = request.user
        super().save_model(request, obj, form, change)
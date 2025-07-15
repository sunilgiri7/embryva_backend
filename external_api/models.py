import uuid
from django.db import models
from django.conf import settings

class APIKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # The direct link to the clinic user is more robust.
    clinic = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL, # So deleting the user doesn't lose the key record
        null=True,
        blank=True,
        limit_choices_to={'user_type': 'clinic'},
        related_name='api_keys'
    )
    # This email is now the primary identifier for the key holder.
    hospital_email = models.EmailField(
        unique=True,
        help_text="The email of the external hospital. It must be unique."
    )
    key = models.CharField(max_length=40, unique=True, editable=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='generated_api_keys',
        limit_choices_to={'user_type': 'admin'}
    )

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = uuid.uuid4().hex
        super().save(*args, **kwargs)

    def __str__(self):
        if self.clinic:
            return f"API Key for {self.clinic.get_full_name()}"
        return f"Pre-registration API Key for {self.hospital_email}"
from django.contrib.auth.models import AbstractUser
from django.db import models

from .managers import UserManager


class User(AbstractUser):
    """University member. Authenticates with an institutional email address."""

    username = None
    first_name = None
    last_name = None

    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=150)
    student_id = models.CharField(max_length=50, blank=True)
    department = models.CharField(max_length=120, blank=True)
    phone = models.CharField(max_length=30, blank=True)
    avatar = models.ImageField(upload_to="avatars/", blank=True, null=True)
    is_email_verified = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["full_name"]

    objects = UserManager()

    class Meta:
        ordering = ["-date_joined"]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return self.full_name

    def get_short_name(self):
        return self.full_name.split(" ")[0] if self.full_name else self.email


class SocialAccount(models.Model):
    """A third-party identity (e.g. a Google account) the user can sign in with."""

    class Provider(models.TextChoices):
        GOOGLE = "google", "Google"

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="social_accounts")
    provider = models.CharField(max_length=20, choices=Provider.choices)
    uid = models.CharField(max_length=255, help_text="The provider's stable account id.")
    email = models.EmailField(help_text="The provider account's email when it was linked.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(fields=["provider", "uid"], name="unique_provider_account"),
            models.UniqueConstraint(fields=["user", "provider"], name="one_account_per_provider"),
        ]

    def __str__(self):
        return f"{self.get_provider_display()}: {self.email}"

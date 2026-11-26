"""Signing in and linking accounts with a verified third-party identity."""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from rest_framework.exceptions import PermissionDenied, ValidationError

from .google import GoogleProfile
from .models import SocialAccount
from .tokens import revoke_refresh_tokens
from .validators import validate_university_email

User = get_user_model()
GOOGLE = SocialAccount.Provider.GOOGLE
FULL_NAME_MAX_LENGTH = User._meta.get_field("full_name").max_length


def user_for_google(profile: GoogleProfile):
    """The user a Google sign-in belongs to: linked before, matched by email, or new.

    A new account is only created for a university email address, like registration.
    """
    try:
        return _resolve_google_user(profile)
    except IntegrityError:
        # A concurrent sign-in created or linked the same account first. It has committed,
        # so resolving again finds it (or reports the conflict).
        return _resolve_google_user(profile)


@transaction.atomic
def _resolve_google_user(profile):
    account = (
        SocialAccount.objects.select_related("user")
        .filter(provider=GOOGLE, uid=profile.uid)
        .first()
    )
    if account:
        _ensure_active(account.user)
        return account.user
    return _link_by_email(profile)


def _ensure_active(user):
    if not user.is_active:
        raise PermissionDenied("This account has been disabled.")


def _link_by_email(profile):
    if not profile.email_verified:
        raise ValidationError("Your Google email address is not verified.")

    user = User.objects.select_for_update().filter(email__iexact=profile.email).first()
    if user is None:
        try:
            validate_university_email(profile.email)
        except DjangoValidationError as exc:
            raise ValidationError(exc.messages) from None
        user = User.objects.create_user(
            email=profile.email,
            password=None,  # unusable: signs in with Google until a password is set
            full_name=(profile.name or profile.email.split("@")[0])[:FULL_NAME_MAX_LENGTH],
            is_email_verified=True,
        )
    else:
        _ensure_active(user)
        if user.social_accounts.filter(provider=GOOGLE).exists():
            raise ValidationError("This account is linked to a different Google account.")
        if not user.is_email_verified:
            # Whoever registered never proved they own this address; Google just did.
            # Drop their password and sessions so they cannot sign in to it.
            user.is_email_verified = True
            user.set_unusable_password()
            user.save(update_fields=["is_email_verified", "password"])
            revoke_refresh_tokens(user)

    SocialAccount.objects.create(user=user, provider=GOOGLE, uid=profile.uid, email=profile.email)
    return user


def connect_google(user, profile: GoogleProfile):
    """Links a Google account to a signed-in user."""
    try:
        with transaction.atomic():
            _check_can_connect(user, profile)
            return SocialAccount.objects.create(
                user=user, provider=GOOGLE, uid=profile.uid, email=profile.email
            )
    except IntegrityError:
        # A concurrent request linked one of the two first; the check now explains which.
        _check_can_connect(user, profile)
        raise


def _check_can_connect(user, profile):
    existing = SocialAccount.objects.filter(provider=GOOGLE, uid=profile.uid).first()
    if existing:
        if existing.user_id == user.pk:
            raise ValidationError("This Google account is already connected.")
        raise ValidationError("This Google account is connected to another AKSARA account.")
    if user.social_accounts.filter(provider=GOOGLE).exists():
        raise ValidationError("Disconnect your current Google account first.")


def disconnect(account: SocialAccount):
    """Unlinks a provider, unless it is the user's only way to sign in."""
    user = account.user
    if not user.has_usable_password() and user.social_accounts.count() == 1:
        raise ValidationError(
            "Set a password before disconnecting: use “Forgot password” to create one."
        )
    account.delete()

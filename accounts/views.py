from django.contrib.auth import get_user_model
from django.contrib.auth.models import update_last_login
from django.db import transaction
from django.shortcuts import get_object_or_404
from drf_spectacular.utils import extend_schema, extend_schema_view, inline_serializer
from rest_framework import generics, serializers, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from . import social
from .emails import EmailNotSent, send_password_reset_email, send_verification_email
from .serializers import (
    ChangePasswordSerializer,
    EmailSerializer,
    GoogleCredentialSerializer,
    LoginSerializer,
    LogoutSerializer,
    PasswordResetConfirmSerializer,
    PublicUserSerializer,
    RegisterSerializer,
    SocialAccountSerializer,
    UserSerializer,
    VerifyEmailSerializer,
)
from .tokens import revoke_refresh_tokens

User = get_user_model()

GENERIC_EMAIL_RESPONSE = {"detail": "If an account exists for that email, a message has been sent."}


DetailResponse = inline_serializer(
    "AccountDetailResponse", fields={"detail": serializers.CharField()}
)
TokenResponse = inline_serializer(
    "AccountTokenResponse",
    fields={
        "access": serializers.CharField(),
        "refresh": serializers.CharField(),
        "user": UserSerializer(),
    },
)


class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    @transaction.atomic
    def perform_create(self, serializer):
        # If the email cannot be sent, roll back so the student can simply register again.
        user = serializer.save()
        if not send_verification_email(user):
            raise EmailNotSent()


@extend_schema_view(post=extend_schema(request=LoginSerializer, responses=TokenResponse))
class LoginView(TokenObtainPairView):
    """Returns `access` and `refresh` tokens plus the user."""

    serializer_class = LoginSerializer
    throttle_scope = "auth"


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    @extend_schema(request=VerifyEmailSerializer, responses=DetailResponse)
    def post(self, request):
        serializer = VerifyEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])
        return Response({"detail": "Email verified. You can now log in."})


class ResendVerificationView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    @extend_schema(request=EmailSerializer, responses=DetailResponse)
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(
            email__iexact=serializer.validated_data["email"], is_email_verified=False
        ).first()
        if user:
            send_verification_email(user)
        return Response(GENERIC_EMAIL_RESPONSE)


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    @extend_schema(request=EmailSerializer, responses=DetailResponse)
    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.filter(
            email__iexact=serializer.validated_data["email"], is_active=True
        ).first()
        if user:
            send_password_reset_email(user)
        return Response(GENERIC_EMAIL_RESPONSE)


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    @extend_schema(request=PasswordResetConfirmSerializer, responses=DetailResponse)
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        user.set_password(serializer.validated_data["new_password"])
        user.save(update_fields=["password"])
        revoke_refresh_tokens(user)
        return Response({"detail": "Password has been reset."})


class ChangePasswordView(APIView):
    @extend_schema(request=ChangePasswordSerializer, responses=DetailResponse)
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        request.user.set_password(serializer.validated_data["new_password"])
        request.user.save(update_fields=["password"])
        revoke_refresh_tokens(request.user)
        return Response({"detail": "Password changed."})


class LogoutView(APIView):
    """Revokes the given refresh token."""

    @extend_schema(request=LogoutSerializer, responses={204: None})
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            token = RefreshToken(serializer.validated_data["refresh"])
        except TokenError:
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        if str(token.get(api_settings.USER_ID_CLAIM)) != str(request.user.pk):
            return Response({"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
        token.blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class PublicUserView(generics.RetrieveAPIView):
    queryset = User.objects.filter(is_active=True)
    serializer_class = PublicUserSerializer


class GoogleLoginView(APIView):
    """Signs in with Google, creating the account on first use.

    Same response as `LoginView`: `access` and `refresh` tokens plus the user.
    """

    permission_classes = [AllowAny]
    throttle_scope = "auth"

    @extend_schema(request=GoogleCredentialSerializer, responses=TokenResponse)
    def post(self, request):
        serializer = GoogleCredentialSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = social.user_for_google(serializer.validated_data["profile"])
        refresh = RefreshToken.for_user(user)
        update_last_login(None, user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "user": UserSerializer(user, context={"request": request}).data,
            }
        )


class GoogleConnectView(APIView):
    """Links a Google account to the signed-in user."""

    throttle_scope = "auth"

    @extend_schema(request=GoogleCredentialSerializer, responses={201: SocialAccountSerializer})
    def post(self, request):
        serializer = GoogleCredentialSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        account = social.connect_google(request.user, serializer.validated_data["profile"])
        return Response(SocialAccountSerializer(account).data, status=status.HTTP_201_CREATED)


class SocialDisconnectView(APIView):
    """Unlinks one of the signed-in user's `providers`."""

    @extend_schema(responses={204: None})
    def delete(self, request, pk):
        social.disconnect(get_object_or_404(request.user.social_accounts, pk=pk))
        return Response(status=status.HTTP_204_NO_CONTENT)

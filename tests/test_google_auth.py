import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from django.db import IntegrityError
from rest_framework_simplejwt.tokens import RefreshToken

from accounts import google, social
from accounts.models import SocialAccount, User
from tests.conftest import PASSWORD

pytestmark = pytest.mark.django_db

LOGIN = "/api/auth/social/google/"
CONNECT = "/api/auth/social/google/connect/"
CLIENT_ID = "test-client.apps.googleusercontent.com"

GOOGLE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def disconnect_url(account):
    return f"/api/auth/social/disconnect/{account.pk}/"


def id_token(claims, key=GOOGLE_KEY, **overrides):
    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 3600,
        **claims,
        **overrides,
    }
    return jwt.encode(payload, key, algorithm="RS256")


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


@pytest.fixture
def google_user(settings, monkeypatch):
    """Stands in for Google. Edit the returned claims to change who signs in."""
    settings.GOOGLE_CLIENT_ID = CLIENT_ID
    settings.GOOGLE_CLIENT_SECRET = "secret"
    claims = {
        "sub": "1234567890",
        "email": "ada@university.edu",
        "email_verified": True,
        "name": "Ada Lovelace",
    }
    monkeypatch.setattr(
        google._signing_keys,
        "get_signing_key_from_jwt",
        lambda token: SimpleNamespace(key=GOOGLE_KEY.public_key()),
    )

    def fake_get(url, params=None, headers=None, timeout=None):
        if url == google.TOKENINFO_URL:  # who an access token was issued to
            return FakeResponse({"aud": CLIENT_ID, "azp": CLIENT_ID, "sub": claims["sub"]})
        return FakeResponse(dict(claims))  # userinfo

    def fake_post(url, data=None, timeout=None):
        assert data["client_secret"] == "secret"
        return FakeResponse({"id_token": id_token(claims), "access_token": "opaque"})

    monkeypatch.setattr(google.requests, "get", fake_get)
    monkeypatch.setattr(google.requests, "post", fake_post)
    return claims


@pytest.fixture
def sign_in(client_for, google_user):
    def _sign_in(**overrides):
        return client_for().post(LOGIN, {"id_token": id_token(google_user, **overrides)})

    return _sign_in


def respond_with(monkeypatch, response):
    monkeypatch.setattr(google.requests, "get", lambda url, **kwargs: response)


# --- Sign-in -----------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["id_token", "access_token", "code"])
def test_first_sign_in_creates_verified_account(client_for, google_user, kind):
    credential = id_token(google_user) if kind == "id_token" else "opaque"

    resp = client_for().post(LOGIN, {kind: credential})

    assert resp.status_code == 200, resp.data
    assert {"access", "refresh", "user"} <= resp.data.keys()
    user = User.objects.get(email="ada@university.edu")
    assert user.full_name == "Ada Lovelace"
    assert user.is_email_verified
    assert not user.has_usable_password()
    assert user.last_login is not None
    assert resp.data["user"]["has_password"] is False
    assert resp.data["user"]["providers"] == [
        {"id": user.social_accounts.get().pk, "provider": "google", "email": "ada@university.edu"}
    ]


def test_returning_user_is_matched_by_google_id_not_email(sign_in, google_user):
    sign_in()
    google_user["email"] = "renamed@university.edu"

    resp = sign_in()

    assert resp.status_code == 200
    assert resp.data["user"]["email"] == "ada@university.edu"
    assert User.objects.count() == 1


def test_links_existing_verified_account_and_keeps_its_password(sign_in, make_user):
    user = make_user(email="Ada@University.edu")

    resp = sign_in()

    assert resp.status_code == 200
    assert resp.data["user"]["id"] == user.pk
    user.refresh_from_db()
    assert user.check_password(PASSWORD)
    assert user.social_accounts.count() == 1


def test_takes_over_unverified_registration_of_the_same_email(sign_in, client_for, make_user):
    squatter = make_user(email="ada@university.edu", verified=False)
    stale = RefreshToken.for_user(squatter)

    assert sign_in().status_code == 200

    squatter.refresh_from_db()
    assert squatter.is_email_verified
    assert not squatter.has_usable_password()
    assert client_for().post("/api/auth/token/refresh/", {"refresh": str(stale)}).status_code == 401


def test_refuses_email_already_linked_to_another_google_account(sign_in, google_user):
    sign_in()
    google_user["sub"] = "another-google-account"

    resp = sign_in()

    assert resp.status_code == 400
    assert resp.data["detail"] == "This account is linked to a different Google account."


def test_new_account_requires_university_email(sign_in, google_user):
    google_user["email"] = "someone@example.com"

    assert sign_in().status_code == 400
    assert not User.objects.exists()


def test_unverified_google_email_is_refused(sign_in, google_user):
    google_user["email_verified"] = False

    resp = sign_in()

    assert resp.status_code == 400
    assert resp.data["detail"] == "Your Google email address is not verified."


def test_long_google_name_is_shortened_to_fit(sign_in, google_user):
    google_user["name"] = "A" * 300

    assert sign_in().status_code == 200
    assert len(User.objects.get().full_name) == 150


def test_disabled_account_cannot_sign_in_and_is_left_untouched(sign_in, make_user):
    user = make_user(email="ada@university.edu", verified=False, is_active=False)

    assert sign_in().status_code == 403

    user.refresh_from_db()
    assert user.check_password(PASSWORD)
    assert not SocialAccount.objects.exists()


def test_disabled_linked_account_cannot_sign_in(sign_in):
    sign_in()
    User.objects.update(is_active=False)

    assert sign_in().status_code == 403


def test_concurrent_first_sign_in_gets_the_account_the_other_request_created(
    google_user, monkeypatch
):
    resolve = social._resolve_google_user
    attempts = []

    def lose_the_race(profile):
        attempts.append(profile)
        if len(attempts) == 1:
            resolve(profile)  # the other request commits the account first
            raise IntegrityError("duplicate key")
        return resolve(profile)

    monkeypatch.setattr(social, "_resolve_google_user", lose_the_race)
    profile = google.GoogleProfile("1234567890", "ada@university.edu", True, "Ada")

    user = social.user_for_google(profile)

    assert user.email == "ada@university.edu"
    assert len(attempts) == 2
    assert SocialAccount.objects.count() == 1


# --- Credential checks ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("overrides", "detail"),
    [
        ({"aud": "someone-else.apps.googleusercontent.com"}, "not issued for AKSARA"),
        ({"iss": "https://evil.example.com"}, "not issued for AKSARA"),
        ({"exp": int(time.time()) - 3600}, "expired"),
    ],
    ids=["audience", "issuer", "expired"],
)
def test_id_token_claims_are_enforced(sign_in, overrides, detail):
    resp = sign_in(**overrides)

    assert resp.status_code == 400
    assert detail in resp.data["detail"]
    assert not User.objects.exists()


def test_id_token_signed_by_another_key_is_refused(client_for, google_user):
    forged = id_token(google_user, key=OTHER_KEY)

    resp = client_for().post(LOGIN, {"id_token": forged})

    assert resp.status_code == 400
    assert resp.data["detail"] == "Google rejected the credential."


def test_malformed_id_token_is_refused_without_fetching_keys(client_for, settings):
    settings.GOOGLE_CLIENT_ID = CLIENT_ID

    resp = client_for().post(LOGIN, {"id_token": "not-a-jwt"})

    assert resp.status_code == 400
    assert resp.data["detail"] == "Google rejected the credential."


def test_access_token_for_another_app_is_refused(client_for, google_user, monkeypatch):
    respond_with(monkeypatch, FakeResponse({"aud": "other", "azp": "other", "sub": "1"}))

    resp = client_for().post(LOGIN, {"access_token": "opaque"})

    assert resp.status_code == 400
    assert resp.data["detail"] == "This Google credential was not issued for AKSARA."


def test_access_token_refused_by_google(client_for, google_user, monkeypatch):
    respond_with(monkeypatch, FakeResponse(ValueError("not json"), status_code=400))

    resp = client_for().post(LOGIN, {"access_token": "expired"})

    assert resp.status_code == 400
    assert resp.data["detail"] == "Google rejected the credential."


@pytest.mark.parametrize(
    "response",
    [FakeResponse({}, status_code=502), FakeResponse(ValueError("not json"))],
    ids=["server-error", "garbage"],
)
def test_google_outage_is_a_503(client_for, google_user, monkeypatch, response):
    respond_with(monkeypatch, response)

    resp = client_for().post(LOGIN, {"access_token": "opaque"})

    assert resp.status_code == 503
    assert resp.data["detail"] == "Google sign-in is unavailable. Please try again."


def test_unreachable_google_is_a_503(client_for, google_user, monkeypatch):
    def unreachable(url, **kwargs):
        raise google.requests.ConnectionError()

    monkeypatch.setattr(google.requests, "get", unreachable)

    assert client_for().post(LOGIN, {"access_token": "opaque"}).status_code == 503


@pytest.mark.parametrize("setting", ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"])
def test_missing_configuration_is_a_503(client_for, google_user, settings, setting):
    setattr(settings, setting, "")

    assert client_for().post(LOGIN, {"code": "c"}).status_code == 503


@pytest.mark.parametrize(
    "body",
    [{}, {"id_token": "a", "access_token": "b"}, {"id_token": "x" * 5000}],
    ids=["none", "two", "too-long"],
)
def test_credential_input_is_validated(client_for, google_user, body):
    assert client_for().post(LOGIN, body).status_code == 400


# --- Connect and disconnect ------------------------------------------------------------


def test_connect_links_google_to_signed_in_user(client_for, sign_in, make_user):
    user = make_user(email="ada.personal@university.edu")
    client = client_for(user)

    resp = client.post(CONNECT, {"access_token": "opaque"})

    assert resp.status_code == 201
    assert resp.data["provider"] == "google"
    assert client.get("/api/auth/me/").data["providers"][0]["email"] == "ada@university.edu"
    # Signing in with that Google account now opens this user's account.
    assert sign_in().data["user"]["id"] == user.pk


def test_connect_refuses_google_account_of_another_user(client_for, sign_in, make_user):
    sign_in()

    resp = client_for(make_user()).post(CONNECT, {"access_token": "opaque"})

    assert resp.status_code == 400
    assert resp.data["detail"] == "This Google account is connected to another AKSARA account."


def test_connect_refuses_a_second_google_account(client_for, google_user, make_user):
    client = client_for(make_user())
    client.post(CONNECT, {"access_token": "opaque"})
    google_user["sub"] = "another-google-account"

    resp = client.post(CONNECT, {"access_token": "opaque"})

    assert resp.status_code == 400
    assert resp.data["detail"] == "Disconnect your current Google account first."


def test_connect_requires_sign_in(client_for, google_user):
    assert client_for().post(CONNECT, {"access_token": "opaque"}).status_code == 401


def test_disconnect_unlinks_provider(client_for, sign_in, make_user):
    user = make_user(email="ada@university.edu")
    sign_in()

    resp = client_for(user).delete(disconnect_url(user.social_accounts.get()))

    assert resp.status_code == 204
    assert not SocialAccount.objects.exists()


def test_disconnect_refused_when_it_is_the_only_way_in(client_for, sign_in):
    sign_in()
    user = User.objects.get()

    resp = client_for(user).delete(disconnect_url(user.social_accounts.get()))

    assert resp.status_code == 400
    assert SocialAccount.objects.exists()


def test_cannot_disconnect_someone_elses_provider(client_for, sign_in, make_user):
    sign_in()

    resp = client_for(make_user()).delete(disconnect_url(SocialAccount.objects.get()))

    assert resp.status_code == 404

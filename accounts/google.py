"""Verifies Google sign-in credentials.

The frontend obtains one of three credentials from Google Identity Services and the
backend turns it into a verified `GoogleProfile`:

- an `id_token` (the "Sign in with Google" button's credential): its signature is checked
  locally against Google's published keys, as Google recommends for production;
- an authorization `code` (popup code flow): exchanged for an ID token using the client
  secret, then checked the same way;
- an `access_token` (token flow, mobile SDKs): opaque, so Google is asked who it belongs to.

Every credential must have been issued to our client ID, so a token minted for another
app cannot be replayed against this API.
"""

import logging
from dataclasses import dataclass

import jwt
import requests
from django.conf import settings
from rest_framework.exceptions import APIException

logger = logging.getLogger(__name__)

CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"
TOKEN_URL = "https://oauth2.googleapis.com/token"
TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
ISSUERS = ["accounts.google.com", "https://accounts.google.com"]
TIMEOUT = 5
CLOCK_SKEW_SECONDS = 30

# Module level so the keys are cached for the life of the process (Google rotates them
# every few days; an unknown key id triggers a refetch).
_signing_keys = jwt.PyJWKClient(CERTS_URL, cache_jwk_set=True, lifespan=60 * 60, timeout=TIMEOUT)


class GoogleAuthError(APIException):
    """The credential is invalid, expired or was issued to another app."""

    status_code = 400
    default_detail = "Google rejected the credential."
    default_code = "google_auth_failed"


class GoogleUnavailable(APIException):
    status_code = 503
    default_detail = "Google sign-in is unavailable. Please try again."
    default_code = "google_unavailable"


@dataclass(frozen=True)
class GoogleProfile:
    uid: str  # Google's stable account id (`sub`); emails can change
    email: str
    email_verified: bool
    name: str
    hosted_domain: str = ""

    @property
    def has_authoritative_email(self):
        return self.email_verified and (
            self.email.endswith("@gmail.com") or bool(self.hosted_domain)
        )


def _client_id():
    if not settings.GOOGLE_CLIENT_ID:
        logger.error("Google sign-in was attempted but GOOGLE_CLIENT_ID is not set.")
        raise GoogleUnavailable()
    return settings.GOOGLE_CLIENT_ID


def _call(method, url, **kwargs):
    """JSON body of a successful Google API call. A 4xx means the credential was refused."""
    try:
        response = method(url, timeout=TIMEOUT, **kwargs)
    except requests.RequestException:
        logger.warning("Could not reach Google at %s.", url, exc_info=True)
        raise GoogleUnavailable() from None
    if 400 <= response.status_code < 500:
        raise GoogleAuthError()
    try:
        if response.status_code != 200:
            raise ValueError(f"HTTP {response.status_code}")
        return response.json()
    except ValueError:
        logger.warning("Unexpected response from Google at %s.", url, exc_info=True)
        raise GoogleUnavailable() from None


def _profile(claims):
    if not claims.get("sub") or not claims.get("email"):
        raise GoogleAuthError("Allow AKSARA to see your email address on Google.")
    verified = claims.get("email_verified")
    return GoogleProfile(
        uid=str(claims["sub"]),
        email=claims["email"].lower().strip(),
        # ID tokens and userinfo carry a boolean, tokeninfo the string "true".
        email_verified=verified is True or verified == "true",
        name=(claims.get("name") or "").strip(),
        hosted_domain=claims.get("hd") or "",
    )


def profile_from_id_token(id_token):
    audience = _client_id()
    try:
        key = _signing_keys.get_signing_key_from_jwt(id_token)
    except jwt.PyJWKClientConnectionError:
        logger.warning("Could not fetch Google's signing keys.", exc_info=True)
        raise GoogleUnavailable() from None
    except (jwt.PyJWKClientError, jwt.DecodeError):
        raise GoogleAuthError() from None
    try:
        claims = jwt.decode(
            id_token,
            key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=ISSUERS,
            leeway=CLOCK_SKEW_SECONDS,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError):
        raise GoogleAuthError("This Google credential was not issued for AKSARA.") from None
    except jwt.ExpiredSignatureError:
        raise GoogleAuthError("Your Google sign-in expired. Please try again.") from None
    except jwt.InvalidTokenError:
        raise GoogleAuthError() from None
    return _profile(claims)


def profile_from_access_token(access_token):
    audience = _client_id()
    info = _call(requests.get, TOKENINFO_URL, params={"access_token": access_token})
    if audience not in (info.get("aud"), info.get("azp")):
        raise GoogleAuthError("This Google credential was not issued for AKSARA.")
    claims = _call(requests.get, USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
    return _profile(claims)


def profile_from_code(code, redirect_uri):
    client_id = _client_id()
    if not settings.GOOGLE_CLIENT_SECRET:
        logger.error("A Google code was sent but GOOGLE_CLIENT_SECRET is not set.")
        raise GoogleUnavailable()
    tokens = _call(
        requests.post,
        TOKEN_URL,
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )
    if not tokens.get("id_token"):
        raise GoogleAuthError("Request the `openid email profile` scopes from Google.")
    return profile_from_id_token(tokens["id_token"])

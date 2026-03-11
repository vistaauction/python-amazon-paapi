"""Credential-version metadata for Amazon Creators API authentication."""

from __future__ import annotations

from dataclasses import dataclass

TOKEN_GRANT_TYPE = "client_credentials"
TOKEN_REQUEST_ENCODING_FORM = "form"
TOKEN_REQUEST_ENCODING_JSON = "json"
V2_SCOPE = "creatorsapi/default"
V3_SCOPE = "creatorsapi::default"


@dataclass(frozen=True)
class CredentialVersionSettings:
    """Authentication settings for a specific Creators API credential version."""

    token_endpoint: str
    scope: str
    token_content_type: str
    token_request_encoding: str
    include_version_in_api_authorization: bool


VERSION_ENDPOINTS = {
    "2.1": "https://creatorsapi.auth.us-east-1.amazoncognito.com/oauth2/token",
    "2.2": "https://creatorsapi.auth.eu-south-2.amazoncognito.com/oauth2/token",
    "2.3": "https://creatorsapi.auth.us-west-2.amazoncognito.com/oauth2/token",
    "3.1": "https://api.amazon.com/auth/o2/token",
    "3.2": "https://api.amazon.co.uk/auth/o2/token",
    "3.3": "https://api.amazon.co.jp/auth/o2/token",
}

SUPPORTED_VERSIONS = tuple(VERSION_ENDPOINTS)
SUPPORTED_VERSIONS_TEXT = ", ".join(SUPPORTED_VERSIONS)

_VERSION_SETTINGS = {
    "2.1": CredentialVersionSettings(
        token_endpoint=VERSION_ENDPOINTS["2.1"],
        scope=V2_SCOPE,
        token_content_type="application/x-www-form-urlencoded",
        token_request_encoding=TOKEN_REQUEST_ENCODING_FORM,
        include_version_in_api_authorization=True,
    ),
    "2.2": CredentialVersionSettings(
        token_endpoint=VERSION_ENDPOINTS["2.2"],
        scope=V2_SCOPE,
        token_content_type="application/x-www-form-urlencoded",
        token_request_encoding=TOKEN_REQUEST_ENCODING_FORM,
        include_version_in_api_authorization=True,
    ),
    "2.3": CredentialVersionSettings(
        token_endpoint=VERSION_ENDPOINTS["2.3"],
        scope=V2_SCOPE,
        token_content_type="application/x-www-form-urlencoded",
        token_request_encoding=TOKEN_REQUEST_ENCODING_FORM,
        include_version_in_api_authorization=True,
    ),
    "3.1": CredentialVersionSettings(
        token_endpoint=VERSION_ENDPOINTS["3.1"],
        scope=V3_SCOPE,
        token_content_type="application/json",
        token_request_encoding=TOKEN_REQUEST_ENCODING_JSON,
        include_version_in_api_authorization=False,
    ),
    "3.2": CredentialVersionSettings(
        token_endpoint=VERSION_ENDPOINTS["3.2"],
        scope=V3_SCOPE,
        token_content_type="application/json",
        token_request_encoding=TOKEN_REQUEST_ENCODING_JSON,
        include_version_in_api_authorization=False,
    ),
    "3.3": CredentialVersionSettings(
        token_endpoint=VERSION_ENDPOINTS["3.3"],
        scope=V3_SCOPE,
        token_content_type="application/json",
        token_request_encoding=TOKEN_REQUEST_ENCODING_JSON,
        include_version_in_api_authorization=False,
    ),
}


def _version_family(version: str) -> str | None:
    """Return the credential-version family."""
    if version.startswith("2."):
        return "2"
    if version.startswith("3."):
        return "3"
    return None


def get_credential_version_settings(
    version: str,
    auth_endpoint: str | None = None,
) -> CredentialVersionSettings:
    """Return auth settings for a credential version.

    A custom auth endpoint preserves the request/authorization behavior of the
    version family while overriding only the token URL.
    """
    settings = _VERSION_SETTINGS.get(version)
    if settings is None:
        family = _version_family(version)
        if family == "2":
            settings = _VERSION_SETTINGS["2.1"]
        elif family == "3":
            settings = _VERSION_SETTINGS["3.1"]

    if settings is None:
        msg = (
            f"Unsupported version: {version}. "
            f"Supported versions are: {SUPPORTED_VERSIONS_TEXT}"
        )
        raise ValueError(msg)

    if auth_endpoint and auth_endpoint.strip():
        return CredentialVersionSettings(
            token_endpoint=auth_endpoint,
            scope=settings.scope,
            token_content_type=settings.token_content_type,
            token_request_encoding=settings.token_request_encoding,
            include_version_in_api_authorization=(
                settings.include_version_in_api_authorization
            ),
        )

    return settings


def build_api_authorization_header(access_token: str, version: str) -> str:
    """Build the Creators API Authorization header for a credential version."""
    settings = get_credential_version_settings(version)
    if settings.include_version_in_api_authorization:
        return f"Bearer {access_token}, Version {version}"
    return f"Bearer {access_token}"

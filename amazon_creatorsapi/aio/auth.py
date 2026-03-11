"""Async OAuth2 token manager for Amazon Creators API.

Handles OAuth2 token acquisition, caching, and automatic refresh using async HTTP.
"""

from __future__ import annotations

import asyncio
import time

from amazon_creatorsapi.errors import AuthenticationError

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    msg = (
        "httpx is required for async support. "
        "Install it with: pip install python-amazon-paapi[async]"
    )
    raise ImportError(msg) from exc

from creatorsapi_python_sdk.auth.credential_versions import (
    TOKEN_GRANT_TYPE,
    V2_SCOPE,
    VERSION_ENDPOINTS,
    get_credential_version_settings,
)


# OAuth2 constants
SCOPE = V2_SCOPE
GRANT_TYPE = TOKEN_GRANT_TYPE

# Token expiration buffer in seconds (refresh 30s before actual expiration)
TOKEN_EXPIRATION_BUFFER = 30


class AsyncOAuth2TokenManager:
    """Async OAuth2 token manager with caching for Amazon Creators API.

    Manages the OAuth2 token lifecycle including:
    - Token acquisition via client credentials grant
    - Token caching with automatic expiration tracking
    - Automatic token refresh when expired
    - Async-safe token refresh with locking

    Args:
        credential_id: OAuth2 credential ID.
        credential_secret: OAuth2 credential secret.
        version: API version (determines auth endpoint).
        auth_endpoint: Optional custom auth endpoint URL.

    """

    def __init__(
        self,
        credential_id: str,
        credential_secret: str,
        version: str,
        auth_endpoint: str | None = None,
    ) -> None:
        """Initialize the async OAuth2 token manager."""
        self._credential_id = credential_id
        self._credential_secret = credential_secret
        self._version = version
        self._settings = get_credential_version_settings(version, auth_endpoint)
        self._auth_endpoint = self._settings.token_endpoint

        self._access_token: str | None = None
        self._expires_at: float | None = None
        self._lock: asyncio.Lock | None = None

    def _determine_auth_endpoint(
        self,
        version: str,
        auth_endpoint: str | None,
    ) -> str:
        """Determine the OAuth2 token endpoint based on version or custom endpoint.

        Args:
            version: API version.
            auth_endpoint: Optional custom auth endpoint.

        Returns:
            The OAuth2 token endpoint URL.

        Raises:
            ValueError: If version is not supported and no custom endpoint provided.

        """
        return get_credential_version_settings(version, auth_endpoint).token_endpoint

    @property
    def lock(self) -> asyncio.Lock:
        """Lazy initialization of the asyncio.Lock.

        The lock must be created lazily to support Python 3.9, where
        asyncio.Lock() requires an event loop to exist. By creating it
        on first access (which happens in an async context), we ensure
        an event loop is available.

        Returns:
            The asyncio.Lock instance.

        """
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def get_token(self) -> str:
        """Get a valid OAuth2 access token, refreshing if necessary.

        Returns:
            A valid access token.

        Raises:
            AuthenticationError: If token acquisition fails.

        """
        if self.is_token_valid():
            # Token is cached and still valid, guaranteed to be str here
            if self._access_token is None:
                msg = "Token should be valid at this point"
                raise AuthenticationError(msg)
            return self._access_token

        # Need to refresh - use lock to prevent concurrent refreshes
        async with self.lock:
            # Double-check after acquiring lock
            if self.is_token_valid():
                if self._access_token is None:
                    msg = "Token should be valid at this point"
                    raise AuthenticationError(msg)
                return self._access_token
            return await self.refresh_token()

    def is_token_valid(self) -> bool:
        """Check if the current token is valid and not expired.

        Returns:
            True if the token is valid, False otherwise.

        """
        return (
            self._access_token is not None
            and self._expires_at is not None
            and time.time() < self._expires_at
        )

    async def refresh_token(self) -> str:
        """Refresh the OAuth2 access token using client credentials grant.

        Returns:
            The new access token.

        Raises:
            AuthenticationError: If token refresh fails.

        """
        request_data = {
            "grant_type": GRANT_TYPE,
            "client_id": self._credential_id,
            "client_secret": self._credential_secret,
            "scope": self._settings.scope,
        }

        headers = {
            "Content-Type": self._settings.token_content_type,
        }

        try:
            async with httpx.AsyncClient() as client:
                request_kwargs = {"headers": headers}
                if self._settings.token_request_encoding == "json":
                    request_kwargs["json"] = request_data
                else:
                    request_kwargs["data"] = request_data
                response = await client.post(self._auth_endpoint, **request_kwargs)

            if response.status_code != 200:  # noqa: PLR2004
                self.clear_token()
                msg = (
                    f"OAuth2 token request failed with status {response.status_code}: "
                    f"{response.text}"
                )
                raise AuthenticationError(msg)

            data = response.json()

            if "access_token" not in data:
                self.clear_token()
                msg = "No access token received from OAuth2 endpoint"
                raise AuthenticationError(msg)

            self._access_token = data["access_token"]
            # Set expiration time with buffer to avoid edge cases
            expires_in = data.get("expires_in", 3600)
            self._expires_at = time.time() + expires_in - TOKEN_EXPIRATION_BUFFER

        except httpx.RequestError as exc:
            self.clear_token()
            msg = f"OAuth2 token request failed: {exc}"
            raise AuthenticationError(msg) from exc

        # At this point, self._access_token is guaranteed to be a string
        if self._access_token is None:
            msg = "Token should be set at this point"
            raise AuthenticationError(msg)
        return self._access_token

    def clear_token(self) -> None:
        """Clear the cached token, forcing a refresh on the next get_token() call."""
        self._access_token = None
        self._expires_at = None

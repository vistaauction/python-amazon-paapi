"""Unit tests for bundled sync SDK auth behavior."""

import time
import unittest
from unittest.mock import MagicMock, patch

from creatorsapi_python_sdk.auth.oauth2_config import OAuth2Config
from creatorsapi_python_sdk.auth.oauth2_token_manager import OAuth2TokenManager


class TestOAuth2Config(unittest.TestCase):
    """Tests for OAuth2Config credential-version behavior."""

    def test_v3_uses_lwa_settings(self) -> None:
        """Version 3.x should use the LwA endpoint and header format."""
        config = OAuth2Config("id", "secret", "3.2", None)

        self.assertEqual(
            config.get_cognito_endpoint(),
            "https://api.amazon.co.uk/auth/o2/token",
        )
        self.assertEqual(config.get_scope(), "creatorsapi::default")
        self.assertEqual(config.get_token_content_type(), "application/json")
        self.assertTrue(config.uses_json_token_request())
        self.assertEqual(
            config.get_api_authorization_header("token-value"),
            "Bearer token-value",
        )

    def test_v2_keeps_version_in_api_authorization_header(self) -> None:
        """Version 2.x should keep the Creators API version suffix."""
        config = OAuth2Config("id", "secret", "2.2", None)

        self.assertEqual(
            config.get_api_authorization_header("token-value"),
            "Bearer token-value, Version 2.2",
        )


class TestOAuth2TokenManager(unittest.TestCase):
    """Tests for sync OAuth2 token manager request encoding."""

    @patch("creatorsapi_python_sdk.auth.oauth2_token_manager.requests.post")
    def test_v3_refresh_token_uses_json_body(
        self,
        mock_post: MagicMock,
    ) -> None:
        """Version 3.x should use JSON when fetching an access token."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "v3-token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        manager = OAuth2TokenManager(OAuth2Config("id", "secret", "3.1", None))

        token = manager.refresh_token()

        self.assertEqual(token, "v3-token")
        self.assertEqual(manager.access_token, "v3-token")
        self.assertIsNotNone(manager.expires_at)

        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(
            kwargs["json"],
            {
                "grant_type": "client_credentials",
                "client_id": "id",
                "client_secret": "secret",
                "scope": "creatorsapi::default",
            },
        )
        self.assertNotIn("data", kwargs)

    @patch("creatorsapi_python_sdk.auth.oauth2_token_manager.requests.post")
    def test_v2_refresh_token_keeps_form_body(
        self,
        mock_post: MagicMock,
    ) -> None:
        """Version 2.x should keep the existing form-encoded token request."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "v2-token",
            "expires_in": 3600,
        }
        mock_post.return_value = mock_response

        manager = OAuth2TokenManager(OAuth2Config("id", "secret", "2.3", None))
        before = time.time()

        token = manager.refresh_token()

        self.assertEqual(token, "v2-token")
        self.assertIsNotNone(manager.expires_at)
        assert manager.expires_at is not None
        self.assertGreater(manager.expires_at, before)

        _, kwargs = mock_post.call_args
        self.assertEqual(
            kwargs["headers"]["Content-Type"],
            "application/x-www-form-urlencoded",
        )
        self.assertEqual(
            kwargs["data"],
            {
                "grant_type": "client_credentials",
                "client_id": "id",
                "client_secret": "secret",
                "scope": "creatorsapi/default",
            },
        )
        self.assertNotIn("json", kwargs)

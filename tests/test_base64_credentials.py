#!/usr/bin/env python
"""
Tests for base64 credential loading functionality
"""

import base64
import json
import os
import pytest
from unittest.mock import patch, MagicMock

# Sample test credentials (not real, just for testing structure)
SAMPLE_SERVICE_ACCOUNT = {
    "type": "service_account",
    "project_id": "test-project",
    "private_key_id": "test-key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n",
    "client_email": "test@test-project.iam.gserviceaccount.com",
    "client_id": "123456789",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
}

SAMPLE_OAUTH_CREDENTIALS = {
    "installed": {
        "client_id": "test-client-id.apps.googleusercontent.com",
        "client_secret": "test-client-secret",
        "redirect_uris": ["http://localhost"]
    }
}

SAMPLE_OAUTH_TOKEN = {
    "token": "test-access-token",
    "refresh_token": "test-refresh-token",
    "token_uri": "https://oauth2.googleapis.com/token",
    "client_id": "test-client-id.apps.googleusercontent.com",
    "client_secret": "test-client-secret",
    "scopes": ["https://www.googleapis.com/auth/spreadsheets"]
}


def encode_json_to_base64(data: dict) -> str:
    """Helper to encode JSON to base64"""
    json_str = json.dumps(data)
    return base64.b64encode(json_str.encode()).decode()


class TestBase64Credentials:
    """Test base64 credential loading"""

    def test_credentials_json_b64_decoding(self):
        """Test that CREDENTIALS_JSON_B64 can be decoded properly"""
        # Encode the sample credentials
        encoded = encode_json_to_base64(SAMPLE_SERVICE_ACCOUNT)
        
        # Decode and verify
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded == SAMPLE_SERVICE_ACCOUNT
        assert decoded["type"] == "service_account"
        assert decoded["project_id"] == "test-project"

    def test_token_json_b64_decoding(self):
        """Test that TOKEN_JSON_B64 can be decoded properly"""
        # Encode the sample token
        encoded = encode_json_to_base64(SAMPLE_OAUTH_TOKEN)
        
        # Decode and verify
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded == SAMPLE_OAUTH_TOKEN
        assert decoded["token"] == "test-access-token"
        assert decoded["refresh_token"] == "test-refresh-token"

    def test_oauth_credentials_b64_decoding(self):
        """Test that OAuth credentials can be decoded properly"""
        # Encode the sample OAuth credentials
        encoded = encode_json_to_base64(SAMPLE_OAUTH_CREDENTIALS)
        
        # Decode and verify
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded == SAMPLE_OAUTH_CREDENTIALS
        assert "installed" in decoded
        assert decoded["installed"]["client_id"] == "test-client-id.apps.googleusercontent.com"

    @patch.dict(os.environ, {
        "CREDENTIALS_JSON_B64": encode_json_to_base64(SAMPLE_SERVICE_ACCOUNT)
    })
    def test_env_var_credentials_json_b64(self):
        """Test that CREDENTIALS_JSON_B64 environment variable is read correctly"""
        encoded = os.environ.get("CREDENTIALS_JSON_B64")
        assert encoded is not None
        
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded["type"] == "service_account"

    @patch.dict(os.environ, {
        "TOKEN_JSON_B64": encode_json_to_base64(SAMPLE_OAUTH_TOKEN)
    })
    def test_env_var_token_json_b64(self):
        """Test that TOKEN_JSON_B64 environment variable is read correctly"""
        encoded = os.environ.get("TOKEN_JSON_B64")
        assert encoded is not None
        
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded["token"] == "test-access-token"

    @patch.dict(os.environ, {
        "CREDENTIALS_JSON_B64": encode_json_to_base64(SAMPLE_OAUTH_CREDENTIALS),
        "TOKEN_JSON_B64": encode_json_to_base64(SAMPLE_OAUTH_TOKEN)
    })
    def test_env_var_both_oauth_parts(self):
        """Test that both OAuth credentials and token can be provided via env vars"""
        creds_encoded = os.environ.get("CREDENTIALS_JSON_B64")
        token_encoded = os.environ.get("TOKEN_JSON_B64")
        
        assert creds_encoded is not None
        assert token_encoded is not None
        
        creds_decoded = json.loads(base64.b64decode(creds_encoded))
        token_decoded = json.loads(base64.b64decode(token_encoded))
        
        assert "installed" in creds_decoded
        assert token_decoded["refresh_token"] == "test-refresh-token"

    def test_credentials_config_backwards_compatibility(self):
        """Test that CREDENTIALS_CONFIG still works (backwards compatibility)"""
        encoded = encode_json_to_base64(SAMPLE_SERVICE_ACCOUNT)
        
        # Both should decode the same way
        decoded = json.loads(base64.b64decode(encoded))
        assert decoded == SAMPLE_SERVICE_ACCOUNT


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


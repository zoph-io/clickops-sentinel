# SPDX-License-Identifier: Apache-2.0
"""SSM SecureString retrieval and caching."""

from unittest.mock import MagicMock

import email_secret


def test_get_api_key_fetches_with_decryption(monkeypatch):
    ssm = MagicMock()
    ssm.get_parameter.return_value = {"Parameter": {"Value": "secret-key"}}
    monkeypatch.setattr(email_secret.boto3, "client", MagicMock(return_value=ssm))
    monkeypatch.setattr(email_secret, "_cache", {})
    monkeypatch.setenv("EMAIL_API_KEY_PARAM", "/clickops-sentinel/email-api-key")

    assert email_secret.get_api_key() == "secret-key"
    ssm.get_parameter.assert_called_once_with(
        Name="/clickops-sentinel/email-api-key", WithDecryption=True
    )


def test_get_api_key_is_cached(monkeypatch):
    ssm = MagicMock()
    ssm.get_parameter.return_value = {"Parameter": {"Value": "secret-key"}}
    monkeypatch.setattr(email_secret.boto3, "client", MagicMock(return_value=ssm))
    monkeypatch.setattr(email_secret, "_cache", {})
    monkeypatch.setenv("EMAIL_API_KEY_PARAM", "/clickops-sentinel/email-api-key")

    assert email_secret.get_api_key() == "secret-key"
    assert email_secret.get_api_key() == "secret-key"
    assert ssm.get_parameter.call_count == 1

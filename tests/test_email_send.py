# SPDX-License-Identifier: Apache-2.0
"""Email transport: provider request shapes with mocked network."""

import io
import json
import urllib.request
from unittest.mock import MagicMock

import pytest

import email_secret
import email_send


@pytest.fixture()
def email_env(monkeypatch):
    env = {
        "EMAIL_ENABLED": "true",
        "EMAIL_PROVIDER": "resend",
        "EMAIL_FROM": "alerts@example.com",
        "EMAIL_TO": "owner@example.com",
        "EMAIL_API_KEY_PARAM": "/clickops-sentinel/email-api-key",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(email_secret, "get_api_key", lambda: "test-key")
    return env


@pytest.fixture()
def captured_requests(monkeypatch):
    requests = []

    def fake_urlopen(request, timeout=None):
        requests.append(request)
        return io.BytesIO(b"{}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return requests


def test_disabled_email_sends_nothing(monkeypatch, captured_requests):
    monkeypatch.setenv("EMAIL_ENABLED", "false")
    assert email_send.send_email("s", "<p>h</p>", "t") is False
    assert captured_requests == []


def test_unknown_provider_returns_false(email_env, monkeypatch, captured_requests):
    monkeypatch.setenv("EMAIL_PROVIDER", "pigeon")
    assert email_send.send_email("s", "<p>h</p>", "t") is False
    assert captured_requests == []


def test_resend_request_shape(email_env, captured_requests):
    assert email_send.send_email("Subject", "<p>html</p>", "text") is True
    request = captured_requests[0]
    assert request.full_url == "https://api.resend.com/emails"
    assert request.get_header("Authorization") == "Bearer test-key"
    assert request.get_header("User-agent") == email_send.USER_AGENT
    body = json.loads(request.data)
    assert body["from"] == "alerts@example.com"
    assert body["to"] == ["owner@example.com"]
    assert body["subject"] == "Subject"
    assert body["html"] == "<p>html</p>"
    assert body["text"] == "text"


def test_postmark_request_shape(email_env, monkeypatch, captured_requests):
    monkeypatch.setenv("EMAIL_PROVIDER", "postmark")
    assert email_send.send_email("Subject", "<p>h</p>", "t") is True
    request = captured_requests[0]
    assert request.full_url == "https://api.postmarkapp.com/email"
    assert request.get_header("X-postmark-server-token") == "test-key"
    body = json.loads(request.data)
    assert body["HtmlBody"] == "<p>h</p>"
    assert body["TextBody"] == "t"


def test_sendgrid_request_shape(email_env, monkeypatch, captured_requests):
    monkeypatch.setenv("EMAIL_PROVIDER", "sendgrid")
    assert email_send.send_email("Subject", "<p>h</p>", "t") is True
    request = captured_requests[0]
    assert request.full_url == "https://api.sendgrid.com/v3/mail/send"
    body = json.loads(request.data)
    assert body["personalizations"][0]["to"][0]["email"] == "owner@example.com"
    types = [item["type"] for item in body["content"]]
    assert types == ["text/plain", "text/html"]


def test_mailgun_request_shape(email_env, monkeypatch, captured_requests):
    monkeypatch.setenv("EMAIL_PROVIDER", "mailgun")
    monkeypatch.setenv("EMAIL_MAILGUN_DOMAIN", "mg.example.com")
    assert email_send.send_email("Subject", "<p>h</p>", "t") is True
    request = captured_requests[0]
    assert request.full_url == "https://api.mailgun.net/v3/mg.example.com/messages"
    assert request.get_header("Authorization").startswith("Basic ")
    assert b"subject=Subject" in request.data


def test_smtp_sends_multipart(email_env, monkeypatch):
    monkeypatch.setenv("EMAIL_PROVIDER", "smtp")
    monkeypatch.setenv("EMAIL_SMTP_HOST", "mail.example.com")
    monkeypatch.setenv("EMAIL_SMTP_PORT", "587")
    server = MagicMock()
    monkeypatch.setattr(email_send.smtplib, "SMTP", MagicMock(return_value=server))
    assert email_send.send_email("Subject", "<p>h</p>", "t") is True
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("alerts@example.com", "test-key")
    from_addr, to_addrs, message = server.sendmail.call_args.args
    assert from_addr == "alerts@example.com"
    assert to_addrs == ["owner@example.com"]
    assert "text/html" in message
    server.quit.assert_called_once()


def test_provider_failure_is_swallowed(email_env, monkeypatch):
    def explode(request, timeout=None):
        raise OSError("network down")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    assert email_send.send_email("Subject", "<p>h</p>", "t") is False

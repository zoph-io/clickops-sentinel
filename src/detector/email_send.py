# SPDX-License-Identifier: Apache-2.0
"""Provider-agnostic email delivery.

Sends multipart (HTML plus plain text) email through an external provider,
selected by the EMAIL_PROVIDER environment variable. HTTP providers use
stdlib urllib only; the smtp provider uses stdlib smtplib for self-hosting.
No third-party dependency, no Amazon SES.

Delivery is best-effort by design: callers wrap send_email in try/except so
an email failure never blocks the chat notification.

This module is duplicated in src/detector and src/investigator because SAM
packages each CodeUri separately. Keep both copies identical.
"""

import base64
import json
import logging
import os
import smtplib
import urllib.parse
import urllib.request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import email_secret

logger = logging.getLogger()

HTTP_TIMEOUT_SECONDS = 10

# Providers such as Resend sit behind Cloudflare, which returns 403 for the
# default "Python-urllib/x.y" User-Agent. Send an explicit one.
USER_AGENT = "clickops-sentinel/1.0"


def email_enabled() -> bool:
    return os.environ.get("EMAIL_ENABLED") == "true"


def _post_json(url: str, payload: dict, headers: dict) -> None:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
            **headers,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        response.read()


def _send_resend(
    api_key: str, from_addr: str, to_addr: str, subject: str, html: str, text: str
) -> None:
    _post_json(
        "https://api.resend.com/emails",
        {
            "from": from_addr,
            "to": [to_addr],
            "subject": subject,
            "html": html,
            "text": text,
        },
        {"Authorization": f"Bearer {api_key}"},
    )


def _send_postmark(
    api_key: str, from_addr: str, to_addr: str, subject: str, html: str, text: str
) -> None:
    _post_json(
        "https://api.postmarkapp.com/email",
        {
            "From": from_addr,
            "To": to_addr,
            "Subject": subject,
            "HtmlBody": html,
            "TextBody": text,
            "MessageStream": "outbound",
        },
        {"X-Postmark-Server-Token": api_key},
    )


def _send_sendgrid(
    api_key: str, from_addr: str, to_addr: str, subject: str, html: str, text: str
) -> None:
    _post_json(
        "https://api.sendgrid.com/v3/mail/send",
        {
            "personalizations": [{"to": [{"email": to_addr}]}],
            "from": {"email": from_addr},
            "subject": subject,
            "content": [
                {"type": "text/plain", "value": text},
                {"type": "text/html", "value": html},
            ],
        },
        {"Authorization": f"Bearer {api_key}"},
    )


def _send_mailgun(
    api_key: str, from_addr: str, to_addr: str, subject: str, html: str, text: str
) -> None:
    """Mailgun uses form encoding and basic auth. EMAIL_MAILGUN_DOMAIN and an
    optional EMAIL_MAILGUN_BASE_URL (EU region) come from the environment."""
    domain = os.environ["EMAIL_MAILGUN_DOMAIN"]
    base_url = os.environ.get("EMAIL_MAILGUN_BASE_URL", "https://api.mailgun.net")
    data = urllib.parse.urlencode(
        {
            "from": from_addr,
            "to": to_addr,
            "subject": subject,
            "html": html,
            "text": text,
        }
    ).encode()
    credentials = base64.b64encode(f"api:{api_key}".encode()).decode()
    request = urllib.request.Request(
        f"{base_url}/v3/{domain}/messages",
        data=data,
        headers={
            "Authorization": f"Basic {credentials}",
            "User-Agent": USER_AGENT,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        response.read()


def _send_smtp(
    api_key: str, from_addr: str, to_addr: str, subject: str, html: str, text: str
) -> None:
    """Self-hosted or generic SMTP. The SSM secret holds the SMTP password;
    host, port, and username come from the environment. STARTTLS is used on
    port 587 (default); port 465 uses implicit TLS."""
    host = os.environ["EMAIL_SMTP_HOST"]
    port = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
    username = os.environ.get("EMAIL_SMTP_USERNAME", from_addr)

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = from_addr
    message["To"] = to_addr
    message.attach(MIMEText(text, "plain"))
    message.attach(MIMEText(html, "html"))

    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=HTTP_TIMEOUT_SECONDS)
    else:
        server = smtplib.SMTP(host, port, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        if port != 465:
            server.starttls()
        if api_key:
            server.login(username, api_key)
        server.sendmail(from_addr, [to_addr], message.as_string())
    finally:
        server.quit()


PROVIDERS = {
    "resend": _send_resend,
    "postmark": _send_postmark,
    "sendgrid": _send_sendgrid,
    "mailgun": _send_mailgun,
    "smtp": _send_smtp,
}


def send_email(subject: str, html: str, text: str) -> bool:
    """Send one email through the configured provider. Returns True when the
    provider accepted the message, False on any failure (logged, not raised)."""
    if not email_enabled():
        return False
    provider_name = os.environ.get("EMAIL_PROVIDER", "resend")
    provider = PROVIDERS.get(provider_name)
    if provider is None:
        logger.error("unknown email provider: %s", provider_name)
        return False
    try:
        api_key = email_secret.get_api_key()
        provider(
            api_key,
            os.environ["EMAIL_FROM"],
            os.environ["EMAIL_TO"],
            subject[:180],
            html,
            text,
        )
        return True
    except Exception as error:  # noqa: BLE001 email is best-effort by design
        logger.error("email delivery failed (%s): %s", provider_name, error)
        return False

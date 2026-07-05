# SPDX-License-Identifier: Apache-2.0
"""Notification content: schema validity and writing style rules."""

import json

import sample_events

import messages
import notify

VERDICT = {
    "verdict": "manual-change-confirmed",
    "confidence": "high",
    "purpose": "Launching a large EC2 instance for ad hoc testing.",
    "security_severity": "low",
    "security_analysis": "No IAM or exposure changes in the session.",
    "cost_impact": "significant",
    "cost_analysis": "One m5.4xlarge on-demand costs roughly 550 USD per month.",
    "session_narrative": "The user browsed AMIs, then launched one instance.",
    "history_context": "First manual change recorded for this actor.",
    "recommendation": "Ask the user to codify the instance in Terraform or terminate it.",
}


def _assert_style(text: str) -> None:
    assert "\u2014" not in text, "em-dash found"
    assert "\u2013" not in text, "en-dash found"
    for char in text:
        assert ord(char) < 0x1F000, f"emoji-range character found: {char!r}"


def test_qdev_payload_schema():
    payload = json.loads(
        notify.build_qdev_payload("Title", "body", "thread-1", "summary", ["clickops"])
    )
    assert payload["version"] == "1.0"
    assert payload["source"] == "custom"
    assert payload["content"]["textType"] == "client-markdown"
    assert payload["content"]["title"] == "Title"
    assert payload["metadata"]["threadId"] == "thread-1"


def test_plain_alert_content_and_style():
    alert = notify.build_plain_alert(
        sample_events.CONSOLE_MUTATION, "alice@example.com", "prod (123456789012)"
    )
    assert alert["title"] == "ClickOps detected: RunInstances"
    assert "ec2.amazonaws.com:RunInstances" in alert["markdown"]
    assert "cloudtrailv2" in alert["markdown"]
    assert "m5.4xlarge" in alert["markdown"]
    _assert_style(alert["markdown"])
    _assert_style(alert["text"])


def test_enriched_alert_leads_with_purpose_and_verdict():
    alert = messages.build_enriched_alert(
        sample_events.CONSOLE_MUTATION, "alice@example.com", "prod", VERDICT
    )
    lines = alert["markdown"].splitlines()
    assert lines[0].startswith("*Purpose*")
    assert lines[1].startswith("*Verdict*")
    assert "manual-change-confirmed" in alert["markdown"]
    assert "550 USD" in alert["markdown"]
    assert "Recommendation" in alert["markdown"]
    _assert_style(alert["markdown"])
    _assert_style(alert["text"])


def test_enriched_alert_hides_empty_history():
    verdict = {**VERDICT, "history_context": "none"}
    alert = messages.build_enriched_alert(
        sample_events.CONSOLE_MUTATION, "alice", "prod", verdict
    )
    assert "*History*" not in alert["markdown"]


def test_failed_call_is_marked():
    record = {**sample_events.CONSOLE_MUTATION, "errorCode": "AccessDenied"}
    alert = messages.build_plain_alert(record, "alice", "prod")
    assert "failed (AccessDenied)" in alert["markdown"]


def test_login_alert_content():
    alert = notify.build_login_alert(
        sample_events.ROOT_LOGIN, "Root user", "prod", "root sign-in"
    )
    assert "root sign-in" in alert["title"]
    assert "MFA used" in alert["markdown"]
    _assert_style(alert["markdown"])


def test_request_parameters_truncation():
    record = {
        **sample_events.CONSOLE_MUTATION,
        "requestParameters": {"blob": "x" * 5000},
    }
    text = notify.summarize_request_parameters(record)
    assert len(text) <= 400 + len("...(truncated)")
    assert text.endswith("...(truncated)")

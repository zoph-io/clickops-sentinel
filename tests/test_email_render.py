# SPDX-License-Identifier: Apache-2.0
"""Email HTML rendering: content, session path, escaping, style rules."""

import sample_events

import criticality
import email_render

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

SESSION_STEPS = [
    {"time": "2026-07-05T11:52:00Z", "name": "ConsoleLogin", "source": "signin.amazonaws.com"},
    {"time": "2026-07-05T11:55:00Z", "name": "DescribeImages", "source": "ec2.amazonaws.com"},
    {"time": "2026-07-05T12:00:00Z", "name": "RunInstances", "source": "ec2.amazonaws.com"},
    {"time": "2026-07-05T12:01:00Z", "name": "CreateTags", "source": "ec2.amazonaws.com"},
]


def _assert_style(text: str) -> None:
    assert "\u2014" not in text, "em-dash found"
    assert "\u2013" not in text, "en-dash found"
    for char in text:
        assert ord(char) < 0x1F000, f"emoji-range character found: {char!r}"


def _enriched(steps=None):
    marked = email_render.mark_highlighted_step(
        steps if steps is not None else SESSION_STEPS, sample_events.CONSOLE_MUTATION
    )
    return email_render.enriched_email(
        sample_events.CONSOLE_MUTATION,
        "alice@example.com",
        "prod (123456789012)",
        VERDICT,
        marked,
    )


def test_enriched_email_contains_verdict_and_cards():
    email = _enriched()
    assert email["subject"] == "ClickOps detected: RunInstances"
    html = email["html"]
    assert "MANUAL CHANGE CONFIRMED" in html
    assert "confidence high" in html
    assert "SIGNIFICANT" in html  # cost impact card
    assert VERDICT["purpose"] in html
    assert VERDICT["recommendation"] in html
    assert "cloudtrailv2" in html
    _assert_style(html)


def test_enriched_email_renders_all_session_steps():
    html = _enriched()["html"]
    assert "CONSOLE SESSION PATH" in html
    for step in SESSION_STEPS:
        assert step["name"] in html
    # Service badges derived from eventSource.
    assert "SIGNIN" in html
    assert "EC2" in html


def test_triggering_event_is_highlighted():
    marked = email_render.mark_highlighted_step(
        SESSION_STEPS, sample_events.CONSOLE_MUTATION
    )
    highlighted = [step for step in marked if step.get("highlight")]
    assert len(highlighted) == 1
    assert highlighted[0]["name"] == "RunInstances"
    assert "this alert" in _enriched()["html"]


def test_highlight_falls_back_to_last_step():
    steps = [
        {"time": "2026-07-05T11:52:00Z", "name": "ConsoleLogin", "source": "signin.amazonaws.com"}
    ]
    marked = email_render.mark_highlighted_step(steps, sample_events.CONSOLE_MUTATION)
    assert marked[-1]["highlight"] is True


def test_long_sessions_are_trimmed_but_keep_highlight():
    steps = [
        {"time": f"2026-07-05T10:{i:02d}:00Z", "name": f"Step{i}", "source": "ec2.amazonaws.com"}
        for i in range(30)
    ]
    steps.append(
        {"time": "2026-07-05T12:00:00Z", "name": "RunInstances", "source": "ec2.amazonaws.com"}
    )
    html = _enriched(steps)["html"]
    assert "RunInstances" in html
    assert "earlier event(s) in this session" in html


def test_html_escaping():
    record = {
        **sample_events.CONSOLE_MUTATION,
        "eventName": "<script>alert(1)</script>",
    }
    email = email_render.plain_email(record, "alice<b>", "prod", "")
    assert "<script>" not in email["html"]
    assert "&lt;script&gt;" in email["html"]


def test_plain_email_shows_failure():
    record = {**sample_events.CONSOLE_MUTATION, "errorCode": "AccessDenied"}
    html = email_render.plain_email(record, "alice", "prod", "note text")["html"]
    assert "FAILED" in html
    assert "AccessDenied" in html
    assert "note text" in html
    _assert_style(html)


def test_login_email_content():
    email = email_render.login_email(
        sample_events.ROOT_LOGIN, "Root user", "prod (123456789012)", "root sign-in"
    )
    assert email["subject"] == "Console sign-in alert: root sign-in"
    html = email["html"]
    assert "ROOT SIGN-IN" in html
    assert "MFA USED" in html
    _assert_style(html)


def test_enriched_email_shows_catalog_match_and_floor():
    rating = criticality.classify(sample_events.SG_OPEN_SSH, overrides="", stack_name="")
    verdict = {**VERDICT, "security_severity": "critical", "agent_security_severity": "medium"}
    email = email_render.enriched_email(
        sample_events.SG_OPEN_SSH, "alice", "prod", verdict, [], rating, sample_events.IP_INFO
    )
    html = email["html"]
    assert email["subject"] == "[CRITICAL] ClickOps detected: AuthorizeSecurityGroupIngress"
    assert "CRITICALITY CATALOG" in html
    assert "NET-001" in html
    assert "https://attack.mitre.org/techniques/T1562/007/" in html
    assert "aws.exfiltration.ec2-security-group-open-port-22-ingress" in html
    assert "Why: port 22 open to 0.0.0.0/0" in html
    assert "Agent rated MEDIUM, raised to the catalog floor." in html
    _assert_style(html)


def test_who_block_shows_network_and_flags():
    ip_info = {**sample_events.IP_INFO, "flags": ["vpn"]}
    html = email_render.plain_email(
        sample_events.CONSOLE_MUTATION, "alice", "prod", "", None, ip_info
    )["html"]
    assert "AS3215 Orange S.A." in html
    assert "Paris, Ile-de-France, FR" in html
    assert "Source flagged: VPN" in html
    _assert_style(html)


def test_plain_email_criticality_card():
    rating = criticality.classify(sample_events.CLOUDTRAIL_STOP, overrides="", stack_name="")
    rated = email_render.plain_email(sample_events.CLOUDTRAIL_STOP, "alice", "prod", "", rating)
    assert rated["subject"] == "[CRITICAL] ClickOps detected: StopLogging"
    assert "LOG-001" in rated["html"]
    unrated = email_render.plain_email(sample_events.CONSOLE_MUTATION, "alice", "prod")
    assert "UNRATED" in unrated["html"]
    assert unrated["subject"] == "ClickOps detected: RunInstances"


def test_session_path_tags_risky_steps():
    steps = [
        {"time": "2026-07-05T11:59:00Z", "name": "StopLogging",
         "source": "cloudtrail.amazonaws.com", "criticality": "critical", "rule": "LOG-001"},
        {"time": "2026-07-05T12:00:00Z", "name": "RunInstances",
         "source": "ec2.amazonaws.com", "criticality": "low", "rule": "CMP-005"},
    ]
    html = _enriched(steps)["html"]
    assert "CRITICAL LOG-001" in html
    assert "LOW CMP-005" not in html


def test_note_email_content():
    email = email_render.note_email("Title here", "Body text here.")
    assert email["subject"] == "Title here"
    assert "Body text here." in email["html"]
    _assert_style(email["html"])

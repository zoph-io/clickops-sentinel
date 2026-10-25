# SPDX-License-Identifier: Apache-2.0
"""Render the email templates locally from test fixtures.

Usage: python scripts/render_email.py [output.html]

Writes docs/email-preview.html by default. Open it in a browser to iterate
on the design offline; no AWS access is needed.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "investigator"))
sys.path.insert(0, str(ROOT / "tests"))

import sample_events  # noqa: E402

import client  # noqa: E402
import criticality  # noqa: E402
import email_render  # noqa: E402
import origin  # noqa: E402

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
    {
        "time": "2026-07-05T11:58:00Z",
        "name": "DescribeInstanceTypes",
        "source": "ec2.amazonaws.com",
    },
    {"time": "2026-07-05T12:00:00Z", "name": "RunInstances", "source": "ec2.amazonaws.com"},
    {"time": "2026-07-05T12:01:00Z", "name": "CreateTags", "source": "ec2.amazonaws.com"},
]


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "email-preview.html"

    record = dict(sample_events.BROWSER_MUTATION)
    ip_info = sample_events.IP_INFO
    steps = email_render.mark_highlighted_step(SESSION_STEPS, record)
    enriched_context = client.new_context(record)
    enriched_context["assessment"] = origin.assess(
        origin.collect(record, enriched_context["client"], ip_info, {"signin_gap_seconds": 1})
    )
    enriched = email_render.enriched_email(
        record, "alice@example.com", "prod (123456789012)", VERDICT, steps,
        criticality.classify(record, overrides="", stack_name=""), ip_info,
        enriched_context,
    )
    # An ordinary browser opening SSH in a console session opened from CLI
    # credentials, from a hosting network, after the country changed.
    exposure = {
        **sample_events.SG_OPEN_SSH,
        "userAgent": sample_events.CHROME_UA,
        "userIdentity": sample_events.FEDERATED_CONSOLE_MUTATION["userIdentity"],
    }
    exposure_ip = {**ip_info, "asn": "AS16509", "isp": "Amazon.com, Inc.", "flags": ["hosting"]}
    context = client.new_context(exposure)
    context["anomalies"] = ["source country changed mid-session: FR to US"]
    context["assessment"] = origin.assess(
        origin.collect(exposure, context["client"], exposure_ip, {"signin_gap_seconds": 389})
    )
    plain = email_render.plain_email(
        exposure, "alice@example.com", "prod (123456789012)",
        "AI investigation unavailable, plain alert.",
        criticality.apply_session_anomalies(
            criticality.classify(exposure, overrides="", stack_name=""), context["anomalies"]
        ),
        exposure_ip,
        context,
    )
    login = email_render.login_email(
        sample_events.ROOT_LOGIN, "Root user", "prod (123456789012)", "root sign-in", ip_info,
        client.parse(sample_events.CHROME_UA),
    )

    followup_record = {
        **sample_events.FEDERATED_CONSOLE_MUTATION,
        "eventName": "DeleteSecurityGroup",
    }
    followup_context = client.new_context(followup_record)
    followup_context["assessment"] = origin.assess(
        origin.collect(
            followup_record, followup_context["client"], ip_info, {"signin_gap_seconds": 389}
        )
    )
    followup = email_render.followup_email(
        followup_record, "botocore-session-1792740938 (assumed role admin)",
        "prod (123456789012)",
        criticality.classify(followup_record, overrides="", stack_name=""), ip_info,
        followup_context,
    )
    notice = email_render.note_email(
        "ClickOps Sentinel: AI budget exhausted for today",
        "The daily Bedrock token budget is spent. Alerts continue on the plain path "
        "until the next UTC day.",
    )

    emails = [enriched, plain, followup, login, notice]
    separator = '<div style="height:32px;"></div>'
    output.write_text(separator.join(email["html"] for email in emails))
    print(f"Wrote {output}")
    print("Subjects: " + " | ".join(email["subject"] for email in emails))


if __name__ == "__main__":
    main()

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

import email_render  # noqa: E402

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

    record = dict(sample_events.CONSOLE_MUTATION)
    steps = email_render.mark_highlighted_step(SESSION_STEPS, record)
    enriched = email_render.enriched_email(
        record, "alice@example.com", "prod (123456789012)", VERDICT, steps
    )
    plain = email_render.plain_email(
        record, "alice@example.com", "prod (123456789012)",
        "AI investigation unavailable, plain alert.",
    )
    login = email_render.login_email(
        sample_events.ROOT_LOGIN, "Root user", "prod (123456789012)", "root sign-in"
    )

    separator = '<div style="height:32px;"></div>'
    output.write_text(
        enriched["html"] + separator + plain["html"] + separator + login["html"]
    )
    print(f"Wrote {output}")
    print(f"Subjects: {enriched['subject']} | {plain['subject']} | {login['subject']}")


if __name__ == "__main__":
    main()

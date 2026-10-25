# SPDX-License-Identifier: Apache-2.0
"""Render the README email screenshots from the real templates.

Each scenario below is fixture data run through email_render, captured with
headless Chrome at 2x, and trimmed to the card. Rerun after any change to
the email design so the README never shows a stale template.

Usage: python scripts/render_screenshots.py   (or: make screenshots)
Needs Google Chrome or Chromium, and ImageMagick (`magick`) for trimming.
"""

import copy
import html
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src" / "detector"))
sys.path.insert(0, str(ROOT / "src" / "investigator"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

import render_brand  # noqa: E402
import sample_events  # noqa: E402

import client  # noqa: E402
import criticality  # noqa: E402
import email_render  # noqa: E402
import messages  # noqa: E402
import notify  # noqa: E402
import origin  # noqa: E402

OUT = ROOT / "docs" / "screenshots"
ACCOUNT = "prod (123456789012)"
PARIS = sample_events.IP_INFO


def _record(base: dict, **overrides) -> dict:
    record = copy.deepcopy(base)
    record.update(overrides)
    return record


def _context(record: dict, ip_info: dict | None, lineage: dict | None = None) -> dict:
    context = client.new_context(record)
    context["assessment"] = origin.assess(
        origin.collect(record, context["client"], ip_info, lineage)
    )
    return context


def _steps(record: dict, steps: list) -> list:
    return email_render.mark_highlighted_step(
        [{"time": t, "name": n, "source": s} for t, n, s in steps], record
    )


SUSPICIOUS_RECORD = _record(
    sample_events.SG_OPEN_SSH,
    eventTime="2026-10-21T22:47:00Z",
    sourceIPAddress="198.51.100.77",
    userAgent=sample_events.CHROME_UA,
)
SUSPICIOUS_IP = {
    "ip": "198.51.100.77",
    "city": "Ashburn",
    "region": "Virginia",
    "country": "US",
    "asn": "AS7922",
    "isp": "Comcast Cable Communications, LLC",
    "flags": [],
}
SUSPICIOUS_VERDICT = {
    "verdict": "suspicious",
    "confidence": "high",
    "purpose": "Opening SSH (port 22) on the production database bastion to the whole "
    "internet, apparently to reach the host from an unmanaged network.",
    "security_severity": "critical",
    "agent_security_severity": "high",
    "security_analysis": "Ingress 0.0.0.0/0 on tcp/22 for sg-0a1b2c3d (prod-bastion). The "
    "session also created a new IAM access key for a service user, which is unusual "
    "for this actor.",
    "cost_impact": "negligible",
    "cost_analysis": "No billable resources created.",
    "session_narrative": "Late-night sign-in from a new IP, straight to the security group "
    "of the bastion, then IAM. No reads of tickets, runbooks, or tags beforehand.",
    "history_context": "First security group change by this actor in 180 days; first "
    "sign-in from this IP range.",
    "recommendation": "Revoke the 0.0.0.0/0 rule now, deactivate the new access key, and "
    "confirm with bob@example.com before re-enabling anything.",
}


def suspicious() -> dict:
    record = SUSPICIOUS_RECORD
    steps = _steps(
        record,
        [
            ("2026-10-21T22:41:00Z", "ConsoleLogin", "signin.amazonaws.com"),
            ("2026-10-21T22:44:00Z", "DescribeSecurityGroups", "ec2.amazonaws.com"),
            ("2026-10-21T22:47:00Z", "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"),
            ("2026-10-21T22:49:00Z", "ListUsers", "iam.amazonaws.com"),
            ("2026-10-21T22:51:00Z", "CreateAccessKey", "iam.amazonaws.com"),
        ],
    )
    return email_render.enriched_email(
        record,
        "bob@example.com",
        ACCOUNT,
        SUSPICIOUS_VERDICT,
        steps,
        criticality.classify(record, overrides="", stack_name=""),
        SUSPICIOUS_IP,
        _context(record, SUSPICIOUS_IP),
    )


def _markdown(text: str) -> str:
    """The subset of Slack mrkdwn the alerts use: *bold*, `code`, <url|label>."""
    text = html.escape(text, quote=False)
    text = re.sub(r"&lt;(https?://[^|]+)\|([^&]+)&gt;", r'<a href="\1">\2</a>', text)
    text = re.sub(r"\*([^*\n]+)\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    return text.replace("\n", "<br>")


def slack() -> dict:
    """Slack as Amazon Q Developer renders it, with the real chat builders."""
    record = SUSPICIOUS_RECORD
    rating = criticality.classify(record, overrides="", stack_name="")
    alert = messages.build_enriched_alert(
        record,
        "bob@example.com",
        ACCOUNT,
        SUSPICIOUS_VERDICT,
        rating,
        SUSPICIOUS_IP,
        _context(record, SUSPICIOUS_IP),
    )
    followup_record = _record(
        record,
        eventSource="iam.amazonaws.com",
        eventName="CreateAccessKey",
        eventTime="2026-10-21T22:51:00Z",
    )
    note = notify.build_followup_note(
        followup_record,
        "bob@example.com",
        criticality.classify(followup_record, overrides="", stack_name=""),
        _context(followup_record, SUSPICIOUS_IP),
    )
    c = email_render.COLOR
    page = f"""<!DOCTYPE html><html><body style="margin:0;background:{c["night"]};
font-family:{email_render.SANS};font-size:15px;line-height:1.5;color:#d1d2d3;">
<div style="margin:24px;background:#1a1d21;border:1px solid #2c2d30;border-radius:12px;">
<div style="padding:14px 20px;border-bottom:1px solid #2c2d30;">
<b style="color:#fff;font-size:17px;"># aws-clickops</b>
<span style="color:#9a9b9e;margin-left:10px;font-size:13px;">
ClickOps Sentinel alerts for prod</span>
</div>
<div style="padding:16px 20px;display:flex;gap:12px;">
<div style="width:38px;height:38px;border-radius:8px;background:#232f3e;color:{c["signal"]};
font-weight:800;display:flex;align-items:center;justify-content:center;flex:none;">Q</div>
<div style="flex:1;">
<div><b style="color:#fff;">Amazon Q Developer</b>
<span style="background:#35373b;color:#ababad;font-size:10px;font-weight:700;padding:1px 4px;
border-radius:3px;margin-left:4px;">APP</span>
<span style="color:#9a9b9e;font-size:12px;margin-left:6px;">22:47</span></div>
<div style="border-left:4px solid {c["danger"]};padding:2px 0 2px 14px;margin-top:6px;">
<div style="color:#fff;font-weight:700;margin-bottom:4px;">{html.escape(alert["title"])}</div>
<div>{_markdown(alert["markdown"])}</div></div>
<div style="color:#1d9bd1;font-size:13px;font-weight:700;margin:14px 0 8px 0;">1 reply</div>
<div style="background:#222529;border-radius:8px;padding:12px 14px;">
<div style="border-left:4px solid {c["mist"]};padding-left:12px;">
<div style="color:#fff;font-weight:700;margin-bottom:4px;">{html.escape(note["title"])}</div>
<div>{_markdown(note["markdown"])}</div></div></div>
</div></div></div></body></html>"""
    page = page.replace("<a href", '<a style="color:#1d9bd1;text-decoration:none;" href')
    page = page.replace("<code>", '<code style="color:#e8912d;font-size:13px;">')
    return {"subject": alert["title"], "html": page}


def savings() -> dict:
    record = _record(
        sample_events.BROWSER_MUTATION,
        eventTime="2026-10-22T09:14:00Z",
        eventSource="rds.amazonaws.com",
        eventName="ModifyDBInstance",
        requestParameters={
            "dBInstanceIdentifier": "staging-postgres",
            "dBInstanceClass": "db.r6g.large",
        },
    )
    verdict = {
        "verdict": "likely-sanctioned-activity",
        "confidence": "medium",
        "purpose": "Right-sizing the staging Postgres instance from db.r6g.2xlarge to "
        "db.r6g.large after a week of low CPU.",
        "security_severity": "low",
        "security_analysis": "No network, encryption, or access changes.",
        "cost_impact": "savings",
        "cost_analysis": "Roughly 520 to 560 USD per month saved on-demand in us-east-1.",
        "session_narrative": "The user reviewed Performance Insights CPU metrics for the "
        "instance, then modified the class with apply-immediately off.",
        "history_context": "alice@example.com made two similar right-sizing changes this quarter.",
        "recommendation": "Mirror the new instance class in the Terraform module so the next "
        "apply does not revert it.",
    }
    steps = _steps(
        record,
        [
            ("2026-10-22T09:02:00Z", "ConsoleLogin", "signin.amazonaws.com"),
            ("2026-10-22T09:05:00Z", "GetResourceMetrics", "pi.amazonaws.com"),
            ("2026-10-22T09:11:00Z", "DescribeDBInstances", "rds.amazonaws.com"),
            ("2026-10-22T09:14:00Z", "ModifyDBInstance", "rds.amazonaws.com"),
        ],
    )
    return email_render.enriched_email(
        record,
        "alice@example.com",
        ACCOUNT,
        verdict,
        steps,
        criticality.classify(record, overrides="", stack_name=""),
        PARIS,
        _context(record, PARIS),
    )


def cost() -> dict:
    record = _record(sample_events.BROWSER_MUTATION)
    verdict = {
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
    steps = _steps(
        record,
        [
            ("2026-07-05T11:52:00Z", "ConsoleLogin", "signin.amazonaws.com"),
            ("2026-07-05T11:55:00Z", "DescribeImages", "ec2.amazonaws.com"),
            ("2026-07-05T11:58:00Z", "DescribeInstanceTypes", "ec2.amazonaws.com"),
            ("2026-07-05T12:00:00Z", "RunInstances", "ec2.amazonaws.com"),
            ("2026-07-05T12:01:00Z", "CreateTags", "ec2.amazonaws.com"),
        ],
    )
    return email_render.enriched_email(
        record,
        "alice@example.com",
        ACCOUNT,
        verdict,
        steps,
        criticality.classify(record, overrides="", stack_name=""),
        PARIS,
        _context(record, PARIS, {"signin_gap_seconds": 1}),
    )


def followup() -> dict:
    record = _record(
        sample_events.FEDERATED_CONSOLE_MUTATION,
        eventName="DeleteSecurityGroup",
        eventSource="ec2.amazonaws.com",
        requestParameters={"groupId": "sg-0123456789abcdef0"},
    )
    ip_info = {**PARIS, "ip": record.get("sourceIPAddress", PARIS["ip"])}
    return email_render.followup_email(
        record,
        "botocore-session-1792740938 (assumed role admin)",
        ACCOUNT,
        criticality.classify(record, overrides="", stack_name=""),
        ip_info,
        _context(record, ip_info, {"signin_gap_seconds": 389}),
    )


def login() -> dict:
    return email_render.login_email(
        sample_events.ROOT_LOGIN,
        "Root user",
        ACCOUNT,
        "root sign-in",
        {**PARIS, "ip": "203.0.113.20"},
        client.parse(sample_events.CHROME_UA),
    )


SCENARIOS = {
    "email-suspicious.png": suspicious,
    "email-savings.png": savings,
    "email-cost.png": cost,
    "email-followup.png": followup,
    "email-login.png": login,
    "slack.png": slack,
}
WIDTHS = {"slack.png": 820}


def capture(browser: str, page_html: str, target: Path, width: int = 640) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        page = Path(tmp) / "email.html"
        page.write_text(page_html)
        raw = Path(tmp) / "raw.png"
        subprocess.run(
            [
                browser,
                "--headless=new",
                "--hide-scrollbars",
                "--disable-gpu",
                "--force-device-scale-factor=2",
                f"--window-size={width},3000",
                f"--screenshot={raw}",
                page.as_uri(),
            ],
            check=True,
            capture_output=True,
        )
        night = email_render.COLOR["night"]
        subprocess.run(
            [
                "magick",
                str(raw),
                "-fuzz",
                "1%",
                "-trim",
                "+repage",
                "-bordercolor",
                night,
                "-border",
                "40",
                str(target),
            ],
            check=True,
        )


def main() -> None:
    browser = render_brand.chrome()
    if not browser:
        sys.exit("Chrome or Chromium is required")
    for name, build in SCENARIOS.items():
        email = build()
        capture(browser, email["html"], OUT / name, WIDTHS.get(name, 640))
        print(f"wrote docs/screenshots/{name}  ({email['subject']})")


if __name__ == "__main__":
    main()

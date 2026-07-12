# SPDX-License-Identifier: Apache-2.0
"""Rich HTML email rendering.

Bulletproof email HTML: table layout, inline styles only, no external
resources, no scripts. The console session path diagram is plain HTML and
CSS so it survives Gmail and Outlook. Project writing style applies to all
rendered output: no em-dashes, no en-dashes, no emojis.

This module is duplicated in src/detector and src/investigator because SAM
packages each CodeUri separately. Keep both copies identical.
"""

import html

DARK = "#0f1420"
BRAND_COLOR = "#7dd3fc"
MUTED = "#64748b"
FAINT = "#94a3b8"
BODY_TEXT = "#1e293b"

VERDICT_STYLES = {
    "manual-change-confirmed": ("MANUAL CHANGE CONFIRMED", "#f59e0b", DARK),
    "likely-sanctioned-activity": ("LIKELY SANCTIONED ACTIVITY", "#22c55e", DARK),
    "suspicious": ("SUSPICIOUS", "#ef4444", "#ffffff"),
}

SEVERITY_STYLES = {
    "none": ("#dcfce7", "#166534"),
    "low": ("#dcfce7", "#166534"),
    "medium": ("#fef3c7", "#92400e"),
    "high": ("#fee2e2", "#991b1b"),
    "critical": ("#fee2e2", "#991b1b"),
}

COST_STYLES = {
    "negligible": ("#f1f5f9", "#334155"),
    "low": ("#f1f5f9", "#334155"),
    "moderate": ("#fef3c7", "#92400e"),
    "significant": ("#fee2e2", "#991b1b"),
    "savings": ("#dcfce7", "#166534"),
}

SERVICE_COLORS = {
    "signin": "#334155",
    "sts": "#334155",
    "ec2": "#0ea5e9",
    "s3": "#16a34a",
    "iam": "#8b5cf6",
    "lambda": "#f97316",
    "dynamodb": "#2563eb",
    "rds": "#2563eb",
    "cloudformation": "#db2777",
}
DEFAULT_SERVICE_COLOR = "#475569"

MAX_PATH_STEPS = 12


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _short_time(iso_time: str) -> str:
    """2026-07-05T12:00:00Z becomes 12:00 UTC."""
    iso_time = str(iso_time or "")
    if len(iso_time) >= 16 and iso_time[10] in ("T", " "):
        return iso_time[11:16] + " UTC"
    return iso_time


def _service_slug(event_source: str) -> str:
    """ec2.amazonaws.com becomes ec2."""
    return str(event_source or "").split(".")[0] or "aws"


def _service_badge(event_source: str, highlighted: bool = False) -> str:
    slug = _service_slug(event_source)
    label = _esc(slug.upper()[:9])
    if highlighted:
        background, color = "#f59e0b", DARK
    else:
        background, color = SERVICE_COLORS.get(slug, DEFAULT_SERVICE_COLOR), "#ffffff"
    return (
        f'<div style="background:{background};color:{color};font-size:10px;'
        f'font-weight:700;padding:6px 0;border-radius:6px;font-family:monospace;">'
        f"{label}</div>"
    )


def cloudtrail_console_link(region: str, event_id: str) -> str:
    return (
        f"https://{region}.console.aws.amazon.com/cloudtrailv2/home"
        f"?region={region}#/events/{event_id}"
    )


def _document(header_html: str, body_html: str) -> str:
    footer = (
        "ClickOps Sentinel &middot; open-source console-change detection "
        "&middot; Apache-2.0"
    )
    return (
        "<!DOCTYPE html>"
        '<html><body style="margin:0;padding:0;background:' + DARK + ';">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{DARK};padding:24px 0;font-family:-apple-system,'
        "'Segoe UI',Roboto,Helvetica,Arial,sans-serif;\">"
        '<tr><td align="center">'
        '<table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        'style="width:600px;max-width:600px;background:#ffffff;border-radius:14px;'
        'overflow:hidden;">'
        + header_html
        + body_html
        + '<tr><td style="background:#f8fafc;padding:14px 24px;'
        'border-top:1px solid #e2e8f0;">'
        f'<div style="color:{FAINT};font-size:11px;">{footer}</div>'
        "</td></tr>"
        "</table></td></tr></table></body></html>"
    )


def _header(title: str, account_label: str, region: str, pills_html: str) -> str:
    parts = [_esc(part) for part in (account_label, region) if part]
    context = " &middot; ".join(parts)
    return (
        f'<tr><td style="background:{DARK};padding:20px 24px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        f'<td style="color:{BRAND_COLOR};font-size:13px;font-weight:700;'
        'letter-spacing:1.5px;">CLICKOPS SENTINEL</td>'
        f'<td align="right" style="color:{FAINT};font-size:12px;'
        f'font-family:monospace;">{context}</td>'
        "</tr></table>"
        f'<div style="color:#ffffff;font-size:20px;font-weight:700;margin-top:12px;">'
        f"{_esc(title)}</div>"
        + (f'<div style="margin-top:10px;">{pills_html}</div>' if pills_html else "")
        + "</td></tr>"
    )


def _pill(label: str, background: str, color: str) -> str:
    return (
        f'<span style="display:inline-block;background:{background};color:{color};'
        'font-size:11px;font-weight:700;padding:5px 11px;border-radius:999px;'
        f'margin-right:6px;">{_esc(label)}</span>'
    )


def _who_block(who: str, source_ip: str, event_time: str) -> str:
    return (
        '<tr><td style="padding:18px 24px 4px 24px;">'
        f'<div style="color:{DARK};font-size:14px;"><b>{_esc(who)}</b></div>'
        f'<div style="color:{FAINT};font-size:12px;font-family:monospace;'
        f'margin-top:2px;">{_esc(source_ip)} &middot; {_esc(event_time)}</div>'
        "</td></tr>"
    )


def _card(label: str, value: str, detail: str, background: str, color: str) -> str:
    detail_html = (
        f'<div style="color:{color};font-size:11px;">{_esc(detail)}</div>'
        if detail
        else ""
    )
    return (
        '<td width="33%" valign="top" style="padding:6px;">'
        f'<div style="background:{background};border-radius:10px;padding:12px;">'
        f'<div style="color:{color};font-size:10px;letter-spacing:.5px;">'
        f"{_esc(label)}</div>"
        f'<div style="color:{color};font-size:14px;font-weight:700;">{_esc(value)}</div>'
        f"{detail_html}</div></td>"
    )


def _cards_row(record: dict, verdict: dict) -> str:
    event_name = record.get("eventName", "UnknownEvent")
    service = _service_slug(record.get("eventSource", ""))
    severity = verdict.get("security_severity", "none")
    cost = verdict.get("cost_impact", "negligible")
    severity_bg, severity_fg = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["none"])
    cost_bg, cost_fg = COST_STYLES.get(cost, COST_STYLES["negligible"])
    return (
        '<tr><td style="padding:12px 18px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        + _card("ACTION", event_name, service, "#f1f5f9", "#334155")
        + _card("SECURITY", severity.upper(), "", severity_bg, severity_fg)
        + _card("COST IMPACT", cost.upper(), "", cost_bg, cost_fg)
        + "</tr></table></td></tr>"
    )


def _section(label: str, text: str) -> str:
    if not text:
        return ""
    return (
        '<tr><td style="padding:8px 24px;">'
        f'<div style="color:{MUTED};font-size:10px;font-weight:700;'
        f'letter-spacing:.5px;">{_esc(label)}</div>'
        f'<div style="color:{BODY_TEXT};font-size:14px;line-height:1.5;">'
        f"{_esc(text)}</div></td></tr>"
    )


def _recommendation(text: str) -> str:
    if not text:
        return ""
    return (
        '<tr><td style="padding:16px 24px 4px 24px;">'
        '<div style="background:#eff6ff;border-left:4px solid #3b82f6;'
        'border-radius:6px;padding:12px 14px;">'
        '<div style="color:#1e40af;font-size:10px;font-weight:700;'
        'letter-spacing:.5px;">RECOMMENDATION</div>'
        f'<div style="color:{BODY_TEXT};font-size:14px;line-height:1.5;">'
        f"{_esc(text)}</div></div></td></tr>"
    )


def _cta(link: str, label: str = "View event in CloudTrail") -> str:
    return (
        '<tr><td style="padding:16px 24px 24px 24px;" align="center">'
        f'<a href="{_esc(link)}" style="display:inline-block;background:{DARK};'
        'color:#ffffff;font-size:13px;font-weight:700;text-decoration:none;'
        f'padding:12px 22px;border-radius:8px;">{_esc(label)}</a></td></tr>'
    )


def _path_step(step: dict, is_last: bool) -> str:
    """One row of the session path: service badge plus action and time."""
    highlighted = bool(step.get("highlight"))
    connector = (
        '<div style="width:2px;height:20px;background:#cbd5e1;margin:0 auto;"></div>'
        if not is_last
        else ""
    )
    badge = _service_badge(step.get("source", ""), highlighted)
    name = _esc(step.get("name", "UnknownEvent"))
    when = _esc(_short_time(step.get("time", "")))
    error = step.get("errorCode")
    meta = when + (f" &middot; failed ({_esc(error)})" if error else "")

    if highlighted:
        body = (
            '<div style="background:#fffbeb;border:1px solid #fcd34d;'
            'border-radius:8px;padding:8px 10px;">'
            f'<div style="color:{DARK};font-size:13px;font-weight:700;'
            f'font-family:monospace;">{name} &larr; this alert</div>'
            f'<div style="color:#92400e;font-size:11px;">{meta}</div></div>'
        )
    else:
        body = (
            f'<div style="color:{DARK};font-size:13px;font-weight:600;'
            f'font-family:monospace;">{name}</div>'
            f'<div style="color:{FAINT};font-size:11px;">{meta}</div>'
        )
    return (
        "<tr>"
        f'<td width="66" valign="top" align="center">{badge}{connector}</td>'
        f'<td valign="top" style="padding-left:12px;padding-bottom:6px;">{body}</td>'
        "</tr>"
    )


def _session_path(session_steps: list) -> str:
    """Vertical stepper of the console session, capped at MAX_PATH_STEPS."""
    if not session_steps:
        return ""
    steps = list(session_steps)
    trimmed = 0
    if len(steps) > MAX_PATH_STEPS:
        # Keep the tail of the timeline but never drop the highlighted step.
        highlight_index = next(
            (i for i, step in enumerate(steps) if step.get("highlight")), None
        )
        start = len(steps) - MAX_PATH_STEPS
        if highlight_index is not None and highlight_index < start:
            start = highlight_index
        trimmed = start
        steps = steps[start : start + MAX_PATH_STEPS]

    rows = []
    if trimmed:
        rows.append(
            "<tr><td></td>"
            f'<td style="padding-left:12px;padding-bottom:6px;color:{FAINT};'
            f'font-size:11px;">{trimmed} earlier event(s) in this session</td></tr>'
        )
    for index, step in enumerate(steps):
        rows.append(_path_step(step, is_last=(index == len(steps) - 1)))

    return (
        '<tr><td style="padding:16px 24px 4px 24px;">'
        f'<div style="color:{MUTED};font-size:10px;font-weight:700;'
        'letter-spacing:.5px;margin-bottom:12px;">CONSOLE SESSION PATH</div>'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
        + "".join(rows)
        + "</table></td></tr>"
    )


def mark_highlighted_step(session_steps: list, record: dict) -> list:
    """Flag the step matching the triggering event, by name and time."""
    name = record.get("eventName")
    time_value = str(record.get("eventTime") or "")
    marked = []
    found = False
    for step in session_steps:
        step = dict(step)
        if (
            not found
            and step.get("name") == name
            and str(step.get("time") or "") == time_value
        ):
            step["highlight"] = True
            found = True
        marked.append(step)
    if not found and marked:
        marked[-1] = dict(marked[-1])
        marked[-1]["highlight"] = True
    return marked


def enriched_email(
    record: dict, who: str, account_label: str, verdict: dict, session_steps: list
) -> dict:
    """Full rich email for an agent verdict: cards, session path, callout."""
    event_name = record.get("eventName", "UnknownEvent")
    region = record.get("awsRegion", "us-east-1")
    link = cloudtrail_console_link(region, record.get("eventID", ""))

    verdict_key = verdict.get("verdict", "manual-change-confirmed")
    verdict_label, verdict_bg, verdict_fg = VERDICT_STYLES.get(
        verdict_key, VERDICT_STYLES["manual-change-confirmed"]
    )
    pills = _pill(verdict_label, verdict_bg, verdict_fg) + _pill(
        f"confidence {verdict.get('confidence', 'unknown')}", "#1e293b", "#e2e8f0"
    )

    history = verdict.get("history_context", "")
    if history and history.lower() == "none":
        history = ""

    body = (
        _who_block(who, record.get("sourceIPAddress", "unknown"), record.get("eventTime", ""))
        + _cards_row(record, verdict)
        + _section("PURPOSE", verdict.get("purpose", ""))
        + _session_path(session_steps)
        + _section("SESSION", verdict.get("session_narrative", ""))
        + _section("SECURITY", verdict.get("security_analysis", ""))
        + _section("COST", verdict.get("cost_analysis", ""))
        + _section("HISTORY", history)
        + _recommendation(verdict.get("recommendation", ""))
        + _cta(link)
    )
    header = _header("Manual console change detected", account_label, region, pills)
    return {
        "subject": f"ClickOps detected: {event_name}",
        "html": _document(header, body),
    }


def plain_email(record: dict, who: str, account_label: str, note: str = "") -> dict:
    """Detection email without agent-derived sections."""
    event_name = record.get("eventName", "UnknownEvent")
    event_source = record.get("eventSource", "unknown")
    region = record.get("awsRegion", "us-east-1")
    link = cloudtrail_console_link(region, record.get("eventID", ""))

    action_note = ""
    if record.get("errorCode"):
        action_note = f"failed ({record['errorCode']})"

    body = (
        _who_block(who, record.get("sourceIPAddress", "unknown"), record.get("eventTime", ""))
        + '<tr><td style="padding:12px 18px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        + _card("ACTION", event_name, _service_slug(event_source), "#f1f5f9", "#334155")
        + _card("REGION", region, "", "#f1f5f9", "#334155")
        + _card(
            "RESULT",
            "FAILED" if action_note else "APPLIED",
            action_note,
            "#fee2e2" if action_note else "#f1f5f9",
            "#991b1b" if action_note else "#334155",
        )
        + "</tr></table></td></tr>"
        + _section("NOTE", note)
        + _cta(link)
    )
    header = _header("Manual console change detected", account_label, region, "")
    return {
        "subject": f"ClickOps detected: {event_name}",
        "html": _document(header, body),
    }


def login_email(record: dict, who: str, account_label: str, reason: str) -> dict:
    """Console sign-in alert email."""
    region = record.get("awsRegion", "us-east-1")
    outcome = (record.get("responseElements") or {}).get("ConsoleLogin", "Unknown")
    mfa = (record.get("additionalEventData") or {}).get("MFAUsed", "Unknown")

    pills = _pill(reason.upper(), "#ef4444", "#ffffff")
    body = (
        _who_block(who, record.get("sourceIPAddress", "unknown"), record.get("eventTime", ""))
        + '<tr><td style="padding:12px 18px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        + _card("OUTCOME", outcome, "", "#f1f5f9", "#334155")
        + _card("MFA USED", mfa, "", "#f1f5f9", "#334155")
        + _card("REGION", region, "", "#f1f5f9", "#334155")
        + "</tr></table></td></tr>"
    )
    header = _header("Console sign-in alert", account_label, region, pills)
    return {
        "subject": f"Console sign-in alert: {reason}",
        "html": _document(header, body),
    }


def note_email(title: str, body_text: str) -> dict:
    """Minimal email for follow-up notes and operational notices."""
    body = (
        '<tr><td style="padding:18px 24px;">'
        f'<div style="color:{BODY_TEXT};font-size:14px;line-height:1.5;">'
        f"{_esc(body_text)}</div></td></tr>"
    )
    header = _header(title, "", "", "")
    return {"subject": title, "html": _document(header, body)}

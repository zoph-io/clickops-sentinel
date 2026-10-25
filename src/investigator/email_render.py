# SPDX-License-Identifier: Apache-2.0
"""Rich HTML email rendering.

Bulletproof email HTML: table layout, inline styles only, no external
resources, no scripts, no images. The brand shows through the wordmark and
the amber signal dot, so every email renders the same with images blocked.
Colors and fonts are the design tokens in docs/brand/tokens.json (a test
keeps them equal); docs/brand/README.md documents the components. Project
writing style applies to all rendered output: no em-dashes, no en-dashes,
no emojis.

This module is duplicated in src/detector and src/investigator because SAM
packages each CodeUri separately. Keep both copies identical.
"""

import html

import client as client_mod
import criticality
import ip_intel
import origin

COLOR = {
    "night": "#0f1420",
    "night_raised": "#1e293b",
    "ink": "#1e293b",
    "slate": "#64748b",
    "mist": "#94a3b8",
    "line": "#e2e8f0",
    "paper": "#f8fafc",
    "surface": "#f1f5f9",
    "white": "#ffffff",
    "signal": "#f59e0b",
    "signal_soft": "#fffbeb",
    "signal_tint": "#fef3c7",
    "signal_line": "#fcd34d",
    "signal_ink": "#92400e",
    "sky": "#7dd3fc",
    "info": "#3b82f6",
    "info_soft": "#eff6ff",
    "info_ink": "#1e40af",
    "danger": "#ef4444",
    "danger_soft": "#fee2e2",
    "danger_ink": "#991b1b",
    "safe": "#22c55e",
    "safe_soft": "#dcfce7",
    "safe_ink": "#166534",
}
FONT = {
    "sans": '-apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif',
    "mono": 'SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace',
}
TAGLINE = "Every click, watched."
REPO_URL = "https://github.com/zoph-io/clickops-sentinel"

DARK = COLOR["night"]
MUTED = COLOR["slate"]
FAINT = COLOR["mist"]
BODY_TEXT = COLOR["ink"]
NEUTRAL_TEXT = "#334155"
SANS = FONT["sans"].replace('"', "'")
MONO = FONT["mono"].replace('"', "'")

# Status stripe across the top of the card: the one-glance severity cue.
TONES = {
    "danger": COLOR["danger"],
    "signal": COLOR["signal"],
    "safe": COLOR["safe"],
    "neutral": COLOR["mist"],
}

VERDICT_STYLES = {
    "manual-change-confirmed": ("MANUAL CHANGE CONFIRMED", COLOR["signal"], DARK),
    "likely-sanctioned-activity": ("LIKELY SANCTIONED ACTIVITY", COLOR["safe"], DARK),
    "suspicious": ("SUSPICIOUS", COLOR["danger"], COLOR["white"]),
}
VERDICT_TONES = {
    "manual-change-confirmed": "signal",
    "likely-sanctioned-activity": "safe",
    "suspicious": "danger",
}

SEVERITY_STYLES = {
    "none": (COLOR["safe_soft"], COLOR["safe_ink"]),
    "low": (COLOR["safe_soft"], COLOR["safe_ink"]),
    "medium": (COLOR["signal_tint"], COLOR["signal_ink"]),
    "high": (COLOR["danger_soft"], COLOR["danger_ink"]),
    "critical": (COLOR["danger_soft"], COLOR["danger_ink"]),
}

COST_STYLES = {
    "negligible": (COLOR["surface"], NEUTRAL_TEXT),
    "low": (COLOR["surface"], NEUTRAL_TEXT),
    "moderate": (COLOR["signal_tint"], COLOR["signal_ink"]),
    "significant": (COLOR["danger_soft"], COLOR["danger_ink"]),
    "savings": (COLOR["safe_soft"], COLOR["safe_ink"]),
}

CALLOUTS = {
    "info": (COLOR["info_soft"], COLOR["info"], COLOR["info_ink"]),
    "neutral": (COLOR["paper"], COLOR["mist"], COLOR["slate"]),
    "signal": (COLOR["signal_soft"], COLOR["signal"], COLOR["signal_ink"]),
}

SERVICE_COLORS = {
    "signin": NEUTRAL_TEXT,
    "sts": NEUTRAL_TEXT,
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


def _level_tone(level: str) -> str:
    return "danger" if criticality.RANK.get(level, 0) >= criticality.RANK["high"] else "signal"


def _service_badge(event_source: str, highlighted: bool = False) -> str:
    slug = _service_slug(event_source)
    label = _esc(slug.upper()[:9])
    if highlighted:
        background, color = COLOR["signal"], DARK
    else:
        background, color = SERVICE_COLORS.get(slug, DEFAULT_SERVICE_COLOR), COLOR["white"]
    return (
        f'<div style="background:{background};color:{color};font-size:10px;'
        f'font-weight:700;padding:6px 0;border-radius:6px;font-family:{MONO};">'
        f"{label}</div>"
    )


def cloudtrail_console_link(region: str, event_id: str) -> str:
    return (
        f"https://{region}.console.aws.amazon.com/cloudtrailv2/home"
        f"?region={region}#/events/{event_id}"
    )


def _document(header_html: str, body_html: str) -> str:
    footer = (
        f'<b style="color:{MUTED};">ClickOps Sentinel</b> &middot; {_esc(TAGLINE)} '
        f'&middot; <a href="{REPO_URL}" style="color:{FAINT};">open source, Apache-2.0</a>'
    )
    return (
        "<!DOCTYPE html>"
        f'<html><body style="margin:0;padding:0;background:{DARK};">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="background:{DARK};padding:24px 0;font-family:{SANS};">'
        '<tr><td align="center">'
        '<table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        f'style="width:600px;max-width:600px;background:{COLOR["white"]};'
        'border-radius:14px;overflow:hidden;">'
        + header_html
        + body_html
        + f'<tr><td style="background:{COLOR["paper"]};padding:14px 24px;'
        f'border-top:1px solid {COLOR["line"]};">'
        f'<div style="color:{FAINT};font-size:11px;">{footer}</div>'
        "</td></tr>"
        "</table></td></tr></table></body></html>"
    )


def _wordmark() -> str:
    """Amber signal dot plus CLICKOPS SENTINEL: the logo, in text."""
    return (
        f'<span style="display:inline-block;width:8px;height:8px;border-radius:50%;'
        f'background:{COLOR["signal"]};border:3px solid #4a3410;'
        'vertical-align:middle;margin-right:8px;"></span>'
        f'<span style="color:{COLOR["white"]};font-size:13px;font-weight:800;'
        'letter-spacing:1.5px;vertical-align:middle;">CLICKOPS</span> '
        f'<span style="color:{COLOR["signal"]};font-size:13px;font-weight:800;'
        'letter-spacing:1.5px;vertical-align:middle;">SENTINEL</span>'
    )


def _header(
    title: str, account_label: str, region: str, pills_html: str, tone: str = "signal"
) -> str:
    parts = [_esc(part) for part in (account_label, region) if part]
    context = " &middot; ".join(parts)
    stripe = TONES.get(tone, TONES["signal"])
    return (
        f'<tr><td style="background:{DARK};border-top:4px solid {stripe};'
        'padding:18px 24px 20px 24px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        f"<td>{_wordmark()}</td>"
        f'<td align="right" style="color:{FAINT};font-size:12px;'
        f'font-family:{MONO};">{context}</td>'
        "</tr></table>"
        f'<div style="color:{COLOR["white"]};font-size:20px;font-weight:700;'
        f'margin-top:14px;">{_esc(title)}</div>'
        + (f'<div style="margin-top:10px;">{pills_html}</div>' if pills_html else "")
        + "</td></tr>"
    )


def _pill(label: str, background: str, color: str) -> str:
    return (
        f'<span style="display:inline-block;background:{background};color:{color};'
        'font-size:11px;font-weight:700;padding:5px 11px;border-radius:999px;'
        f'margin-right:6px;">{_esc(label)}</span>'
    )


def _level_pill(level: str) -> str:
    background, color = SEVERITY_STYLES.get(level, SEVERITY_STYLES["none"])
    return _pill(level.upper(), background, color)


def _eyebrow(label: str, margin_bottom: int = 0) -> str:
    """Small uppercase section label, the same everywhere."""
    return (
        f'<div style="color:{MUTED};font-size:10px;font-weight:700;letter-spacing:.5px;'
        f'margin-bottom:{margin_bottom}px;">{label}</div>'
    )


def _who_block(
    who: str,
    source_ip: str,
    event_time: str,
    ip_info: dict | None = None,
    client_info: dict | None = None,
    context: dict | None = None,
) -> str:
    network_html = ""
    if ip_info:
        parts = [_esc(part) for part in (ip_intel.network(ip_info), ip_intel.place(ip_info))]
        network_html = (
            f'<div style="color:{MUTED};font-size:12px;margin-top:2px;">'
            + " &middot; ".join(part for part in parts if part)
            + "</div>"
        )
        if ip_info.get("flags"):
            flags = ", ".join(flag.upper() for flag in ip_info["flags"])
            network_html += (
                f'<div style="color:{COLOR["danger_ink"]};font-size:11px;font-weight:700;'
                f'margin-top:2px;">Source flagged: {_esc(flags)}</div>'
            )
    client_html = ""
    client_line = client_mod.describe(client_info)
    if client_line:
        if context and context.get("origin") == "api":
            client_line += " (API call, not the console)"
        automated = client_mod.is_automated(client_info)
        color = COLOR["signal_ink"] if automated else MUTED
        weight = "700" if automated else "400"
        client_html = (
            f'<div style="color:{color};font-size:12px;font-weight:{weight};margin-top:2px;">'
            f"Client: {_esc(client_line)}</div>"
        )
    for anomaly in (context or {}).get("anomalies", []):
        client_html += (
            f'<div style="color:{COLOR["danger_ink"]};font-size:11px;font-weight:700;'
            f'margin-top:2px;">Session anomaly: {_esc(anomaly)}</div>'
        )
    for observation in (context or {}).get("observations", []):
        client_html += (
            f'<div style="color:{COLOR["signal_ink"]};font-size:11px;margin-top:2px;">'
            f"Note: {_esc(observation)}</div>"
        )
    assessment = (context or {}).get("assessment")
    if assessment and assessment.get("evidence"):
        machine = assessment.get("driver") in ("ai-agent", "automation")
        color = COLOR["signal_ink"] if machine else MUTED
        client_html += (
            f'<div style="color:{color};font-size:12px;font-weight:700;margin-top:6px;">'
            f"Driven by: {_esc(origin.describe(assessment))}</div>"
        )
        for line in origin.evidence_lines(assessment):
            client_html += (
                f'<div style="color:{MUTED};font-size:11px;margin-top:1px;">'
                f"&middot; {_esc(line)}</div>"
            )
        if assessment.get("conflict"):
            client_html += (
                f'<div style="color:{COLOR["danger_ink"]};font-size:11px;font-weight:700;'
                f'margin-top:2px;">Signals disagree: {_esc(assessment["conflict"])}</div>'
            )
    return (
        '<tr><td style="padding:18px 24px 4px 24px;">'
        f'<div style="color:{DARK};font-size:14px;"><b>{_esc(who)}</b></div>'
        f'<div style="color:{FAINT};font-size:12px;font-family:{MONO};'
        f'margin-top:2px;">{_esc(source_ip)} &middot; {_esc(event_time)}</div>'
        f"{network_html}{client_html}"
        "</td></tr>"
    )


def _header_title(context: dict | None) -> str:
    return {
        "ClickOps by an AI agent detected": "Console change by an AI agent",
        "AI agent change detected": "AI agent change detected",
        "Automated ClickOps detected": "Automated console change detected",
    }.get(client_mod.headline(context), "Manual console change detected")


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


def _cards(*cards: str) -> str:
    return (
        '<tr><td style="padding:12px 18px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr>'
        + "".join(cards)
        + "</tr></table></td></tr>"
    )


def _action_card(record: dict) -> str:
    return _card(
        "ACTION",
        record.get("eventName", "UnknownEvent"),
        _service_slug(record.get("eventSource", "")),
        COLOR["surface"],
        NEUTRAL_TEXT,
    )


def _criticality_card(rating: dict | None) -> str:
    level = criticality.level_of(rating)
    if not level:
        return _card("CRITICALITY", "UNRATED", "no catalog match", COLOR["surface"], NEUTRAL_TEXT)
    background, color = SEVERITY_STYLES.get(level, SEVERITY_STYLES["none"])
    return _card("CRITICALITY", level.upper(), rating["rule_id"], background, color)


def _result_card(record: dict) -> str:
    error = record.get("errorCode")
    if error:
        return _card(
            "RESULT", "FAILED", f"failed ({error})", COLOR["danger_soft"], COLOR["danger_ink"]
        )
    return _card("RESULT", "APPLIED", "", COLOR["surface"], NEUTRAL_TEXT)


def _facts_row(record: dict, rating: dict | None) -> str:
    """Action, criticality, result: the three facts every detection carries."""
    return _cards(_action_card(record), _criticality_card(rating), _result_card(record))


def _cards_row(record: dict, verdict: dict, rating: dict | None = None) -> str:
    severity = verdict.get("security_severity", "none")
    cost = verdict.get("cost_impact", "negligible")
    severity_bg, severity_fg = SEVERITY_STYLES.get(severity, SEVERITY_STYLES["none"])
    cost_bg, cost_fg = COST_STYLES.get(cost, COST_STYLES["negligible"])
    rule_id = rating["rule_id"] if rating else ""
    return _cards(
        _action_card(record),
        _card("SECURITY", severity.upper(), rule_id, severity_bg, severity_fg),
        _card("COST IMPACT", cost.upper(), "", cost_bg, cost_fg),
    )


def _criticality_block(rating: dict | None, agent_severity: str = "") -> str:
    """Catalog match: rule, tactic, ATT&CK and Stratus references, reasons."""
    if not rating:
        return ""
    level = rating["level"]
    background, color = SEVERITY_STYLES.get(level, SEVERITY_STYLES["none"])
    lines = [
        f'<div style="color:{DARK};font-size:14px;font-weight:700;">'
        f"{_esc(rating['rule_id'])} &middot; {_esc(rating['title'])}</div>"
    ]
    meta = []
    if rating.get("tactic"):
        meta.append(_esc(rating["tactic"]))
    for technique in rating.get("techniques", []):
        name = criticality.TECHNIQUES.get(technique, "")
        meta.append(
            f'<a href="{_esc(criticality.technique_url(technique))}" '
            f'style="color:{color};font-weight:700;">{_esc(technique)}</a> {_esc(name)}'
        )
    if meta:
        lines.append(
            f'<div style="color:{BODY_TEXT};font-size:12px;">{" &middot; ".join(meta)}</div>'
        )
    if rating.get("stratus"):
        lines.append(
            f'<div style="color:{MUTED};font-size:12px;font-family:{MONO};">'
            f"Stratus Red Team: {_esc(', '.join(rating['stratus']))}</div>"
        )
    if rating.get("reasons"):
        lines.append(
            f'<div style="color:{BODY_TEXT};font-size:12px;">'
            f"Why: {_esc('; '.join(rating['reasons']))}</div>"
        )
    if agent_severity and agent_severity != level:
        lines.append(
            f'<div style="color:{MUTED};font-size:11px;">'
            f"Agent rated {_esc(agent_severity.upper())}, raised to the catalog floor.</div>"
        )
    return (
        '<tr><td style="padding:8px 24px;">'
        + _eyebrow(f"CRITICALITY CATALOG &middot; {_esc(level.upper())}")
        + f'<div style="background:{background};border-left:4px solid {color};'
        'border-radius:6px;padding:10px 12px;margin-top:4px;">'
        + "".join(lines)
        + "</div></td></tr>"
    )


def _section(label: str, text: str) -> str:
    if not text:
        return ""
    return (
        '<tr><td style="padding:8px 24px;">'
        + _eyebrow(_esc(label))
        + f'<div style="color:{BODY_TEXT};font-size:14px;line-height:1.5;">'
        f"{_esc(text)}</div></td></tr>"
    )


def _callout(label: str, text: str, tone: str = "info") -> str:
    """Boxed note with a colored rule: recommendation, context, notices."""
    if not text:
        return ""
    background, rule, ink = CALLOUTS.get(tone, CALLOUTS["info"])
    return (
        '<tr><td style="padding:16px 24px 4px 24px;">'
        f'<div style="background:{background};border-left:4px solid {rule};'
        'border-radius:6px;padding:12px 14px;">'
        f'<div style="color:{ink};font-size:10px;font-weight:700;'
        f'letter-spacing:.5px;">{_esc(label)}</div>'
        f'<div style="color:{BODY_TEXT};font-size:14px;line-height:1.5;">'
        f"{_esc(text)}</div></div></td></tr>"
    )


def _cta(link: str, label: str = "View event in CloudTrail") -> str:
    return (
        '<tr><td style="padding:16px 24px 24px 24px;" align="center">'
        f'<a href="{_esc(link)}" style="display:inline-block;background:{DARK};'
        f'color:{COLOR["white"]};font-size:13px;font-weight:700;text-decoration:none;'
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
    level = step.get("criticality", "")
    if criticality.RANK.get(level, 0) >= criticality.RANK["medium"]:
        level_color = SEVERITY_STYLES[level][1]
        meta += (
            f' &middot; <span style="color:{level_color};font-weight:700;">'
            f"{_esc(level.upper())} {_esc(step.get('rule', ''))}</span>"
        )

    if highlighted:
        body = (
            f'<div style="background:{COLOR["signal_soft"]};'
            f'border:1px solid {COLOR["signal_line"]};border-radius:8px;padding:8px 10px;">'
            f'<div style="color:{DARK};font-size:13px;font-weight:700;'
            f'font-family:{MONO};">{name} &larr; this alert</div>'
            f'<div style="color:{COLOR["signal_ink"]};font-size:11px;">{meta}</div></div>'
        )
    else:
        body = (
            f'<div style="color:{DARK};font-size:13px;font-weight:600;'
            f'font-family:{MONO};">{name}</div>'
            f'<div style="color:{FAINT};font-size:11px;">{meta}</div>'
        )
    return (
        "<tr>"
        f'<td width="66" valign="top" align="center">{badge}{connector}</td>'
        f'<td valign="top" style="padding-left:12px;padding-bottom:6px;">{body}</td>'
        "</tr>"
    )


def _session_path(session_steps: list, label: str = "CONSOLE SESSION PATH") -> str:
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
        + _eyebrow(_esc(label), margin_bottom=12)
        + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0">'
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


def _who(record: dict, who: str, ip_info: dict | None, context: dict | None) -> str:
    return _who_block(
        who,
        record.get("sourceIPAddress", "unknown"),
        record.get("eventTime", ""),
        ip_info,
        (context or {}).get("client"),
        context,
    )


def enriched_email(
    record: dict,
    who: str,
    account_label: str,
    verdict: dict,
    session_steps: list,
    rating: dict | None = None,
    ip_info: dict | None = None,
    context: dict | None = None,
) -> dict:
    """Full rich email for an agent verdict: cards, session path, callout."""
    event_name = record.get("eventName", "UnknownEvent")
    region = record.get("awsRegion", "us-east-1")
    link = cloudtrail_console_link(region, record.get("eventID", ""))

    verdict_key = verdict.get("verdict", "manual-change-confirmed")
    if verdict_key not in VERDICT_STYLES:
        verdict_key = "manual-change-confirmed"
    verdict_label, verdict_bg, verdict_fg = VERDICT_STYLES[verdict_key]
    pills = _pill(verdict_label, verdict_bg, verdict_fg) + _pill(
        f"confidence {verdict.get('confidence', 'unknown')}", COLOR["night_raised"], COLOR["line"]
    )
    severity = verdict.get("security_severity", "")
    tone = VERDICT_TONES[verdict_key]
    if _level_tone(severity) == "danger":
        tone = "danger"

    history = verdict.get("history_context", "")
    if history and history.lower() == "none":
        history = ""

    api_origin = (context or {}).get("origin") == "api"
    body = (
        _who(record, who, ip_info, context)
        + _cards_row(record, verdict, rating)
        + _section("PURPOSE", verdict.get("purpose", ""))
        + _criticality_block(rating, verdict.get("agent_security_severity", ""))
        + _session_path(
            session_steps, "AGENT SESSION PATH" if api_origin else "CONSOLE SESSION PATH"
        )
        + _section("SESSION", verdict.get("session_narrative", ""))
        + _section("SECURITY", verdict.get("security_analysis", ""))
        + _section("COST", verdict.get("cost_analysis", ""))
        + _section("HISTORY", history)
        + _callout("RECOMMENDATION", verdict.get("recommendation", ""), "info")
        + _cta(link)
    )
    header = _header(_header_title(context), account_label, region, pills, tone)
    prefix = criticality.title_prefix(severity)
    return {
        "subject": f"{prefix}{client_mod.headline(context)}: {event_name}",
        "html": _document(header, body),
    }


def plain_email(
    record: dict,
    who: str,
    account_label: str,
    note: str = "",
    rating: dict | None = None,
    ip_info: dict | None = None,
    context: dict | None = None,
) -> dict:
    """Detection email without agent-derived sections."""
    event_name = record.get("eventName", "UnknownEvent")
    region = record.get("awsRegion", "us-east-1")
    link = cloudtrail_console_link(region, record.get("eventID", ""))
    level = criticality.level_of(rating)

    body = (
        _who(record, who, ip_info, context)
        + _facts_row(record, rating)
        + _criticality_block(rating)
        + _section("NOTE", note)
        + _cta(link)
    )
    header = _header(_header_title(context), account_label, region, "", _level_tone(level))
    return {
        "subject": f"{criticality.title_prefix(level)}{client_mod.headline(context)}: {event_name}",
        "html": _document(header, body),
    }


def followup_email(
    record: dict,
    who: str,
    account_label: str,
    rating: dict | None = None,
    ip_info: dict | None = None,
    context: dict | None = None,
    cooldown_minutes: int = 30,
) -> dict:
    """Another change in a session investigated within the cooldown window."""
    event_name = record.get("eventName", "UnknownEvent")
    region = record.get("awsRegion", "us-east-1")
    link = cloudtrail_console_link(region, record.get("eventID", ""))
    level = criticality.level_of(rating)

    pills = _pill("FOLLOW-UP", COLOR["night_raised"], COLOR["line"])
    if level:
        pills += _level_pill(level)
    why = (
        f"ClickOps Sentinel investigated this session less than {cooldown_minutes} "
        "minutes ago, so this change joins that alert instead of starting a new "
        "investigation. A critical change, or a session that switches client or "
        "country, always gets its own investigation."
    )
    body = (
        _who(record, who, ip_info, context)
        + _facts_row(record, rating)
        + _criticality_block(rating)
        + _callout("WHY NO NEW INVESTIGATION", why, "neutral")
        + _cta(link)
    )
    header = _header(
        "Same session, additional change", account_label, region, pills, _level_tone(level)
    )
    return {
        "subject": f"{criticality.title_prefix(level)}Same session, additional change: "
        f"{event_name}",
        "html": _document(header, body),
    }


def login_email(
    record: dict,
    who: str,
    account_label: str,
    reason: str,
    ip_info: dict | None = None,
    client_info: dict | None = None,
) -> dict:
    """Console sign-in alert email."""
    region = record.get("awsRegion", "us-east-1")
    outcome = (record.get("responseElements") or {}).get("ConsoleLogin", "Unknown")
    mfa = (record.get("additionalEventData") or {}).get("MFAUsed", "Unknown")

    pills = _pill(reason.upper(), COLOR["danger"], COLOR["white"])
    body = (
        _who_block(
            who,
            record.get("sourceIPAddress", "unknown"),
            record.get("eventTime", ""),
            ip_info,
            client_info,
        )
        + _cards(
            _card("OUTCOME", outcome, "", COLOR["surface"], NEUTRAL_TEXT),
            _card("MFA USED", mfa, "", COLOR["surface"], NEUTRAL_TEXT),
            _card("REGION", region, "", COLOR["surface"], NEUTRAL_TEXT),
        )
        + '<tr><td style="padding:0 0 12px 0;"></td></tr>'
    )
    header = _header("Console sign-in alert", account_label, region, pills, "danger")
    return {
        "subject": f"Console sign-in alert: {reason}",
        "html": _document(header, body),
    }


def note_email(title: str, body_text: str, label: str = "NOTICE") -> dict:
    """Operational notice, such as the AI budget running out for the day."""
    body = (
        _callout(label, body_text, "neutral")
        + '<tr><td style="padding:0 0 20px 0;"></td></tr>'
    )
    header = _header(title, "", "", _pill(label, COLOR["night_raised"], COLOR["line"]), "neutral")
    return {"subject": title, "html": _document(header, body)}

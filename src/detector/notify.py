# SPDX-License-Identifier: Apache-2.0
"""Plain (non-AI) notification publishing for the detector.

Chat messages use the Amazon Q Developer custom notification schema so they
render natively in Slack and Microsoft Teams. Email messages are plain text.
"""

import json

import client as client_mod
import criticality
import ip_intel


def cloudtrail_console_link(region: str, event_id: str) -> str:
    return (
        f"https://{region}.console.aws.amazon.com/cloudtrailv2/home"
        f"?region={region}#/events/{event_id}"
    )


def build_qdev_payload(
    title: str,
    description_markdown: str,
    thread_id: str,
    summary: str,
    keywords: list | None = None,
) -> str:
    """Amazon Q Developer custom notification JSON envelope."""
    payload = {
        "version": "1.0",
        "source": "custom",
        "content": {
            "textType": "client-markdown",
            "title": title,
            "description": description_markdown,
        },
        "metadata": {
            "threadId": thread_id,
            "summary": summary,
            "eventType": "clickops-sentinel",
        },
    }
    if keywords:
        payload["content"]["keywords"] = keywords
    return json.dumps(payload)


def summarize_request_parameters(record: dict, limit: int = 400) -> str:
    """Compact, truncated view of requestParameters for message context."""
    params = record.get("requestParameters")
    if not params:
        return ""
    text = json.dumps(params, default=str, separators=(",", ":"))
    if len(text) > limit:
        text = text[:limit] + "...(truncated)"
    return text


def _client_fields(context: dict | None) -> list:
    """Origin, client, and session signals as (label, value) pairs."""
    if not context:
        return []
    fields = []
    if context.get("origin") == "api":
        fields.append(("Origin", "API call, not the console"))
    client_line = client_mod.describe(context.get("client"))
    if client_line:
        fields.append(("Client", client_line))
    signals = client_mod.signal_lines(context)
    if signals:
        fields.append(("Client signals", "; ".join(signals)))
    return fields


def build_plain_alert(
    record: dict,
    who: str,
    account_label: str,
    rating: dict | None = None,
    ip_info: dict | None = None,
    context: dict | None = None,
) -> dict:
    """Build title, markdown, and plain-text bodies for a detection alert."""
    event_name = record.get("eventName", "UnknownEvent")
    event_source = record.get("eventSource", "unknown")
    region = record.get("awsRegion", "us-east-1")
    event_id = record.get("eventID", "")
    event_time = record.get("eventTime", "")
    source_ip = record.get("sourceIPAddress", "unknown")
    error_code = record.get("errorCode")
    link = cloudtrail_console_link(region, event_id)
    params = summarize_request_parameters(record)
    source_network = ip_intel.describe(ip_info)

    level = criticality.level_of(rating)
    title = f"{criticality.title_prefix(level)}{client_mod.headline(context)}: {event_name}"
    client_fields = _client_fields(context)
    lines = []
    if rating:
        lines.append(f"*Criticality*: {criticality.describe(rating)}")
    lines += [
        f"*Who*: {who}",
        f"*Action*: {event_source}:{event_name}",
        f"*Account*: {account_label}",
        f"*Region*: {region}",
        f"*Time*: {event_time}",
        f"*Source IP*: {source_ip}",
    ]
    if source_network:
        lines.append(f"*Source network*: {source_network}")
    lines += [f"*{label}*: {value}" for label, value in client_fields]
    if error_code:
        lines.append(f"*Result*: failed ({error_code})")
    if params:
        lines.append(f"*Request*: `{params}`")
    lines.append(f"<{link}|View event in CloudTrail>")
    markdown = "\n".join(lines)

    text_lines = [title]
    if rating:
        text_lines.append(f"Criticality: {criticality.describe(rating)}")
    text_lines += [
        f"Who: {who}",
        f"Action: {event_source}:{event_name}",
        f"Account: {account_label}",
        f"Region: {region}",
        f"Time: {event_time}",
        f"Source IP: {source_ip}",
    ]
    if source_network:
        text_lines.append(f"Source network: {source_network}")
    text_lines += [f"{label}: {value}" for label, value in client_fields]
    if error_code:
        text_lines.append(f"Result: failed ({error_code})")
    if params:
        text_lines.append(f"Request: {params}")
    text_lines.append(f"Event: {link}")
    plain_text = "\n".join(text_lines)

    return {"title": title, "markdown": markdown, "text": plain_text}


def build_login_alert(
    record: dict,
    who: str,
    account_label: str,
    reason: str,
    ip_info: dict | None = None,
    client_info: dict | None = None,
) -> dict:
    """Build bodies for a console sign-in alert."""
    region = record.get("awsRegion", "us-east-1")
    event_time = record.get("eventTime", "")
    source_ip = record.get("sourceIPAddress", "unknown")
    outcome = (record.get("responseElements") or {}).get("ConsoleLogin", "Unknown")
    mfa = (record.get("additionalEventData") or {}).get("MFAUsed", "Unknown")
    source_network = ip_intel.describe(ip_info)

    title = f"Console sign-in alert: {reason}"
    lines = [
        f"*Who*: {who}",
        f"*Outcome*: {outcome}",
        f"*MFA used*: {mfa}",
        f"*Account*: {account_label}",
        f"*Region*: {region}",
        f"*Time*: {event_time}",
        f"*Source IP*: {source_ip}",
    ]
    if source_network:
        lines.append(f"*Source network*: {source_network}")
    if client_mod.describe(client_info):
        lines.append(f"*Client*: {client_mod.describe(client_info)}")
    markdown = "\n".join(lines)
    plain_text = title + "\n" + markdown.replace("*", "")
    return {"title": title, "markdown": markdown, "text": plain_text}


def build_followup_note(
    record: dict, who: str, rating: dict | None = None, context: dict | None = None
) -> dict:
    """Short note for additional changes within an already-investigated session."""
    event_name = record.get("eventName", "UnknownEvent")
    event_source = record.get("eventSource", "unknown")
    region = record.get("awsRegion", "us-east-1")
    event_id = record.get("eventID", "")
    link = cloudtrail_console_link(region, event_id)
    level = criticality.level_of(rating)
    title = f"Same session, additional change: {event_name}"
    if level:
        title += f" ({level.upper()})"
    rating_line = f"\nCriticality: {criticality.describe(rating)}" if rating else ""
    signals = client_mod.signal_lines(context)
    if signals:
        rating_line += f"\nClient signals: {'; '.join(signals)}"
    markdown = (
        f"{who} also performed {event_source}:{event_name} "
        f"in the session investigated above. <{link}|View event>{rating_line}"
    )
    plain_text = (
        f"{title}\n{who} also performed {event_source}:{event_name}"
        f"{rating_line}\nEvent: {link}"
    )
    return {"title": title, "markdown": markdown, "text": plain_text}


def publish(
    sns_client,
    chat_topic_arn: str,
    chat_enabled: bool,
    alert: dict,
    thread_id: str,
) -> None:
    """Publish the chat notification. Email goes through email_send instead."""
    if chat_enabled:
        sns_client.publish(
            TopicArn=chat_topic_arn,
            Message=build_qdev_payload(
                title=alert["title"],
                description_markdown=alert["markdown"],
                thread_id=thread_id,
                summary=alert["title"],
                keywords=["clickops"],
            ),
        )

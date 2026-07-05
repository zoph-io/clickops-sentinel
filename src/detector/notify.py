# SPDX-License-Identifier: Apache-2.0
"""Plain (non-AI) notification publishing for the detector.

Chat messages use the Amazon Q Developer custom notification schema so they
render natively in Slack and Microsoft Teams. Email messages are plain text.
"""

import json


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
            "eventType": "clickops-notifier",
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


def build_plain_alert(record: dict, who: str, account_label: str) -> dict:
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

    title = f"ClickOps detected: {event_name}"
    lines = [
        f"*Who*: {who}",
        f"*Action*: {event_source}:{event_name}",
        f"*Account*: {account_label}",
        f"*Region*: {region}",
        f"*Time*: {event_time}",
        f"*Source IP*: {source_ip}",
    ]
    if error_code:
        lines.append(f"*Result*: failed ({error_code})")
    if params:
        lines.append(f"*Request*: `{params}`")
    lines.append(f"<{link}|View event in CloudTrail>")
    markdown = "\n".join(lines)

    text_lines = [
        title,
        f"Who: {who}",
        f"Action: {event_source}:{event_name}",
        f"Account: {account_label}",
        f"Region: {region}",
        f"Time: {event_time}",
        f"Source IP: {source_ip}",
    ]
    if error_code:
        text_lines.append(f"Result: failed ({error_code})")
    if params:
        text_lines.append(f"Request: {params}")
    text_lines.append(f"Event: {link}")
    plain_text = "\n".join(text_lines)

    return {"title": title, "markdown": markdown, "text": plain_text}


def build_login_alert(record: dict, who: str, account_label: str, reason: str) -> dict:
    """Build bodies for a console sign-in alert."""
    region = record.get("awsRegion", "us-east-1")
    event_time = record.get("eventTime", "")
    source_ip = record.get("sourceIPAddress", "unknown")
    outcome = (record.get("responseElements") or {}).get("ConsoleLogin", "Unknown")
    mfa = (record.get("additionalEventData") or {}).get("MFAUsed", "Unknown")

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
    markdown = "\n".join(lines)
    plain_text = title + "\n" + markdown.replace("*", "")
    return {"title": title, "markdown": markdown, "text": plain_text}


def build_followup_note(record: dict, who: str) -> dict:
    """Short note for additional changes within an already-investigated session."""
    event_name = record.get("eventName", "UnknownEvent")
    event_source = record.get("eventSource", "unknown")
    region = record.get("awsRegion", "us-east-1")
    event_id = record.get("eventID", "")
    link = cloudtrail_console_link(region, event_id)
    title = f"Same session, additional change: {event_name}"
    markdown = (
        f"{who} also performed {event_source}:{event_name} "
        f"in the session investigated above. <{link}|View event>"
    )
    plain_text = f"{title}\n{who} also performed {event_source}:{event_name}\nEvent: {link}"
    return {"title": title, "markdown": markdown, "text": plain_text}


def publish(
    sns_client,
    chat_topic_arn: str,
    email_topic_arn: str,
    chat_enabled: bool,
    email_enabled: bool,
    alert: dict,
    thread_id: str,
) -> None:
    """Publish an alert to the enabled channels."""
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
    if email_enabled:
        sns_client.publish(
            TopicArn=email_topic_arn,
            Subject=alert["title"][:99],
            Message=alert["text"],
        )

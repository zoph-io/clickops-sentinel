# SPDX-License-Identifier: Apache-2.0
"""Notification formatting and publishing for the investigator.

Enriched messages lead with the agent's purpose assessment and verdict.
The plain variants are the fallback when investigation is unavailable.
"""

import json

SEVERITY_LABELS = {
    "none": "none",
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
    "critical": "CRITICAL",
}


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


def _base_fields(record: dict, who: str, account_label: str) -> list:
    event_name = record.get("eventName", "UnknownEvent")
    event_source = record.get("eventSource", "unknown")
    region = record.get("awsRegion", "us-east-1")
    fields = [
        ("Who", who),
        ("Action", f"{event_source}:{event_name}"),
        ("Account", account_label),
        ("Region", region),
        ("Time", record.get("eventTime", "")),
        ("Source IP", record.get("sourceIPAddress", "unknown")),
    ]
    if record.get("errorCode"):
        fields.append(("Result", f"failed ({record['errorCode']})"))
    return fields


def build_enriched_alert(record: dict, who: str, account_label: str, verdict: dict) -> dict:
    """Alert built from the agent's structured verdict."""
    event_name = record.get("eventName", "UnknownEvent")
    region = record.get("awsRegion", "us-east-1")
    event_id = record.get("eventID", "")
    link = cloudtrail_console_link(region, event_id)

    severity = verdict.get("security_severity", "none")
    cost = verdict.get("cost_impact", "negligible")
    title = f"ClickOps detected: {event_name}"

    markdown_lines = [
        f"*Purpose*: {verdict.get('purpose', 'unknown')}",
        f"*Verdict*: {verdict.get('verdict', 'unknown')} "
        f"(confidence {verdict.get('confidence', 'unknown')})",
        f"*Security*: {SEVERITY_LABELS.get(severity, severity)}. "
        f"{verdict.get('security_analysis', '')}",
        f"*Cost*: {cost}. {verdict.get('cost_analysis', '')}",
    ]
    for label, value in _base_fields(record, who, account_label):
        markdown_lines.append(f"*{label}*: {value}")
    markdown_lines.append(f"*Session*: {verdict.get('session_narrative', '')}")
    history = verdict.get("history_context", "")
    if history and history.lower() != "none":
        markdown_lines.append(f"*History*: {history}")
    markdown_lines.append(f"*Recommendation*: {verdict.get('recommendation', '')}")
    markdown_lines.append(f"<{link}|View event in CloudTrail>")
    markdown = "\n".join(markdown_lines)

    text = title + "\n" + markdown.replace("*", "").replace(
        f"<{link}|View event in CloudTrail>", f"Event: {link}"
    )
    return {"title": title, "markdown": markdown, "text": text}


def build_plain_alert(record: dict, who: str, account_label: str, note: str = "") -> dict:
    """Fallback alert without agent-derived sections."""
    event_name = record.get("eventName", "UnknownEvent")
    region = record.get("awsRegion", "us-east-1")
    event_id = record.get("eventID", "")
    link = cloudtrail_console_link(region, event_id)

    title = f"ClickOps detected: {event_name}"
    markdown_lines = [
        f"*{label}*: {value}" for label, value in _base_fields(record, who, account_label)
    ]
    if note:
        markdown_lines.append(f"_{note}_")
    markdown_lines.append(f"<{link}|View event in CloudTrail>")
    markdown = "\n".join(markdown_lines)

    text = title + "\n" + markdown.replace("*", "").replace("_", "").replace(
        f"<{link}|View event in CloudTrail>", f"Event: {link}"
    )
    return {"title": title, "markdown": markdown, "text": text}


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

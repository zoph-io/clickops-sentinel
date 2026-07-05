# SPDX-License-Identifier: Apache-2.0
"""CloudTrail investigation tools exposed to the agent.

All tools enforce client-side throttling (LookupEvents allows 2 requests per
second) and hard page caps, and truncate their output before it enters the
model context.
"""

import json
import time
from datetime import UTC, datetime, timedelta

MAX_PAGES = 3
PAGE_SIZE = 50
THROTTLE_SECONDS = 0.55
MAX_TOOL_OUTPUT_CHARS = 8000
MAX_PARAMS_CHARS = 300


def _truncate(text: str, limit: int) -> str:
    if len(text) > limit:
        return text[:limit] + "...(truncated)"
    return text


def summarize_cloudtrail_event(raw_event: dict) -> dict:
    """Reduce a raw CloudTrail record to the fields that matter for reasoning."""
    user_identity = raw_event.get("userIdentity") or {}
    summary = {
        "time": raw_event.get("eventTime"),
        "name": raw_event.get("eventName"),
        "source": raw_event.get("eventSource"),
        "region": raw_event.get("awsRegion"),
        "readOnly": raw_event.get("readOnly"),
        "ip": raw_event.get("sourceIPAddress"),
        "accessKeyId": user_identity.get("accessKeyId") or raw_event.get("accessKeyId"),
        "fromConsole": raw_event.get("sessionCredentialFromConsole"),
    }
    if raw_event.get("errorCode"):
        summary["errorCode"] = raw_event["errorCode"]
    params = raw_event.get("requestParameters")
    if params:
        summary["requestParameters"] = _truncate(
            json.dumps(params, default=str, separators=(",", ":")), MAX_PARAMS_CHARS
        )
    return summary


def _lookup(cloudtrail_client, lookup_attributes: list, hours: int) -> list:
    """Paged LookupEvents with throttling and page caps."""
    end = datetime.now(UTC)
    start = end - timedelta(hours=hours)
    events = []
    token = None
    for _page in range(MAX_PAGES):
        kwargs = {
            "StartTime": start,
            "EndTime": end,
            "MaxResults": PAGE_SIZE,
        }
        if lookup_attributes:
            kwargs["LookupAttributes"] = lookup_attributes
        if token:
            kwargs["NextToken"] = token
        response = cloudtrail_client.lookup_events(**kwargs)
        for item in response.get("Events", []):
            try:
                raw = json.loads(item.get("CloudTrailEvent", "{}"))
            except json.JSONDecodeError:
                raw = {}
            raw.setdefault("eventTime", str(item.get("EventTime", "")))
            raw.setdefault("eventName", item.get("EventName", ""))
            events.append(raw)
        token = response.get("NextToken")
        if not token:
            break
        time.sleep(THROTTLE_SECONDS)
    return events


def lookup_events_by_user(cloudtrail_client, username: str, hours: int) -> str:
    """Retrace a user's activity. Accepts a username, role session name, or a
    temporary access key ID (ASIA prefix), grouping the timeline by console
    session (one temporary access key equals one session).
    """
    username = (username or "").strip()
    if username.startswith(("ASIA", "AKIA")):
        attribute = {"AttributeKey": "AccessKeyId", "AttributeValue": username}
    else:
        attribute = {"AttributeKey": "Username", "AttributeValue": username}
    events = _lookup(cloudtrail_client, [attribute], hours)

    sessions: dict = {}
    for raw in events:
        summary = summarize_cloudtrail_event(raw)
        key = summary.get("accessKeyId") or "no-session-key"
        sessions.setdefault(key, []).append(summary)
    for timeline in sessions.values():
        timeline.sort(key=lambda item: item.get("time") or "")

    result = {
        "query": username,
        "window_hours": hours,
        "event_count": len(events),
        "sessions": sessions,
    }
    return _truncate(json.dumps(result, default=str), MAX_TOOL_OUTPUT_CHARS)


def lookup_events_by_ip(cloudtrail_client, ip: str, hours: int) -> str:
    """Mutating activity from one source IP. CloudTrail LookupEvents cannot
    filter by IP server-side, so this scans recent write events and filters
    client-side, bounded by the page cap.
    """
    attribute = {"AttributeKey": "ReadOnly", "AttributeValue": "false"}
    events = _lookup(cloudtrail_client, [attribute], hours)
    matches = [
        summarize_cloudtrail_event(raw)
        for raw in events
        if raw.get("sourceIPAddress") == ip
    ]
    matches.sort(key=lambda item: item.get("time") or "")
    result = {
        "ip": ip,
        "window_hours": hours,
        "scanned_write_events": len(events),
        "matching_events": matches,
        "note": "scan is bounded, absence of matches is not proof of absence",
    }
    return _truncate(json.dumps(result, default=str), MAX_TOOL_OUTPUT_CHARS)


def get_event_details(cloudtrail_client, event_id: str) -> str:
    """Full raw CloudTrail record for one event ID."""
    attribute = {"AttributeKey": "EventId", "AttributeValue": event_id}
    events = _lookup(cloudtrail_client, [attribute], hours=24 * 7)
    if not events:
        return json.dumps({"error": f"event {event_id} not found in the last 7 days"})
    return _truncate(json.dumps(events[0], default=str), MAX_TOOL_OUTPUT_CHARS)

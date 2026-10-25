# SPDX-License-Identifier: Apache-2.0
"""Detector Lambda.

Receives CloudTrail events from the EventBridge default bus: console
changes, API changes by clients labelled as AI agents, and changes made
through AWS-managed MCP servers. Filters out noise, deduplicates, extracts
the human identity, tracks the client per session and per actor, weighs who
drove the change, and either hands off to the investigator Lambda (AI path)
or publishes a plain notification directly.
"""

import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError

import client as client_mod
import criticality
import email_render
import email_send
import identity as identity_mod
import ip_intel
import lineage as lineage_mod
import notify
import origin
import suppressed_actions as sup

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

DEDUP_TTL_SECONDS = 24 * 3600
# Console sessions last at most 12 hours.
SESSION_CLIENT_TTL_SECONDS = 12 * 3600

_clients: dict = {}
_account_alias_cache: list = []


def _client(name: str):
    """name is a service, or service@region for a client pinned to a region."""
    if name not in _clients:
        service, _, region = name.partition("@")
        _clients[name] = boto3.client(service, region_name=region or None)
    return _clients[name]


def _table_name() -> str:
    return os.environ["TABLE_NAME"]


def log_decision(event_id: str, decision: str, **fields) -> None:
    """Structured JSON log line for every processed event."""
    entry = {"eventID": event_id, "decision": decision}
    entry.update(fields)
    logger.info(json.dumps(entry, default=str))


def get_account_label(record: dict) -> str:
    """Account id plus a human-readable name (cloudandthings issue 84)."""
    account_id = record.get("recipientAccountId", "unknown")
    friendly = os.environ.get("ACCOUNT_FRIENDLY_NAME", "")
    if not friendly:
        friendly = _resolve_account_alias()
    return f"{friendly} ({account_id})" if friendly else account_id


def _resolve_account_alias() -> str:
    if not _account_alias_cache:
        try:
            aliases = _client("iam").list_account_aliases().get("AccountAliases", [])
            _account_alias_cache.append(aliases[0] if aliases else "")
        except ClientError:
            _account_alias_cache.append("")
    return _account_alias_cache[0]


def is_duplicate(event_id: str) -> bool:
    """Conditional put on the eventID. EventBridge delivery is at-least-once."""
    try:
        _client("dynamodb").put_item(
            TableName=_table_name(),
            Item={
                "pk": {"S": f"EVENT#{event_id}"},
                "sk": {"S": "DEDUP"},
                "ttl": {"N": str(int(time.time()) + DEDUP_TTL_SECONDS)},
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return False
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return True
        raise


def session_cooldown_active(session_id: str) -> bool:
    """One investigation per console session per cooldown window.

    Returns False (and records the session) when a new investigation may
    start, True when the session was investigated recently.
    """
    cooldown_minutes = int(os.environ.get("SESSION_COOLDOWN_MINUTES", "30"))
    now = int(time.time())
    try:
        _client("dynamodb").put_item(
            TableName=_table_name(),
            Item={
                "pk": {"S": f"SESSION#{session_id}"},
                "sk": {"S": "COOLDOWN"},
                "expires_at": {"N": str(now + cooldown_minutes * 60)},
                "ttl": {"N": str(now + cooldown_minutes * 60)},
            },
            ConditionExpression="attribute_not_exists(pk) OR expires_at < :now",
            ExpressionAttributeValues={":now": {"N": str(now)}},
        )
        return False
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return True
        raise


def extract_session_id(record: dict) -> str:
    """The temporary access key identifies one console or agent session."""
    user_identity = record.get("userIdentity") or {}
    return (
        user_identity.get("accessKeyId")
        or record.get("accessKeyId")
        or user_identity.get("principalId")
        or "unknown-session"
    )


def is_watched_change(record: dict) -> tuple[bool, str]:
    """Re-check the EventBridge rule conditions, defense in depth.

    Watched: console changes, and when agent API watching is enabled, API
    changes whose user agent carries an AI agent app ID (AWS_SDK_UA_APP_ID)
    and changes made through an AWS-managed MCP server.
    """
    from_console = record.get("sessionCredentialFromConsole") in (True, "true")
    invoked_by = (record.get("userIdentity") or {}).get("invokedBy")
    via_mcp = bool(client_mod.mcp_server(invoked_by)[1])
    agent_api = (
        not from_console
        and os.environ.get("AGENT_API_CHANGES", "true") == "true"
        and (via_mcp or client_mod.parse(record.get("userAgent"))["kind"] == "ai-agent")
    )
    if not from_console and not agent_api:
        return False, "not a console session or a labelled AI agent"
    read_only = record.get("readOnly")
    if read_only in (True, "true"):
        return False, "read-only event"
    if invoked_by and not via_mcp:
        return False, f"invoked by service {invoked_by}"
    return True, ""


def _old_value(response, name: str) -> str | list:
    attributes = response.get("Attributes") if isinstance(response, dict) else None
    value = attributes.get(name) if isinstance(attributes, dict) else None
    if not isinstance(value, dict):
        return ""
    return value.get("S") or value.get("SS") or ""


def track_client(session_id: str, actor_id: str, context: dict, ip_info: dict | None) -> None:
    """Compare this change's client and country with the session and the actor's history.

    A session that switches client or country mid-session is an anomaly (a
    stolen session cookie or temporary credentials replayed elsewhere). A
    client the actor never used before is an observation. Best-effort.
    """
    info = context["client"]
    fingerprint = info["fingerprint"]
    if not fingerprint:
        return
    country = (ip_info or {}).get("country", "")
    now = int(time.time())
    table = _table_name()
    dynamodb = _client("dynamodb")

    names = {"#f": "fingerprint", "#l": "client_label", "#t": "ttl"}
    values = {
        ":f": {"S": fingerprint},
        ":l": {"S": client_mod.describe(info)},
        ":t": {"N": str(now + SESSION_CLIENT_TTL_SECONDS)},
    }
    expression = "SET #f = :f, #l = :l, #t = :t"
    if country:
        names["#c"] = "country"
        values[":c"] = {"S": country}
        expression += ", #c = :c"
    try:
        response = dynamodb.update_item(
            TableName=table,
            Key={"pk": {"S": f"SESSION#{session_id}"}, "sk": {"S": "CLIENT"}},
            UpdateExpression=expression,
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
            ReturnValues="UPDATED_OLD",
        )
        old_fingerprint = _old_value(response, "fingerprint")
        old_country = _old_value(response, "country")
        if old_fingerprint and old_fingerprint != fingerprint:
            old_label = _old_value(response, "client_label") or "another client"
            switch = f"{old_label} to {client_mod.describe(info)}"
            # Browser to browser is a replayed session; CloudShell or a CLI
            # sharing the session is ordinary use, worth noting only.
            if client_mod.is_browser_fingerprint(old_fingerprint) and client_mod.is_browser(info):
                context["anomalies"].append(f"client changed mid-session: {switch}")
            else:
                context["observations"].append(f"session used from several clients: {switch}")
        if old_country and country and old_country != country:
            context["anomalies"].append(
                f"source country changed mid-session: {old_country} to {country}"
            )
    except Exception as error:  # noqa: BLE001 tracking must never block the alert
        logger.warning("session client tracking failed: %s", error)

    history_days = int(os.environ.get("CLIENT_HISTORY_DAYS", "180"))
    try:
        response = dynamodb.update_item(
            TableName=table,
            Key={"pk": {"S": f"ACTOR#{actor_id}"}, "sk": {"S": "CLIENTS"}},
            UpdateExpression="ADD #fps :fp SET #t = :t",
            ExpressionAttributeNames={"#fps": "fingerprints", "#t": "ttl"},
            ExpressionAttributeValues={
                ":fp": {"SS": [fingerprint]},
                ":t": {"N": str(now + history_days * 24 * 3600)},
            },
            ReturnValues="UPDATED_OLD",
        )
        known = _old_value(response, "fingerprints")
        if known and fingerprint not in known:
            context["observations"].append(
                f"first change by this actor from {client_mod.describe(info)}"
            )
    except Exception as error:  # noqa: BLE001 tracking must never block the alert
        logger.warning("actor client tracking failed: %s", error)


def session_lineage(session_id: str, record: dict) -> dict:
    """How the session's credentials were obtained, looked up once per session.

    Event history lags a few minutes, so an incomplete result is cached only
    once the session is old enough for the lag to be over.
    """
    if os.environ.get("SESSION_LINEAGE", "true") != "true":
        return {}
    if (record.get("userIdentity") or {}).get("type") != "AssumedRole":
        return {}
    key = {"pk": {"S": f"SESSION#{session_id}"}, "sk": {"S": "LINEAGE"}}
    dynamodb = _client("dynamodb")
    try:
        cached = dynamodb.get_item(TableName=_table_name(), Key=key)
        item = cached.get("Item") if isinstance(cached, dict) else None
        if isinstance(item, dict) and isinstance(item.get("lineage"), dict):
            return json.loads(item["lineage"].get("S") or "{}")
    except Exception as error:  # noqa: BLE001 lineage is best-effort
        logger.warning("session lineage cache read failed: %s", error)

    result = lineage_mod.lookup(record, lambda region: _client(f"cloudtrail@{region}"))
    attributes = ((record.get("userIdentity") or {}).get("sessionContext") or {}).get(
        "attributes"
    ) or {}
    created = origin.parse_time(attributes.get("creationDate"))
    settled = created is not None and time.time() - created.timestamp() > 1800
    if lineage_mod.complete(record, result) or settled:
        try:
            dynamodb.update_item(
                TableName=_table_name(),
                Key=key,
                UpdateExpression="SET #l = :l, #t = :t",
                ExpressionAttributeNames={"#l": "lineage", "#t": "ttl"},
                ExpressionAttributeValues={
                    ":l": {"S": json.dumps(result)},
                    ":t": {"N": str(int(time.time()) + SESSION_CLIENT_TTL_SECONDS)},
                },
            )
        except Exception as error:  # noqa: BLE001 lineage is best-effort
            logger.warning("session lineage cache write failed: %s", error)
    return result


def _publish_chat(alert: dict, thread_id: str) -> None:
    notify.publish(
        sns_client=_client("sns"),
        chat_topic_arn=os.environ["CHAT_TOPIC_ARN"],
        chat_enabled=os.environ.get("CHAT_ENABLED") == "true",
        alert=alert,
        thread_id=thread_id,
    )


def publish_plain(
    record: dict,
    who: str,
    session_id: str,
    rating: dict | None,
    ip_info: dict | None,
    context: dict,
) -> None:
    account_label = get_account_label(record)
    alert = notify.build_plain_alert(record, who, account_label, rating, ip_info, context)
    _publish_chat(alert, session_id)
    email = email_render.plain_email(record, who, account_label, "", rating, ip_info, context)
    email_send.send_email(email["subject"], email["html"], alert["text"])


def publish_followup(
    record: dict, who: str, session_id: str, rating: dict | None, context: dict
) -> None:
    alert = notify.build_followup_note(record, who, rating, context)
    _publish_chat(alert, session_id)
    email = email_render.note_email(alert["title"], alert["text"])
    email_send.send_email(email["subject"], email["html"], alert["text"])


def invoke_investigator(
    record: dict,
    who: dict,
    account_label: str,
    session_id: str,
    ip_info: dict | None,
    context: dict,
) -> None:
    payload = {
        "record": record,
        "identity": who,
        "account_label": account_label,
        "session_id": session_id,
        "ip_info": ip_info,
        "context": context,
    }
    _client("lambda").invoke(
        FunctionName=os.environ["INVESTIGATOR_FUNCTION_NAME"],
        InvocationType="Event",
        Payload=json.dumps(payload, default=str).encode(),
    )


def handle_change(record: dict) -> dict:
    event_id = record.get("eventID", "unknown")
    event_name = record.get("eventName", "")

    accepted, reason = is_watched_change(record)
    if not accepted:
        log_decision(event_id, "skipped", reason=reason, eventName=event_name)
        return {"decision": "skipped", "reason": reason}

    suppressed = sup.build_suppression_set(os.environ.get("EXTRA_SUPPRESSED_ACTIONS", ""))
    if sup.is_suppressed(record, suppressed):
        log_decision(event_id, "suppressed", eventName=event_name)
        return {"decision": "suppressed"}

    if is_duplicate(event_id):
        log_decision(event_id, "deduplicated", eventName=event_name)
        return {"decision": "deduplicated"}

    who = identity_mod.extract_identity(record)
    session_id = extract_session_id(record)
    account_label = get_account_label(record)
    context = client_mod.new_context(record)
    ip_info = ip_intel.lookup(record.get("sourceIPAddress"))
    track_client(session_id, who["actor_id"], context, ip_info)
    context["lineage"] = session_lineage(session_id, record)
    context["assessment"] = origin.assess(
        origin.collect(record, context["client"], ip_info, context["lineage"])
    )
    rating = criticality.apply_session_anomalies(
        criticality.classify(record), context["anomalies"]
    )
    level = criticality.level_of(rating)
    log_fields = {
        "eventName": event_name,
        "actor": who["actor_id"],
        "criticality": level,
        "origin": context["origin"],
        "client": context["client"]["kind"],
        "agent": context["client"]["agent"],
        "driver": context["assessment"]["driver"],
        "confidence": context["assessment"]["confidence"],
        "anomalies": len(context["anomalies"]),
    }

    ai_enabled = os.environ.get("ENABLE_AI") == "true"
    cooldown_bypassed = False
    if ai_enabled and session_cooldown_active(session_id):
        # A session that switched client or country gets a fresh investigation.
        if not criticality.bypasses_cooldown(rating) and not context["anomalies"]:
            publish_followup(record, who["display"], session_id, rating, context)
            log_decision(event_id, "followup", session=session_id, **log_fields)
            return {"decision": "followup"}
        cooldown_bypassed = True

    if ai_enabled:
        try:
            invoke_investigator(record, who, account_label, session_id, ip_info, context)
            log_decision(
                event_id, "investigating", cooldown_bypassed=cooldown_bypassed, **log_fields
            )
            return {"decision": "investigating"}
        except ClientError as error:
            # Never drop an alert: fall back to the plain path.
            logger.error("investigator invoke failed: %s", error)

    publish_plain(record, who["display"], session_id, rating, ip_info, context)
    log_decision(event_id, "notified", **log_fields)
    return {"decision": "notified"}


def handle_console_login(record: dict) -> dict:
    """Alert on root sign-ins, sign-ins without MFA, and failed sign-ins."""
    event_id = record.get("eventID", "unknown")
    user_identity = record.get("userIdentity") or {}
    outcome = (record.get("responseElements") or {}).get("ConsoleLogin", "")
    mfa = (record.get("additionalEventData") or {}).get("MFAUsed", "")

    reasons = []
    if user_identity.get("type") == "Root":
        reasons.append("root sign-in")
    if outcome == "Failure":
        reasons.append("failed sign-in")
    # Federated sign-ins report MFA at the IdP, so only flag explicit "No".
    if mfa == "No" and outcome != "Failure":
        reasons.append("sign-in without MFA")

    if not reasons:
        log_decision(event_id, "login-ok")
        return {"decision": "login-ok"}

    if is_duplicate(event_id):
        log_decision(event_id, "deduplicated")
        return {"decision": "deduplicated"}

    who = identity_mod.extract_identity(record)
    account_label = get_account_label(record)
    reason = ", ".join(reasons)
    ip_info = ip_intel.lookup(record.get("sourceIPAddress"))
    info = client_mod.parse(record.get("userAgent"))
    alert = notify.build_login_alert(
        record, who["display"], account_label, reason, ip_info, info
    )
    _publish_chat(alert, f"signin-{event_id}")
    email = email_render.login_email(
        record, who["display"], account_label, reason, ip_info, info
    )
    email_send.send_email(email["subject"], email["html"], alert["text"])
    log_decision(event_id, "login-alert", reasons=reasons)
    return {"decision": "login-alert"}


def lambda_handler(event: dict, context) -> dict:
    detail_type = event.get("detail-type", "")
    record = event.get("detail") or {}
    if detail_type == "AWS Console Sign In via CloudTrail":
        return handle_console_login(record)
    return handle_change(record)

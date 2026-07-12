# SPDX-License-Identifier: Apache-2.0
"""Detector Lambda.

Receives CloudTrail management events from the EventBridge default bus,
filters out noise, deduplicates, extracts the human identity, and either
hands off to the investigator Lambda (AI path) or publishes a plain
notification directly.
"""

import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError

import email_render
import email_send
import identity as identity_mod
import notify
import suppressed_actions as sup

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

DEDUP_TTL_SECONDS = 24 * 3600

_clients: dict = {}
_account_alias_cache: list = []


def _client(name: str):
    if name not in _clients:
        _clients[name] = boto3.client(name)
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
    """The temporary access key identifies one console session."""
    user_identity = record.get("userIdentity") or {}
    return (
        user_identity.get("accessKeyId")
        or record.get("accessKeyId")
        or user_identity.get("principalId")
        or "unknown-session"
    )


def is_console_mutation(record: dict) -> tuple[bool, str]:
    """Re-check the EventBridge rule conditions, defense in depth."""
    from_console = record.get("sessionCredentialFromConsole")
    if from_console not in (True, "true"):
        return False, "not a console session"
    read_only = record.get("readOnly")
    if read_only in (True, "true"):
        return False, "read-only event"
    invoked_by = (record.get("userIdentity") or {}).get("invokedBy")
    if invoked_by:
        return False, f"invoked by service {invoked_by}"
    return True, ""


def _publish_chat(alert: dict, thread_id: str) -> None:
    notify.publish(
        sns_client=_client("sns"),
        chat_topic_arn=os.environ["CHAT_TOPIC_ARN"],
        chat_enabled=os.environ.get("CHAT_ENABLED") == "true",
        alert=alert,
        thread_id=thread_id,
    )


def publish_plain(record: dict, who: str, session_id: str) -> None:
    account_label = get_account_label(record)
    alert = notify.build_plain_alert(record, who, account_label)
    _publish_chat(alert, session_id)
    email = email_render.plain_email(record, who, account_label)
    email_send.send_email(email["subject"], email["html"], alert["text"])


def publish_followup(record: dict, who: str, session_id: str) -> None:
    alert = notify.build_followup_note(record, who)
    _publish_chat(alert, session_id)
    email = email_render.note_email(alert["title"], alert["text"])
    email_send.send_email(email["subject"], email["html"], alert["text"])


def invoke_investigator(record: dict, who: dict, account_label: str, session_id: str) -> None:
    payload = {
        "record": record,
        "identity": who,
        "account_label": account_label,
        "session_id": session_id,
    }
    _client("lambda").invoke(
        FunctionName=os.environ["INVESTIGATOR_FUNCTION_NAME"],
        InvocationType="Event",
        Payload=json.dumps(payload, default=str).encode(),
    )


def handle_console_action(record: dict) -> dict:
    event_id = record.get("eventID", "unknown")
    event_name = record.get("eventName", "")

    accepted, reason = is_console_mutation(record)
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

    ai_enabled = os.environ.get("ENABLE_AI") == "true"
    if ai_enabled:
        if session_cooldown_active(session_id):
            publish_followup(record, who["display"], session_id)
            log_decision(event_id, "followup", eventName=event_name, session=session_id)
            return {"decision": "followup"}
        try:
            invoke_investigator(record, who, account_label, session_id)
            log_decision(event_id, "investigating", eventName=event_name, actor=who["actor_id"])
            return {"decision": "investigating"}
        except ClientError as error:
            # Never drop an alert: fall back to the plain path.
            logger.error("investigator invoke failed: %s", error)

    publish_plain(record, who["display"], session_id)
    log_decision(event_id, "notified", eventName=event_name, actor=who["actor_id"])
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
    alert = notify.build_login_alert(record, who["display"], account_label, reason)
    _publish_chat(alert, f"signin-{event_id}")
    email = email_render.login_email(record, who["display"], account_label, reason)
    email_send.send_email(email["subject"], email["html"], alert["text"])
    log_decision(event_id, "login-alert", reasons=reasons)
    return {"decision": "login-alert"}


def lambda_handler(event: dict, context) -> dict:
    detail_type = event.get("detail-type", "")
    record = event.get("detail") or {}
    if detail_type == "AWS Console Sign In via CloudTrail":
        return handle_console_login(record)
    return handle_console_action(record)

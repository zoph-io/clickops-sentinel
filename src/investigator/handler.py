# SPDX-License-Identifier: Apache-2.0
"""Investigator Lambda.

Runs a Claude agent on Amazon Bedrock for each detection handed off by the
detector. The agent retraces the console session, correlates adjacent
changes, assesses purpose plus security and FinOps impact, and the enriched
verdict drives the notification. Delivery is guaranteed: any failure in the
AI path falls back to the plain notification.
"""

import json
import logging
import os
import time
from datetime import UTC, datetime

import boto3

import agent_loop
import budget
import email_render
import email_send
import memory
import messages
import tools

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_clients: dict = {}

SYSTEM_PROMPT = """\
You are an AWS security and cloud cost analyst embedded in ClickOps Sentinel,
a tool that alerts an account owner when someone changes infrastructure
manually through the AWS Console instead of infrastructure as code.

You receive one CloudTrail event that was made with console session
credentials. Investigate it with the tools provided, then deliver a critical,
evidence-based judgment. Think about:

1. Purpose: retrace the user's console session (lookup_events_by_user with
   the session access key or username) to understand what they were trying
   to accomplish overall, not just this single call. Check adjacent activity
   from the same IP when it adds signal.
2. Legitimacy: is this a genuine manual modification a human made in the
   console? Failed calls, service-linked noise, or activity that looks like
   sanctioned break-glass work should lower the alarm level.
3. Security implications: privilege escalation paths (new IAM users,
   policies, access keys, trust policy edits), public exposure (security
   groups open to 0.0.0.0/0, S3 public access, resource policies), weakened
   defenses (encryption or logging disabled, GuardDuty, CloudTrail, Config
   changes, MFA removal), and secrets handling.
4. FinOps implications: instance or cluster launches (type and count from
   request parameters), provisioned capacity, perpetual-billing resources
   (NAT gateways, load balancers, elastic IPs, VPC endpoints), storage
   growth. Estimate a rough monthly dollar range when the parameters allow.
   Terminating or downsizing resources is a saving, report it positively.
5. History: use get_actor_memory to check whether this actor has prior
   verdicts or known patterns.

Be economical with tools: each investigation has a strict token budget.
Usually one session retrace and one memory lookup suffice. When you have
enough evidence, or when told the budget is nearly exhausted, call
submit_verdict. Keep every text field factual, specific, and short. Do not
use emojis or em-dashes anywhere in your output.
"""

TOOL_SPECS = [
    {
        "toolSpec": {
            "name": "lookup_events_by_user",
            "description": (
                "Retrace recent CloudTrail activity for a user. Pass a "
                "username, role session name, or temporary access key ID "
                "(ASIA prefix) to get the timeline grouped by console session."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "hours": {"type": "integer", "minimum": 1, "maximum": 72},
                    },
                    "required": ["username"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "lookup_events_by_ip",
            "description": (
                "Find recent mutating CloudTrail events from one source IP "
                "address. Bounded scan, useful for adjacent-change and "
                "credential-sharing checks."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "ip": {"type": "string"},
                        "hours": {"type": "integer", "minimum": 1, "maximum": 72},
                    },
                    "required": ["ip"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_event_details",
            "description": "Fetch the full raw CloudTrail record for an event ID.",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {"event_id": {"type": "string"}},
                    "required": ["event_id"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "get_actor_memory",
            "description": (
                "Retrieve long-term memory about this actor: prior "
                "investigation verdicts and behavioral patterns."
            ),
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                }
            },
        }
    },
]


def _client(name: str):
    if name not in _clients:
        _clients[name] = boto3.client(name)
    return _clients[name]


def log_decision(event_id: str, decision: str, **fields) -> None:
    entry = {"eventID": event_id, "decision": decision}
    entry.update(fields)
    logger.info(json.dumps(entry, default=str))


def _publish(alert: dict, thread_id: str) -> None:
    messages.publish(
        sns_client=_client("sns"),
        chat_topic_arn=os.environ["CHAT_TOPIC_ARN"],
        chat_enabled=os.environ.get("CHAT_ENABLED") == "true",
        alert=alert,
        thread_id=thread_id,
    )


def _send_email(email: dict, text: str) -> None:
    """Best-effort rich email; failures are logged and never block delivery."""
    email_send.send_email(email["subject"], email["html"], text)


def _session_steps(record: dict, session_id: str) -> list:
    """Timeline of the triggering console session for the email diagram."""
    try:
        lookback = int(os.environ.get("LOOKBACK_HOURS", "6"))
        steps = tools.session_timeline(_client("cloudtrail"), session_id, lookback)
    except Exception as error:  # noqa: BLE001 diagram is best-effort
        logger.warning("session timeline lookup failed: %s", error)
        steps = []
    if not steps:
        # Always show at least the triggering event.
        steps = [tools.summarize_cloudtrail_event(record)]
    return email_render.mark_highlighted_step(steps, record)


def _publish_metrics(usage: dict, budget_used_percent: float) -> None:
    try:
        _client("cloudwatch").put_metric_data(
            Namespace=os.environ.get("METRICS_NAMESPACE", "ClickOpsSentinel"),
            MetricData=[
                {"MetricName": "InputTokens", "Value": usage["inputTokens"], "Unit": "Count"},
                {"MetricName": "OutputTokens", "Value": usage["outputTokens"], "Unit": "Count"},
                {"MetricName": "InvestigationCount", "Value": 1, "Unit": "Count"},
                {
                    "MetricName": "BudgetUsedPercent",
                    "Value": min(budget_used_percent, 100.0),
                    "Unit": "Percent",
                },
            ],
        )
    except Exception as error:  # noqa: BLE001 metrics are best-effort
        logger.warning("metric publish failed: %s", error)


def _write_investigation_record(
    record: dict, identity: dict, verdict: dict, usage: dict
) -> None:
    retention_days = int(os.environ.get("MEMORY_RETENTION_DAYS", "180"))
    now = datetime.now(UTC)
    event_id = record.get("eventID", "unknown")
    try:
        _client("dynamodb").put_item(
            TableName=os.environ["TABLE_NAME"],
            Item={
                "pk": {"S": "INVESTIGATION"},
                "sk": {"S": f"{now.isoformat()}#{event_id}"},
                "actor": {"S": identity.get("actor_id", "unknown")},
                "event_name": {"S": record.get("eventName", "")},
                "event_source": {"S": record.get("eventSource", "")},
                "region": {"S": record.get("awsRegion", "")},
                "verdict": {"S": verdict.get("verdict", "unknown")},
                "purpose": {"S": verdict.get("purpose", "")[:500]},
                "security_severity": {"S": verdict.get("security_severity", "none")},
                "cost_impact": {"S": verdict.get("cost_impact", "negligible")},
                "tokens_used": {"N": str(usage["inputTokens"] + usage["outputTokens"])},
                "ttl": {"N": str(int(time.time()) + retention_days * 24 * 3600)},
            },
        )
    except Exception as error:  # noqa: BLE001 statistics are best-effort
        logger.warning("investigation record write failed: %s", error)


def _build_user_prompt(record: dict, identity: dict, account_label: str) -> str:
    lookback = int(os.environ.get("LOOKBACK_HOURS", "6"))
    event_summary = tools.summarize_cloudtrail_event(record)
    return (
        "Investigate this manual console change.\n\n"
        f"Event: {json.dumps(event_summary, default=str)}\n"
        f"Actor: {identity.get('display')} (id {identity.get('actor_id')}, "
        f"type {identity.get('kind')})\n"
        f"Account: {account_label}\n"
        f"Suggested lookback window: {lookback} hours.\n"
        f"Session access key for retrace: {event_summary.get('accessKeyId') or 'unknown'}"
    )


def run_investigation(
    record: dict, identity: dict, account_label: str, session_id: str
) -> dict | None:
    """Run the agent, returns the verdict or None when it could not conclude."""
    memory_id = os.environ.get("MEMORY_ID", "")
    lookback = int(os.environ.get("LOOKBACK_HOURS", "6"))
    cloudtrail = _client("cloudtrail")

    def tool_lookup_user(username: str, hours: int = lookback) -> str:
        return tools.lookup_events_by_user(cloudtrail, username, min(hours, 72))

    def tool_lookup_ip(ip: str, hours: int = lookback) -> str:
        return tools.lookup_events_by_ip(cloudtrail, ip, min(hours, 72))

    def tool_event_details(event_id: str) -> str:
        return tools.get_event_details(cloudtrail, event_id)

    def tool_actor_memory(query: str) -> str:
        return memory.retrieve_actor_history(
            _client("bedrock-agentcore"), memory_id, identity["actor_id"], query
        )

    verdict, usage = agent_loop.run_agent(
        bedrock_client=_client("bedrock-runtime"),
        model_id=os.environ["MODEL_ID"],
        system_prompt=SYSTEM_PROMPT,
        user_prompt=_build_user_prompt(record, identity, account_label),
        tool_specs=TOOL_SPECS,
        tool_dispatch={
            "lookup_events_by_user": tool_lookup_user,
            "lookup_events_by_ip": tool_lookup_ip,
            "get_event_details": tool_event_details,
            "get_actor_memory": tool_actor_memory,
        },
        max_turns=int(os.environ.get("MAX_AGENT_TURNS", "8")),
        max_total_tokens=int(os.environ.get("MAX_INVESTIGATION_TOKENS", "60000")),
    )

    total_tokens = usage["inputTokens"] + usage["outputTokens"]
    daily_budget = int(os.environ.get("DAILY_TOKEN_BUDGET", "2000000"))
    used_today = budget.consume_tokens(
        _client("dynamodb"), os.environ["TABLE_NAME"], total_tokens
    )
    _publish_metrics(usage, used_today / daily_budget * 100.0)

    if verdict is None:
        return None

    _write_investigation_record(record, identity, verdict, usage)
    memory.save_investigation(
        memory_client=_client("bedrock-agentcore"),
        memory_id=memory_id,
        actor_id=identity["actor_id"],
        session_id=session_id,
        event_summary=(
            f"Console change by {identity.get('display')}: "
            f"{record.get('eventSource')}:{record.get('eventName')} "
            f"in {record.get('awsRegion')} at {record.get('eventTime')}"
        ),
        verdict_summary=(
            f"Verdict {verdict.get('verdict')} (confidence {verdict.get('confidence')}). "
            f"Purpose: {verdict.get('purpose')} "
            f"Security {verdict.get('security_severity')}: {verdict.get('security_analysis')} "
            f"Cost {verdict.get('cost_impact')}: {verdict.get('cost_analysis')} "
            f"Recommendation: {verdict.get('recommendation')}"
        ),
    )
    return verdict


def lambda_handler(event: dict, context) -> dict:
    record = event.get("record") or {}
    identity = event.get("identity") or {
        "display": "Unknown",
        "actor_id": "unknown",
        "kind": "Unknown",
    }
    account_label = event.get("account_label", "unknown")
    session_id = event.get("session_id", "unknown-session")
    event_id = record.get("eventID", "unknown")

    # Budget pre-check: skip the AI path entirely when today's budget is gone.
    daily_budget = int(os.environ.get("DAILY_TOKEN_BUDGET", "2000000"))
    try:
        used = budget.tokens_used_today(_client("dynamodb"), os.environ["TABLE_NAME"])
    except Exception as error:  # noqa: BLE001 budget check is best-effort
        logger.warning("budget check failed: %s", error)
        used = 0

    if used >= daily_budget:
        note = "AI investigation skipped: daily token budget exhausted."
        alert = messages.build_plain_alert(record, identity["display"], account_label, note)
        _publish(alert, session_id)
        _send_email(
            email_render.plain_email(record, identity["display"], account_label, note),
            alert["text"],
        )
        try:
            if budget.try_claim_exhaustion_notice(_client("dynamodb"), os.environ["TABLE_NAME"]):
                notice_text = (
                    "ClickOps Sentinel: the daily Bedrock token budget is "
                    "spent. Alerts continue on the plain path until the "
                    "next UTC day."
                )
                _publish(
                    {
                        "title": "ClickOps Sentinel: AI budget exhausted for today",
                        "markdown": (
                            "The daily Bedrock token budget is spent. Alerts "
                            "continue on the plain path until the next UTC day."
                        ),
                        "text": notice_text,
                    },
                    "budget-notice",
                )
                _send_email(
                    email_render.note_email(
                        "ClickOps Sentinel: AI budget exhausted for today", notice_text
                    ),
                    notice_text,
                )
        except Exception as error:  # noqa: BLE001 notice is best-effort
            logger.warning("budget notice failed: %s", error)
        log_decision(event_id, "budget-exhausted", tokens_used=used)
        return {"decision": "budget-exhausted"}

    try:
        verdict = run_investigation(record, identity, account_label, session_id)
    except Exception as error:  # noqa: BLE001 never drop an alert
        logger.error("investigation failed: %s", error)
        verdict = None

    if verdict is None:
        note = "AI investigation unavailable, plain alert."
        alert = messages.build_plain_alert(
            record, identity["display"], account_label, note
        )
        _publish(alert, session_id)
        _send_email(
            email_render.plain_email(record, identity["display"], account_label, note),
            alert["text"],
        )
        log_decision(event_id, "notified-plain")
        return {"decision": "notified-plain"}

    alert = messages.build_enriched_alert(record, identity["display"], account_label, verdict)
    _publish(alert, session_id)
    if email_send.email_enabled():
        steps = _session_steps(record, session_id)
        _send_email(
            email_render.enriched_email(
                record, identity["display"], account_label, verdict, steps
            ),
            alert["text"],
        )
    log_decision(
        event_id,
        "notified-enriched",
        verdict=verdict.get("verdict"),
        security=verdict.get("security_severity"),
        cost=verdict.get("cost_impact"),
    )
    return {"decision": "notified-enriched", "verdict": verdict.get("verdict")}

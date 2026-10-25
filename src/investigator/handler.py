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
import client as client_mod
import criticality
import email_render
import email_send
import ip_intel
import memory
import messages
import origin
import tools

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

_clients: dict = {}

_SCALE_LINES = "\n".join(
    f"   - {level}: {criticality.SCALE[level]}" for level in reversed(criticality.LEVELS)
)

SYSTEM_PROMPT = f"""\
You are an AWS security and cloud cost analyst embedded in ClickOps Sentinel,
a tool that alerts an account owner when someone changes infrastructure
manually through the AWS Console, or when an AI agent changes it through the
API, instead of going through infrastructure as code.

You receive one CloudTrail event that was made with console session
credentials, or through the API by a client whose user agent identifies an
AI agent. Investigate it with the tools provided, then deliver a critical,
evidence-based judgment. Think about:

1. Purpose: retrace the user's console session (lookup_events_by_user with
   the session access key or username) to understand what they were trying
   to accomplish overall, not just this single call. Check adjacent activity
   from the same IP when it adds signal.
2. Legitimacy: is this a genuine manual modification made outside IaC, by
   a human in the console or by an AI agent? Failed calls, service-linked
   noise, or activity that looks like sanctioned break-glass work should
   lower the alarm level.
3. Security implications: privilege escalation paths (new IAM users,
   policies, access keys, trust policy edits), public exposure (security
   groups open to 0.0.0.0/0, S3 public access, resource policies), weakened
   defenses (encryption or logging disabled, GuardDuty, CloudTrail, Config
   changes, MFA removal), and secrets handling. Rate security_severity on
   this scale:
{_SCALE_LINES}
   The event comes pre-rated by the ClickOps Sentinel criticality catalog, a
   deterministic referential mapped to MITRE ATT&CK and Stratus Red Team.
   That rating is a floor applied after you answer, so never argue it down:
   raise it when context warrants (several risky actions chained in one
   session, an unfamiliar network or country for this actor, a VPN, proxy,
   Tor, or hosting source). Express legitimacy through the verdict instead.
   Session events carry their own catalog rating in the criticality field.
4. Source network: the source IP comes with its network owner and
   approximate location when available. A change of country or network
   within the session or against the actor's history raises suspicion.
   Use lookup_ip_intel, when offered, for other IPs you see in the session.
5. FinOps implications: instance or cluster launches (type and count from
   request parameters), provisioned capacity, perpetual-billing resources
   (NAT gateways, load balancers, elastic IPs, VPC endpoints), storage
   growth. Estimate a rough monthly dollar range when the parameters allow.
   Terminating or downsizing resources is a saving, report it positively.
6. Who drove it: you receive a deterministic assessment (person, AI agent,
   or automation, with a confidence level) and the evidence behind it.
   AWS-asserted evidence outweighs client-reported evidence. The user agent
   is self-reported: an agent marker is evidence an agent was involved, but
   an ordinary browser does not prove a person, since an agent can drive the
   user's own browser. AWS-asserted signals include a console session opened
   from CLI or SDK credentials (an agent, a console helper, or stolen keys),
   calls through an AWS-managed MCP server, source identity, session tags,
   long-term access keys, MFA, and a cloud or hosting source network. In the
   session retrace, agents tend to start with GetCallerIdentity and retry
   failing calls; people browse console pages before changing something.
   Confirm or challenge the assessment with what you find, and say whether a
   person appears to have directed an agent. An AI agent changing
   infrastructure outside IaC is drift like any console change. A session
   that switches browser or country mid-session suggests a stolen session
   cookie or credentials replayed elsewhere. Session events carry their
   client.
7. History: use get_actor_memory to check whether this actor has prior
   verdicts or known patterns, including the networks, countries, and
   clients they usually work from.

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

IP_TOOL_SPEC = {
    "toolSpec": {
        "name": "lookup_ip_intel",
        "description": (
            "Resolve a public IP address to its network owner (ASN, ISP), "
            "approximate location, and VPN, proxy, Tor, or hosting flags when "
            "the provider reports them."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            }
        },
    }
}


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
    record: dict,
    identity: dict,
    verdict: dict,
    usage: dict,
    rating: dict | None,
    ip_info: dict | None,
    context: dict | None,
) -> None:
    retention_days = int(os.environ.get("MEMORY_RETENTION_DAYS", "180"))
    now = datetime.now(UTC)
    event_id = record.get("eventID", "unknown")
    item = {
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
    }
    if rating:
        item["criticality_rule"] = {"S": rating["rule_id"]}
    if ip_info and ip_info.get("country"):
        item["source_country"] = {"S": ip_info["country"]}
    if ip_intel.network(ip_info):
        item["source_network"] = {"S": ip_intel.network(ip_info)[:200]}
    info = (context or {}).get("client") or {}
    if info.get("kind"):
        item["client_kind"] = {"S": info["kind"]}
        item["client"] = {"S": client_mod.describe(info)[:200]}
    if info.get("agent"):
        item["agent"] = {"S": info["agent"]}
    if (context or {}).get("anomalies"):
        item["session_anomalies"] = {"N": str(len(context["anomalies"]))}
    assessment = (context or {}).get("assessment") or {}
    if assessment.get("driver"):
        item["driver"] = {"S": assessment["driver"]}
        item["driver_confidence"] = {"S": assessment.get("confidence", "low")}
    try:
        _client("dynamodb").put_item(TableName=os.environ["TABLE_NAME"], Item=item)
    except Exception as error:  # noqa: BLE001 statistics are best-effort
        logger.warning("investigation record write failed: %s", error)


def _build_user_prompt(
    record: dict,
    identity: dict,
    account_label: str,
    rating: dict | None,
    ip_info: dict | None,
    context: dict | None = None,
) -> str:
    lookback = int(os.environ.get("LOOKBACK_HOURS", "6"))
    event_summary = tools.summarize_cloudtrail_event(record)
    if rating:
        catalog = json.dumps(rating)
    else:
        catalog = "no catalog match, rate it from the scale"
    context = context or client_mod.new_context(record)
    if context["origin"] == "api":
        opening = "Investigate this API change made by an AI agent."
    else:
        opening = "Investigate this manual console change."
    signals = "; ".join(client_mod.signal_lines(context)) or "none"
    assessment = context.get("assessment")
    driven_by = origin.describe(assessment) or "not assessed"
    evidence = "; ".join(origin.evidence_lines(assessment, limit=8)) or "none"
    conflict = (assessment or {}).get("conflict") or "none"
    return (
        f"{opening}\n\n"
        f"Event: {json.dumps(event_summary, default=str)}\n"
        f"Actor: {identity.get('display')} (id {identity.get('actor_id')}, "
        f"type {identity.get('kind')})\n"
        f"Account: {account_label}\n"
        f"Criticality catalog: {catalog}\n"
        f"Source network: {ip_intel.describe(ip_info) or 'unavailable'}\n"
        f"Client: {client_mod.describe(context['client']) or 'unknown'}\n"
        f"Client signals: {signals}\n"
        f"Driven by (deterministic assessment): {driven_by}\n"
        f"Assessment evidence: {evidence}\n"
        f"Signals disagree: {conflict}\n"
        f"Suggested lookback window: {lookback} hours.\n"
        f"Session access key for retrace: {event_summary.get('accessKeyId') or 'unknown'}"
    )


def apply_catalog_floor(verdict: dict, rating: dict | None) -> dict:
    """Raise the agent's severity to the catalog floor, keeping its own rating."""
    agent_severity = verdict.get("security_severity", "none")
    final = criticality.apply_floor(agent_severity, rating)
    if final != agent_severity:
        verdict["agent_security_severity"] = agent_severity
        verdict["security_severity"] = final
    return verdict


def run_investigation(
    record: dict,
    identity: dict,
    account_label: str,
    session_id: str,
    rating: dict | None = None,
    ip_info: dict | None = None,
    context: dict | None = None,
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

    def tool_ip_intel(ip: str) -> str:
        info = ip_intel.lookup(ip)
        if info is None:
            return json.dumps({"ip": ip, "error": "not a public IP, or lookup unavailable"})
        return json.dumps(info)

    tool_specs = list(TOOL_SPECS)
    tool_dispatch = {
        "lookup_events_by_user": tool_lookup_user,
        "lookup_events_by_ip": tool_lookup_ip,
        "get_event_details": tool_event_details,
        "get_actor_memory": tool_actor_memory,
    }
    if ip_intel.enabled():
        tool_specs.append(IP_TOOL_SPEC)
        tool_dispatch["lookup_ip_intel"] = tool_ip_intel

    if context is None:
        context = client_mod.new_context(record)
    if not context.get("assessment"):
        context["assessment"] = origin.assess(
            origin.collect(record, context["client"], ip_info, context.get("lineage"))
        )
    if rating is None:
        rating = criticality.apply_session_anomalies(
            criticality.classify(record), context["anomalies"]
        )

    verdict, usage = agent_loop.run_agent(
        bedrock_client=_client("bedrock-runtime"),
        model_id=os.environ["MODEL_ID"],
        system_prompt=SYSTEM_PROMPT,
        user_prompt=_build_user_prompt(
            record, identity, account_label, rating, ip_info, context
        ),
        tool_specs=tool_specs,
        tool_dispatch=tool_dispatch,
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

    verdict = apply_catalog_floor(verdict, rating)
    _write_investigation_record(record, identity, verdict, usage, rating, ip_info, context)
    source = ip_intel.describe(ip_info)
    client_line = client_mod.describe(context["client"])
    driven_by = origin.describe(context.get("assessment"))
    change = "Console change" if context["origin"] == "console" else "API change"
    memory.save_investigation(
        memory_client=_client("bedrock-agentcore"),
        memory_id=memory_id,
        actor_id=identity["actor_id"],
        session_id=session_id,
        event_summary=(
            f"{change} by {identity.get('display')}: "
            f"{record.get('eventSource')}:{record.get('eventName')} "
            f"in {record.get('awsRegion')} at {record.get('eventTime')}"
            + (f" from {record.get('sourceIPAddress')} ({source})" if source else "")
            + (f" using {client_line}" if client_line else "")
            + (f", driven by {driven_by}" if driven_by else "")
            + (f". Catalog rule {rating['rule_id']} ({rating['level']})" if rating else "")
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
    # The detector tracks the client across the session; older payloads lack it.
    context = event.get("context") or client_mod.new_context(record)
    rating = criticality.apply_session_anomalies(
        criticality.classify(record), context.get("anomalies", [])
    )
    # The detector looks the IP up once; payloads from older detectors lack the key.
    if "ip_info" in event:
        ip_info = event["ip_info"]
    else:
        ip_info = ip_intel.lookup(record.get("sourceIPAddress"))
    if not context.get("assessment"):
        context["assessment"] = origin.assess(
            origin.collect(record, context["client"], ip_info, context.get("lineage"))
        )
    who = identity["display"]

    def publish_plain(note: str) -> None:
        alert = messages.build_plain_alert(
            record, who, account_label, note, rating, ip_info, context
        )
        _publish(alert, session_id)
        _send_email(
            email_render.plain_email(record, who, account_label, note, rating, ip_info, context),
            alert["text"],
        )

    # Budget pre-check: skip the AI path entirely when today's budget is gone.
    daily_budget = int(os.environ.get("DAILY_TOKEN_BUDGET", "2000000"))
    try:
        used = budget.tokens_used_today(_client("dynamodb"), os.environ["TABLE_NAME"])
    except Exception as error:  # noqa: BLE001 budget check is best-effort
        logger.warning("budget check failed: %s", error)
        used = 0

    if used >= daily_budget:
        publish_plain("AI investigation skipped: daily token budget exhausted.")
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

    steps = _session_steps(record, session_id)
    behavior = origin.behavior_evidence(steps, record)
    if behavior:
        context["assessment"] = origin.assess(context["assessment"]["evidence"] + behavior)

    try:
        verdict = run_investigation(
            record, identity, account_label, session_id, rating, ip_info, context
        )
    except Exception as error:  # noqa: BLE001 never drop an alert
        logger.error("investigation failed: %s", error)
        verdict = None

    if verdict is None:
        publish_plain("AI investigation unavailable, plain alert.")
        log_decision(event_id, "notified-plain", criticality=criticality.level_of(rating))
        return {"decision": "notified-plain"}

    alert = messages.build_enriched_alert(
        record, who, account_label, verdict, rating, ip_info, context
    )
    _publish(alert, session_id)
    if email_send.email_enabled():
        _send_email(
            email_render.enriched_email(
                record, who, account_label, verdict, steps, rating, ip_info, context
            ),
            alert["text"],
        )
    log_decision(
        event_id,
        "notified-enriched",
        verdict=verdict.get("verdict"),
        security=verdict.get("security_severity"),
        criticality_rule=rating["rule_id"] if rating else "",
        client=context["client"].get("kind", ""),
        agent=context["client"].get("agent", ""),
        driver=context["assessment"]["driver"],
        confidence=context["assessment"]["confidence"],
        cost=verdict.get("cost_impact"),
    )
    return {"decision": "notified-enriched", "verdict": verdict.get("verdict")}

# SPDX-License-Identifier: Apache-2.0
"""Investigator handler paths: budget exhaustion, fallback, enrichment."""

import json
from unittest.mock import MagicMock

import sample_events

import client

VERDICT = {
    "verdict": "suspicious",
    "confidence": "medium",
    "purpose": "Creating an IAM user outside IaC.",
    "security_severity": "high",
    "security_analysis": "New IAM user opens a persistent access path.",
    "cost_impact": "negligible",
    "cost_analysis": "No billable resources.",
    "session_narrative": "Sign-in, IAM browsing, user creation.",
    "history_context": "none",
    "recommendation": "Ask the user and consider reverting.",
}


def wire(investigator_handler, monkeypatch, sns=None, dynamodb=None):
    fakes = {
        "sns": sns or MagicMock(),
        "dynamodb": dynamodb or MagicMock(),
        "cloudwatch": MagicMock(),
        "cloudtrail": MagicMock(),
        "bedrock-runtime": MagicMock(),
        "bedrock-agentcore": MagicMock(),
        "email": MagicMock(return_value=True),
    }
    monkeypatch.setattr(investigator_handler, "_clients", fakes)
    monkeypatch.setattr(investigator_handler.email_send, "send_email", fakes["email"])
    return fakes


def payload():
    return {
        "record": dict(sample_events.CONSOLE_MUTATION),
        "identity": {
            "display": "alice@example.com (Identity Center)",
            "actor_id": "alice@example.com",
            "kind": "AssumedRole",
        },
        "account_label": "prod (123456789012)",
        "session_id": "ASIAEXAMPLEKEY",
    }


def chat_payloads(sns):
    """All Q Developer JSON payloads published to the chat topic."""
    payloads = []
    for call in sns.publish.call_args_list:
        if call.kwargs["TopicArn"].endswith(":chat"):
            payloads.append(json.loads(call.kwargs["Message"]))
    return payloads


def test_budget_exhausted_falls_back_with_notice(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(
        investigator_handler.budget, "tokens_used_today", lambda *args: 99999999
    )
    monkeypatch.setattr(
        investigator_handler.budget, "try_claim_exhaustion_notice", lambda *args: True
    )
    result = investigator_handler.lambda_handler(payload(), None)
    assert result["decision"] == "budget-exhausted"
    titles = [item["content"]["title"] for item in chat_payloads(fakes["sns"])]
    assert any("ClickOps detected" in title for title in titles)
    assert any("budget exhausted" in title for title in titles)


def test_investigation_failure_never_drops_the_alert(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(
        investigator_handler.budget, "tokens_used_today", lambda *args: 0
    )

    def explode(*args, **kwargs):
        raise RuntimeError("bedrock is down")

    monkeypatch.setattr(investigator_handler, "run_investigation", explode)
    result = investigator_handler.lambda_handler(payload(), None)
    assert result["decision"] == "notified-plain"
    payloads = chat_payloads(fakes["sns"])
    assert len(payloads) == 1
    assert "AI investigation unavailable" in payloads[0]["content"]["description"]


def test_verdict_produces_enriched_notification(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(
        investigator_handler.budget, "tokens_used_today", lambda *args: 0
    )
    monkeypatch.setattr(
        investigator_handler, "run_investigation", lambda *args: dict(VERDICT)
    )
    result = investigator_handler.lambda_handler(payload(), None)
    assert result["decision"] == "notified-enriched"
    assert result["verdict"] == "suspicious"
    body = chat_payloads(fakes["sns"])[0]["content"]["description"]
    assert body.startswith("*Purpose*")
    assert "HIGH" in body
    assert "Recommendation" in body
    # Rich email sent with the session path.
    fakes["email"].assert_called_once()
    subject, html, text = fakes["email"].call_args.args
    # High and critical alerts carry the level for mail filtering.
    assert subject == "[HIGH] ClickOps detected: RunInstances"
    assert "CONSOLE SESSION PATH" in html
    assert "RunInstances" in html


def test_payload_ip_info_is_used_without_a_second_lookup(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(investigator_handler.budget, "tokens_used_today", lambda *args: 0)
    lookup = MagicMock()
    monkeypatch.setattr(investigator_handler.ip_intel, "lookup", lookup)
    seen = {}

    def fake_run(record, identity, account_label, session_id, rating, ip_info, context):
        seen.update(rating=rating, ip_info=ip_info)
        return dict(VERDICT)

    monkeypatch.setattr(investigator_handler, "run_investigation", fake_run)
    data = {**payload(), "ip_info": sample_events.IP_INFO}
    investigator_handler.lambda_handler(data, None)
    lookup.assert_not_called()
    assert seen["ip_info"]["country"] == "FR"
    assert seen["rating"]["rule_id"] == "CMP-005"
    body = chat_payloads(fakes["sns"])[0]["content"]["description"]
    assert "*Catalog*: CMP-005" in body
    assert "*Source network*: AS3215 Orange S.A." in body


def test_plain_fallback_keeps_criticality(investigator_handler, base_env, monkeypatch):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(investigator_handler.budget, "tokens_used_today", lambda *args: 0)
    monkeypatch.setattr(investigator_handler, "run_investigation", lambda *args: None)
    data = {**payload(), "record": dict(sample_events.CLOUDTRAIL_STOP)}
    investigator_handler.lambda_handler(data, None)
    content = chat_payloads(fakes["sns"])[0]["content"]
    assert content["title"] == "[CRITICAL] ClickOps detected: StopLogging"
    assert content["description"].startswith("*Criticality*: CRITICAL. LOG-001")


def test_catalog_floor_raises_agent_severity(investigator_handler, base_env, monkeypatch):
    fakes = wire(investigator_handler, monkeypatch)
    captured = {}

    def fake_agent(**kwargs):
        captured.update(kwargs)
        return {**VERDICT, "security_severity": "low"}, {"inputTokens": 10, "outputTokens": 5}

    monkeypatch.setattr(investigator_handler.agent_loop, "run_agent", fake_agent)
    monkeypatch.setattr(investigator_handler.budget, "consume_tokens", lambda *args: 15)
    monkeypatch.setattr(investigator_handler.memory, "save_investigation", lambda **kw: None)
    data = payload()
    record = dict(sample_events.CLOUDTRAIL_STOP)
    verdict = investigator_handler.run_investigation(
        record, data["identity"], data["account_label"], data["session_id"],
        None, sample_events.IP_INFO,
    )
    assert verdict["security_severity"] == "critical"
    assert verdict["agent_security_severity"] == "low"
    # The agent saw the catalog rating and the source network.
    assert '"rule_id": "LOG-001"' in captured["user_prompt"]
    assert "AS3215 Orange S.A., near Paris" in captured["user_prompt"]
    assert "- critical:" in captured["system_prompt"]
    # The record keeps the rule and source for statistics.
    item = fakes["dynamodb"].put_item.call_args.kwargs["Item"]
    assert item["criticality_rule"]["S"] == "LOG-001"
    assert item["source_country"]["S"] == "FR"
    assert item["source_network"]["S"] == "AS3215 Orange S.A."
    assert item["security_severity"]["S"] == "critical"


def test_ip_tool_is_offered_only_when_lookup_is_enabled(
    investigator_handler, base_env, monkeypatch
):
    wire(investigator_handler, monkeypatch)
    offered = []

    def fake_agent(**kwargs):
        offered.append({spec["toolSpec"]["name"] for spec in kwargs["tool_specs"]})
        assert set(kwargs["tool_dispatch"]) == offered[-1]
        return None, {"inputTokens": 0, "outputTokens": 0}

    monkeypatch.setattr(investigator_handler.agent_loop, "run_agent", fake_agent)
    monkeypatch.setattr(investigator_handler.budget, "consume_tokens", lambda *args: 0)
    data = payload()
    args = (data["record"], data["identity"], data["account_label"], data["session_id"])
    investigator_handler.run_investigation(*args)
    monkeypatch.setenv("IP_LOOKUP_PROVIDER", "ipinfo")
    investigator_handler.run_investigation(*args)
    assert "lookup_ip_intel" not in offered[0]
    assert "lookup_ip_intel" in offered[1]


def test_run_investigation_consumes_budget_and_records(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)

    monkeypatch.setattr(
        investigator_handler.agent_loop,
        "run_agent",
        lambda **kwargs: (dict(VERDICT), {"inputTokens": 1200, "outputTokens": 300}),
    )
    consumed = {}

    def fake_consume(client, table, tokens):
        consumed["tokens"] = tokens
        return tokens

    monkeypatch.setattr(investigator_handler.budget, "consume_tokens", fake_consume)
    saved = {}
    monkeypatch.setattr(
        investigator_handler.memory,
        "save_investigation",
        lambda **kwargs: saved.update(kwargs),
    )

    data = payload()
    verdict = investigator_handler.run_investigation(
        data["record"], data["identity"], data["account_label"], data["session_id"]
    )
    assert verdict["verdict"] == "suspicious"
    assert consumed["tokens"] == 1500
    # Investigation record written for statistics.
    put_calls = fakes["dynamodb"].put_item.call_args_list
    assert any(
        call.kwargs["Item"]["pk"]["S"] == "INVESTIGATION" for call in put_calls
    )
    # Memory saved with the verdict summary.
    assert "suspicious" in saved["verdict_summary"]
    # Token metrics published.
    fakes["cloudwatch"].put_metric_data.assert_called_once()


def agent_context(anomalies=(), observations=()):
    context = client.new_context(sample_events.AGENT_API_MUTATION)
    context["anomalies"] = list(anomalies)
    context["observations"] = list(observations)
    return context


def test_agent_api_change_is_reported_as_an_agent_change(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(investigator_handler.budget, "tokens_used_today", lambda *args: 0)
    monkeypatch.setattr(
        investigator_handler, "run_investigation", lambda *args: dict(VERDICT)
    )
    data = {
        **payload(),
        "record": dict(sample_events.AGENT_API_MUTATION),
        "context": agent_context(),
    }
    investigator_handler.lambda_handler(data, None)
    content = chat_payloads(fakes["sns"])[0]["content"]
    assert content["title"] == "[HIGH] AI agent change detected: RunInstances"
    assert "*Origin*: API call, not the console" in content["description"]
    assert "*Client*: AI agent cursor-agent via AWS CLI on macOS" in content["description"]
    subject, html, _text = fakes["email"].call_args.args
    assert subject == "[HIGH] AI agent change detected: RunInstances"
    assert "AGENT SESSION PATH" in html


def test_session_anomaly_from_the_detector_raises_the_plain_rating(
    investigator_handler, base_env, monkeypatch
):
    fakes = wire(investigator_handler, monkeypatch)
    monkeypatch.setattr(investigator_handler.budget, "tokens_used_today", lambda *args: 0)
    monkeypatch.setattr(investigator_handler, "run_investigation", lambda *args: None)
    anomaly = "client changed mid-session: Chrome on macOS to Headless Chrome on Linux"
    data = {**payload(), "context": agent_context(anomalies=[anomaly])}
    investigator_handler.lambda_handler(data, None)
    content = chat_payloads(fakes["sns"])[0]["content"]
    assert content["title"].startswith("[HIGH] ")
    assert anomaly in content["description"]


def test_agent_sees_client_and_record_keeps_it(investigator_handler, base_env, monkeypatch):
    fakes = wire(investigator_handler, monkeypatch)
    captured = {}

    def fake_agent(**kwargs):
        captured.update(kwargs)
        return dict(VERDICT), {"inputTokens": 10, "outputTokens": 5}

    monkeypatch.setattr(investigator_handler.agent_loop, "run_agent", fake_agent)
    monkeypatch.setattr(investigator_handler.budget, "consume_tokens", lambda *args: 15)
    saved = {}
    monkeypatch.setattr(
        investigator_handler.memory, "save_investigation", lambda **kw: saved.update(kw)
    )
    data = payload()
    context = agent_context(observations=["first change by this actor from AI agent"])
    investigator_handler.run_investigation(
        dict(sample_events.AGENT_API_MUTATION), data["identity"], data["account_label"],
        data["session_id"], None, None, context,
    )
    prompt = captured["user_prompt"]
    assert prompt.startswith("Investigate this API change made by a client labelled as an AI")
    assert "Client: AI agent cursor-agent via AWS CLI on macOS" in prompt
    assert "Client signals: first change by this actor from AI agent" in prompt
    assert "6. Client:" in captured["system_prompt"]
    item = fakes["dynamodb"].put_item.call_args.kwargs["Item"]
    assert item["client_kind"]["S"] == "ai-agent"
    assert item["agent"]["S"] == "cursor-agent"
    assert "using AI agent cursor-agent" in saved["event_summary"]
    assert saved["event_summary"].startswith("API change by")

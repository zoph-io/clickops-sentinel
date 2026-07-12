# SPDX-License-Identifier: Apache-2.0
"""Investigator handler paths: budget exhaustion, fallback, enrichment."""

import json
from unittest.mock import MagicMock

import sample_events

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
    assert subject == "ClickOps detected: RunInstances"
    assert "CONSOLE SESSION PATH" in html
    assert "RunInstances" in html


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

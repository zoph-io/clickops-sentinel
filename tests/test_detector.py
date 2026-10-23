# SPDX-License-Identifier: Apache-2.0
"""Detector decision paths with mocked AWS clients."""

import json
from unittest.mock import MagicMock

import sample_events
from botocore.exceptions import ClientError


def client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": code}}, "Operation")


def wire(detector_handler, monkeypatch, dynamodb=None, sns=None, lam=None, iam=None):
    """Install fake clients, a fake email sender, and reset module caches."""
    fakes = {
        "dynamodb": dynamodb or MagicMock(),
        "sns": sns or MagicMock(),
        "lambda": lam or MagicMock(),
        "iam": iam or MagicMock(),
        "email": MagicMock(return_value=True),
    }
    monkeypatch.setattr(detector_handler, "_clients", fakes)
    monkeypatch.setattr(detector_handler, "_account_alias_cache", [])
    monkeypatch.setattr(detector_handler.email_send, "send_email", fakes["email"])
    return fakes


def test_console_mutation_goes_to_investigator(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "investigating"
    fakes["lambda"].invoke.assert_called_once()
    assert fakes["lambda"].invoke.call_args.kwargs["InvocationType"] == "Event"
    fakes["sns"].publish.assert_not_called()


def test_duplicate_event_is_dropped(detector_handler, base_env, monkeypatch):
    dynamodb = MagicMock()
    dynamodb.put_item.side_effect = client_error("ConditionalCheckFailedException")
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "deduplicated"
    fakes["sns"].publish.assert_not_called()
    fakes["lambda"].invoke.assert_not_called()


def test_cli_event_is_skipped(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.CLI_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "skipped"
    assert "console" in result["reason"]
    fakes["dynamodb"].put_item.assert_not_called()


def test_readonly_event_is_skipped(detector_handler, base_env, monkeypatch):
    wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_READONLY)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "skipped"


def test_suppressed_action_is_dropped(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.SUPPRESSED_ACTION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "suppressed"
    fakes["sns"].publish.assert_not_called()


def test_service_invoked_event_is_skipped(detector_handler, base_env, monkeypatch):
    wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.SERVICE_INVOKED)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "skipped"
    assert "invoked by service" in result["reason"]


def test_session_cooldown_produces_followup(detector_handler, base_env, monkeypatch):
    dynamodb = MagicMock()
    # First put (dedup) succeeds, second put (cooldown) hits the condition.
    dynamodb.put_item.side_effect = [
        {},
        client_error("ConditionalCheckFailedException"),
    ]
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "followup"
    fakes["lambda"].invoke.assert_not_called()
    # Chat and email both receive the follow-up note.
    assert fakes["sns"].publish.call_count == 1
    fakes["email"].assert_called_once()


def test_ai_disabled_notifies_directly(detector_handler, base_env, monkeypatch):
    monkeypatch.setenv("ENABLE_AI", "false")
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "notified"
    assert fakes["sns"].publish.call_count == 1
    fakes["email"].assert_called_once()
    fakes["lambda"].invoke.assert_not_called()


def test_investigator_failure_falls_back_to_plain(detector_handler, base_env, monkeypatch):
    lam = MagicMock()
    lam.invoke.side_effect = client_error("ServiceException")
    fakes = wire(detector_handler, monkeypatch, lam=lam)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "notified"
    assert fakes["sns"].publish.call_count == 1
    fakes["email"].assert_called_once()


def test_root_login_alerts(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(
        sample_events.ROOT_LOGIN, detail_type="AWS Console Sign In via CloudTrail"
    )
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "login-alert"
    assert fakes["sns"].publish.call_count == 1
    fakes["email"].assert_called_once()


def test_login_without_mfa_alerts(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(
        sample_events.MFA_LESS_LOGIN, detail_type="AWS Console Sign In via CloudTrail"
    )
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "login-alert"
    assert fakes["sns"].publish.call_count == 1
    fakes["email"].assert_called_once()


def test_normal_login_is_quiet(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(
        sample_events.NORMAL_LOGIN, detail_type="AWS Console Sign In via CloudTrail"
    )
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "login-ok"
    fakes["sns"].publish.assert_not_called()
    fakes["email"].assert_not_called()


def test_critical_change_bypasses_session_cooldown(detector_handler, base_env, monkeypatch):
    dynamodb = MagicMock()
    dynamodb.put_item.side_effect = [
        {},
        client_error("ConditionalCheckFailedException"),
    ]
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.CLOUDTRAIL_STOP)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "investigating"
    fakes["lambda"].invoke.assert_called_once()
    fakes["sns"].publish.assert_not_called()


def test_followup_note_carries_criticality(detector_handler, base_env, monkeypatch):
    dynamodb = MagicMock()
    dynamodb.put_item.side_effect = [
        {},
        client_error("ConditionalCheckFailedException"),
    ]
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    detector_handler.lambda_handler(event, None)
    message = json.loads(fakes["sns"].publish.call_args.kwargs["Message"])
    assert message["content"]["title"].endswith("(LOW)")
    assert "CMP-005" in message["content"]["description"]


def test_ip_info_is_looked_up_once_and_handed_to_investigator(
    detector_handler, base_env, monkeypatch
):
    fakes = wire(detector_handler, monkeypatch)
    lookup = MagicMock(return_value=sample_events.IP_INFO)
    monkeypatch.setattr(detector_handler.ip_intel, "lookup", lookup)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    detector_handler.lambda_handler(event, None)
    lookup.assert_called_once_with("203.0.113.10")
    payload = json.loads(fakes["lambda"].invoke.call_args.kwargs["Payload"])
    assert payload["ip_info"]["isp"] == "Orange S.A."


def test_plain_alert_shows_criticality_and_source_network(
    detector_handler, base_env, monkeypatch
):
    monkeypatch.setenv("ENABLE_AI", "false")
    fakes = wire(detector_handler, monkeypatch)
    monkeypatch.setattr(
        detector_handler.ip_intel, "lookup", MagicMock(return_value=sample_events.IP_INFO)
    )
    event = sample_events.eventbridge_envelope(sample_events.SG_OPEN_SSH)
    detector_handler.lambda_handler(event, None)
    message = json.loads(fakes["sns"].publish.call_args.kwargs["Message"])
    assert message["content"]["title"] == (
        "[CRITICAL] ClickOps detected: AuthorizeSecurityGroupIngress"
    )
    description = message["content"]["description"]
    assert description.startswith("*Criticality*: CRITICAL. NET-001")
    assert "*Source network*: AS3215 Orange S.A., near Paris" in description
    subject, html, _text = fakes["email"].call_args.args
    assert subject.startswith("[CRITICAL]")
    assert "CRITICALITY CATALOG" in html
    assert "Orange S.A." in html


def test_login_alert_includes_source_network(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    monkeypatch.setattr(
        detector_handler.ip_intel, "lookup", MagicMock(return_value=sample_events.IP_INFO)
    )
    event = sample_events.eventbridge_envelope(
        sample_events.ROOT_LOGIN, detail_type="AWS Console Sign In via CloudTrail"
    )
    detector_handler.lambda_handler(event, None)
    message = json.loads(fakes["sns"].publish.call_args.kwargs["Message"])
    assert "Source network" in message["content"]["description"]


def test_account_alias_resolution(detector_handler, base_env, monkeypatch):
    monkeypatch.setenv("ACCOUNT_FRIENDLY_NAME", "")
    iam = MagicMock()
    iam.list_account_aliases.return_value = {"AccountAliases": ["prod-alias"]}
    wire(detector_handler, monkeypatch, iam=iam)
    label = detector_handler.get_account_label(sample_events.CONSOLE_MUTATION)
    assert label == "prod-alias (123456789012)"

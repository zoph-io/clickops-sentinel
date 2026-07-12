# SPDX-License-Identifier: Apache-2.0
"""Detector decision paths with mocked AWS clients."""

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


def test_account_alias_resolution(detector_handler, base_env, monkeypatch):
    monkeypatch.setenv("ACCOUNT_FRIENDLY_NAME", "")
    iam = MagicMock()
    iam.list_account_aliases.return_value = {"AccountAliases": ["prod-alias"]}
    wire(detector_handler, monkeypatch, iam=iam)
    label = detector_handler.get_account_label(sample_events.CONSOLE_MUTATION)
    assert label == "prod-alias (123456789012)"

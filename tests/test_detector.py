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


# --- Clients and AI agents ------------------------------------------------------


def tracking(session=None, actor=None):
    """Fake DynamoDB whose update_item returns old session and actor attributes."""
    dynamodb = MagicMock()
    dynamodb.update_item.side_effect = [
        {"Attributes": session or {}},
        {"Attributes": actor or {}},
    ]
    return dynamodb


def test_labelled_agent_api_change_is_investigated(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.AGENT_API_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "investigating"
    payload = json.loads(fakes["lambda"].invoke.call_args.kwargs["Payload"])
    assert payload["context"]["origin"] == "api"
    assert payload["context"]["client"]["agent"] == "cursor-agent"


def test_agent_api_watching_can_be_disabled(detector_handler, base_env, monkeypatch):
    monkeypatch.setenv("AGENT_API_CHANGES", "false")
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.AGENT_API_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "skipped"
    fakes["lambda"].invoke.assert_not_called()


def test_agent_browser_title_names_the_agent(detector_handler, base_env, monkeypatch):
    monkeypatch.setenv("ENABLE_AI", "false")
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.AGENT_BROWSER_MUTATION)
    detector_handler.lambda_handler(event, None)
    message = json.loads(fakes["sns"].publish.call_args.kwargs["Message"])
    assert message["content"]["title"] == "ClickOps by an AI agent detected: RunInstances"
    assert "*Client*: Cursor browser (AI agent tool) on macOS" in message["content"]["description"]
    subject, html, _text = fakes["email"].call_args.args
    assert subject == "ClickOps by an AI agent detected: RunInstances"
    assert "Console change by an AI agent" in html


def test_browser_switch_mid_session_is_an_anomaly(detector_handler, base_env, monkeypatch):
    dynamodb = tracking(
        session={
            "fingerprint": {"S": "browser|Firefox|Windows"},
            "client_label": {"S": "Firefox on Windows"},
        }
    )
    # Dedup succeeds, then the session cooldown is active.
    dynamodb.put_item.side_effect = [{}, client_error("ConditionalCheckFailedException")]
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.BROWSER_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "investigating", "anomalies bypass the cooldown"
    payload = json.loads(fakes["lambda"].invoke.call_args.kwargs["Payload"])
    assert payload["context"]["anomalies"] == [
        "client changed mid-session: Firefox on Windows to Chrome on macOS"
    ]
    session_update = dynamodb.update_item.call_args_list[0].kwargs
    assert session_update["Key"]["pk"]["S"] == "SESSION#ASIAEXAMPLEKEY"
    assert session_update["ExpressionAttributeValues"][":f"]["S"] == "browser|Chrome|macOS"


def test_browser_to_cli_switch_is_only_an_observation(detector_handler, base_env, monkeypatch):
    dynamodb = tracking(
        session={"fingerprint": {"S": "cli|AWS CLI|macOS"}, "client_label": {"S": "AWS CLI"}}
    )
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.BROWSER_MUTATION)
    detector_handler.lambda_handler(event, None)
    payload = json.loads(fakes["lambda"].invoke.call_args.kwargs["Payload"])
    assert payload["context"]["anomalies"] == []
    assert payload["context"]["observations"] == [
        "session used from several clients: AWS CLI to Chrome on macOS"
    ]


def test_country_switch_mid_session_raises_the_rating(detector_handler, base_env, monkeypatch):
    monkeypatch.setenv("ENABLE_AI", "false")
    dynamodb = tracking(
        session={"fingerprint": {"S": "browser|Chrome|macOS"}, "country": {"S": "US"}}
    )
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    monkeypatch.setattr(
        detector_handler.ip_intel, "lookup", MagicMock(return_value=sample_events.IP_INFO)
    )
    event = sample_events.eventbridge_envelope(sample_events.BROWSER_MUTATION)
    detector_handler.lambda_handler(event, None)
    message = json.loads(fakes["sns"].publish.call_args.kwargs["Message"])
    assert message["content"]["title"] == "[HIGH] ClickOps detected: RunInstances"
    description = message["content"]["description"]
    assert "source country changed mid-session: US to FR" in description
    assert "*Client signals*:" in description


def test_first_client_for_actor_is_an_observation(detector_handler, base_env, monkeypatch):
    dynamodb = tracking(actor={"fingerprints": {"SS": ["browser|Firefox|Windows"]}})
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.BROWSER_MUTATION)
    detector_handler.lambda_handler(event, None)
    payload = json.loads(fakes["lambda"].invoke.call_args.kwargs["Payload"])
    assert payload["context"]["observations"] == [
        "first change by this actor from Chrome on macOS"
    ]
    actor_update = dynamodb.update_item.call_args_list[1].kwargs
    assert actor_update["Key"]["pk"]["S"] == "ACTOR#alice@example.com"


def test_known_client_and_first_ever_client_are_quiet(detector_handler, base_env, monkeypatch):
    for actor in ({"fingerprints": {"SS": ["browser|Chrome|macOS"]}}, {}):
        fakes = wire(detector_handler, monkeypatch, dynamodb=tracking(actor=actor))
        event = sample_events.eventbridge_envelope(sample_events.BROWSER_MUTATION)
        detector_handler.lambda_handler(event, None)
        payload = json.loads(fakes["lambda"].invoke.call_args.kwargs["Payload"])
        assert payload["context"]["observations"] == []


def test_tracking_failure_never_blocks_the_alert(detector_handler, base_env, monkeypatch):
    dynamodb = MagicMock()
    dynamodb.update_item.side_effect = client_error("ProvisionedThroughputExceededException")
    fakes = wire(detector_handler, monkeypatch, dynamodb=dynamodb)
    event = sample_events.eventbridge_envelope(sample_events.BROWSER_MUTATION)
    result = detector_handler.lambda_handler(event, None)
    assert result["decision"] == "investigating"
    fakes["lambda"].invoke.assert_called_once()


def test_aws_internal_user_agent_is_not_tracked(detector_handler, base_env, monkeypatch):
    fakes = wire(detector_handler, monkeypatch)
    event = sample_events.eventbridge_envelope(sample_events.CONSOLE_MUTATION)
    detector_handler.lambda_handler(event, None)
    fakes["dynamodb"].update_item.assert_not_called()

# SPDX-License-Identifier: Apache-2.0
"""Who drove a change: evidence collection and weighing."""

import copy

import pytest
import sample_events

import client
import origin

FEDERATED_LINEAGE = {"signin_gap_seconds": 389}
FRESH_LINEAGE = {"signin_gap_seconds": 1}


def assess(record, ip_info=None, lineage=None, steps=None):
    info = client.parse(record.get("userAgent"))
    return origin.assess(origin.collect(record, info, ip_info, lineage, steps))


def with_mfa(record):
    record = copy.deepcopy(record)
    record["userIdentity"]["sessionContext"] = {"attributes": {"mfaAuthenticated": "true"}}
    return record


def test_agent_browser_on_federated_console_session_is_an_agent_with_high_confidence():
    result = assess(sample_events.FEDERATED_CONSOLE_MUTATION, lineage=FEDERATED_LINEAGE)
    assert result["driver"] == "ai-agent"
    assert result["confidence"] == "high"
    signals = [item["signal"] for item in result["evidence"]]
    # Session name and sign-in gap tell the same story: counted once.
    assert sum("federation" == item["group"] for item in result["evidence"]) == 1
    assert any("created 6 minutes earlier" in signal for signal in signals)
    assert result["conflict"] == ""


def test_plain_browser_on_federated_session_is_automation_and_a_conflict():
    record = dict(sample_events.FEDERATED_CONSOLE_MUTATION, userAgent=sample_events.CHROME_UA)
    result = assess(record, lineage=FEDERATED_LINEAGE)
    assert result["driver"] == "automation"
    assert result["confidence"] == "medium"
    assert "looks like a person (ordinary browser (Chrome on macOS))" in result["conflict"]
    context = {"origin": "console", "client": client.parse(record["userAgent"])}
    context["assessment"] = result
    assert client.headline(context) == "Automated ClickOps detected"


def test_browser_with_fresh_sign_in_is_a_person_but_never_high_without_proof():
    result = assess(sample_events.BROWSER_MUTATION, lineage=FRESH_LINEAGE)
    assert (result["driver"], result["confidence"]) == ("human", "medium")
    proven = assess(with_mfa(sample_events.BROWSER_MUTATION), lineage=FRESH_LINEAGE)
    assert (proven["driver"], proven["confidence"]) == ("human", "high")


def test_console_alone_is_a_person_with_low_confidence():
    result = assess(sample_events.CONSOLE_MUTATION)
    assert (result["driver"], result["confidence"]) == ("human", "low")


def test_labelled_agent_cli_is_an_agent_with_high_confidence():
    record = copy.deepcopy(sample_events.AGENT_API_MUTATION)
    record["userIdentity"]["arn"] = (
        "arn:aws:sts::123456789012:assumed-role/admin/botocore-session-1"
    )
    result = assess(record)
    assert (result["driver"], result["confidence"]) == ("ai-agent", "high")
    assert any(item["signal"] == "user agent app ID cursor-agent" for item in result["evidence"])


def test_mcp_server_call_is_aws_asserted_and_counted_once():
    result = assess(sample_events.MCP_MUTATION)
    assert (result["driver"], result["confidence"]) == ("ai-agent", "high")
    assert [item["signal"] for item in result["evidence"] if item["driver"] == "ai-agent"] == [
        "called through AWS MCP Server"
    ]


@pytest.mark.parametrize(
    ("source_identity", "driver"),
    [("cursor-agent", "ai-agent"), ("claude.martin@example.com", "human"), ("jdoe", "human")],
)
def test_source_identity_names_an_agent_but_never_a_person_by_email(source_identity, driver):
    record = copy.deepcopy(sample_events.CLI_MUTATION)
    record["userIdentity"]["sessionContext"] = {"sourceIdentity": source_identity}
    items = origin.identity_evidence(record)
    assert [item["driver"] for item in items] == [driver]


def test_agent_role_names_are_strong_evidence(monkeypatch):
    monkeypatch.setenv("AGENT_ROLE_NAMES", "AgentAccess")
    record = copy.deepcopy(sample_events.CLI_MUTATION)
    record["userIdentity"]["arn"] = "arn:aws:sts::123456789012:assumed-role/AgentAccess/run-42"
    items = origin.identity_evidence(record)
    assert items[0]["signal"] == "role AgentAccess is reserved for AI agents"
    assert items[0]["strength"] == "strong"


def test_long_term_access_key_points_to_automation():
    record = copy.deepcopy(sample_events.CLI_MUTATION)
    record["userIdentity"] = {"type": "IAMUser", "userName": "ci", "accessKeyId": "AKIAEXAMPLE"}
    assert origin.identity_evidence(record)[0]["driver"] == "automation"


def test_session_tag_and_agent_minted_credentials_from_lineage():
    lineage = {
        "assume_role": {
            "tags": {"AccessType": "AI"},
            "caller_agent": "cursor-agent",
            "mfa": False,
        }
    }
    signals = [item["signal"] for item in origin.lineage_evidence(lineage)]
    assert signals == [
        "session tag AccessType=AI marks an AI agent",
        "credentials minted by AI agent cursor-agent",
    ]


def test_hosting_network_points_to_automation():
    items = origin.network_evidence({"asn": "AS16509", "isp": "Amazon.com, Inc.", "flags": []})
    assert items[0]["driver"] == "automation"
    assert "AS16509 Amazon.com, Inc." in items[0]["signal"]
    assert origin.network_evidence(sample_events.IP_INFO) == []
    assert origin.network_evidence({"asn": "AS1", "flags": ["hosting"]})[0]["strength"] == "medium"


def test_behavior_patterns_present_in_the_session():
    record = sample_events.BROWSER_MUTATION
    steps = [
        {"name": "GetCallerIdentity", "time": "2026-07-05T11:50:00Z", "readOnly": True},
        {"name": "CreateTags", "time": "2026-07-05T11:51:00Z", "errorCode": "InvalidParameter"},
        {"name": "CreateTags", "time": "2026-07-05T11:51:10Z"},
        {"name": "PutRule", "time": "2026-07-05T11:52:00Z", "errorCode": "ValidationException"},
        {"name": "PutRule", "time": "2026-07-05T11:52:30Z"},
    ] + [
        {"name": "DescribeInstances", "time": f"2026-07-05T11:58:0{n}Z", "readOnly": True}
        for n in range(5)
    ]
    signals = [item["signal"] for item in origin.behavior_evidence(steps, record)]
    assert signals == [
        "GetCallerIdentity in the session, a typical CLI or agent first step",
        "trial and error: 2 failing calls retried until they succeeded",
        "5 console page reads in the 5 minutes before the change",
    ]
    assert origin.behavior_evidence([], record) == []


def test_no_evidence_is_unknown():
    assert origin.assess([]) == {
        "driver": "unknown",
        "confidence": "low",
        "evidence": [],
        "conflict": "",
    }


def test_fields_and_lines_for_alerts():
    result = assess(sample_events.FEDERATED_CONSOLE_MUTATION, lineage=FEDERATED_LINEAGE)
    fields = dict(origin.fields(result))
    assert fields["Driven by"] == "AI agent, high confidence"
    assert "(AWS, medium)" in fields["Evidence"]
    assert "(client, strong)" in fields["Evidence"]
    assert origin.fields(None) == []
    assert origin.describe(None) == ""


def test_duration_wording():
    assert origin.duration(45) == "45 seconds"
    assert origin.duration(389) == "6 minutes"
    assert origin.duration(19800) == "5.5 hours"

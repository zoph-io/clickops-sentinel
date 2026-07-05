# SPDX-License-Identifier: Apache-2.0
"""CloudTrail agent tools with a mocked client."""

import json

import sample_events

import tools


class FakeCloudTrail:
    def __init__(self, pages):
        self.pages = list(pages)
        self.calls = []

    def lookup_events(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0) if self.pages else {"Events": []}


def page_of(records, next_token=None):
    page = {
        "Events": [
            {"CloudTrailEvent": json.dumps(record), "EventName": record.get("eventName")}
            for record in records
        ]
    }
    if next_token:
        page["NextToken"] = next_token
    return page


def test_lookup_by_username_uses_username_attribute():
    client = FakeCloudTrail([page_of([sample_events.CONSOLE_MUTATION])])
    result = json.loads(tools.lookup_events_by_user(client, "alice@example.com", 6))
    attribute = client.calls[0]["LookupAttributes"][0]
    assert attribute["AttributeKey"] == "Username"
    assert result["event_count"] == 1
    assert "ASIAEXAMPLEKEY" in result["sessions"]


def test_lookup_by_access_key_routes_to_access_key_attribute():
    client = FakeCloudTrail([page_of([sample_events.CONSOLE_MUTATION])])
    tools.lookup_events_by_user(client, "ASIAEXAMPLEKEY", 6)
    attribute = client.calls[0]["LookupAttributes"][0]
    assert attribute["AttributeKey"] == "AccessKeyId"


def test_lookup_groups_events_by_session():
    other_session = {
        **sample_events.CONSOLE_MUTATION,
        "userIdentity": {
            **sample_events.CONSOLE_MUTATION["userIdentity"],
            "accessKeyId": "ASIAOTHERKEY",
        },
    }
    client = FakeCloudTrail(
        [page_of([sample_events.CONSOLE_MUTATION, other_session])]
    )
    result = json.loads(tools.lookup_events_by_user(client, "alice@example.com", 6))
    assert set(result["sessions"]) == {"ASIAEXAMPLEKEY", "ASIAOTHERKEY"}


def test_lookup_by_ip_filters_client_side():
    matching = sample_events.CONSOLE_MUTATION
    non_matching = {**sample_events.CONSOLE_MUTATION, "sourceIPAddress": "198.51.100.9"}
    client = FakeCloudTrail([page_of([matching, non_matching])])
    result = json.loads(tools.lookup_events_by_ip(client, "203.0.113.10", 6))
    assert client.calls[0]["LookupAttributes"][0]["AttributeKey"] == "ReadOnly"
    assert result["scanned_write_events"] == 2
    assert len(result["matching_events"]) == 1
    assert result["matching_events"][0]["ip"] == "203.0.113.10"


def test_get_event_details_not_found():
    client = FakeCloudTrail([{"Events": []}])
    result = json.loads(tools.get_event_details(client, "deadbeef"))
    assert "error" in result


def test_page_cap_is_enforced():
    pages = [
        page_of([sample_events.CONSOLE_MUTATION], next_token=f"token-{index}")
        for index in range(10)
    ]
    client = FakeCloudTrail(pages)
    tools.lookup_events_by_user(client, "alice@example.com", 6)
    assert len(client.calls) == tools.MAX_PAGES


def test_tool_output_is_truncated():
    big = {
        **sample_events.CONSOLE_MUTATION,
        "requestParameters": {"blob": "y" * 20000},
    }
    client = FakeCloudTrail([page_of([big] * 40)])
    result = tools.lookup_events_by_user(client, "alice@example.com", 6)
    assert len(result) <= tools.MAX_TOOL_OUTPUT_CHARS + len("...(truncated)")


def test_summarize_keeps_key_fields_and_truncates_parameters():
    summary = tools.summarize_cloudtrail_event(
        {
            **sample_events.CONSOLE_MUTATION,
            "requestParameters": {"blob": "z" * 2000},
            "errorCode": "AccessDenied",
        }
    )
    assert summary["name"] == "RunInstances"
    assert summary["errorCode"] == "AccessDenied"
    assert len(summary["requestParameters"]) <= 300 + len("...(truncated)")

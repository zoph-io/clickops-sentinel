# SPDX-License-Identifier: Apache-2.0
"""Session lineage from CloudTrail event history, with a fake CloudTrail."""

import copy
import json

import pytest
import sample_events

import lineage


class FakeCloudTrail:
    """Answers LookupEvents per lookup attribute, records every call."""

    def __init__(self, region, by_attribute, calls, fail=False):
        self.region = region
        self.by_attribute = by_attribute
        self.calls = calls
        self.fail = fail

    def lookup_events(self, **kwargs):
        attribute = kwargs["LookupAttributes"][0]
        self.calls.append((self.region, attribute["AttributeKey"], attribute["AttributeValue"]))
        if self.fail:
            raise RuntimeError("throttled")
        events = self.by_attribute.get((self.region, attribute["AttributeKey"]), [])
        return {"Events": [{"CloudTrailEvent": json.dumps(event)} for event in events]}


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(lineage.time, "sleep", lambda _seconds: None)


def factory(by_attribute, calls, fail=False):
    return lambda region: FakeCloudTrail(region, by_attribute, calls, fail)


def test_finds_assume_role_in_event_region_and_sign_in_in_us_east_1():
    calls = []
    by_attribute = {
        ("eu-west-1", "ResourceName"): [sample_events.ASSUME_ROLE_FOR_FEDERATED],
        ("us-east-1", "EventName"): [sample_events.CONSOLE_LOGIN_FOR_FEDERATED],
    }
    record = sample_events.FEDERATED_CONSOLE_MUTATION
    result = lineage.lookup(record, factory(by_attribute, calls))
    assert result == {
        "assume_role": {
            "caller_client": "AI agent cursor-agent via AWS CLI on macOS",
            "caller_agent": "cursor-agent",
            "tags": {"AccessType": "AI"},
            "mfa": False,
        },
        "signin_gap_seconds": 389,
    }
    assert lineage.complete(record, result)
    assert calls == [
        ("eu-west-1", "ResourceName", sample_events.FEDERATED_ROLE_ARN),
        ("eu-west-1", "EventName", "ConsoleLogin"),
        ("us-east-1", "EventName", "ConsoleLogin"),
    ]


def test_ignores_events_of_other_sessions():
    other = copy.deepcopy(sample_events.CONSOLE_LOGIN_FOR_FEDERATED)
    other["userIdentity"]["arn"] = "arn:aws:sts::123456789012:assumed-role/admin/someone-else"
    by_attribute = {("us-east-1", "EventName"): [other]}
    record = sample_events.FEDERATED_CONSOLE_MUTATION
    result = lineage.lookup(record, factory(by_attribute, []))
    assert result == {}
    assert not lineage.complete(record, result)


def test_api_sessions_skip_the_sign_in_lookup():
    record = copy.deepcopy(sample_events.FEDERATED_CONSOLE_MUTATION)
    del record["sessionCredentialFromConsole"]
    calls = []
    lineage.lookup(record, factory({}, calls))
    assert {key for _region, key, _value in calls} == {"ResourceName"}


def test_failures_return_what_was_found():
    record = sample_events.FEDERATED_CONSOLE_MUTATION
    assert lineage.lookup(record, factory({}, [], fail=True)) == {}


def test_identities_without_a_role_session_are_not_looked_up():
    calls = []
    assert lineage.lookup(sample_events.CONSOLE_MUTATION, factory({}, calls)) == {}
    assert calls == []

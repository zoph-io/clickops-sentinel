# SPDX-License-Identifier: Apache-2.0
import sample_events

import suppressed_actions as sup


def test_suppresses_amazon_q_chatter():
    suppressed = sup.build_suppression_set("")
    assert sup.is_suppressed(sample_events.SUPPRESSED_ACTION, suppressed)


def test_does_not_suppress_real_mutation():
    suppressed = sup.build_suppression_set("")
    assert not sup.is_suppressed(sample_events.CONSOLE_MUTATION, suppressed)


def test_readonly_prefix_defense():
    suppressed = sup.build_suppression_set("")
    record = {"eventSource": "ec2.amazonaws.com", "eventName": "DescribeWeirdThing"}
    assert sup.is_suppressed(record, suppressed)


def test_extra_actions_are_merged():
    suppressed = sup.build_suppression_set("glue:StartJobRun, ce:CreateReport")
    record = {"eventSource": "glue.amazonaws.com", "eventName": "StartJobRun"}
    assert sup.is_suppressed(record, suppressed)


def test_service_prefix_extraction():
    assert sup.service_from_event_source("ec2.amazonaws.com") == "ec2"
    assert sup.service_from_event_source("sso-directory.amazonaws.com") == "sso-directory"
    assert sup.service_from_event_source("") == ""


def test_battle_tested_entries_present():
    for entry in (
        "iot:RegisterCertificate",
        "route53domains:TransferDomain",
        "signin:CheckMfa",
        "sts:AssumeRole",
        "q:StartConversation",
    ):
        assert entry in sup.DEFAULT_SUPPRESSED_ACTIONS

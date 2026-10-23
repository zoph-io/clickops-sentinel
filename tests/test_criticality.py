# SPDX-License-Identifier: Apache-2.0
"""Criticality catalog: integrity, parameter checks, modifiers, overrides."""

import dataclasses
import json
import re

import pytest
import sample_events

import criticality

ACCOUNT = "111111111111"
OTHER_ACCOUNT = "999999999999"
STACK = "clickops-sentinel"


def rate(source: str, name: str, params=None, **extra):
    record = {
        "recipientAccountId": ACCOUNT,
        "userIdentity": {"type": "AssumedRole"},
        "eventSource": f"{source}.amazonaws.com",
        "eventName": name,
        "requestParameters": params,
        **extra,
    }
    return criticality.classify(record, overrides="", stack_name=STACK)


def trust(principal) -> str:
    return json.dumps(
        {"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]}
    )


def ingress(cidr: str, protocol: str = "tcp", low=22, high=22) -> dict:
    permission = {"ipProtocol": protocol, "ipRanges": {"items": [{"cidrIp": cidr}]}}
    if low is not None:
        permission.update({"fromPort": low, "toPort": high})
    return {"ipPermissions": {"items": [permission]}}


# --- Catalog integrity -------------------------------------------------------


def test_rule_ids_are_unique_and_well_formed():
    ids = [rule.rule_id for rule in criticality.RULES + criticality.MODIFIER_RULES]
    assert len(ids) == len(set(ids))
    for rule_id in ids:
        assert re.fullmatch(r"[A-Z]+-\d{3}", rule_id), rule_id


def test_every_action_maps_to_exactly_one_rule():
    seen = {}
    for rule in criticality.RULES:
        assert rule.actions, rule.rule_id
        for action in rule.actions:
            assert re.fullmatch(r"[a-z0-9-]+:[A-Za-z]+", action), action
            assert action not in seen, f"{action} in {seen.get(action)} and {rule.rule_id}"
            seen[action] = rule.rule_id


def test_rules_reference_known_levels_tactics_and_techniques():
    tactics = {
        "Initial Access", "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
        "Collection", "Exfiltration", "Impact",
    }
    for rule in criticality.RULES + criticality.MODIFIER_RULES:
        assert rule.level in criticality.LEVELS
        assert rule.tactic in tactics, rule.rule_id
        for technique in rule.techniques:
            assert technique in criticality.TECHNIQUES, f"{rule.rule_id}: {technique}"
        for stratus in rule.stratus:
            assert stratus.startswith("aws."), stratus


def test_escalation_checks_are_documented():
    for rule in criticality.RULES:
        if rule.escalate is not None:
            assert (rule.escalate.__doc__ or "").strip(), rule.rule_id


def test_scale_and_response_cover_every_level():
    assert set(criticality.SCALE) == set(criticality.LEVELS)
    assert set(criticality.RESPONSE) == set(criticality.LEVELS)


# --- Base ratings and parameter checks ---------------------------------------


@pytest.mark.parametrize(
    ("source", "name", "params", "level", "rule_id"),
    [
        ("cloudtrail", "StopLogging", {"name": "t"}, "critical", "LOG-001"),
        ("organizations", "LeaveOrganization", None, "critical", "ORG-001"),
        ("organizations", "DetachPolicy", {"policyId": "p-1"}, "critical", "ORG-002"),
        ("guardduty", "DeleteDetector", {"detectorId": "d"}, "critical", "DET-001"),
        ("guardduty", "UpdateDetector", {"enable": False}, "critical", "DET-002"),
        ("guardduty", "UpdateDetector", {"findingPublishingFrequency": "SIX_HOURS"},
         "medium", "DET-002"),
        ("iam", "CreateAccessKey", {"userName": "bob"}, "high", "IAM-002"),
        ("iam", "AttachRolePolicy",
         {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, "critical", "IAM-004"),
        ("iam", "AttachRolePolicy",
         {"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, "high", "IAM-004"),
        ("iam", "PutUserPolicy",
         {"policyDocument": json.dumps(
             {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})},
         "critical", "IAM-004"),
        ("iam", "UpdateAssumeRolePolicy",
         {"policyDocument": trust({"AWS": f"arn:aws:iam::{OTHER_ACCOUNT}:root"})},
         "critical", "IAM-006"),
        ("iam", "UpdateAssumeRolePolicy",
         {"policyDocument": trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})}, "high", "IAM-006"),
        ("iam", "CreateRole",
         {"assumeRolePolicyDocument": trust({"Service": "lambda.amazonaws.com"})},
         "medium", "IAM-007"),
        ("iam", "CreateRole", {"assumeRolePolicyDocument": trust({"AWS": OTHER_ACCOUNT})},
         "high", "IAM-007"),
        ("sso", "AttachManagedPolicyToPermissionSet",
         {"managedPolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
         "critical", "IDC-001"),
        ("ec2", "AuthorizeSecurityGroupIngress", ingress("0.0.0.0/0"), "critical", "NET-001"),
        ("ec2", "AuthorizeSecurityGroupIngress", ingress("10.0.0.0/8"), "medium", "NET-001"),
        ("ec2", "AuthorizeSecurityGroupIngress", ingress("0.0.0.0/0", low=443, high=443),
         "medium", "NET-001"),
        ("ec2", "AuthorizeSecurityGroupIngress", ingress("0.0.0.0/0", low=8080, high=8090),
         "high", "NET-001"),
        ("ec2", "AuthorizeSecurityGroupIngress", ingress("0.0.0.0/0", "-1", None),
         "critical", "NET-001"),
        ("ec2", "AuthorizeSecurityGroupIngress", ingress("0.0.0.0/0", "icmp", -1, -1),
         "medium", "NET-001"),
        ("ec2", "ModifySecurityGroupRules",
         {"ModifySecurityGroupRulesRequest": {"SecurityGroupRule": {"SecurityGroupRule": {
             "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "CidrIpv4": "0.0.0.0/0"}}}},
         "critical", "NET-001"),
        ("s3", "PutBucketPolicy",
         {"bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                          "Action": "s3:GetObject"}]}},
         "critical", "DATA-003"),
        ("s3", "PutBucketPolicy",
         {"bucketPolicy": {"Statement": [{"Effect": "Allow", "Principal": "*",
                                          "Action": "s3:GetObject",
                                          "Condition": {"StringEquals": {"aws:PrincipalOrgID":
                                                                         "o-1"}}}]}},
         "medium", "DATA-003"),
        ("s3", "PutBucketPolicy",
         {"bucketPolicy": {"Statement": [{"Effect": "Allow",
                                          "Principal": {"AWS": OTHER_ACCOUNT},
                                          "Action": "s3:GetObject"}]}},
         "high", "DATA-003"),
        ("s3", "PutBucketAcl",
         {"AccessControlPolicy": {"AccessControlList": {"Grant": [
             {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}}},
         "critical", "DATA-003"),
        ("s3", "PutBucketPublicAccessBlock",
         {"PublicAccessBlockConfiguration": {"BlockPublicPolicy": False}}, "high", "DATA-002"),
        ("s3", "PutBucketPublicAccessBlock",
         {"PublicAccessBlockConfiguration": {"BlockPublicPolicy": True}}, "low", "DATA-002"),
        ("s3", "PutBucketVersioning", {"VersioningConfiguration": {"Status": "Suspended"}},
         "high", "DATA-009"),
        ("ec2", "ModifySnapshotAttribute",
         {"createVolumePermission": {"add": {"items": [{"group": "all"}]}}},
         "critical", "DATA-004"),
        ("ec2", "ModifyImageAttribute",
         {"launchPermission": {"add": {"items": [{"userId": OTHER_ACCOUNT}]}}},
         "high", "DATA-004"),
        ("rds", "ModifyDBSnapshotAttribute",
         {"attributeName": "restore", "valuesToAdd": ["all"]}, "critical", "DATA-005"),
        ("rds", "DeleteDBInstance", {"skipFinalSnapshot": True}, "high", "DATA-011"),
        ("rds", "ModifyDBInstance", {"publiclyAccessible": True}, "high", "DATA-013"),
        ("kms", "ScheduleKeyDeletion", {"keyId": "k"}, "critical", "KMS-001"),
        ("lambda", "AddPermission20150331v2", {"principal": "*"}, "critical", "CMP-007"),
        ("lambda", "AddPermission20150331v2",
         {"principal": "s3.amazonaws.com", "sourceArn": "arn:aws:s3:::b"}, "medium", "CMP-007"),
        ("lambda", "CreateFunctionUrlConfig20211031", {"authType": "NONE"}, "high", "CMP-007"),
        ("lambda", "UpdateFunctionCode20150331v2", {"functionName": "f"}, "high", "CMP-006"),
        ("ec2", "RunInstances", {"instanceType": "p4d.24xlarge"}, "high", "CMP-005"),
        ("ec2", "RunInstances",
         {"instanceType": "t3.micro", "instancesSet": {"items": [{"maxCount": 20}]}},
         "high", "CMP-005"),
        ("ec2", "RunInstances", {"instanceType": "t3.micro"}, "low", "CMP-005"),
        ("ec2", "ModifyInstanceMetadataOptions", {"httpTokens": "optional"}, "high", "CMP-004"),
        ("ec2", "ModifyInstanceAttribute", {"userData": "<sensitiveDataRemoved>"},
         "high", "CMP-003"),
        ("cloudtrail", "PutEventSelectors",
         {"eventSelectors": [{"readWriteType": "All", "includeManagementEvents": False}]},
         "critical", "LOG-002"),
        ("ssm", "SendCommand", {"documentName": "AWS-RunShellScript"}, "high", "CMP-001"),
    ],
)
def test_catalog_ratings(source, name, params, level, rule_id):
    rating = rate(source, name, params)
    assert rating is not None
    assert (rating["level"], rating["rule_id"]) == (level, rule_id)


MALFORMED_PARAMS = [
    None,
    "text",
    ["list"],
    {"ipPermissions": "x", "policy": 7, "launchPermission": {"add": "x"}},
    {"items": None, "attributeName": None, "userData": 5, "maxCount": "many"},
]


@pytest.mark.parametrize("params", MALFORMED_PARAMS)
def test_parameter_checks_tolerate_malformed_requests(params, caplog):
    for rule in criticality.RULES:
        for action in rule.actions:
            service, name = action.split(":")
            rating = rate(service, name, params)
            assert rating["rule_id"] == rule.rule_id
    assert "parameter check" not in caplog.text


def test_failing_parameter_check_keeps_base_level(monkeypatch):
    rule = criticality._INDEX["ec2:AuthorizeSecurityGroupIngress"]

    def broken(record):
        raise KeyError("boom")

    monkeypatch.setitem(
        criticality._INDEX,
        "ec2:AuthorizeSecurityGroupIngress",
        dataclasses.replace(rule, escalate=broken),
    )
    rating = rate("ec2", "AuthorizeSecurityGroupIngress", ingress("0.0.0.0/0"))
    assert rating["level"] == rule.level


def test_unknown_action_is_unrated():
    assert rate("ec2", "CreateTags", {"resourcesSet": {}}) is None


def test_read_only_event_is_unrated():
    assert rate("cloudtrail", "StopLogging", {"name": "t"}, readOnly=True) is None


def test_parameter_check_adds_reason_and_technique():
    rating = rate("ec2", "RunInstances", {"instanceType": "g5.xlarge"})
    assert "T1496.001" in rating["techniques"]
    assert any("g5.xlarge" in reason for reason in rating["reasons"])


# --- Modifiers ----------------------------------------------------------------


def test_failed_call_is_lowered_one_level_and_marked():
    rating = rate("cloudtrail", "StopLogging", {"name": "t"}, errorCode="AccessDenied")
    assert rating["level"] == "high"
    assert any("AccessDenied" in reason for reason in rating["reasons"])


def test_failed_low_call_stays_low():
    rating = rate("ec2", "RunInstances", {"instanceType": "t3.micro"}, errorCode="X")
    assert rating["level"] == "low"


def test_root_user_raises_to_high_even_without_a_rule():
    rating = rate("ec2", "CreateTags", {}, userIdentity={"type": "Root"})
    assert (rating["level"], rating["rule_id"]) == ("high", "ROOT-001")
    raised = rate("ec2", "RunInstances", {"instanceType": "t3.micro"},
                  userIdentity={"type": "Root"})
    assert (raised["level"], raised["rule_id"]) == ("high", "CMP-005")
    assert "performed by the root user" in raised["reasons"]


def test_changes_to_the_sentinel_stack_are_flagged():
    rating = rate("events", "DisableRule", {"name": f"{STACK}-ConsoleActionRule-ABC"})
    assert (rating["level"], rating["rule_id"]) == ("high", "SELF-001")


def test_short_stack_names_do_not_match_everything():
    record = {"eventSource": "events.amazonaws.com", "eventName": "DisableRule",
              "requestParameters": {"name": "abc-rule"}}
    assert criticality.classify(record, overrides="", stack_name="abc") is None


# --- Overrides ---------------------------------------------------------------


def test_override_rates_an_uncatalogued_action():
    record = {"eventSource": "ec2.amazonaws.com", "eventName": "CreateVpc"}
    rating = criticality.classify(record, overrides="ec2:CreateVpc=high", stack_name="")
    assert (rating["level"], rating["rule_id"]) == ("high", "CUSTOM")


def test_override_cannot_hide_a_public_exposure():
    record = {
        "recipientAccountId": ACCOUNT,
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateRole",
        "requestParameters": {"assumeRolePolicyDocument": trust({"AWS": "*"})},
    }
    rating = criticality.classify(record, overrides="iam:CreateRole=low", stack_name="")
    assert rating["level"] == "critical"


def test_invalid_overrides_are_ignored():
    assert criticality.parse_overrides("bad, ec2:X=nope, ,ec2:CreateVpc=LOW") == {
        "ec2:CreateVpc": "low"
    }


def test_classify_reads_environment_defaults(monkeypatch):
    monkeypatch.setenv("CRITICALITY_OVERRIDES", "ec2:CreateVpc=medium")
    monkeypatch.setenv("STACK_NAME", STACK)
    rating = criticality.classify({"eventSource": "ec2.amazonaws.com", "eventName": "CreateVpc"})
    assert rating["level"] == "medium"


# --- Helpers -----------------------------------------------------------------


def test_apply_floor_only_raises():
    rating = {"level": "high"}
    assert criticality.apply_floor("low", rating) == "high"
    assert criticality.apply_floor("critical", rating) == "critical"
    assert criticality.apply_floor("medium", None) == "medium"
    assert criticality.apply_floor("bogus", None) == "none"


def test_only_critical_bypasses_cooldown():
    assert criticality.bypasses_cooldown({"level": "critical"})
    assert not criticality.bypasses_cooldown({"level": "high"})
    assert not criticality.bypasses_cooldown(None)


def test_title_prefix_for_high_and_critical_only():
    assert criticality.title_prefix("critical") == "[CRITICAL] "
    assert criticality.title_prefix("high") == "[HIGH] "
    assert criticality.title_prefix("medium") == ""
    assert criticality.title_prefix("") == ""


def test_describe_is_chat_safe():
    rating = criticality.classify(sample_events.SG_OPEN_SSH, overrides="", stack_name="")
    text = criticality.describe(rating)
    assert text.startswith("CRITICAL. NET-001")
    assert "T1562.007" in text
    assert "Port 22 open to 0.0.0.0/0" in text
    assert "*" not in text
    assert "\u2014" not in text and "\u2013" not in text


def test_technique_url():
    assert criticality.technique_url("T1562.008") == (
        "https://attack.mitre.org/techniques/T1562/008/"
    )

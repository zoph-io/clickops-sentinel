# SPDX-License-Identifier: Apache-2.0
"""Recorded-style CloudTrail records used across tests."""

import copy


def eventbridge_envelope(record: dict, detail_type: str = "AWS API Call via CloudTrail") -> dict:
    return {
        "version": "0",
        "id": "eb-1",
        "detail-type": detail_type,
        "source": "aws.ec2",
        "account": "123456789012",
        "time": "2026-07-05T12:00:00Z",
        "region": "us-east-1",
        "resources": [],
        "detail": copy.deepcopy(record),
    }


CONSOLE_MUTATION = {
    "eventVersion": "1.09",
    "eventID": "11111111-1111-1111-1111-111111111111",
    "eventTime": "2026-07-05T12:00:00Z",
    "eventSource": "ec2.amazonaws.com",
    "eventName": "RunInstances",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.10",
    "userAgent": "AWS Internal",
    "readOnly": False,
    "sessionCredentialFromConsole": "true",
    "recipientAccountId": "123456789012",
    "requestParameters": {
        "instancesSet": {"items": [{"instanceType": "m5.4xlarge", "minCount": 1}]}
    },
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "AROAEXAMPLE:alice@example.com",
        "arn": (
            "arn:aws:sts::123456789012:assumed-role/"
            "AWSReservedSSO_AdministratorAccess_abc123def456/alice@example.com"
        ),
        "accountId": "123456789012",
        "accessKeyId": "ASIAEXAMPLEKEY",
    },
}

CLI_MUTATION = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "22222222-2222-2222-2222-222222222222",
    "userAgent": "aws-cli/2.22.0 md/awscrt",
}
del CLI_MUTATION["sessionCredentialFromConsole"]

CONSOLE_READONLY = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "33333333-3333-3333-3333-333333333333",
    "eventName": "DescribeInstances",
    "readOnly": True,
}

SUPPRESSED_ACTION = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "44444444-4444-4444-4444-444444444444",
    "eventSource": "q.amazonaws.com",
    "eventName": "StartConversation",
}

SERVICE_INVOKED = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "55555555-5555-5555-5555-555555555555",
}
SERVICE_INVOKED["userIdentity"] = {
    **copy.deepcopy(CONSOLE_MUTATION["userIdentity"]),
    "invokedBy": "cloudformation.amazonaws.com",
}

IDENTITY_CENTER_EVENT = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "66666666-6666-6666-6666-666666666666",
    "userIdentity": {
        "type": "IdentityCenterUser",
        "userId": "9a8b7c6d-example",
        "identityStoreArn": "arn:aws:identitystore::123456789012:identitystore/d-1234567890",
        "accountId": "123456789012",
    },
}

UNKNOWN_IDENTITY_EVENT = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "77777777-7777-7777-7777-777777777777",
    "eventSource": "iot.amazonaws.com",
    "eventName": "AttachPolicy",
    "userIdentity": {"type": "Unknown", "principalId": "odd-principal-string"},
}

ROOT_LOGIN = {
    "eventVersion": "1.09",
    "eventID": "88888888-8888-8888-8888-888888888888",
    "eventTime": "2026-07-05T08:00:00Z",
    "eventSource": "signin.amazonaws.com",
    "eventName": "ConsoleLogin",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "203.0.113.20",
    "recipientAccountId": "123456789012",
    "userIdentity": {
        "type": "Root",
        "principalId": "123456789012",
        "arn": "arn:aws:iam::123456789012:root",
        "accountId": "123456789012",
    },
    "responseElements": {"ConsoleLogin": "Success"},
    "additionalEventData": {"MFAUsed": "Yes"},
}

MFA_LESS_LOGIN = {
    **copy.deepcopy(ROOT_LOGIN),
    "eventID": "99999999-9999-9999-9999-999999999999",
    "userIdentity": {
        "type": "IAMUser",
        "userName": "bob",
        "accountId": "123456789012",
    },
    "additionalEventData": {"MFAUsed": "No"},
}

NORMAL_LOGIN = {
    **copy.deepcopy(MFA_LESS_LOGIN),
    "eventID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "additionalEventData": {"MFAUsed": "Yes"},
}

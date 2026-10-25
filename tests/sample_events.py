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

# User agents recorded in CloudTrail.
CHROME_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"
)
CURSOR_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Cursor/3.27.6 Chrome/148.0.7778.280 Electron/42.11.16 Safari/537.36"
)
AGENT_CLI_UA = (
    "aws-cli/2.38.5 md/awscrt#0.38.0 ua/2.1 os/macos#27.0.0 md/arch#arm64 "
    "lang/python#3.15.1 m/b,n,i cfg/retry-mode#standard app/cursor-agent "
    "md/installer#source md/prompt#off md/command#ec2.run-instances"
)

AGENT_API_MUTATION = {
    **copy.deepcopy(CLI_MUTATION),
    "eventID": "23232323-2323-2323-2323-232323232323",
    "userAgent": AGENT_CLI_UA,
}

BROWSER_MUTATION = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "24242424-2424-2424-2424-242424242424",
    "userAgent": CHROME_UA,
}

AGENT_BROWSER_MUTATION = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "25252525-2525-2525-2525-252525252525",
    "userAgent": CURSOR_UA,
}

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

CLOUDTRAIL_STOP = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StopLogging",
    "requestParameters": {
        "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail"
    },
}

SG_OPEN_SSH = {
    **copy.deepcopy(CONSOLE_MUTATION),
    "eventID": "cccccccc-cccc-cccc-cccc-cccccccccccc",
    "eventName": "AuthorizeSecurityGroupIngress",
    "requestParameters": {
        "groupId": "sg-0123456789abcdef0",
        "ipPermissions": {
            "items": [
                {
                    "ipProtocol": "tcp",
                    "fromPort": 22,
                    "toPort": 22,
                    "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                }
            ]
        },
    },
}

# Normalized ip_intel.lookup() output for the CONSOLE_MUTATION source IP.
IP_INFO = {
    "ip": "203.0.113.10",
    "city": "Paris",
    "region": "Ile-de-France",
    "country": "FR",
    "asn": "AS3215",
    "isp": "Orange S.A.",
    "flags": [],
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

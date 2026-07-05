# SPDX-License-Identifier: Apache-2.0
import sample_events

import identity


def test_sso_assumed_role_resolves_email_and_permission_set():
    who = identity.extract_identity(sample_events.CONSOLE_MUTATION)
    assert who["kind"] == "AssumedRole"
    assert "alice@example.com" in who["display"]
    assert "AdministratorAccess" in who["display"]
    assert who["actor_id"] == "alice@example.com"


def test_plain_assumed_role():
    record = {
        "userIdentity": {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/DeployRole/build-42",
        }
    }
    who = identity.extract_identity(record)
    assert who["display"] == "build-42 (assumed role DeployRole)"


def test_identity_center_user():
    who = identity.extract_identity(sample_events.IDENTITY_CENTER_EVENT)
    assert who["kind"] == "IdentityCenterUser"
    assert "9a8b7c6d-example" in who["display"]


def test_iam_user():
    who = identity.extract_identity(sample_events.MFA_LESS_LOGIN)
    assert who["display"] == "IAM user bob"
    assert who["actor_id"] == "bob"


def test_root():
    who = identity.extract_identity(sample_events.ROOT_LOGIN)
    assert who["display"] == "Root user"
    assert who["actor_id"] == "root"


def test_unknown_type_never_crashes():
    who = identity.extract_identity(sample_events.UNKNOWN_IDENTITY_EVENT)
    assert who["kind"] == "Unknown"
    assert "odd-principal-string" in who["display"]


def test_missing_user_identity():
    who = identity.extract_identity({})
    assert who["display"].startswith("Unknown identity")
    assert who["actor_id"] == "no_principal"

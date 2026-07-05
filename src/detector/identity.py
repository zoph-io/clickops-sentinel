# SPDX-License-Identifier: Apache-2.0
"""Extract a human-readable identity from a CloudTrail userIdentity element.

Handles the identity types emitted as of the July 2025 IAM Identity Center
CloudTrail changes (IdentityCenterUser with userId and identityStoreArn) as
well as AssumedRole, IAMUser, Root, and gracefully degrades on Unknown.
"""

import re

EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")


def _sanitize_actor_id(value: str) -> str:
    """Reduce an identifier to characters safe for memory namespaces."""
    return re.sub(r"[^A-Za-z0-9._@-]", "_", value)[:128] or "unknown"


def extract_identity(record: dict) -> dict:
    """Return {display, actor_id, kind} for a CloudTrail record.

    display is shown in notifications, actor_id keys memory namespaces and
    statistics, kind is the raw userIdentity type.
    """
    user_identity = record.get("userIdentity") or {}
    kind = user_identity.get("type") or "Unknown"

    if kind == "Root":
        return {"display": "Root user", "actor_id": "root", "kind": kind}

    if kind == "IAMUser":
        name = user_identity.get("userName", "unknown-iam-user")
        return {
            "display": f"IAM user {name}",
            "actor_id": _sanitize_actor_id(name),
            "kind": kind,
        }

    if kind == "AssumedRole":
        return _extract_assumed_role(user_identity, kind)

    if kind == "IdentityCenterUser":
        user_id = user_identity.get("userId", "unknown")
        return {
            "display": f"Identity Center user {user_id}",
            "actor_id": _sanitize_actor_id(user_id),
            "kind": kind,
        }

    if kind == "FederatedUser":
        arn = user_identity.get("arn", "")
        name = arn.rsplit("/", 1)[-1] if arn else "unknown"
        return {
            "display": f"Federated user {name}",
            "actor_id": _sanitize_actor_id(name),
            "kind": kind,
        }

    # Unknown or missing type: never crash, surface what we have
    # (cloudandthings issue 101).
    principal = (
        user_identity.get("principalId")
        or user_identity.get("arn")
        or "no principal"
    )
    return {
        "display": f"Unknown identity (principal: {principal})",
        "actor_id": _sanitize_actor_id(str(principal)),
        "kind": kind,
    }


def _extract_assumed_role(user_identity: dict, kind: str) -> dict:
    """AssumedRole ARNs look like arn:aws:sts::<acct>:assumed-role/<role>/<session>.

    The session name is often the human (an email for SSO federation), so it
    leads the display. Identity Center permission set roles start with
    AWSReservedSSO_ and are labeled as such.
    """
    arn = user_identity.get("arn", "")
    role_name = "unknown-role"
    session_name = ""
    match = re.search(r"assumed-role/([^/]+)/(.+)$", arn)
    if match:
        role_name, session_name = match.group(1), match.group(2)
    else:
        # Fall back to principalId, format <roleId>:<sessionName>.
        principal = user_identity.get("principalId", "")
        if ":" in principal:
            session_name = principal.split(":", 1)[1]

    email = EMAIL_RE.search(session_name or "")
    who = email.group(0) if email else session_name or "unknown-session"

    if role_name.startswith("AWSReservedSSO_"):
        # Strip the permission set random suffix for readability.
        permission_set = role_name.removeprefix("AWSReservedSSO_").rsplit("_", 1)[0]
        display = f"{who} (Identity Center, permission set {permission_set})"
    else:
        display = f"{who} (assumed role {role_name})"

    return {
        "display": display,
        "actor_id": _sanitize_actor_id(who),
        "kind": kind,
    }

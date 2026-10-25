# SPDX-License-Identifier: Apache-2.0
"""Criticality scale and catalog for console changes.

The catalog is a deterministic referential that rates the inherent risk of a
CloudTrail action on a five-level scale, before and independently of the AI
investigation. Each rule maps one or more "service:EventName" actions to a
level and a MITRE ATT&CK tactic, plus the ATT&CK technique and the Stratus
Red Team attack technique it corresponds to, when there is one. Some rules
inspect requestParameters and escalate: a security group opened to the
internet on SSH rates higher than one opened to a private range.

The resulting level is a floor. The agent may raise it from context, never
lower it, and uses its verdict to say whether a risky change looks
sanctioned. Without AI the rating still drives the plain alert.

Render the catalog for review with `make catalog-doc`
(docs/criticality-catalog.md).

This module is duplicated in src/detector and src/investigator because SAM
packages each CodeUri separately. Keep both copies identical.
"""

import json
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

logger = logging.getLogger()

LEVELS = ("none", "low", "medium", "high", "critical")
RANK = {level: index for index, level in enumerate(LEVELS)}

SCALE = {
    "critical": (
        "Disables audit logging or threat detection, changes the AWS Organization "
        "or its guardrails, grants administrator access or a cross-account "
        "backdoor, or exposes data publicly."
    ),
    "high": (
        "Creates credentials or privileges, weakens authentication, opens "
        "internet exposure, runs code or commands on existing resources, or "
        "destroys data without a recovery path."
    ),
    "medium": (
        "Changes a security control with limited blast radius: private-range "
        "firewall rules, encryption or key state, backups and retention, "
        "account-scoped resource policies."
    ),
    "low": "Ordinary resource change with no exposure or privilege change.",
    "none": "Cosmetic change only, such as tags or descriptions.",
}

RESPONSE = {
    "critical": "Act now: confirm with the actor and contain.",
    "high": "Review the same day.",
    "medium": "Review within the week.",
    "low": "Codify in IaC or revert during routine drift cleanup.",
    "none": "No action.",
}

TECHNIQUES = {
    "T1078.004": "Valid Accounts: Cloud Accounts",
    "T1098": "Account Manipulation",
    "T1098.001": "Account Manipulation: Additional Cloud Credentials",
    "T1098.003": "Account Manipulation: Additional Cloud Roles",
    "T1098.006": "Account Manipulation: Additional Container Cluster Roles",
    "T1136.003": "Create Account: Cloud Account",
    "T1484": "Domain or Tenant Policy Modification",
    "T1484.002": "Domain or Tenant Policy Modification: Trust Modification",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1496.001": "Resource Hijacking: Compute Hijacking",
    "T1496.004": "Resource Hijacking: Cloud Service Hijacking",
    "T1530": "Data from Cloud Storage",
    "T1531": "Account Access Removal",
    "T1535": "Unused/Unsupported Cloud Regions",
    "T1537": "Transfer Data to Cloud Account",
    "T1550.004": "Use Alternate Authentication Material: Web Session Cookie",
    "T1552.005": "Unsecured Credentials: Cloud Instance Metadata API",
    "T1556.006": "Modify Authentication Process: Multi-Factor Authentication",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1562.007": "Impair Defenses: Disable or Modify Cloud Firewall",
    "T1562.008": "Impair Defenses: Disable or Modify Cloud Logs",
    "T1648": "Serverless Execution",
    "T1651": "Cloud Administration Command",
    "T1666": "Modify Cloud Resource Hierarchy",
}

STRATUS_URL = "https://stratus-red-team.cloud/attack-techniques/AWS/"

WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
# Remote administration, file sharing, databases, caches, and container APIs.
SENSITIVE_PORTS = (
    20, 21, 22, 23, 445, 1433, 1521, 2375, 2376, 3306, 3389,
    5432, 5900, 6379, 9200, 11211, 27017,
)
WEB_PORTS = frozenset({80, 443})
ICMP_PROTOCOLS = frozenset({"icmp", "icmpv6", "1", "58"})
ADMIN_POLICY_SUFFIXES = ("/AdministratorAccess", "/IAMFullAccess")
GPU_FAMILY_RE = re.compile(r"^(p\d|g\d|trn\d|inf\d|dl\d)", re.IGNORECASE)
MASS_LAUNCH_COUNT = 10
ACCOUNT_RE = re.compile(r"^(\d{12})$|^arn:aws[\w-]*:(?:iam|sts)::(\d{12}):")
# Lambda and CloudFront version their event names, e.g. UpdateFunctionCode20150331v2.
EVENT_VERSION_RE = re.compile(r"(\d{8}(v\d+)?|\d{4}_\d{2}_\d{2})$")
POLICY_KEYS = (
    "policyDocument",
    "assumeRolePolicyDocument",
    "bucketPolicy",
    "policy",
    "resourcePolicy",
    "policyText",
    "inlinePolicy",
)


class Finding(NamedTuple):
    level: str
    reason: str
    techniques: tuple = ()


@dataclass(frozen=True)
class Rule:
    rule_id: str
    level: str
    tactic: str
    title: str
    actions: tuple
    techniques: tuple = ()
    stratus: tuple = ()
    escalate: Callable[[dict], Finding | None] | None = None


# ---------------------------------------------------------------------------
# Parameter helpers. CloudTrail wraps lists as {"items": [...]} and embeds
# policies either as objects or as JSON strings.
# ---------------------------------------------------------------------------


def _params(record: dict) -> dict:
    params = record.get("requestParameters")
    return params if isinstance(params, dict) else {}


def _items(value) -> list:
    if isinstance(value, dict):
        value = value.get("items", [])
    return value if isinstance(value, list) else []


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _is_false(value) -> bool:
    return value is False or str(value).lower() == "false"


def _is_true(value) -> bool:
    return value is True or str(value).lower() == "true"


def _port(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_json(document):
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        try:
            parsed = json.loads(document)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _statements(document) -> list:
    parsed = _as_json(document) or {}
    return [st for st in _as_list(parsed.get("Statement")) if isinstance(st, dict)]


def _aws_principals(principal) -> list:
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        return [str(value) for value in _as_list(principal.get("AWS"))]
    return []


def _account_of(principal: str) -> str:
    match = ACCOUNT_RE.match(str(principal or ""))
    return (match.group(1) or match.group(2)) if match else ""


def _worse(current: Finding | None, candidate: Finding | None) -> Finding | None:
    if candidate is None:
        return current
    if current is None or RANK[candidate.level] > RANK[current.level]:
        return candidate
    return current


def _find_policy(params: dict):
    for key in POLICY_KEYS:
        if params.get(key):
            return params[key]
    if str(params.get("attributeName", "")) == "Policy":
        return params.get("attributeValue")
    attributes = params.get("attributes")
    if isinstance(attributes, dict):
        return attributes.get("Policy")
    return None


def _policy_exposure(record: dict, external_level: str) -> Finding | None:
    own_account = str(record.get("recipientAccountId", ""))
    worst = None
    for statement in _statements(_find_policy(_params(record))):
        if statement.get("Effect") != "Allow":
            continue
        principals = _aws_principals(statement.get("Principal"))
        if "*" in principals:
            if statement.get("Condition"):
                worst = _worse(
                    worst, Finding("medium", "policy allows any principal, scoped by conditions")
                )
            else:
                return Finding("critical", "policy allows any principal")
        external = sorted(
            {_account_of(p) for p in principals} - {"", own_account}
        )
        if external:
            worst = _worse(
                worst, Finding(external_level, f"policy grants access to account {external[0]}")
            )
    return worst


def _grants_admin(document) -> bool:
    for statement in _statements(document):
        if statement.get("Effect") != "Allow":
            continue
        actions = _as_list(statement.get("Action"))
        if ("*" in actions or "iam:*" in actions) and "*" in _as_list(statement.get("Resource")):
            return True
    return False


def _walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _ingress_rules(params: dict) -> list:
    """Normalize ingress rules to (protocol, from_port, to_port, cidrs)."""
    rules = []
    for permission in _items(params.get("ipPermissions")):
        cidrs = {r.get("cidrIp") for r in _items(permission.get("ipRanges"))}
        cidrs |= {r.get("cidrIpv6") for r in _items(permission.get("ipv6Ranges"))}
        rules.append(
            (
                str(permission.get("ipProtocol", "")).lower(),
                _port(permission.get("fromPort")),
                _port(permission.get("toPort")),
                cidrs,
            )
        )
    # ModifySecurityGroupRules nests rules with capitalized keys.
    for node in _walk_dicts(params):
        if "CidrIpv4" in node or "CidrIpv6" in node:
            rules.append(
                (
                    str(node.get("IpProtocol", "")).lower(),
                    _port(node.get("FromPort")),
                    _port(node.get("ToPort")),
                    {node.get("CidrIpv4"), node.get("CidrIpv6")},
                )
            )
    return rules


# ---------------------------------------------------------------------------
# Escalation checks. The first docstring line is published in the catalog
# document, keep it a plain-language sentence.
# ---------------------------------------------------------------------------


def _world_open_ingress(record: dict) -> Finding | None:
    """Open to 0.0.0.0/0 or ::/0: critical on all ports or admin and database ports, high on other ports except a single 80 or 443."""  # noqa: E501
    worst = None
    for protocol, low, high, cidrs in _ingress_rules(_params(record)):
        world = sorted(c for c in cidrs if c in WORLD_CIDRS)
        if not world or protocol in ICMP_PROTOCOLS:
            continue
        if protocol == "-1" or low is None or high is None or low < 0:
            finding = Finding("critical", f"all ports open to {world[0]}")
        else:
            exposed = [p for p in SENSITIVE_PORTS if low <= p <= high]
            span = f"port {low}" if low == high else f"ports {low}-{high}"
            if exposed:
                including = "" if low == high else f", including {exposed[0]}"
                finding = Finding("critical", f"{span} open to {world[0]}{including}")
            elif low == high and low in WEB_PORTS:
                continue
            else:
                finding = Finding("high", f"{span} open to {world[0]}")
        worst = _worse(worst, finding)
    return worst


def _ec2_share(record: dict) -> Finding | None:
    """Shared with every AWS account (group all): critical. Shared with specific accounts: high."""
    params = _params(record)
    container = params.get("createVolumePermission") or params.get("launchPermission") or {}
    added = _items(container.get("add") if isinstance(container, dict) else None)
    if any(str(item.get("group", "")).lower() == "all" for item in added):
        return Finding("critical", "made public to every AWS account")
    accounts = [str(item["userId"]) for item in added if item.get("userId")]
    if accounts:
        return Finding("high", f"shared with account {accounts[0]}")
    return None


def _rds_share(record: dict) -> Finding | None:
    """Restore permission added for all accounts: critical. For specific accounts: high."""
    params = _params(record)
    if str(params.get("attributeName", "")).lower() != "restore":
        return None
    values = [str(value) for value in _items(params.get("valuesToAdd"))]
    if any(value.lower() == "all" for value in values):
        return Finding("critical", "snapshot made public to every AWS account")
    if values:
        return Finding("high", f"snapshot shared with account {values[0]}")
    return None


def _resource_policy_exposure(record: dict) -> Finding | None:
    """Policy allows any principal without conditions: critical. Grants another account: high."""
    return _policy_exposure(record, external_level="high")


def _trust_policy_exposure(record: dict) -> Finding | None:
    """Trust allows any principal, or another account (cross-account backdoor): critical."""
    return _policy_exposure(record, external_level="critical")


def _new_role_exposure(record: dict) -> Finding | None:
    """Trust allows any principal: critical. Trusts another account: high."""
    return _policy_exposure(record, external_level="high")


def _admin_grant(record: dict) -> Finding | None:
    """AdministratorAccess, IAMFullAccess, or an inline policy allowing all actions on all resources: critical."""  # noqa: E501
    params = _params(record)
    arn = str(params.get("policyArn") or params.get("managedPolicyArn") or "")
    if arn.endswith(ADMIN_POLICY_SUFFIXES):
        return Finding("critical", f"{arn.rsplit('/', 1)[-1]} granted")
    document = params.get("policyDocument") or params.get("inlinePolicy")
    if document and _grants_admin(document):
        return Finding("critical", "policy allows all actions on all resources")
    return None


def _s3_acl_public(record: dict) -> Finding | None:
    """Bucket policy open to any principal, or an ACL granting AllUsers or AuthenticatedUsers: critical. Policy granting another account: high."""  # noqa: E501
    text = json.dumps(_params(record), default=str)
    markers = ("groups/global/AllUsers", "groups/global/AuthenticatedUsers")
    if any(marker in text for marker in markers) or re.search(
        r"(public-read|authenticated-read)", text
    ):
        return Finding("critical", "bucket ACL grants public access")
    return _policy_exposure(record, external_level="high")


def _public_access_block_off(record: dict) -> Finding | None:
    """Any of the four Block Public Access settings turned off: high."""
    config = _params(record).get("PublicAccessBlockConfiguration") or {}
    if not isinstance(config, dict):
        return None
    keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
    disabled = [key for key in keys if key in config and _is_false(config[key])]
    if disabled:
        return Finding("high", f"{disabled[0]} turned off", ("T1530",))
    return None


def _versioning_suspended(record: dict) -> Finding | None:
    """Versioning suspended: high, overwritten or deleted objects lose their recovery path."""
    if "Suspended" in json.dumps(_params(record), default=str):
        return Finding("high", "bucket versioning suspended", ("T1490",))
    return None


def _guardduty_disabled(record: dict) -> Finding | None:
    """Detector set to disabled (enable false): critical."""
    if _is_false(_params(record).get("enable", True)):
        return Finding("critical", "GuardDuty detector disabled")
    return None


def _trail_selectors(record: dict) -> Finding | None:
    """Event selectors that drop management events or keep only read events: critical."""
    for selector in _items(_params(record).get("eventSelectors")):
        if _is_false(selector.get("includeManagementEvents", True)):
            return Finding("critical", "management events excluded from the trail")
        if str(selector.get("readWriteType", "")) == "ReadOnly":
            return Finding("critical", "write events excluded from the trail")
    return None


def _imds_v1(record: dict) -> Finding | None:
    """IMDSv1 re-enabled (HttpTokens optional): high."""
    params = _params(record)
    tokens = str(params.get("httpTokens") or params.get("HttpTokens") or "")
    if tokens.lower() == "optional":
        return Finding("high", "IMDSv1 re-enabled (HttpTokens optional)", ("T1552.005",))
    return None


def _user_data(record: dict) -> Finding | None:
    """User data replaced: high, it runs as root on the next boot."""
    if "userData" in _params(record):
        return Finding("high", "instance user data replaced")
    return None


def _instance_launch(record: dict) -> Finding | None:
    """GPU or accelerator instance types, or 10 or more instances in one call: high (compute hijacking pattern)."""  # noqa: E501
    params = _params(record)
    items = _items(params.get("instancesSet")) or [params]
    for item in items:
        instance_type = str(item.get("instanceType") or params.get("instanceType") or "")
        if GPU_FAMILY_RE.match(instance_type):
            return Finding(
                "high", f"GPU instance type {instance_type}, a cryptomining target", ("T1496.001",)
            )
        count = max(_port(item.get("maxCount")) or 0, _port(item.get("minCount")) or 0)
        if count >= MASS_LAUNCH_COUNT:
            return Finding("high", f"{count} instances in one call", ("T1496.001",))
    return None


def _lambda_exposure(record: dict) -> Finding | None:
    """Any principal without a source condition: critical. Another account, or a function URL with auth type NONE: high."""  # noqa: E501
    params = _params(record)
    principal = str(params.get("principal", ""))
    scoped = any(params.get(key) for key in ("sourceArn", "sourceAccount", "principalOrgID"))
    if principal == "*" and not scoped:
        return Finding("critical", "function invocable by any principal")
    if str(params.get("authType", "")).upper() == "NONE":
        return Finding("high", "function URL allows unauthenticated calls")
    account = _account_of(principal)
    if account and account != str(record.get("recipientAccountId", "")):
        return Finding("high", f"function invocable by account {account}")
    return None


def _rds_modify(record: dict) -> Finding | None:
    """Made public or master password reset: high. Deletion protection disabled: medium."""
    params = _params(record)
    if _is_true(params.get("publiclyAccessible")):
        return Finding("high", "database made publicly accessible", ("T1530",))
    if "masterUserPassword" in params:
        return Finding("high", "master user password reset", ("T1098",))
    if _is_false(params.get("deletionProtection", True)):
        return Finding("medium", "deletion protection disabled", ("T1490",))
    return None


def _skip_final_snapshot(record: dict) -> Finding | None:
    """Database deleted without a final snapshot: high."""
    if _is_true(_params(record).get("skipFinalSnapshot")):
        return Finding("high", "deleted without a final snapshot")
    return None


def _pitr_disabled(record: dict) -> Finding | None:
    """Point-in-time recovery turned off: medium."""
    spec = _params(record).get("pointInTimeRecoverySpecification") or {}
    if isinstance(spec, dict) and _is_false(spec.get("pointInTimeRecoveryEnabled", True)):
        return Finding("medium", "point-in-time recovery disabled")
    return None


def _ssm_document_public(record: dict) -> Finding | None:
    """Document shared with all accounts: high."""
    accounts = [str(value).lower() for value in _items(_params(record).get("accountIdsToAdd"))]
    if "all" in accounts:
        return Finding("high", "document shared publicly")
    return None


# ---------------------------------------------------------------------------
# The catalog. Rule IDs are stable references: never renumber, retire IDs
# instead of reusing them.
# ---------------------------------------------------------------------------

RULES = (
    # AWS Organizations and account governance.
    Rule(
        "ORG-001", "critical", "Defense Evasion",
        "Account removed from the AWS Organization or organization deleted",
        ("organizations:LeaveOrganization", "organizations:RemoveAccountFromOrganization",
         "organizations:DeleteOrganization"),
        ("T1666",), ("aws.defense-evasion.organizations-leave",),
    ),
    Rule(
        "ORG-002", "critical", "Defense Evasion",
        "Organization guardrail policy detached, deleted, or disabled",
        ("organizations:DetachPolicy", "organizations:DeletePolicy",
         "organizations:DisablePolicyType"),
        ("T1484",),
    ),
    Rule(
        "ORG-003", "high", "Defense Evasion",
        "Organization policy created, changed, or attached",
        ("organizations:CreatePolicy", "organizations:UpdatePolicy",
         "organizations:AttachPolicy", "organizations:EnablePolicyType"),
        ("T1484",),
    ),
    Rule(
        "ORG-004", "high", "Persistence",
        "Account created, invited, or moved in the organization",
        ("organizations:CreateAccount", "organizations:CreateGovCloudAccount",
         "organizations:InviteAccountToOrganization", "organizations:AcceptHandshake",
         "organizations:MoveAccount"),
        ("T1666",),
    ),
    Rule(
        "ORG-005", "high", "Defense Evasion",
        "Delegated administrator or trusted service access changed",
        ("organizations:RegisterDelegatedAdministrator",
         "organizations:DeregisterDelegatedAdministrator",
         "organizations:EnableAWSServiceAccess", "organizations:DisableAWSServiceAccess"),
        ("T1484",),
    ),
    Rule(
        "ORG-006", "high", "Persistence",
        "Centralized root access settings changed",
        ("iam:EnableOrganizationsRootCredentialsManagement",
         "iam:DisableOrganizationsRootCredentialsManagement",
         "iam:EnableOrganizationsRootSessions", "iam:DisableOrganizationsRootSessions"),
    ),
    Rule(
        "ORG-007", "medium", "Defense Evasion",
        "Account security or billing contacts changed",
        ("account:PutAlternateContact", "account:DeleteAlternateContact",
         "account:PutContactInformation"),
    ),
    Rule(
        "ORG-008", "medium", "Defense Evasion",
        "Opt-in region enabled",
        ("account:EnableRegion",),
        ("T1535",),
    ),
    # IAM identities, credentials, and permissions.
    Rule(
        "IAM-001", "high", "Persistence",
        "IAM user created",
        ("iam:CreateUser",),
        ("T1136.003",), ("aws.persistence.iam-create-admin-user",),
    ),
    Rule(
        "IAM-002", "high", "Persistence",
        "Long-term credentials created for an IAM user",
        ("iam:CreateAccessKey", "iam:CreateServiceSpecificCredential",
         "iam:UploadSSHPublicKey", "iam:UploadSigningCertificate"),
        ("T1098.001",), ("aws.persistence.iam-backdoor-user",),
    ),
    Rule(
        "IAM-003", "high", "Persistence",
        "Console password created or changed for an IAM user",
        ("iam:CreateLoginProfile", "iam:UpdateLoginProfile"),
        ("T1098.001",),
        ("aws.persistence.iam-create-user-login-profile",
         "aws.privilege-escalation.iam-update-user-login-profile"),
    ),
    Rule(
        "IAM-004", "high", "Privilege Escalation",
        "Permissions policy attached, written, or versioned",
        ("iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy",
         "iam:PutUserPolicy", "iam:PutRolePolicy", "iam:PutGroupPolicy",
         "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"),
        ("T1098.003",), (), _admin_grant,
    ),
    Rule(
        "IAM-005", "high", "Privilege Escalation",
        "User added to an IAM group",
        ("iam:AddUserToGroup",),
        ("T1098.003",),
    ),
    Rule(
        "IAM-006", "high", "Persistence",
        "Role trust policy changed",
        ("iam:UpdateAssumeRolePolicy",),
        ("T1098",), ("aws.persistence.iam-backdoor-role",), _trust_policy_exposure,
    ),
    Rule(
        "IAM-007", "medium", "Persistence",
        "IAM role created",
        ("iam:CreateRole",),
        ("T1098.003",), ("aws.persistence.iam-create-backdoor-role",), _new_role_exposure,
    ),
    Rule(
        "IAM-008", "high", "Defense Evasion",
        "MFA device deactivated or deleted",
        ("iam:DeactivateMFADevice", "iam:DeleteVirtualMFADevice"),
        ("T1556.006",),
    ),
    Rule(
        "IAM-009", "critical", "Persistence",
        "SAML identity provider created or changed",
        ("iam:CreateSAMLProvider", "iam:UpdateSAMLProvider"),
        ("T1484.002",),
    ),
    Rule(
        "IAM-010", "high", "Persistence",
        "OIDC identity provider created or changed",
        ("iam:CreateOpenIDConnectProvider", "iam:AddClientIDToOpenIDConnectProvider",
         "iam:UpdateOpenIDConnectProviderThumbprint"),
        ("T1484.002",),
    ),
    Rule(
        "IAM-011", "high", "Privilege Escalation",
        "Permissions boundary removed",
        ("iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary"),
    ),
    Rule(
        "IAM-012", "medium", "Defense Evasion",
        "Account password policy changed or deleted",
        ("iam:UpdateAccountPasswordPolicy", "iam:DeleteAccountPasswordPolicy"),
    ),
    Rule(
        "IAM-013", "medium", "Impact",
        "IAM user or console access removed",
        ("iam:DeleteUser", "iam:DeleteLoginProfile"),
        ("T1531",),
    ),
    Rule(
        "IAM-014", "high", "Persistence",
        "IAM Roles Anywhere trust anchor created or changed",
        ("rolesanywhere:CreateTrustAnchor", "rolesanywhere:UpdateTrustAnchor"),
        ("T1098",), ("aws.persistence.rolesanywhere-create-trust-anchor",),
    ),
    # IAM Identity Center.
    Rule(
        "IDC-001", "high", "Privilege Escalation",
        "Identity Center permission set or account assignment changed",
        ("sso:CreateAccountAssignment", "sso:CreatePermissionSet", "sso:UpdatePermissionSet",
         "sso:AttachManagedPolicyToPermissionSet", "sso:PutInlinePolicyToPermissionSet",
         "sso:AttachCustomerManagedPolicyReferenceToPermissionSet"),
        ("T1098.003",), (), _admin_grant,
    ),
    Rule(
        "IDC-002", "high", "Persistence",
        "Identity Center user created or added to a group",
        ("identitystore:CreateUser", "identitystore:CreateGroupMembership",
         "sso-directory:CreateUser", "sso-directory:AddMemberToGroup"),
        ("T1136.003",),
    ),
    # Audit logging.
    Rule(
        "LOG-001", "critical", "Defense Evasion",
        "CloudTrail logging stopped or trail deleted",
        ("cloudtrail:StopLogging", "cloudtrail:DeleteTrail"),
        ("T1562.008",),
        ("aws.defense-evasion.cloudtrail-stop", "aws.defense-evasion.cloudtrail-delete"),
    ),
    Rule(
        "LOG-002", "high", "Defense Evasion",
        "CloudTrail trail or event selectors changed",
        ("cloudtrail:UpdateTrail", "cloudtrail:PutEventSelectors"),
        ("T1562.008",), ("aws.defense-evasion.cloudtrail-event-selectors",), _trail_selectors,
    ),
    Rule(
        "LOG-003", "critical", "Defense Evasion",
        "CloudTrail Lake event data store stopped or deleted",
        ("cloudtrail:StopEventDataStoreIngestion", "cloudtrail:DeleteEventDataStore"),
        ("T1562.008",),
    ),
    Rule(
        "LOG-004", "critical", "Defense Evasion",
        "AWS Config recording stopped or deleted",
        ("config:StopConfigurationRecorder", "config:DeleteConfigurationRecorder",
         "config:DeleteDeliveryChannel"),
        ("T1562.008",),
    ),
    Rule(
        "LOG-005", "high", "Defense Evasion",
        "VPC flow logs deleted",
        ("ec2:DeleteFlowLogs",),
        ("T1562.008",), ("aws.defense-evasion.vpc-remove-flow-logs",),
    ),
    Rule(
        "LOG-006", "high", "Defense Evasion",
        "DNS query logging removed",
        ("route53resolver:DeleteResolverQueryLogConfig",
         "route53resolver:DisassociateResolverQueryLogConfig",
         "route53:DeleteQueryLoggingConfig"),
        ("T1562.008",), ("aws.defense-evasion.dns-delete-logs",),
    ),
    Rule(
        "LOG-007", "high", "Defense Evasion",
        "CloudWatch log group, stream, or subscription deleted",
        ("logs:DeleteLogGroup", "logs:DeleteLogStream", "logs:DeleteSubscriptionFilter"),
        ("T1562.008",),
    ),
    Rule(
        "LOG-008", "medium", "Defense Evasion",
        "Log retention or S3 access logging changed",
        ("logs:PutRetentionPolicy", "s3:PutBucketLogging"),
        ("T1562.008",),
    ),
    Rule(
        "LOG-009", "high", "Defense Evasion",
        "Bedrock model invocation logging deleted",
        ("bedrock:DeleteModelInvocationLoggingConfiguration",),
        ("T1562.008",),
    ),
    Rule(
        "LOG-010", "medium", "Defense Evasion",
        "CloudWatch alarms deleted or alarm actions disabled",
        ("monitoring:DeleteAlarms", "monitoring:DisableAlarmActions"),
    ),
    # Threat detection and posture services.
    Rule(
        "DET-001", "critical", "Defense Evasion",
        "GuardDuty detector deleted or disconnected from its administrator",
        ("guardduty:DeleteDetector", "guardduty:DisassociateFromMasterAccount",
         "guardduty:DisassociateFromAdministratorAccount", "guardduty:StopMonitoringMembers",
         "guardduty:DeleteMembers", "guardduty:DisassociateMembers"),
        ("T1562.001",),
    ),
    Rule(
        "DET-002", "medium", "Defense Evasion",
        "GuardDuty detector settings changed",
        ("guardduty:UpdateDetector",),
        ("T1562.001",), (), _guardduty_disabled,
    ),
    Rule(
        "DET-003", "high", "Defense Evasion",
        "GuardDuty findings filtered, trusted IPs added, or export removed",
        ("guardduty:CreateFilter", "guardduty:UpdateFilter", "guardduty:CreateIPSet",
         "guardduty:UpdateIPSet", "guardduty:DeletePublishingDestination"),
        ("T1562.001",),
    ),
    Rule(
        "DET-004", "critical", "Defense Evasion",
        "Security Hub disabled or disconnected from its administrator",
        ("securityhub:DisableSecurityHub", "securityhub:DisassociateFromAdministratorAccount",
         "securityhub:DisassociateFromMasterAccount"),
        ("T1562.001",),
    ),
    Rule(
        "DET-005", "high", "Defense Evasion",
        "Security Hub standards, controls, or integrations disabled",
        ("securityhub:BatchDisableStandards", "securityhub:UpdateStandardsControl",
         "securityhub:DisableImportFindingsForProduct"),
        ("T1562.001",),
    ),
    Rule(
        "DET-006", "high", "Defense Evasion",
        "Security service disabled or detection rule deleted",
        ("access-analyzer:DeleteAnalyzer", "macie2:DisableMacie", "inspector2:Disable",
         "detective:DeleteGraph", "config:DeleteConfigRule", "config:DeleteConformancePack"),
        ("T1562.001",),
    ),
    Rule(
        "DET-007", "medium", "Defense Evasion",
        "Automatic suppression or archive rule for findings created",
        ("securityhub:CreateAutomationRule", "access-analyzer:CreateArchiveRule"),
        ("T1562.001",),
    ),
    # Network exposure.
    Rule(
        "NET-001", "medium", "Defense Evasion",
        "Security group ingress rule added or changed",
        ("ec2:AuthorizeSecurityGroupIngress", "ec2:ModifySecurityGroupRules"),
        ("T1562.007",), ("aws.exfiltration.ec2-security-group-open-port-22-ingress",),
        _world_open_ingress,
    ),
    Rule(
        "NET-002", "medium", "Lateral Movement",
        "VPC peering connection created or accepted",
        ("ec2:CreateVpcPeeringConnection", "ec2:AcceptVpcPeeringConnection"),
    ),
    Rule(
        "NET-003", "high", "Persistence",
        "EC2 serial console access enabled",
        ("ec2:EnableSerialConsoleAccess",),
    ),
    Rule(
        "NET-004", "medium", "Defense Evasion",
        "Web application firewall ACL deleted or detached",
        ("wafv2:DeleteWebACL", "wafv2:DisassociateWebACL"),
        ("T1562.007",),
    ),
    # Data exposure, exfiltration, and destruction.
    Rule(
        "DATA-001", "high", "Collection",
        "S3 Block Public Access removed",
        ("s3:DeleteBucketPublicAccessBlock", "s3:DeleteAccountPublicAccessBlock"),
        ("T1530",),
    ),
    Rule(
        "DATA-002", "low", "Collection",
        "S3 Block Public Access settings changed",
        ("s3:PutBucketPublicAccessBlock", "s3:PutAccountPublicAccessBlock"),
        (), (), _public_access_block_off,
    ),
    Rule(
        "DATA-003", "medium", "Collection",
        "S3 bucket policy or ACL changed",
        ("s3:PutBucketPolicy", "s3:PutBucketAcl"),
        ("T1530",), ("aws.exfiltration.s3-backdoor-bucket-policy",), _s3_acl_public,
    ),
    Rule(
        "DATA-004", "medium", "Exfiltration",
        "EBS snapshot or AMI permissions changed",
        ("ec2:ModifySnapshotAttribute", "ec2:ModifyImageAttribute"),
        ("T1537",), ("aws.exfiltration.ec2-share-ebs-snapshot", "aws.exfiltration.ec2-share-ami"),
        _ec2_share,
    ),
    Rule(
        "DATA-005", "medium", "Exfiltration",
        "RDS snapshot permissions changed",
        ("rds:ModifyDBSnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute"),
        ("T1537",), ("aws.exfiltration.rds-share-snapshot",), _rds_share,
    ),
    Rule(
        "DATA-006", "high", "Exfiltration",
        "S3 replication configured",
        ("s3:PutBucketReplication",),
        ("T1537",),
    ),
    Rule(
        "DATA-007", "high", "Impact",
        "Backup vault, plan, or vault lock deleted",
        ("backup:DeleteBackupVault", "backup:DeleteBackupPlan",
         "backup:DeleteBackupVaultLockConfiguration"),
        ("T1490",),
    ),
    Rule(
        "DATA-008", "medium", "Impact",
        "Snapshot, backup, or recovery point deleted",
        ("ec2:DeleteSnapshot", "rds:DeleteDBSnapshot", "rds:DeleteDBClusterSnapshot",
         "dynamodb:DeleteBackup", "backup:DeleteRecoveryPoint"),
        ("T1490",),
    ),
    Rule(
        "DATA-009", "low", "Impact",
        "S3 bucket versioning changed",
        ("s3:PutBucketVersioning",),
        (), (), _versioning_suspended,
    ),
    Rule(
        "DATA-010", "medium", "Impact",
        "S3 lifecycle rule changed",
        ("s3:PutBucketLifecycle", "s3:PutBucketLifecycleConfiguration"),
        ("T1485",), ("aws.defense-evasion.cloudtrail-lifecycle-rule",),
    ),
    Rule(
        "DATA-011", "medium", "Impact",
        "Bucket, table, or database deleted",
        ("s3:DeleteBucket", "dynamodb:DeleteTable", "rds:DeleteDBInstance",
         "rds:DeleteDBCluster"),
        ("T1485",), (), _skip_final_snapshot,
    ),
    Rule(
        "DATA-012", "low", "Impact",
        "DynamoDB continuous backups changed",
        ("dynamodb:UpdateContinuousBackups",),
        ("T1490",), (), _pitr_disabled,
    ),
    Rule(
        "DATA-013", "low", "Collection",
        "RDS instance or cluster modified",
        ("rds:ModifyDBInstance", "rds:ModifyDBCluster"),
        (), (), _rds_modify,
    ),
    Rule(
        "DATA-014", "medium", "Collection",
        "Secrets Manager resource policy changed",
        ("secretsmanager:PutResourcePolicy",),
        ("T1530",), (), _resource_policy_exposure,
    ),
    Rule(
        "DATA-015", "low", "Collection",
        "Resource policy changed on a repository, topic, queue, or backup vault",
        ("ecr:SetRepositoryPolicy", "sns:SetTopicAttributes", "sqs:SetQueueAttributes",
         "backup:PutBackupVaultAccessPolicy"),
        (), (), _resource_policy_exposure,
    ),
    # Encryption keys.
    Rule(
        "KMS-001", "critical", "Impact",
        "KMS key scheduled for deletion",
        ("kms:ScheduleKeyDeletion",),
        ("T1485",),
    ),
    Rule(
        "KMS-002", "high", "Impact",
        "KMS key disabled or key policy changed",
        ("kms:DisableKey", "kms:PutKeyPolicy"),
        ("T1486",), (), _resource_policy_exposure,
    ),
    Rule(
        "KMS-003", "medium", "Impact",
        "KMS grant created, rotation disabled, or key material imported",
        ("kms:CreateGrant", "kms:DisableKeyRotation", "kms:ImportKeyMaterial"),
    ),
    Rule(
        "KMS-004", "medium", "Defense Evasion",
        "EBS encryption by default disabled",
        ("ec2:DisableEbsEncryptionByDefault",),
    ),
    # Compute and code execution.
    Rule(
        "CMP-001", "high", "Execution",
        "Command run on instances through Systems Manager",
        ("ssm:SendCommand",),
        ("T1651",), ("aws.execution.ssm-send-command",),
    ),
    Rule(
        "CMP-002", "medium", "Execution",
        "Session Manager session started",
        ("ssm:StartSession",),
        ("T1651",), ("aws.execution.ssm-start-session",),
    ),
    Rule(
        "CMP-003", "low", "Execution",
        "EC2 instance attribute modified",
        ("ec2:ModifyInstanceAttribute",),
        (), ("aws.execution.ec2-user-data",), _user_data,
    ),
    Rule(
        "CMP-004", "low", "Credential Access",
        "Instance metadata options changed",
        ("ec2:ModifyInstanceMetadataOptions", "ec2:ModifyInstanceMetadataDefaults"),
        (), (), _imds_v1,
    ),
    Rule(
        "CMP-005", "low", "Execution",
        "EC2 instances launched",
        ("ec2:RunInstances",),
        (), ("aws.execution.ec2-launch-unusual-instances",), _instance_launch,
    ),
    Rule(
        "CMP-006", "high", "Persistence",
        "Lambda function code replaced",
        ("lambda:UpdateFunctionCode",),
        (), ("aws.persistence.lambda-overwrite-code",),
    ),
    Rule(
        "CMP-007", "medium", "Persistence",
        "Lambda function permission or function URL changed",
        ("lambda:AddPermission", "lambda:CreateFunctionUrlConfig",
         "lambda:UpdateFunctionUrlConfig"),
        (), ("aws.persistence.lambda-backdoor-function",), _lambda_exposure,
    ),
    Rule(
        "CMP-008", "low", "Persistence",
        "Lambda configuration changed or layer published",
        ("lambda:UpdateFunctionConfiguration", "lambda:PublishLayerVersion"),
        (), ("aws.persistence.lambda-layer-extension",),
    ),
    Rule(
        "CMP-009", "low", "Execution",
        "Lambda function created",
        ("lambda:CreateFunction",),
        ("T1648",),
    ),
    Rule(
        "CMP-010", "medium", "Persistence",
        "EC2 key pair created or imported",
        ("ec2:CreateKeyPair", "ec2:ImportKeyPair"),
    ),
    Rule(
        "CMP-011", "high", "Privilege Escalation",
        "EKS cluster access granted",
        ("eks:CreateAccessEntry", "eks:AssociateAccessPolicy"),
        ("T1098.006",),
    ),
    Rule(
        "CMP-012", "medium", "Persistence",
        "Systems Manager document sharing changed",
        ("ssm:ModifyDocumentPermission",),
        (), (), _ssm_document_public,
    ),
    # Resource and service abuse.
    Rule(
        "ABU-001", "medium", "Impact",
        "Bedrock model access enabled",
        ("bedrock:PutUseCaseForModelAccess", "bedrock:CreateFoundationModelAgreement",
         "bedrock:PutFoundationModelEntitlement"),
        ("T1496.004",),
    ),
    Rule(
        "ABU-002", "medium", "Impact",
        "SES sending enabled or production access requested",
        ("ses:PutAccountDetails", "ses:UpdateAccountSendingEnabled",
         "ses:PutAccountSendingAttributes"),
        ("T1496.004",),
    ),
    Rule(
        "ABU-003", "medium", "Impact",
        "Service quota increase requested",
        ("servicequotas:RequestServiceQuotaIncrease",),
        ("T1496.001",),
    ),
)

ROOT_RULE = Rule(
    "ROOT-001", "high", "Privilege Escalation",
    "Change made by the root user",
    (),
    ("T1078.004",),
)

SELF_RULE = Rule(
    "SELF-001", "high", "Defense Evasion",
    "Change to ClickOps Sentinel's own resources",
    (),
    ("T1562.001",),
)

SESSION_RULE = Rule(
    "SES-001", "high", "Lateral Movement",
    "Session switched client or country mid-session",
    (),
    ("T1550.004",),
)

MODIFIER_RULES = (ROOT_RULE, SELF_RULE, SESSION_RULE)

_INDEX: dict = {}
for _rule in RULES:
    for _action in _rule.actions:
        _INDEX.setdefault(_action, _rule)


def normalize_event_name(event_name: str) -> str:
    return EVENT_VERSION_RE.sub("", str(event_name or ""))


def action_key(record: dict) -> str:
    """service:EventName, the same format as the suppression list."""
    service = str(record.get("eventSource") or "").removesuffix(".amazonaws.com")
    return f"{service}:{normalize_event_name(record.get('eventName', ''))}"


def parse_overrides(csv: str) -> dict:
    """Parse "service:Action=level" pairs. Invalid entries are logged and skipped."""
    overrides = {}
    for entry in (csv or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        action, _, level = entry.partition("=")
        action, level = action.strip(), level.strip().lower()
        if ":" not in action or level not in RANK:
            logger.warning("ignoring invalid criticality override: %s", entry)
            continue
        overrides[action] = level
    return overrides


def _lowered(level: str) -> str:
    return LEVELS[max(RANK[level] - 1, RANK["low"])]


def _touches_sentinel(record: dict, stack_name: str) -> bool:
    if len(stack_name) < 4:
        return False
    params = record.get("requestParameters")
    return bool(params) and stack_name in json.dumps(params, default=str)


def classify(record: dict, overrides: str | None = None, stack_name: str | None = None):
    """Rate one CloudTrail record against the catalog.

    Returns a JSON-serializable dict (level, rule_id, title, tactic,
    techniques, stratus, reasons) or None when nothing in the catalog
    applies. overrides and stack_name default to the CRITICALITY_OVERRIDES
    and STACK_NAME environment variables.
    """
    if overrides is None:
        overrides = os.environ.get("CRITICALITY_OVERRIDES", "")
    if stack_name is None:
        stack_name = os.environ.get("STACK_NAME", "")
    if _is_true(record.get("readOnly")):
        return None

    key = action_key(record)
    rule = _INDEX.get(key)
    override = parse_overrides(overrides).get(key)
    if rule is None and override is not None:
        rule = Rule("CUSTOM", override, "", f"Operator rating for {key}", (key,))
    is_root = (record.get("userIdentity") or {}).get("type") == "Root"
    touches_self = _touches_sentinel(record, stack_name)
    if rule is None:
        if touches_self:
            rule = SELF_RULE
        elif is_root:
            rule = ROOT_RULE
        else:
            return None

    level = override or rule.level
    techniques = list(rule.techniques)
    reasons = []

    def raise_to(candidate: str, reason: str, extra: tuple = ()) -> None:
        nonlocal level
        if RANK[candidate] > RANK[level]:
            level = candidate
        reasons.append(reason)
        techniques.extend(t for t in extra if t not in techniques)

    if rule.escalate is not None:
        try:
            finding = rule.escalate(record)
        except Exception as error:  # noqa: BLE001 rating must never block the alert
            logger.warning("parameter check %s failed: %s", rule.rule_id, error)
            finding = None
        if finding is not None:
            raise_to(finding.level, finding.reason, finding.techniques)
    if touches_self and rule is not SELF_RULE:
        raise_to(SELF_RULE.level, "targets ClickOps Sentinel resources", SELF_RULE.techniques)
    if is_root and rule is not ROOT_RULE:
        raise_to(ROOT_RULE.level, "performed by the root user", ROOT_RULE.techniques)

    error_code = record.get("errorCode")
    if error_code:
        level = _lowered(level)
        reasons.append(f"call failed ({error_code}), attempt only")

    return {
        "level": level,
        "rule_id": rule.rule_id,
        "title": rule.title,
        "tactic": rule.tactic,
        "techniques": techniques,
        "stratus": list(rule.stratus),
        "reasons": reasons,
    }


def apply_session_anomalies(rating, anomalies) -> dict | None:
    """Raise a rating to the SES-001 floor when the session switched client or country.

    Anomalies are reasons found outside the record itself, by comparing it
    with earlier events of the same session. Without a catalog match the
    session rule becomes the rating.
    """
    if not anomalies:
        return rating
    rule = SESSION_RULE
    if rating is None:
        rating = {
            "level": rule.level,
            "rule_id": rule.rule_id,
            "title": rule.title,
            "tactic": rule.tactic,
            "techniques": list(rule.techniques),
            "stratus": [],
            "reasons": [],
        }
    else:
        rating = {**rating, "reasons": list(rating["reasons"])}
        rating["level"] = apply_floor(rule.level, rating)
        rating["techniques"] = rating["techniques"] + [
            t for t in rule.techniques if t not in rating["techniques"]
        ]
    rating["reasons"] += [reason for reason in anomalies if reason not in rating["reasons"]]
    return rating


def level_of(rating) -> str:
    return rating["level"] if rating else ""


def apply_floor(level: str, rating) -> str:
    """The higher of the agent's level and the catalog floor."""
    level = level if level in RANK else "none"
    if rating and RANK[rating["level"]] > RANK[level]:
        return rating["level"]
    return level


def title_prefix(level: str) -> str:
    """High and critical alerts carry the level in the title, for filtering and routing."""
    return f"[{level.upper()}] " if level in ("high", "critical") else ""


def bypasses_cooldown(rating) -> bool:
    """Critical changes are always investigated, even inside a session cooldown."""
    return level_of(rating) == "critical"


def technique_url(technique_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def references(rating) -> str:
    """Tactic, MITRE ATT&CK, and Stratus Red Team references as one line."""
    if not rating:
        return ""
    parts = [rating["tactic"]] if rating.get("tactic") else []
    if rating.get("techniques"):
        parts.append("MITRE ATT&CK " + ", ".join(rating["techniques"]))
    if rating.get("stratus"):
        parts.append("Stratus Red Team " + ", ".join(rating["stratus"]))
    return "; ".join(parts)


def describe(rating, with_level: bool = True) -> str:
    """One-line summary for chat and plain-text bodies."""
    if not rating:
        return ""
    text = f"{rating['rule_id']} {rating['title']}"
    refs = references(rating)
    if refs:
        text += f" ({refs})"
    if rating.get("reasons"):
        why = "; ".join(rating["reasons"])
        text += ". " + why[0].upper() + why[1:]
    if with_level:
        text = f"{rating['level'].upper()}. {text}"
    return text

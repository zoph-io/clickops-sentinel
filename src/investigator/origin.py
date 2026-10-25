# SPDX-License-Identifier: Apache-2.0
"""Who drove a change: a person, an AI agent, or other automation.

Combines independent signals into one verdict with a confidence level. Each
signal is a piece of evidence with a strength and a source. AWS-asserted
evidence (session lineage, invokedBy, source identity, credential type,
source network) is recorded by AWS and outweighs client-reported evidence
(user agent, app ID), which the client chooses. When the two disagree, the
disagreement is reported.

A person is never rated high confidence on ordinary signals alone: an agent
driving the user's own browser looks exactly like the user. It takes MFA or
a source identity to get there.

Duplicated in both Lambda packages (each CodeUri is packaged separately);
keep the copies identical.
"""

import os
import re
from datetime import datetime

import client as client_mod

DRIVER_LABELS = {
    "ai-agent": "AI agent",
    "automation": "Automation",
    "human": "Person",
    "unknown": "Unknown",
}
POINTS = {"strong": 3, "medium": 2, "weak": 1}
# A console sign-in mints fresh credentials. Credentials created earlier were
# turned into a console session (GetSigninToken federation).
FEDERATION_GAP_SECONDS = 120
SDK_SESSION_RE = re.compile(
    r"^(botocore-session|aws-go-sdk|aws-sdk-js|aws-sdk-java|aws-sdk-rust|"
    r"aws-dotnet-sdk-session)-\d+$"
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
# Cloud and hosting networks: cloud agents, CI runners, and VPN exits live here.
HOSTING_ASNS = {
    "AS16509": "Amazon",
    "AS14618": "Amazon",
    "AS8987": "Amazon",
    "AS15169": "Google",
    "AS396982": "Google Cloud",
    "AS8075": "Microsoft",
    "AS14061": "DigitalOcean",
    "AS24940": "Hetzner",
    "AS16276": "OVHcloud",
    "AS12876": "Scaleway",
    "AS63949": "Akamai Linode",
    "AS20473": "Vultr",
    "AS31898": "Oracle Cloud",
    "AS45102": "Alibaba Cloud",
    "AS132203": "Tencent Cloud",
    "AS36351": "IBM Cloud",
    "AS51167": "Contabo",
    "AS9009": "M247",
    "AS212238": "Datacamp",
}
MAX_EVIDENCE_LINES = 4


def _clean(value) -> str:
    return re.sub(r"[^\w.\-+@= ]", "", str(value or ""))[:80]


def evidence(signal: str, driver: str, strength: str, source: str, group: str = "") -> dict:
    """One piece of evidence. group: pieces sharing a group count once."""
    return {
        "signal": signal,
        "driver": driver,
        "strength": strength,
        "source": source,
        "group": group,
    }


def _points(item: dict) -> int:
    points = POINTS.get(item.get("strength"), 0)
    # AWS-asserted evidence outweighs what the client says about itself.
    if item.get("source") == "aws" and item.get("strength") in ("medium", "strong"):
        points += 1
    return points


def _agent_label(name: str) -> bool:
    """Agent markers apply to tool names, never to people's names or emails."""
    return bool(name) and not EMAIL_RE.search(name) and client_mod.is_agent_name(name)


def agent_role_names() -> tuple:
    raw = os.environ.get("AGENT_ROLE_NAMES", "")
    return tuple(name.strip().lower() for name in raw.split(",") if name.strip())


def session_parts(record: dict) -> tuple[str, str]:
    """(role name, session name) of an assumed-role identity, else empty strings."""
    arn = (record.get("userIdentity") or {}).get("arn", "")
    match = re.search(r":assumed-role/([^/]+)/(.+)$", arn)
    return (match.group(1), match.group(2)) if match else ("", "")


def parse_time(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} seconds"
    if seconds < 7200:
        return f"{seconds // 60} minutes"
    return f"{seconds / 3600:.1f} hours"


def identity_evidence(record: dict) -> list:
    """Evidence AWS records about the credentials themselves."""
    user_identity = record.get("userIdentity") or {}
    session_context = user_identity.get("sessionContext") or {}
    attributes = session_context.get("attributes") or {}
    console = record.get("sessionCredentialFromConsole") in (True, "true")
    items = []

    _prefix, server = client_mod.mcp_server(user_identity.get("invokedBy"))
    if server:
        items.append(
            evidence(f"called through {server}", "ai-agent", "strong", "aws", group="mcp")
        )

    source_identity = _clean(session_context.get("sourceIdentity"))
    if source_identity:
        if _agent_label(source_identity):
            items.append(
                evidence(
                    f"source identity {source_identity} marks an AI agent",
                    "ai-agent",
                    "strong",
                    "aws",
                )
            )
        else:
            items.append(
                evidence(f"source identity {source_identity}", "human", "medium", "aws")
            )

    role, session = session_parts(record)
    if role and any(name in role.lower() for name in agent_role_names()):
        items.append(
            evidence(f"role {role} is reserved for AI agents", "ai-agent", "strong", "aws")
        )
    if SDK_SESSION_RE.match(session):
        if console:
            items.append(
                evidence(
                    f"console session runs on CLI or SDK credentials ({session})",
                    "automation",
                    "medium",
                    "aws",
                    group="federation",
                )
            )
        else:
            items.append(
                evidence(f"CLI or SDK credentials ({session})", "automation", "weak", "aws")
            )
    elif _agent_label(session):
        items.append(
            evidence(f"role session name {_clean(session)} marks an AI agent", "ai-agent",
                     "medium", "aws")
        )

    access_key = str(user_identity.get("accessKeyId") or "")
    if user_identity.get("type") == "IAMUser" and access_key.startswith("AKIA"):
        items.append(
            evidence("long-term IAM user access key", "automation", "medium", "aws")
        )
    if str(attributes.get("mfaAuthenticated")).lower() == "true":
        items.append(evidence("session authenticated with MFA", "human", "medium", "aws"))
    if console:
        items.append(evidence("console session credentials", "human", "weak", "aws"))
    return items


def client_evidence(info: dict) -> list:
    """Evidence from the user agent, which the client reports about itself."""
    kind = (info or {}).get("kind", "")
    label = client_mod.describe(info)
    if kind == "agent-browser":
        return [evidence(f"user agent: {label}", "ai-agent", "strong", "client")]
    if kind == "ai-agent":
        if info.get("agent", "").endswith("-mcp"):
            return []  # AWS-asserted, counted from invokedBy
        return [evidence(f"user agent app ID {info.get('agent')}", "ai-agent", "strong", "client")]
    if kind == "automated-browser":
        return [evidence(f"user agent: {label}", "automation", "strong", "client")]
    if kind == "browser":
        return [evidence(f"ordinary browser ({label})", "human", "weak", "client")]
    if kind == "cloudshell":
        return [evidence("CloudShell", "human", "weak", "client")]
    if kind in ("cli", "sdk"):
        return [evidence(f"user agent: {label}", "automation", "weak", "client")]
    return []


def network_evidence(ip_info) -> list:
    """A cloud or hosting source network points to a cloud agent, CI, or a VPN."""
    if not ip_info:
        return []
    owner = HOSTING_ASNS.get(ip_info.get("asn", ""))
    if not owner and "hosting" not in (ip_info.get("flags") or []):
        return []
    network = " ".join(p for p in (ip_info.get("asn"), ip_info.get("isp") or owner) if p)
    return [
        evidence(
            f"source network {network} is a cloud or hosting provider "
            "(a cloud agent, CI, or a VPN)",
            "automation",
            "medium",
            "aws",
        )
    ]


def lineage_evidence(lineage) -> list:
    """Evidence from how the session's credentials were obtained.

    lineage: {"signin_gap_seconds", "assume_role": {"caller_client",
    "caller_agent", "tags", "mfa"}}, as looked up by the detector.
    """
    lineage = lineage or {}
    items = []
    gap = lineage.get("signin_gap_seconds")
    if isinstance(gap, (int, float)):
        if gap >= FEDERATION_GAP_SECONDS:
            items.append(
                evidence(
                    f"console signed in with credentials created {duration(gap)} earlier: "
                    "CLI or SDK credentials turned into a console session",
                    "automation",
                    "medium",
                    "aws",
                    group="federation",
                )
            )
        else:
            items.append(
                evidence(
                    "console sign-in minted fresh credentials",
                    "human",
                    "weak",
                    "aws",
                    group="federation",
                )
            )
    assume = lineage.get("assume_role") or {}
    for key, value in (assume.get("tags") or {}).items():
        if _agent_label(key) or _agent_label(value) or str(value).lower() == "ai":
            items.append(
                evidence(
                    f"session tag {_clean(key)}={_clean(value)} marks an AI agent",
                    "ai-agent",
                    "strong",
                    "aws",
                )
            )
            break
    if assume.get("caller_agent"):
        items.append(
            evidence(
                f"credentials minted by AI agent {_clean(assume['caller_agent'])}",
                "ai-agent",
                "medium",
                "client",
            )
        )
    if assume.get("mfa"):
        items.append(evidence("role assumed with MFA", "human", "medium", "aws"))
    return items


def behavior_evidence(steps: list, record: dict) -> list:
    """Evidence from the session's call sequence (investigator only).

    Event history lags a few minutes, so absence of a pattern proves nothing;
    only patterns that are present count.
    """
    if not steps:
        return []
    items = []
    names = [step.get("name") for step in steps]
    if "GetCallerIdentity" in names:
        items.append(
            evidence(
                "GetCallerIdentity in the session, a typical CLI or agent first step",
                "automation",
                "weak",
                "aws",
            )
        )
    retried = set()
    for index, step in enumerate(steps):
        if step.get("errorCode") and any(
            later.get("name") == step.get("name") and not later.get("errorCode")
            for later in steps[index + 1 :]
        ):
            retried.add(step.get("name"))
    if len(retried) >= 2:
        items.append(
            evidence(
                f"trial and error: {len(retried)} failing calls retried until they succeeded",
                "ai-agent",
                "weak",
                "aws",
            )
        )
    change_time = parse_time(record.get("eventTime"))
    if change_time and record.get("sessionCredentialFromConsole") in (True, "true"):
        page_reads = 0
        for step in steps:
            step_time = parse_time(step.get("time"))
            if (
                step_time
                and step.get("readOnly") in (True, "true")
                and 0 <= (change_time - step_time).total_seconds() <= 300
            ):
                page_reads += 1
        if page_reads >= 5:
            items.append(
                evidence(
                    f"{page_reads} console page reads in the 5 minutes before the change",
                    "human",
                    "weak",
                    "aws",
                )
            )
    return items


def _dedupe(items: list) -> list:
    """Keep the strongest piece per group, every ungrouped piece once.

    On a tie the later piece wins: collect() lists lineage, the more specific
    evidence, after identity.
    """
    best: dict = {}
    result = []
    for item in items:
        group = item.get("group")
        if not group:
            if item not in result:
                result.append(item)
            continue
        if group not in best or _points(item) >= _points(best[group]):
            best[group] = item
    return result + list(best.values())


def assess(items: list) -> dict:
    """Weigh the evidence: driver, confidence, the evidence itself, and any conflict.

    Machine-driven evidence (AI agent and other automation) adds up against
    human evidence; an AI agent is automation, so the two never compete.
    """
    items = sorted(_dedupe(items), key=lambda item: -_points(item))
    human = sum(_points(item) for item in items if item["driver"] == "human")
    agent = sum(_points(item) for item in items if item["driver"] == "ai-agent")
    machine = agent + sum(_points(item) for item in items if item["driver"] == "automation")

    if not items or human == machine:
        driver = "unknown"
    elif machine > human:
        driver = "ai-agent" if agent else "automation"
    else:
        driver = "human"

    top, margin = max(human, machine), abs(human - machine)
    if driver == "unknown":
        confidence = "low"
    elif top >= 4 and margin >= 3:
        confidence = "high"
    elif margin >= 1 and top >= 2:
        confidence = "medium"
    else:
        confidence = "low"
    if driver == "human" and confidence == "high":
        proof = any(
            item["driver"] == "human" and item["source"] == "aws" and item["strength"] != "weak"
            for item in items
        )
        if not proof:
            confidence = "medium"

    conflict = ""
    looks_human = [i for i in items if i["driver"] == "human" and i["source"] == "client"]
    machine_aws = [
        i for i in items
        if i["driver"] != "human" and i["source"] == "aws" and i["strength"] != "weak"
    ]
    if looks_human and machine_aws:
        conflict = (
            f"the client looks like a person ({looks_human[0]['signal']}), "
            f"but {machine_aws[0]['signal']}"
        )
    return {
        "driver": driver,
        "confidence": confidence,
        "evidence": items,
        "conflict": conflict,
    }


def collect(record: dict, info: dict, ip_info=None, lineage=None, steps=None) -> list:
    return (
        identity_evidence(record)
        + client_evidence(info)
        + network_evidence(ip_info)
        + lineage_evidence(lineage)
        + behavior_evidence(steps or [], record)
    )


def describe(assessment) -> str:
    """For example 'AI agent, high confidence'."""
    if not assessment:
        return ""
    label = DRIVER_LABELS.get(assessment.get("driver"), "Unknown")
    return f"{label}, {assessment.get('confidence', 'low')} confidence"


def fields(assessment) -> list:
    """(label, value) pairs for alerts: the verdict, its evidence, any conflict."""
    if not assessment or not assessment.get("evidence"):
        return []
    result = [("Driven by", describe(assessment))]
    lines = evidence_lines(assessment)
    if lines:
        result.append(("Evidence", "; ".join(lines)))
    if assessment.get("conflict"):
        result.append(("Signals disagree", assessment["conflict"]))
    return result


def evidence_lines(assessment, limit: int = MAX_EVIDENCE_LINES) -> list:
    """Strongest evidence first, AWS-asserted pieces marked."""
    if not assessment:
        return []
    lines = []
    for item in assessment.get("evidence", [])[:limit]:
        marker = "AWS" if item.get("source") == "aws" else "client"
        lines.append(f"{item['signal']} ({marker}, {item['strength']})")
    return lines

# SPDX-License-Identifier: Apache-2.0
"""How a session's credentials were obtained, from CloudTrail event history.

Two lookups per role session and region, cached by the caller:

- the console sign-in (console sessions only): credentials created well
  before the sign-in were turned into a console session with
  GetSigninToken, the path agents, console helpers, and stolen keys take;
- the AssumeRole call that minted the session: who called it with which
  client, with which session tags, with or without MFA.

Event history is regional. Sign-ins land in us-east-1 or the regional
sign-in endpoint's region, AssumeRole in the STS endpoint's region, so both
the event's region and us-east-1 are searched. Best-effort: every failure
returns what was found so far.
"""

import json
import logging
import time
from datetime import UTC, datetime, timedelta

import client as client_mod
import origin

logger = logging.getLogger()

SIGNIN_REGION = "us-east-1"
# AssumeRole is logged the same second the session is created.
ASSUME_ROLE_WINDOW_SECONDS = 15
# A role session lasts at most 12 hours; its sign-in comes within that time.
MAX_SESSION_SECONDS = 12 * 3600
THROTTLE_SECONDS = 0.55
ASSUME_ROLE_EVENTS = ("AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity")


def _regions(record: dict) -> list:
    region = record.get("awsRegion") or SIGNIN_REGION
    return [region] if region == SIGNIN_REGION else [region, SIGNIN_REGION]


def _events(cloudtrail, attribute: dict, start: datetime, end: datetime) -> list:
    response = cloudtrail.lookup_events(
        LookupAttributes=[attribute], StartTime=start, EndTime=end, MaxResults=50
    )
    events = []
    for item in (response or {}).get("Events", []) if isinstance(response, dict) else []:
        try:
            events.append(json.loads(item.get("CloudTrailEvent", "{}")))
        except (TypeError, json.JSONDecodeError):
            continue
    return events


def _tags(params: dict) -> dict:
    tags = {}
    for tag in params.get("tags") or []:
        if isinstance(tag, dict) and tag.get("key"):
            tags[str(tag["key"])] = str(tag.get("value", ""))
    principal_tags = params.get("principalTags")
    if isinstance(principal_tags, dict):
        tags.update({str(k): str(v) for k, v in principal_tags.items()})
    return tags


def _signin_gap(event: dict, arn: str, created: datetime) -> int | None:
    if event.get("eventName") != "ConsoleLogin":
        return None
    if (event.get("userIdentity") or {}).get("arn") != arn:
        return None
    signed_in = origin.parse_time(event.get("eventTime"))
    return int((signed_in - created).total_seconds()) if signed_in else None


def _assume_role(event: dict, arn: str) -> dict | None:
    if event.get("eventName") not in ASSUME_ROLE_EVENTS:
        return None
    assumed = ((event.get("responseElements") or {}).get("assumedRoleUser") or {}).get("arn")
    if assumed != arn:
        return None
    params = event.get("requestParameters") or {}
    caller = client_mod.parse(event.get("userAgent"))
    return {
        "caller_client": client_mod.describe(caller),
        "caller_agent": caller.get("agent", "") if client_mod.is_agent(caller) else "",
        "tags": _tags(params),
        "mfa": bool(params.get("serialNumber")),
    }


def lookup(record: dict, cloudtrail_for) -> dict:
    """{"signin_gap_seconds", "assume_role"}, keys present only when found.

    cloudtrail_for(region) returns a CloudTrail client for that region.
    """
    user_identity = record.get("userIdentity") or {}
    arn = user_identity.get("arn", "")
    role, session = origin.session_parts(record)
    attributes = (user_identity.get("sessionContext") or {}).get("attributes") or {}
    created = origin.parse_time(attributes.get("creationDate"))
    issuer = ((user_identity.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
    if not (role and session and created):
        return {}

    console = record.get("sessionCredentialFromConsole") in (True, "true")
    now = datetime.now(UTC)
    result: dict = {}
    calls = 0
    for region in _regions(record):
        try:
            cloudtrail = cloudtrail_for(region)
            if issuer and "assume_role" not in result:
                if calls:
                    time.sleep(THROTTLE_SECONDS)
                calls += 1
                window = timedelta(seconds=ASSUME_ROLE_WINDOW_SECONDS)
                attribute = {"AttributeKey": "ResourceName", "AttributeValue": issuer}
                for event in _events(cloudtrail, attribute, created - window, created + window):
                    found = _assume_role(event, arn)
                    if found:
                        result["assume_role"] = found
                        break
            if console and "signin_gap_seconds" not in result:
                if calls:
                    time.sleep(THROTTLE_SECONDS)
                calls += 1
                # Sign-ins are rare, unlike the session's own events, so one
                # page of ConsoleLogin events always reaches back to its start.
                end = min(now, created + timedelta(seconds=MAX_SESSION_SECONDS))
                attribute = {"AttributeKey": "EventName", "AttributeValue": "ConsoleLogin"}
                gaps = [
                    gap
                    for event in _events(cloudtrail, attribute, created - timedelta(minutes=1), end)
                    if (gap := _signin_gap(event, arn, created)) is not None
                ]
                if gaps:
                    result["signin_gap_seconds"] = min(gaps)
        except Exception as error:  # noqa: BLE001 lineage is best-effort
            logger.warning("session lineage lookup failed in %s: %s", region, error)
    return result


def complete(record: dict, result: dict) -> bool:
    """Whether the lookup found everything it can, so the caller may cache it."""
    console = record.get("sessionCredentialFromConsole") in (True, "true")
    return "assume_role" in result and (not console or "signin_gap_seconds" in result)

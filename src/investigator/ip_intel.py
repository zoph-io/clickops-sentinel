# SPDX-License-Identifier: Apache-2.0
"""Source IP enrichment: network owner (ASN and ISP) and approximate location.

Looks up the source IP of a console action through an external provider
selected by IP_LOOKUP_PROVIDER: "ipinfo" (ipinfo.io, the default) or "none"
to disable enrichment. Only globally routable addresses are looked up;
CloudTrail also reports values such as "AWS Internal", service hostnames,
and private VPC addresses, which are skipped. An optional provider token is
read from the SSM SecureString named by IP_LOOKUP_TOKEN_PARAM.

Enrichment is best-effort: any failure returns None and the alert goes out
without it. Results are cached for the lifetime of the execution
environment, so one console session costs one lookup.

This module is duplicated in src/detector and src/investigator because SAM
packages each CodeUri separately. Keep both copies identical.
"""

import ipaddress
import json
import logging
import os
import re
import urllib.parse
import urllib.request

logger = logging.getLogger()

HTTP_TIMEOUT_SECONDS = 3
USER_AGENT = "clickops-sentinel/1.0"
MAX_CACHE_ENTRIES = 256
PRIVACY_FLAGS = ("vpn", "proxy", "tor", "relay", "hosting")
MAX_FIELD_LENGTH = 80
# Network names come from WHOIS data the IP owner controls: keep chat markup
# and line breaks out of alerts and the agent prompt.
_UNSAFE = re.compile(r"[<>|*_`~\[\]\x00-\x1f\x7f]+")

_cache: dict = {}
_token_cache: dict = {}


def enabled() -> bool:
    return os.environ.get("IP_LOOKUP_PROVIDER", "ipinfo") != "none"


def is_public_ip(value) -> bool:
    try:
        return ipaddress.ip_address(str(value or "").strip()).is_global
    except ValueError:
        return False


def _token() -> str:
    parameter_name = os.environ.get("IP_LOOKUP_TOKEN_PARAM", "")
    if not parameter_name:
        return ""
    if parameter_name not in _token_cache:
        # Imported here so email rendering (make preview-email) works without boto3.
        import boto3

        response = boto3.client("ssm").get_parameter(Name=parameter_name, WithDecryption=True)
        _token_cache[parameter_name] = response["Parameter"]["Value"]
    return _token_cache[parameter_name]


def _fetch_ipinfo(ip: str) -> dict:
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    token = _token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        f"https://ipinfo.io/{urllib.parse.quote(ip)}/json", headers=headers
    )
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return json.loads(response.read())


def _clean(value) -> str:
    return " ".join(_UNSAFE.sub(" ", str(value or "")).split())[:MAX_FIELD_LENGTH]


def parse_ipinfo(ip: str, data) -> dict | None:
    """Normalize an ipinfo.io response (free, paid, or Lite format)."""
    if not isinstance(data, dict) or data.get("bogon"):
        return None
    asn_field = data.get("asn")
    if isinstance(asn_field, dict):
        asn, isp = str(asn_field.get("asn", "")), str(asn_field.get("name", ""))
    elif isinstance(asn_field, str):
        asn, isp = asn_field, str(data.get("as_name", ""))
    else:
        asn, isp = "", ""
    org = str(data.get("org") or "")
    if not asn and org.startswith("AS"):
        asn, _, isp = org.partition(" ")
    isp = isp or org

    privacy = data.get("privacy") if isinstance(data.get("privacy"), dict) else {}
    flags = [flag for flag in PRIVACY_FLAGS if privacy.get(flag)]
    if (
        isinstance(asn_field, dict)
        and asn_field.get("type") == "hosting"
        and "hosting" not in flags
    ):
        flags.append("hosting")

    return {
        "ip": ip,
        "city": _clean(data.get("city")),
        "region": _clean(data.get("region")),
        "country": _clean(data.get("country") or data.get("country_code")),
        "asn": _clean(asn),
        "isp": _clean(isp),
        "flags": flags,
    }


def lookup(ip) -> dict | None:
    """Network and approximate location of a public IP, or None."""
    ip = str(ip or "").strip()
    if not enabled() or not is_public_ip(ip):
        return None
    if ip in _cache:
        return _cache[ip]
    provider = os.environ.get("IP_LOOKUP_PROVIDER", "ipinfo")
    if provider != "ipinfo":
        logger.error("unknown IP lookup provider: %s", provider)
        return None
    try:
        info = parse_ipinfo(ip, _fetch_ipinfo(ip))
    except Exception as error:  # noqa: BLE001 enrichment is best-effort by design
        logger.warning("IP lookup failed for %s: %s", ip, error)
        return None
    if len(_cache) >= MAX_CACHE_ENTRIES:
        _cache.clear()
    _cache[ip] = info
    return info


def place(info) -> str:
    """City, region, country, as far as known."""
    if not info:
        return ""
    return ", ".join(
        part for part in (info.get("city"), info.get("region"), info.get("country")) if part
    )


def network(info) -> str:
    """AS number and network owner, for example AS3215 Orange S.A."""
    if not info:
        return ""
    return " ".join(part for part in (info.get("asn"), info.get("isp")) if part)


def describe(info) -> str:
    """One line: network, approximate location, and privacy flags."""
    if not info:
        return ""
    parts = []
    if network(info):
        parts.append(network(info))
    if place(info):
        parts.append(f"near {place(info)}")
    if info.get("flags"):
        parts.append("flagged " + ", ".join(flag.upper() for flag in info["flags"]))
    return ", ".join(parts)

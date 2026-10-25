# SPDX-License-Identifier: Apache-2.0
"""Classify the CloudTrail userAgent: what made the call, human or agent.

The user agent is self-reported by the client. An agent marker is evidence
that an agent was involved; an ordinary browser proves nothing, since an
agent driving the user's own browser looks exactly like the user.

Duplicated in both Lambda packages (each CodeUri is packaged separately);
keep the copies identical.
"""

import os
import re

DEFAULT_AGENT_MARKERS = (
    "claude,cursor,codex,copilot,kiro,amazon-q,q-cli,cline,windsurf,aider,"
    "gemini,opencode,goose,devin,agent,mcp"
)

KIND_LABELS = {
    "browser": "Browser",
    "agent-browser": "AI agent browser",
    "automated-browser": "Automated browser",
    "embedded-browser": "Embedded browser",
    "ai-agent": "AI agent",
    "cloudshell": "CloudShell",
    "iac": "Infrastructure as code",
    "cli": "AWS CLI",
    "sdk": "AWS SDK",
    "aws-service": "AWS service",
    "unknown": "Unknown client",
}
AGENT_KINDS = frozenset({"agent-browser", "ai-agent"})
AUTOMATED_KINDS = AGENT_KINDS | {"automated-browser"}
BROWSER_KINDS = frozenset({"browser", "agent-browser", "automated-browser", "embedded-browser"})

APP_ID_RE = re.compile(r"(?:^|\s)app/(\S+)")
EXEC_ENV_RE = re.compile(r"(?:^|\s)exec-env/(\S+)")
SDK_OS_RE = re.compile(r"(?:^|\s)os/([a-z]+)")
PRODUCT_RE = re.compile(r"([A-Za-z][\w.\-]*)/\d[\w.\-]*")
AUTOMATION_RE = re.compile(r"HeadlessChrome|Playwright|Puppeteer|Selenium|PhantomJS|Cypress", re.I)
# Product tokens every Chromium, WebKit, or Gecko user agent carries.
BROWSER_TOKENS = frozenset(
    {"Mozilla", "AppleWebKit", "Chrome", "Chromium", "Safari", "Electron", "Version",
     "Gecko", "Firefox", "Edg", "OPR", "Mobile", "HeadlessChrome"}
)
IAC_TOOLS = (
    ("Terraform", "Terraform"),
    ("OpenTofu", "OpenTofu"),
    ("pulumi", "Pulumi"),
    ("aws-cdk", "AWS CDK"),
    ("cdktf", "CDK for Terraform"),
    ("aws-sam-cli", "AWS SAM CLI"),
    ("crossplane", "Crossplane"),
    ("ansible", "Ansible"),
)
SDK_OS_NAMES = {"macos": "macOS", "linux": "Linux", "windows": "Windows", "android": "Android"}
MAX_LABEL_LENGTH = 80
# AWS-managed MCP servers call AWS on the user's behalf and stamp invokedBy,
# sourceIPAddress, and userAgent with their service principal.
MCP_SERVICE_RE = re.compile(r"^([a-z0-9-]+-mcp)\.amazonaws\.com$")
MCP_SERVER_NAMES = {
    "aws-mcp": "AWS MCP Server",
    "eks-mcp": "Amazon EKS MCP Server",
    "ecs-mcp": "Amazon ECS MCP Server",
}


def agent_markers() -> tuple:
    raw = os.environ.get("AGENT_APP_IDS", DEFAULT_AGENT_MARKERS)
    return tuple(marker.strip().lower() for marker in raw.split(",") if marker.strip())


def is_agent_name(name: str) -> bool:
    name = name.lower()
    return any(marker == "*" or marker in name for marker in agent_markers())


def mcp_server(value) -> tuple[str, str]:
    """(principal prefix, display name) of an AWS-managed MCP server, or empty strings."""
    match = MCP_SERVICE_RE.match(str(value or "").strip())
    if not match:
        return "", ""
    prefix = match.group(1)
    return prefix, MCP_SERVER_NAMES.get(prefix, f"{prefix} MCP server")


def _safe(value: str) -> str:
    return re.sub(r"[^\w.\-+ ]", "", value)[:MAX_LABEL_LENGTH]


def _browser_os(user_agent: str) -> str:
    if "iPhone" in user_agent or "iPad" in user_agent:
        return "iOS"
    if "Android" in user_agent:
        return "Android"
    if "Windows" in user_agent:
        return "Windows"
    if "CrOS" in user_agent:
        return "ChromeOS"
    if "Mac OS X" in user_agent or "Macintosh" in user_agent:
        return "macOS"
    if "Linux" in user_agent:
        return "Linux"
    return ""


def _browser_family(user_agent: str) -> str:
    for token, family in (
        ("HeadlessChrome/", "Headless Chrome"),
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
    ):
        if token in user_agent:
            return family
    return "Safari" if "Safari/" in user_agent else "browser"


def _embedding_app(user_agent: str) -> str:
    """The Electron app hosting the browser, e.g. Cursor in 'Cursor/3.27.6 Chrome/...'."""
    for name in PRODUCT_RE.findall(user_agent):
        if name not in BROWSER_TOKENS:
            return _safe(name)
    return ""


def _result(kind: str, name: str = "", os_name: str = "", agent: str = "") -> dict:
    label = name or KIND_LABELS[kind]
    if kind == "agent-browser":
        label = f"{name} browser (AI agent tool)"
    elif kind == "embedded-browser":
        label = f"{name} embedded browser"
    elif kind == "ai-agent":
        label = f"AI agent {agent}"
    elif kind == "aws-service":
        label = f"AWS service {name}".strip()
    if kind in ("aws-service", "unknown"):
        fingerprint = ""
    else:
        fingerprint = f"{kind}|{name}|{os_name}" + (f"|{agent}" if agent else "")
    return {
        "kind": kind,
        "label": label,
        "os": os_name,
        "agent": agent,
        "fingerprint": fingerprint,
    }


def _parse_browser(user_agent: str) -> dict:
    os_name = _browser_os(user_agent)
    if AUTOMATION_RE.search(user_agent):
        match = AUTOMATION_RE.search(user_agent)
        name = "Headless Chrome" if match.group(0) == "HeadlessChrome" else match.group(0)
        return _result("automated-browser", name, os_name)
    if "Electron/" in user_agent:
        app = _embedding_app(user_agent) or "Electron"
        if is_agent_name(app):
            return _result("agent-browser", app, os_name, agent=app)
        return _result("embedded-browser", app, os_name)
    return _result("browser", _browser_family(user_agent), os_name)


def _parse_tool(user_agent: str) -> dict:
    os_match = SDK_OS_RE.search(user_agent)
    os_name = SDK_OS_NAMES.get(os_match.group(1), os_match.group(1)) if os_match else ""
    app = APP_ID_RE.search(user_agent)
    app_id = _safe(app.group(1)) if app else ""
    lowered = user_agent.lower()
    agent = app_id if app_id and is_agent_name(app_id) else ""
    iac = next((name for marker, name in IAC_TOOLS if marker.lower() in lowered), "")

    # An agent applying IaC is the desired path, not drift: attributed, not alerted.
    if iac:
        result = _result("iac", iac, os_name, agent=agent)
        if agent:
            result["label"] = f"{iac}, run by AI agent {agent}"
        return result
    if agent:
        tool = "AWS CLI" if "aws-cli/" in lowered else "AWS SDK"
        result = _result("ai-agent", tool, os_name, agent=agent)
        result["label"] = f"AI agent {agent} via {tool}"
        return result

    exec_env = EXEC_ENV_RE.search(user_agent)
    if exec_env and "cloudshell" in exec_env.group(1).lower():
        return _result("cloudshell", "CloudShell", os_name)
    if "aws-cli/" in lowered:
        result = _result("cli", "AWS CLI", os_name)
    elif re.search(r"boto3/|botocore/|aws-sdk-|aws-cli/", lowered):
        sdk = PRODUCT_RE.findall(user_agent)
        result = _result("sdk", f"AWS SDK ({_safe(sdk[0])})" if sdk else "AWS SDK", os_name)
    else:
        products = PRODUCT_RE.findall(user_agent)
        result = _result("unknown", _safe(products[0]) if products else "", os_name)
    if app_id:
        result["label"] += f", app {app_id}"
    return result


def parse(user_agent) -> dict:
    """kind, label, os, agent (name when an AI agent is identified), fingerprint.

    The fingerprint ignores versions, so browser updates do not register as
    a new client. It is empty for AWS services and unrecognized clients.
    """
    user_agent = str(user_agent or "").strip()
    if not user_agent:
        return _result("unknown")
    if user_agent.startswith("AWS Internal"):
        return _result("aws-service", "AWS Internal")
    prefix, server = mcp_server(user_agent)
    if server:
        result = _result("ai-agent", server, agent=prefix)
        result["label"] = f"AI agent via {server}"
        return result
    if user_agent.endswith(".amazonaws.com") or user_agent.startswith("awslambda-worker"):
        return _result("aws-service", _safe(user_agent.split()[0].split("/")[0]))
    if user_agent.startswith("Mozilla/"):
        return _parse_browser(user_agent)
    return _parse_tool(user_agent)


def is_browser(info) -> bool:
    return bool(info) and info.get("kind") in BROWSER_KINDS


def is_browser_fingerprint(fingerprint: str) -> bool:
    return str(fingerprint or "").split("|", 1)[0] in BROWSER_KINDS


def is_agent(info) -> bool:
    return bool(info) and info.get("kind") in AGENT_KINDS


def is_automated(info) -> bool:
    return bool(info) and info.get("kind") in AUTOMATED_KINDS


def describe(info) -> str:
    """One line, for example 'Chrome on macOS' or 'AI agent cursor-agent via AWS CLI on macOS'."""
    if not info:
        return ""
    label = info.get("label", "")
    return f"{label} on {info['os']}" if info.get("os") else label


def new_context(record: dict) -> dict:
    """Client context of one change, before any session or history signal."""
    console = record.get("sessionCredentialFromConsole") in (True, "true")
    return {
        "origin": "console" if console else "api",
        "client": parse(record.get("userAgent")),
        "anomalies": [],
        "observations": [],
    }


def headline(context) -> str:
    """Alert title without the event name, for example 'AI agent change detected'.

    Follows the combined origin assessment when it is at least medium
    confidence, so AWS-asserted evidence can name an agent the user agent hides.
    """
    context = context or {}
    info = context.get("client")
    console = context.get("origin", "console") == "console"
    assessment = context.get("assessment") or {}
    driver = assessment.get("driver") if assessment.get("confidence") in ("medium", "high") else ""
    if is_agent(info) or driver == "ai-agent":
        return "ClickOps by an AI agent detected" if console else "AI agent change detected"
    if is_automated(info) or driver == "automation":
        return "Automated ClickOps detected"
    return "ClickOps detected"


def signal_lines(context) -> list:
    """Session anomalies first, then observations such as a first-seen client."""
    context = context or {}
    return list(context.get("anomalies", [])) + list(context.get("observations", []))

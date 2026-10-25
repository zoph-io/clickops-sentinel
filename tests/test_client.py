# SPDX-License-Identifier: Apache-2.0
"""User agent classification: browsers, agent browsers, AI agents, tools."""

import pytest
import sample_events

import client


@pytest.mark.parametrize(
    ("user_agent", "kind", "described", "agent"),
    [
        (sample_events.CHROME_UA, "browser", "Chrome on macOS", ""),
        (
            sample_events.CURSOR_UA,
            "agent-browser",
            "Cursor browser (AI agent tool) on macOS",
            "Cursor",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
            "browser",
            "Firefox on Windows",
            "",
        ),
        (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0",
            "browser",
            "Edge on Windows",
            "",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/19.0 Safari/605.1.15",
            "browser",
            "Safari on macOS",
            "",
        ),
        (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
            "HeadlessChrome/150.0.0.0 Safari/537.36",
            "automated-browser",
            "Headless Chrome on Linux",
            "",
        ),
        (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Slack/4.41.0 Chrome/130.0 Electron/33.0 Safari/537.36",
            "embedded-browser",
            "Slack embedded browser on macOS",
            "",
        ),
        (
            sample_events.AGENT_CLI_UA,
            "ai-agent",
            "AI agent cursor-agent via AWS CLI on macOS",
            "cursor-agent",
        ),
        (
            "Boto3/1.43.108 md/Botocore#1.43.113 ua/2.1 os/linux#6.1 app/claude-code",
            "ai-agent",
            "AI agent claude-code via AWS SDK on Linux",
            "claude-code",
        ),
        (
            "aws-cli/2.38.3 md/awscrt#0.37.0 ua/2.1 os/macos#27.0.0 "
            "md/command#ec2.delete-security-group",
            "cli",
            "AWS CLI on macOS",
            "",
        ),
        (
            "Boto3/1.43.108 md/Botocore#1.43.113 ua/2.1 os/linux#6.1 app/billing-report",
            "sdk",
            "AWS SDK (Boto3), app billing-report on Linux",
            "",
        ),
        (
            "aws-cli/2.27.0 Python/3.13 Linux/6.1 exec-env/CloudShell command/ec2.create-tags",
            "cloudshell",
            "CloudShell",
            "",
        ),
        (
            "APN/1.0 HashiCorp/1.0 Terraform/1.9.8 (+https://www.terraform.io) "
            "terraform-provider-aws/5.100.0 aws-sdk-go-v2/1.36.3 ua/2.1 os/linux lang/go#1",
            "iac",
            "Terraform on Linux",
            "",
        ),
        (
            "Boto3/1.43.108 md/Botocore#1.43.113 ua/2.1 os/macos#27.0.0 "
            "Botocore/1.43.113 aws-sam-cli/1.169.0/fe828",
            "iac",
            "AWS SAM CLI on macOS",
            "",
        ),
        ("ecs.amazonaws.com", "aws-service", "AWS service ecs.amazonaws.com", ""),
        ("AWS Internal", "aws-service", "AWS service AWS Internal", ""),
        ("awslambda-worker/1.0", "aws-service", "AWS service awslambda-worker", ""),
        ("", "unknown", "Unknown client", ""),
    ],
)
def test_parse(user_agent, kind, described, agent):
    info = client.parse(user_agent)
    assert info["kind"] == kind
    assert client.describe(info) == described
    assert info["agent"] == agent


def test_fingerprint_ignores_versions_and_skips_services():
    older = client.parse(sample_events.CHROME_UA.replace("156.0.0.0", "150.0.0.0"))
    assert older["fingerprint"] == client.parse(sample_events.CHROME_UA)["fingerprint"]
    assert client.parse("ecs.amazonaws.com")["fingerprint"] == ""
    assert client.parse("")["fingerprint"] == ""
    agent = client.parse(sample_events.AGENT_CLI_UA)["fingerprint"]
    assert agent == "ai-agent|AWS CLI|macOS|cursor-agent"


def test_agent_applying_iac_is_attributed_but_not_an_agent_change():
    info = client.parse(
        "APN/1.0 HashiCorp/1.0 Terraform/1.9.8 terraform-provider-aws/5.100.0 "
        "aws-sdk-go-v2/1.36.3 ua/2.1 os/linux app/claude-code"
    )
    assert info["kind"] == "iac"
    assert info["agent"] == "claude-code"
    assert client.describe(info) == "Terraform, run by AI agent claude-code on Linux"
    assert not client.is_agent(info)


def test_aws_managed_mcp_servers_are_ai_agents():
    info = client.parse("aws-mcp.amazonaws.com")
    assert (info["kind"], info["agent"]) == ("ai-agent", "aws-mcp")
    assert client.describe(info) == "AI agent via AWS MCP Server"
    assert client.mcp_server("eks-mcp.amazonaws.com") == ("eks-mcp", "Amazon EKS MCP Server")
    assert client.mcp_server("cloudformation.amazonaws.com") == ("", "")
    assert client.parse("cloudformation.amazonaws.com")["kind"] == "aws-service"


def test_agent_markers_are_configurable(monkeypatch):
    monkeypatch.setenv("AGENT_APP_IDS", "my-bot")
    assert client.parse(sample_events.AGENT_CLI_UA)["kind"] == "cli"
    assert client.parse("Boto3/1.43 ua/2.1 app/my-bot-7")["kind"] == "ai-agent"
    assert client.parse(sample_events.CURSOR_UA)["kind"] == "embedded-browser"

    monkeypatch.setenv("AGENT_APP_IDS", "*")
    assert client.parse("Boto3/1.43 ua/2.1 app/billing-report")["kind"] == "ai-agent"


def test_owner_controlled_values_are_stripped_of_markup():
    info = client.parse("Boto3/1.43 ua/2.1 app/<https://evil|claude>")
    assert "<" not in info["label"] and "|" not in info["label"]


def test_new_context_and_headline():
    console = client.new_context(sample_events.BROWSER_MUTATION)
    assert console["origin"] == "console"
    assert client.headline(console) == "ClickOps detected"

    agent_browser = client.new_context(sample_events.AGENT_BROWSER_MUTATION)
    assert client.headline(agent_browser) == "ClickOps by an AI agent detected"

    api = client.new_context(sample_events.AGENT_API_MUTATION)
    assert api["origin"] == "api"
    assert client.headline(api) == "AI agent change detected"

    headless = {
        "origin": "console",
        "client": client.parse("Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/150.0 Safari/537"),
    }
    assert client.headline(headless) == "Automated ClickOps detected"
    assert client.headline(None) == "ClickOps detected"


def test_signal_lines_put_anomalies_first():
    context = {"anomalies": ["a"], "observations": ["b"]}
    assert client.signal_lines(context) == ["a", "b"]
    assert client.signal_lines(None) == []


def test_browser_fingerprints():
    assert client.is_browser_fingerprint("browser|Chrome|macOS")
    assert client.is_browser_fingerprint("agent-browser|Cursor|macOS")
    assert not client.is_browser_fingerprint("cli|AWS CLI|macOS")
    assert not client.is_browser_fingerprint("")

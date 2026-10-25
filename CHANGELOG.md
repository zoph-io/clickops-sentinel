# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.0] - 2026-10-25

### Added

- Client classification from the CloudTrail user agent on every alert and
  in the agent's context: browser, AI agent browser (such as Cursor's
  built-in browser), automated browser (headless Chrome, Playwright),
  CloudShell, IaC tools, CLI and SDK, and AI agents through the API.
- API changes by AI agents that set `AWS_SDK_UA_APP_ID` are alerted like
  console changes, through a second EventBridge rule. New
  `WatchAgentApiChanges` and `AgentAppIds` parameters.
- Session anomalies: a session that switches browser or source country
  between two changes is raised to at least high (new catalog modifier
  SES-001, MITRE T1550.004) and bypasses the session cooldown.
- First change by a person from a client never seen for them is noted on
  the alert. `make stats` breaks investigations down by client and AI agent.
- Who drove each change: a person, an AI agent, or automation, with a
  confidence level and the evidence, on every alert, in the agent's
  context, in investigation records, and in `make stats`. The verdict
  weighs AWS-recorded evidence above the self-reported user agent: a console
  session opened from CLI or SDK credentials (looked up once per session in
  CloudTrail Event History, with the `AssumeRole` call behind it), session
  tags, source identity, agent session names, long-term access keys, MFA,
  cloud or hosting source networks, and call patterns in the session
  retrace. Disagreement between client and AWS evidence is reported, and a
  person is never rated high confidence without MFA or a source identity.
  New `AgentRoleNames` parameter; the detector gains
  `cloudtrail:LookupEvents`.
- Changes made through AWS-managed MCP servers (`invokedBy`
  `*-mcp.amazonaws.com`) are alerted as AI agent changes through a third
  EventBridge rule, under `WatchAgentApiChanges`. They are data events, so
  the trail must log them.
- Criticality scale (none, low, medium, high, critical) and a deterministic
  catalog of risky AWS actions mapped to MITRE ATT&CK and Stratus Red Team,
  published in `docs/criticality-catalog.md` (`make catalog-doc`). Parameter
  checks raise the level for public exposure, admin grants, cross-account
  trust, and similar requests; root and self-targeting changes are rated at
  least high; failed calls are lowered one level. The rating is a floor
  under the agent's security severity, appears on every alert (including the
  plain path), prefixes high and critical subjects and chat titles, and
  critical changes bypass the session cooldown. New `CriticalityOverrides`
  parameter.
- Source IP enrichment through ipinfo.io: network owner, AS number,
  approximate location, and VPN, proxy, Tor, or hosting flags on alerts,
  sign-in alerts, and as a `lookup_ip_intel` agent tool. New
  `IpLookupProvider` (`ipinfo` or `none`) and `IpLookupTokenParam`
  parameters.
- `make stats` breaks investigations down by catalog rule, source country,
  and source network.

### Changed

- Rewrote the README around the value proposition, with a "Try it" path
  near the top and mock screenshots rendered from the real templates
  (suspicious, savings, and cost-impact emails, a sign-in alert, a Slack
  thread, and `make stats` output). The hand-drawn `docs/email-mock.png`
  was replaced by these renders.

## [0.2.0] - 2026-07-12

### Changed

- Renamed the project from ClickOps Notifier to ClickOps Sentinel: stack
  name, CloudWatch metrics namespace (`ClickOpsSentinel`), AgentCore Memory
  resource name, and chat notification metadata. Redeploying replaces the
  memory store; accumulated actor memory rebuilds over time.
- Email delivery replaced: plain-text SNS email subscription removed in
  favor of rich HTML email (with a visual console session path) sent through
  a pluggable external provider (Resend by default; Postmark, Mailgun,
  SendGrid, or self-hosted SMTP).
- Hardened the supply chain: grouped Dependabot updates, added `pip-audit`
  and dependency review to CI, and bumped pinned dev and runtime
  dependencies.

### Added

- Rich HTML email alerts with verdict, security and cost cards, and a
  step-by-step session path diagram of the console session.
- `make preview-email` target to render the email templates locally from
  test fixtures.
- FOSS governance: `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue and pull
  request templates, and README status badges.

### Fixed

- Set an explicit `User-Agent` on outbound email HTTP requests so
  Cloudflare-fronted providers (e.g. Resend) no longer reject them with
  HTTP 403.

## [0.1.0]

### Added

- Initial release.
- Real-time detection of manual AWS Console changes via the EventBridge
  default bus and the CloudTrail `sessionCredentialFromConsole` flag.
- Agentic investigation of each detection with Claude on Amazon Bedrock:
  session retrace via CloudTrail LookupEvents, adjacent-change correlation,
  purpose assessment, security and FinOps impact analysis.
- Long-term investigation memory with Amazon Bedrock AgentCore Memory.
- Notifications through Amazon Q Developer in chat applications (Slack and
  Microsoft Teams) and email via SNS.
- Layered Bedrock consumption guardrails: per-call token caps,
  per-investigation ceilings, daily token budget, session cooldown, and
  CloudWatch budget metrics.
- Deduplication and investigation statistics backed by DynamoDB.
- ConsoleLogin alerts for root sign-ins and sign-ins without MFA.

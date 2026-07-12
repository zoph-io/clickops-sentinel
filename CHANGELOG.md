# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

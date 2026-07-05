# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

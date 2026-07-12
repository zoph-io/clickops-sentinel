# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues.

Instead, use GitHub private vulnerability reporting on this repository: open
the Security tab and choose "Report a vulnerability". Include a description
of the issue, steps to reproduce, and the potential impact.

You can expect an acknowledgement within 72 hours. Please allow a reasonable
time to investigate and release a fix before any public disclosure.

## Supported versions

Only the latest release on the `main` branch receives security fixes.

## Scope notes

ClickOps Sentinel runs entirely inside your AWS account. It reads CloudTrail
Event History, writes to one DynamoDB table, invokes Amazon Bedrock, and
sends notifications. The email provider API key is stored as an SSM
SecureString parameter and is fetched at runtime with decryption; it never
appears in CloudFormation outputs or Lambda environment variables.

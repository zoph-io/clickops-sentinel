---
name: Bug report
about: Something does not work as documented
title: ""
labels: bug
assignees: ""
---

## Description

A clear and concise description of the bug.

## Steps to reproduce

1. Deploy with parameters `...`
2. Perform action `...` in the console
3. Observe `...`

## Expected behavior

What you expected to happen.

## Actual behavior

What happened instead. Include the detector or investigator Lambda decision
log line if available (structured JSON, one line per event).

## Environment

- Region:
- Deployment method: `make deploy` / `sam deploy`
- `EnableAIInvestigation`: true / false
- Email provider (if email-related): resend / postmark / mailgun / sendgrid / smtp

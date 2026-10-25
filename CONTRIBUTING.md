# Contributing to ClickOps Sentinel

Thank you for considering a contribution. This project welcomes bug reports,
feature requests, documentation improvements, and pull requests.

## Development setup

Prerequisites: Python 3.13, AWS SAM CLI, GNU make.

```bash
make install    # create .venv and install dev dependencies
make lint       # ruff
make test       # pytest, fully offline, no AWS credentials needed
make validate   # sam validate --lint
```

## Guidelines

- Tests must not require AWS credentials or make network calls. Mock boto3
  clients in unit tests.
- Keep the suppression list (`src/detector/suppressed_actions.py`) sorted and
  commented with the reason for each nonobvious entry.
- The criticality catalog (`criticality.py`), IP enrichment
  (`ip_intel.py`), user agent classification (`client.py`), and the
  who-drove-it assessment (`origin.py`) exist in both `src/detector/` and
  `src/investigator/` and must stay identical, as do the email modules. After changing catalog
  rules, run `make catalog-doc`; a test fails if
  `docs/criticality-catalog.md` is stale. Give each rule a MITRE ATT&CK
  technique and, where one exists, a Stratus Red Team technique.
- Writing style for docs, code comments, commit messages, and notification
  content: no em-dashes and no emojis.
- Visual changes follow the [brand and design system](docs/brand/README.md).
  Colors live in `docs/brand/tokens.json` and in `COLOR` in
  `email_render.py`; a test keeps them equal. Build emails from the existing
  components (`_header`, `_who_block`, `_cards`, `_callout`, `_cta`) rather
  than new one-off markup. After changing an email, run `make screenshots`
  so the README shows the real template. Logo changes go in
  `scripts/render_brand.py`, then `make brand`.
- Follow conventional commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`)
  where practical.

## Reporting noisy events

If you receive alerts for an action that is read-only in practice or that can
only be performed from the console, open an issue with the `eventSource` and
`eventName` from the alert so it can be added to the default suppression list.

## Pull requests

1. Fork and create a feature branch.
2. Add or update tests for your change.
3. Ensure `make lint test validate` passes.
4. Open a pull request describing the motivation and behavior change.

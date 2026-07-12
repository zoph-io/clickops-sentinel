# SPDX-License-Identifier: Apache-2.0
"""Test wiring.

Both Lambda source directories are flat module layouts (SAM packages each
CodeUri separately), and both contain a handler.py. Non-colliding modules are
imported normally via sys.path; the two handler.py files are loaded under
unique module names.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DETECTOR_DIR = ROOT / "src" / "detector"
INVESTIGATOR_DIR = ROOT / "src" / "investigator"

for path in (DETECTOR_DIR, INVESTIGATOR_DIR):
    sys.path.insert(0, str(path))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def detector_handler():
    return _load_module("detector_handler", DETECTOR_DIR / "handler.py")


@pytest.fixture(scope="session")
def investigator_handler():
    return _load_module("investigator_handler", INVESTIGATOR_DIR / "handler.py")


@pytest.fixture()
def base_env(monkeypatch):
    """Environment variables both handlers rely on."""
    env = {
        "TABLE_NAME": "test-table",
        "CHAT_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:chat",
        "CHAT_ENABLED": "true",
        "EMAIL_ENABLED": "true",
        "EMAIL_PROVIDER": "resend",
        "EMAIL_FROM": "alerts@example.com",
        "EMAIL_TO": "owner@example.com",
        "EMAIL_API_KEY_PARAM": "/clickops-sentinel/email-api-key",
        "ENABLE_AI": "true",
        "INVESTIGATOR_FUNCTION_NAME": "investigator",
        "EXTRA_SUPPRESSED_ACTIONS": "",
        "ACCOUNT_FRIENDLY_NAME": "test-account",
        "SESSION_COOLDOWN_MINUTES": "30",
        "MODEL_ID": "us.anthropic.claude-sonnet-4-6",
        "MEMORY_ID": "mem-test",
        "LOOKBACK_HOURS": "6",
        "DAILY_TOKEN_BUDGET": "2000000",
        "MAX_AGENT_TURNS": "8",
        "MAX_INVESTIGATION_TOKENS": "60000",
        "MEMORY_RETENTION_DAYS": "180",
        "METRICS_NAMESPACE": "ClickOpsSentinel",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return env

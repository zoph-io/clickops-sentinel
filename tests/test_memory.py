# SPDX-License-Identifier: Apache-2.0
"""AgentCore Memory wrappers degrade instead of raising."""

from unittest.mock import MagicMock

import memory


def test_retrieve_returns_records():
    client = MagicMock()
    client.retrieve_memory_records.return_value = {
        "memoryRecordSummaries": [
            {"content": {"text": "Actor made three manual changes last month."}},
            {"content": {"text": "Prior verdict: likely-sanctioned-activity."}},
        ]
    }
    result = memory.retrieve_actor_history(client, "mem-1", "alice", "prior verdicts")
    assert "three manual changes" in result
    assert result.startswith("- ")
    kwargs = client.retrieve_memory_records.call_args.kwargs
    assert kwargs["namespace"] == "/actors/alice/facts"


def test_retrieve_with_no_history():
    client = MagicMock()
    client.retrieve_memory_records.return_value = {"memoryRecordSummaries": []}
    result = memory.retrieve_actor_history(client, "mem-1", "alice", "anything")
    assert result == "no prior history for this actor"


def test_retrieve_failure_degrades():
    client = MagicMock()
    client.retrieve_memory_records.side_effect = RuntimeError("service down")
    result = memory.retrieve_actor_history(client, "mem-1", "alice", "anything")
    assert result == "memory retrieval failed"


def test_retrieve_without_memory_id():
    result = memory.retrieve_actor_history(MagicMock(), "", "alice", "anything")
    assert result == "memory is not enabled"


def test_save_failure_is_swallowed():
    client = MagicMock()
    client.create_event.side_effect = RuntimeError("service down")
    memory.save_investigation(client, "mem-1", "alice", "session", "event", "verdict")


def test_save_builds_conversational_payload():
    client = MagicMock()
    memory.save_investigation(
        client, "mem-1", "alice", "ASIAKEY", "event summary", "verdict summary"
    )
    kwargs = client.create_event.call_args.kwargs
    assert kwargs["actorId"] == "alice"
    assert kwargs["sessionId"] == "ASIAKEY"
    roles = [item["conversational"]["role"] for item in kwargs["payload"]]
    assert roles == ["USER", "ASSISTANT"]

# SPDX-License-Identifier: Apache-2.0
"""AgentCore Memory access, best-effort.

Memory failures never block a notification: every call swallows client
errors and returns a degraded result instead.
"""

import logging
from datetime import UTC, datetime

logger = logging.getLogger()

MAX_RECORDS = 10


def retrieve_actor_history(memory_client, memory_id: str, actor_id: str, query: str) -> str:
    """Long-term memory records for an actor, semantic search over facts."""
    if not memory_id:
        return "memory is not enabled"
    try:
        response = memory_client.retrieve_memory_records(
            memoryId=memory_id,
            namespace=f"/actors/{actor_id}/facts",
            searchCriteria={"searchQuery": query[:500], "topK": MAX_RECORDS},
        )
        records = [
            summary.get("content", {}).get("text", "")
            for summary in response.get("memoryRecordSummaries", [])
        ]
        records = [text for text in records if text]
        if not records:
            return "no prior history for this actor"
        return "\n".join(f"- {text}" for text in records)
    except Exception as error:  # noqa: BLE001 memory is best-effort
        logger.warning("memory retrieval failed: %s", error)
        return "memory retrieval failed"


def save_investigation(
    memory_client,
    memory_id: str,
    actor_id: str,
    session_id: str,
    event_summary: str,
    verdict_summary: str,
) -> None:
    """Persist the investigation as a conversational event so the built-in
    semantic and summary strategies extract long-term records from it."""
    if not memory_id:
        return
    try:
        memory_client.create_event(
            memoryId=memory_id,
            actorId=actor_id,
            sessionId=session_id,
            eventTimestamp=datetime.now(UTC),
            payload=[
                {
                    "conversational": {
                        "role": "USER",
                        "content": {"text": event_summary[:4000]},
                    }
                },
                {
                    "conversational": {
                        "role": "ASSISTANT",
                        "content": {"text": verdict_summary[:4000]},
                    }
                },
            ],
        )
    except Exception as error:  # noqa: BLE001 memory is best-effort
        logger.warning("memory save failed: %s", error)

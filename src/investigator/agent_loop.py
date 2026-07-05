# SPDX-License-Identifier: Apache-2.0
"""A deliberately small agent loop on the Bedrock Converse API.

No framework: the loop is a few dozen lines, which keeps token guardrails
exact and dependencies to boto3 only. The agent concludes by calling the
submit_verdict tool; when the turn or token ceiling approaches, it is forced
to conclude with whatever evidence it has.
"""

import json
import logging

logger = logging.getLogger()

MAX_TOKENS_PER_CALL = 1500

VERDICT_TOOL = {
    "toolSpec": {
        "name": "submit_verdict",
        "description": (
            "Submit the final investigation verdict. Call this exactly once, "
            "when the investigation is complete or when instructed to conclude."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "verdict": {
                        "type": "string",
                        "enum": [
                            "manual-change-confirmed",
                            "likely-sanctioned-activity",
                            "suspicious",
                        ],
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["low", "medium", "high"],
                    },
                    "purpose": {
                        "type": "string",
                        "description": (
                            "What the user was apparently trying to accomplish, "
                            "one or two sentences."
                        ),
                    },
                    "security_severity": {
                        "type": "string",
                        "enum": ["none", "low", "medium", "high", "critical"],
                    },
                    "security_analysis": {
                        "type": "string",
                        "description": (
                            "Security posture impact: privilege escalation, public "
                            "exposure, weakened defenses, secrets. One to three sentences."
                        ),
                    },
                    "cost_impact": {
                        "type": "string",
                        "enum": ["negligible", "low", "moderate", "significant", "savings"],
                    },
                    "cost_analysis": {
                        "type": "string",
                        "description": (
                            "Monthly spend impact with a rough dollar range when "
                            "inferable. One to three sentences."
                        ),
                    },
                    "session_narrative": {
                        "type": "string",
                        "description": (
                            "Timeline of the console session: what was read and changed "
                            "before and after this event, adjacent changes."
                        ),
                    },
                    "history_context": {
                        "type": "string",
                        "description": (
                            "Relevant prior verdicts and patterns for this actor "
                            "from memory, or 'none'."
                        ),
                    },
                    "recommendation": {
                        "type": "string",
                        "description": (
                            "What the account owner should do: import into IaC, revert, "
                            "ask the user, or ignore. One or two sentences."
                        ),
                    },
                },
                "required": [
                    "verdict",
                    "confidence",
                    "purpose",
                    "security_severity",
                    "security_analysis",
                    "cost_impact",
                    "cost_analysis",
                    "session_narrative",
                    "history_context",
                    "recommendation",
                ],
            }
        },
    }
}


def build_tool_config(tool_specs: list) -> dict:
    return {"tools": tool_specs + [VERDICT_TOOL]}


def run_agent(
    bedrock_client,
    model_id: str,
    system_prompt: str,
    user_prompt: str,
    tool_specs: list,
    tool_dispatch: dict,
    max_turns: int,
    max_total_tokens: int,
) -> tuple[dict | None, dict]:
    """Run the tool-use loop until submit_verdict or a ceiling is hit.

    Returns (verdict_or_None, usage) where usage has inputTokens and
    outputTokens accumulated across all calls.
    """
    messages = [{"role": "user", "content": [{"text": user_prompt}]}]
    usage = {"inputTokens": 0, "outputTokens": 0}
    tool_config = build_tool_config(tool_specs)
    conclude_requested = False

    for turn in range(max_turns):
        response = bedrock_client.converse(
            modelId=model_id,
            system=[{"text": system_prompt}],
            messages=messages,
            toolConfig=tool_config,
            inferenceConfig={"maxTokens": MAX_TOKENS_PER_CALL},
        )
        call_usage = response.get("usage", {})
        usage["inputTokens"] += call_usage.get("inputTokens", 0)
        usage["outputTokens"] += call_usage.get("outputTokens", 0)

        message = response.get("output", {}).get("message", {})
        messages.append(message)

        tool_uses = [
            block["toolUse"]
            for block in message.get("content", [])
            if "toolUse" in block
        ]

        if not tool_uses:
            if response.get("stopReason") == "end_turn" and not conclude_requested:
                # The model answered in prose. Ask it to conclude formally.
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {"text": "Call submit_verdict now with your conclusion."}
                        ],
                    }
                )
                conclude_requested = True
                continue
            break

        tool_results = []
        verdict = None
        for tool_use in tool_uses:
            name = tool_use["name"]
            tool_input = tool_use.get("input") or {}
            if name == "submit_verdict":
                verdict = tool_input
                tool_results.append(
                    _tool_result(tool_use["toolUseId"], {"status": "accepted"})
                )
                continue
            handler = tool_dispatch.get(name)
            if handler is None:
                tool_results.append(
                    _tool_result(tool_use["toolUseId"], {"error": f"unknown tool {name}"})
                )
                continue
            try:
                output = handler(**tool_input)
            except Exception as error:  # noqa: BLE001 tool failures go to the model
                logger.warning("tool %s failed: %s", name, error)
                output = json.dumps({"error": str(error)[:500]})
            tool_results.append(_tool_result(tool_use["toolUseId"], output))

        if verdict is not None:
            return verdict, usage

        messages.append({"role": "user", "content": tool_results})

        total = usage["inputTokens"] + usage["outputTokens"]
        approaching_ceiling = total >= int(max_total_tokens * 0.8)
        last_turn_next = turn >= max_turns - 2
        if (approaching_ceiling or last_turn_next) and not conclude_requested:
            messages.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "text": (
                                "Investigation budget is nearly exhausted. Stop "
                                "using tools and call submit_verdict now with "
                                "your best conclusion from the evidence so far."
                            )
                        }
                    ],
                }
            )
            conclude_requested = True

    return None, usage


def _tool_result(tool_use_id: str, content) -> dict:
    if isinstance(content, str):
        payload = [{"text": content}]
    else:
        payload = [{"json": content}]
    return {
        "toolResult": {
            "toolUseId": tool_use_id,
            "content": payload,
        }
    }

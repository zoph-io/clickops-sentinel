# SPDX-License-Identifier: Apache-2.0
"""Agent loop behavior with a scripted fake Bedrock client."""

import agent_loop

VERDICT_INPUT = {
    "verdict": "manual-change-confirmed",
    "confidence": "high",
    "purpose": "Testing",
    "security_severity": "low",
    "security_analysis": "None found.",
    "cost_impact": "low",
    "cost_analysis": "Minor.",
    "session_narrative": "Single change.",
    "history_context": "none",
    "recommendation": "Import into IaC.",
}


class FakeBedrock:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def tool_use_response(name, tool_input, usage=(100, 50)):
    return {
        "stopReason": "tool_use",
        "usage": {"inputTokens": usage[0], "outputTokens": usage[1]},
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "t1",
                            "name": name,
                            "input": tool_input,
                        }
                    }
                ],
            }
        },
    }


def prose_response(text="I think this is fine.", usage=(100, 50)):
    return {
        "stopReason": "end_turn",
        "usage": {"inputTokens": usage[0], "outputTokens": usage[1]},
        "output": {
            "message": {"role": "assistant", "content": [{"text": text}]}
        },
    }


TOOL_SPEC = [
    {
        "toolSpec": {
            "name": "lookup",
            "description": "test tool",
            "inputSchema": {"json": {"type": "object", "properties": {}}},
        }
    }
]


def run(bedrock, dispatch=None, max_turns=8, max_total_tokens=60000):
    return agent_loop.run_agent(
        bedrock_client=bedrock,
        model_id="us.anthropic.claude-sonnet-4-6",
        system_prompt="system",
        user_prompt="investigate",
        tool_specs=TOOL_SPEC,
        tool_dispatch=dispatch or {"lookup": lambda **kwargs: "{}"},
        max_turns=max_turns,
        max_total_tokens=max_total_tokens,
    )


def test_tool_call_then_verdict():
    bedrock = FakeBedrock(
        [
            tool_use_response("lookup", {}),
            tool_use_response("submit_verdict", VERDICT_INPUT),
        ]
    )
    verdict, usage = run(bedrock)
    assert verdict["verdict"] == "manual-change-confirmed"
    assert usage == {"inputTokens": 200, "outputTokens": 100}
    assert len(bedrock.calls) == 2


def test_prose_answer_is_asked_to_conclude():
    bedrock = FakeBedrock(
        [
            prose_response(),
            tool_use_response("submit_verdict", VERDICT_INPUT),
        ]
    )
    verdict, _ = run(bedrock)
    assert verdict is not None
    # The follow-up user message asks for a formal conclusion.
    last_messages = bedrock.calls[1]["messages"]
    assert any(
        "submit_verdict" in block.get("text", "")
        for message in last_messages
        for block in message.get("content", [])
        if isinstance(block, dict)
    )


def test_model_that_never_concludes_returns_none():
    bedrock = FakeBedrock([prose_response(), prose_response()])
    verdict, usage = run(bedrock)
    assert verdict is None
    assert usage["inputTokens"] == 200


def test_token_ceiling_forces_conclusion():
    bedrock = FakeBedrock(
        [
            tool_use_response("lookup", {}, usage=(50000, 5000)),
            tool_use_response("submit_verdict", VERDICT_INPUT),
        ]
    )
    verdict, _ = run(bedrock, max_total_tokens=60000)
    assert verdict is not None
    second_call_messages = bedrock.calls[1]["messages"]
    texts = [
        block.get("text", "")
        for message in second_call_messages
        for block in message.get("content", [])
        if isinstance(block, dict)
    ]
    assert any("nearly exhausted" in text for text in texts)


def test_turn_cap_is_enforced():
    responses = [tool_use_response("lookup", {}) for _ in range(10)]
    bedrock = FakeBedrock(responses)
    verdict, _ = run(bedrock, max_turns=3)
    assert verdict is None
    assert len(bedrock.calls) == 3


def test_unknown_tool_reports_error_to_model():
    bedrock = FakeBedrock(
        [
            tool_use_response("nonexistent", {}),
            tool_use_response("submit_verdict", VERDICT_INPUT),
        ]
    )
    verdict, _ = run(bedrock)
    assert verdict is not None
    tool_results = [
        block["toolResult"]
        for message in bedrock.calls[1]["messages"]
        for block in message.get("content", [])
        if isinstance(block, dict) and "toolResult" in block
    ]
    assert any("error" in result["content"][0].get("json", {}) for result in tool_results)


def test_tool_exception_is_passed_to_model_not_raised():
    def broken(**kwargs):
        raise RuntimeError("boom")

    bedrock = FakeBedrock(
        [
            tool_use_response("lookup", {}),
            tool_use_response("submit_verdict", VERDICT_INPUT),
        ]
    )
    verdict, _ = run(bedrock, dispatch={"lookup": broken})
    assert verdict is not None

    max_tokens = bedrock.calls[0]["inferenceConfig"]["maxTokens"]
    assert max_tokens == agent_loop.MAX_TOKENS_PER_CALL

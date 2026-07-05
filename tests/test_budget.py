# SPDX-License-Identifier: Apache-2.0
"""Daily token budget counter with a mocked DynamoDB client."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

import budget


def test_tokens_used_today_empty_table():
    dynamodb = MagicMock()
    dynamodb.get_item.return_value = {}
    assert budget.tokens_used_today(dynamodb, "table") == 0


def test_tokens_used_today_reads_counter():
    dynamodb = MagicMock()
    dynamodb.get_item.return_value = {"Item": {"tokens_used": {"N": "12345"}}}
    assert budget.tokens_used_today(dynamodb, "table") == 12345


def test_consume_tokens_adds_atomically():
    dynamodb = MagicMock()
    dynamodb.update_item.return_value = {"Attributes": {"tokens_used": {"N": "5000"}}}
    total = budget.consume_tokens(dynamodb, "table", 5000)
    assert total == 5000
    kwargs = dynamodb.update_item.call_args.kwargs
    assert "ADD tokens_used" in kwargs["UpdateExpression"]
    assert kwargs["ExpressionAttributeValues"][":tokens"] == {"N": "5000"}


def test_exhaustion_notice_is_sent_once():
    dynamodb = MagicMock()
    dynamodb.put_item.side_effect = [
        {},
        ClientError(
            {"Error": {"Code": "ConditionalCheckFailedException", "Message": ""}},
            "PutItem",
        ),
    ]
    assert budget.try_claim_exhaustion_notice(dynamodb, "table") is True
    assert budget.try_claim_exhaustion_notice(dynamodb, "table") is False

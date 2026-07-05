# SPDX-License-Identifier: Apache-2.0
"""Daily Bedrock token budget backed by a DynamoDB atomic counter."""

import time
from datetime import UTC, datetime

from botocore.exceptions import ClientError

BUDGET_ITEM_TTL_SECONDS = 3 * 24 * 3600


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


def tokens_used_today(dynamodb_client, table_name: str) -> int:
    response = dynamodb_client.get_item(
        TableName=table_name,
        Key={"pk": {"S": f"BUDGET#{_today()}"}, "sk": {"S": "TOKENS"}},
    )
    item = response.get("Item")
    if not item:
        return 0
    return int(item.get("tokens_used", {}).get("N", "0"))


def consume_tokens(dynamodb_client, table_name: str, tokens: int) -> int:
    """Add tokens to today's counter, returns the new total."""
    response = dynamodb_client.update_item(
        TableName=table_name,
        Key={"pk": {"S": f"BUDGET#{_today()}"}, "sk": {"S": "TOKENS"}},
        UpdateExpression="ADD tokens_used :tokens SET #ttl = if_not_exists(#ttl, :ttl)",
        ExpressionAttributeNames={"#ttl": "ttl"},
        ExpressionAttributeValues={
            ":tokens": {"N": str(tokens)},
            ":ttl": {"N": str(int(time.time()) + BUDGET_ITEM_TTL_SECONDS)},
        },
        ReturnValues="UPDATED_NEW",
    )
    return int(response["Attributes"]["tokens_used"]["N"])


def try_claim_exhaustion_notice(dynamodb_client, table_name: str) -> bool:
    """True when this caller should send today's one-time budget notice."""
    try:
        dynamodb_client.put_item(
            TableName=table_name,
            Item={
                "pk": {"S": f"BUDGETNOTICE#{_today()}"},
                "sk": {"S": "SENT"},
                "ttl": {"N": str(int(time.time()) + BUDGET_ITEM_TTL_SECONDS)},
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        return True
    except ClientError as error:
        if error.response["Error"]["Code"] == "ConditionalCheckFailedException":
            return False
        raise

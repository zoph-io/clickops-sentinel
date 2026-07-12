# SPDX-License-Identifier: Apache-2.0
"""Print investigation statistics from the ClickOps Sentinel state table.

Usage: python scripts/stats.py --stack-name clickops-sentinel --region us-east-1 --days 30
"""

import argparse
from collections import Counter
from datetime import UTC, datetime, timedelta

import boto3


def resolve_table_name(stack_name: str, region: str) -> str:
    cloudformation = boto3.client("cloudformation", region_name=region)
    response = cloudformation.describe_stacks(StackName=stack_name)
    for output in response["Stacks"][0].get("Outputs", []):
        if output["OutputKey"] == "StateTableName":
            return output["OutputValue"]
    raise SystemExit(f"StateTableName output not found on stack {stack_name}")


def fetch_investigations(table_name: str, region: str, days: int) -> list:
    dynamodb = boto3.client("dynamodb", region_name=region)
    since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    items = []
    kwargs = {
        "TableName": table_name,
        "KeyConditionExpression": "pk = :pk AND sk >= :since",
        "ExpressionAttributeValues": {
            ":pk": {"S": "INVESTIGATION"},
            ":since": {"S": since},
        },
    }
    while True:
        response = dynamodb.query(**kwargs)
        items.extend(response.get("Items", []))
        token = response.get("LastEvaluatedKey")
        if not token:
            break
        kwargs["ExclusiveStartKey"] = token
    return items


def print_counter(title: str, counter: Counter, limit: int = 10) -> None:
    print(f"\n{title}")
    for key, count in counter.most_common(limit):
        print(f"  {count:5d}  {key}")


def main() -> None:
    parser = argparse.ArgumentParser(description="ClickOps Sentinel statistics")
    parser.add_argument("--stack-name", default="clickops-sentinel")
    parser.add_argument("--region", default=None)
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()

    table_name = resolve_table_name(args.stack_name, args.region)
    items = fetch_investigations(table_name, args.region, args.days)

    if not items:
        print(f"No investigations recorded in the last {args.days} days.")
        return

    actors = Counter()
    verdicts = Counter()
    severities = Counter()
    cost_impacts = Counter()
    services = Counter()
    total_tokens = 0
    for item in items:
        actors[item.get("actor", {}).get("S", "unknown")] += 1
        verdicts[item.get("verdict", {}).get("S", "unknown")] += 1
        severities[item.get("security_severity", {}).get("S", "none")] += 1
        cost_impacts[item.get("cost_impact", {}).get("S", "negligible")] += 1
        services[item.get("event_source", {}).get("S", "unknown")] += 1
        total_tokens += int(item.get("tokens_used", {}).get("N", "0"))

    print(f"ClickOps investigations, last {args.days} days: {len(items)}")
    print(f"Total Bedrock tokens used: {total_tokens}")
    print_counter("Top actors", actors)
    print_counter("Verdicts", verdicts)
    print_counter("Security severity", severities)
    print_counter("Cost impact", cost_impacts)
    print_counter("Services touched", services)


if __name__ == "__main__":
    main()

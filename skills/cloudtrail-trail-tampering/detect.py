#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "boto3>=1.34.0",
#     "botocore>=1.34.0",
# ]
# ///
"""
CloudTrail trail-tampering detection skill.

Detects events that disable or weaken audit logging:
- DeleteTrail
- StopLogging
- UpdateTrail (with logging disabled)
- PutBucketPublicAccessBlock (with all protections disabled)
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from botocore.client import BaseClient

# Event names we query for
TARGET_EVENT_NAMES: list[str] = [
    "DeleteTrail",
    "StopLogging",
    "UpdateTrail",
    "PutBucketPublicAccessBlock",
]

# Fixture data for --dry-run mode
DRY_RUN_FIXTURES: list[dict] = [
    {
        "EventId": "fixture-delete-001",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "malicious-user",
        "Resources": [
            {"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "audit-trail"}
        ],
        "CloudTrailEvent": json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/malicious-user",
                "principalId": "AIDAEXAMPLE",
                "userName": "malicious-user"
            },
            "requestParameters": {"name": "audit-trail"}
        })
    },
    {
        "EventId": "fixture-stop-001",
        "EventName": "StopLogging",
        "EventTime": datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "another-user",
        "Resources": [
            {"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "main-trail"}
        ],
        "CloudTrailEvent": json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/another-user"
            },
            "requestParameters": {"name": "main-trail"}
        })
    },
    {
        "EventId": "fixture-update-disable-001",
        "EventName": "UpdateTrail",
        "EventTime": datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "attacker",
        "Resources": [
            {"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "prod-trail"}
        ],
        "CloudTrailEvent": json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/attacker"
            },
            "requestParameters": {"name": "prod-trail", "isLogging": False}
        })
    },
    {
        "EventId": "fixture-pab-disabled-001",
        "EventName": "PutBucketPublicAccessBlock",
        "EventTime": datetime(2024, 1, 15, 13, 0, 0, tzinfo=timezone.utc),
        "EventSource": "s3.amazonaws.com",
        "Username": "bucket-modifier",
        "Resources": [
            {"ResourceType": "AWS::S3::Bucket", "ResourceName": "sensitive-logs-bucket"}
        ],
        "CloudTrailEvent": json.dumps({
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/bucket-modifier"
            },
            "requestParameters": {
                "bucketName": "sensitive-logs-bucket",
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            }
        })
    }
]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """
    Parse CLI arguments for trail tampering detection.

    Args:
        argv: Command-line arguments. If None, uses sys.argv[1:].

    Returns:
        Namespace with:
            - lookback_hours: int (default 24)
            - dry_run: bool (default False)
    """
    parser = argparse.ArgumentParser(
        description="Detect CloudTrail events that disable or weaken audit logging."
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        default=24,
        help="Hours to look back for events (default: 24)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use fixture data instead of AWS API",
    )
    return parser.parse_args(argv)


def fetch_events(client: "BaseClient", lookback_hours: int) -> list[dict]:
    """
    Fetch CloudTrail events for target event names within lookback window.

    Args:
        client: boto3 CloudTrail client
        lookback_hours: Hours to look back from current time

    Returns:
        List of CloudTrail event dicts as returned by LookupEvents API

    Raises:
        botocore.exceptions.ClientError: On AWS API errors
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=lookback_hours)

    all_events: list[dict] = []

    for event_name in TARGET_EVENT_NAMES:
        # Manual pagination - LookupEvents does NOT support get_paginator()
        next_token: str | None = None

        while True:
            kwargs: dict = {
                "LookupAttributes": [
                    {"AttributeKey": "EventName", "AttributeValue": event_name}
                ],
                "StartTime": start_time,
                "EndTime": end_time,
            }
            if next_token is not None:
                kwargs["NextToken"] = next_token

            response = client.lookup_events(**kwargs)
            all_events.extend(response.get("Events", []))

            next_token = response.get("NextToken")
            if next_token is None:
                break

    return all_events


def is_tampering_event(event: dict) -> bool:
    """
    Determine if a CloudTrail event represents audit trail tampering.

    Args:
        event: CloudTrail event dict with 'EventName' and 'CloudTrailEvent' keys

    Returns:
        True if event is a tampering event, False otherwise

    Classification Rules:
        - DeleteTrail: Always tampering
        - StopLogging: Always tampering
        - UpdateTrail: Tampering only if requestParameters.isLogging is False
        - PutBucketPublicAccessBlock: Tampering only if ALL FOUR protections are False
    """
    event_name = event.get("EventName", "")

    # Unconditional tampering events
    if event_name in ("DeleteTrail", "StopLogging"):
        return True

    # Parse CloudTrailEvent JSON for detailed inspection
    cloud_trail_event_str = event.get("CloudTrailEvent", "{}")
    try:
        cloud_trail_event = json.loads(cloud_trail_event_str)
    except json.JSONDecodeError:
        return False

    request_params = cloud_trail_event.get("requestParameters", {})

    # UpdateTrail: only flag if isLogging explicitly False
    if event_name == "UpdateTrail":
        return request_params.get("isLogging") is False

    # PutBucketPublicAccessBlock: flag if ALL FOUR protections disabled
    if event_name == "PutBucketPublicAccessBlock":
        config = request_params.get("PublicAccessBlockConfiguration", {})
        return (
            config.get("BlockPublicAcls") is False
            and config.get("IgnorePublicAcls") is False
            and config.get("BlockPublicPolicy") is False
            and config.get("RestrictPublicBuckets") is False
        )

    return False


def extract_finding(event: dict) -> dict:
    """
    Extract finding fields from a CloudTrail event.

    Args:
        event: CloudTrail event dict

    Returns:
        Dict with keys:
            - event_time: str (ISO 8601 UTC, format: YYYY-MM-DDTHH:MM:SS+00:00)
            - principal: str (ARN, userName, or principalId)
            - action: str (EventName)
            - target_resource: str (trail name or bucket name)
            - severity: str (always "high")

    Note:
        Python's datetime.isoformat() produces '+00:00' suffix for UTC,
        not 'Z'. Both are valid ISO 8601.
    """
    # Parse CloudTrailEvent for user identity and request params
    cloud_trail_event_str = event.get("CloudTrailEvent", "{}")
    try:
        cloud_trail_event = json.loads(cloud_trail_event_str)
    except json.JSONDecodeError:
        cloud_trail_event = {}

    user_identity = cloud_trail_event.get("userIdentity", {})
    request_params = cloud_trail_event.get("requestParameters", {})

    # Extract principal with fallback chain
    principal = (
        user_identity.get("arn")
        or user_identity.get("userName")
        or user_identity.get("principalId")
        or "unknown"
    )

    # Extract target resource
    target_resource = (
        request_params.get("name")  # Trail name for CloudTrail events
        or request_params.get("bucketName")  # Bucket name for S3 events
        or (
            event.get("Resources", [{}])[0].get("ResourceName")
            if event.get("Resources")
            else None
        )
        or "unknown"
    )

    # Format event time as ISO 8601
    event_time = event.get("EventTime")
    if hasattr(event_time, "isoformat"):
        event_time_str = event_time.isoformat()
    else:
        event_time_str = str(event_time)

    return {
        "event_time": event_time_str,
        "principal": principal,
        "action": event.get("EventName", "unknown"),
        "target_resource": target_resource,
        "severity": "high",
    }


def format_markdown_table(findings: list[dict]) -> str:
    """
    Format findings as a markdown table.

    Args:
        findings: List of finding dicts from extract_finding()

    Returns:
        Markdown table string with header and separator rows,
        even if findings list is empty.

    Output Format:
        | event_time | principal | action | target_resource | severity |
        |------------|-----------|--------|-----------------|----------|
        | 2024-01-15T10:30:00+00:00 | arn:aws:iam::... | DeleteTrail | audit-trail | high |
    """
    headers = ["event_time", "principal", "action", "target_resource", "severity"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(["----------"] * len(headers)) + "|",
    ]
    for f in findings:
        row = [str(f.get(h, "")) for h in headers]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """
    Main entry point for trail tampering detection.

    Args:
        argv: Command-line arguments. If None, uses sys.argv[1:].

    Returns:
        0 on success, 1 on error

    Flow:
        1. Parse arguments
        2. Fetch events (from fixtures if --dry-run, else AWS API)
        3. Filter to tampering events via is_tampering_event()
        4. Extract findings via extract_finding()
        5. Format and print markdown table
    """
    args = parse_args(argv)

    if args.dry_run:
        events = DRY_RUN_FIXTURES
    else:
        try:
            import boto3
            import botocore.exceptions

            client = boto3.client("cloudtrail")
            events = fetch_events(client, args.lookback_hours)
        except botocore.exceptions.ClientError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    tampering_events = [e for e in events if is_tampering_event(e)]
    findings = [extract_finding(e) for e in tampering_events]

    table = format_markdown_table(findings)
    print(table)

    return 0


if __name__ == "__main__":
    sys.exit(main())

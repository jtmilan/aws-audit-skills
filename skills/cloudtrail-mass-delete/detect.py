#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "boto3>=1.34.0",
# ]
# ///

"""
CloudTrail Mass Delete Detector

Detects bursts of >10 Delete* API calls within 5-minute windows from the same
principal in CloudTrail logs.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Type alias for CloudTrail event dict (as returned by boto3)
CloudTrailEvent = dict[str, Any]

# Detection parameters (hardcoded per PRD scope)
WINDOW_SECONDS: int = 300  # 5 minutes
BURST_THRESHOLD: int = 10  # >10 events triggers detection
MAX_SAMPLE_ACTIONS: int = 3


@dataclass(frozen=True, slots=True)
class BurstWindow:
    """Represents a detected burst of delete operations within a time window."""
    window_start: datetime  # UTC, start of 5-min window
    principal: str          # IAM principal ARN
    action_count: int       # Number of Delete* events in window
    sample_actions: tuple[str, ...]  # Up to 3 unique action names, sorted alphabetically


def extract_principal(event: CloudTrailEvent) -> str | None:
    """
    Extract IAM principal ARN from CloudTrail event.

    Args:
        event: CloudTrail event dict with 'CloudTrailEvent' JSON string

    Returns:
        Principal ARN string, or None if not extractable

    Extraction priority:
        1. userIdentity.arn (most common)
        2. Fall back to "{accountId}:{userName}" format if arn missing
        3. None if userIdentity is missing entirely
    """
    try:
        cloud_trail_event_str = event.get("CloudTrailEvent", "{}")
        cloud_trail_event = json.loads(cloud_trail_event_str)
        user_identity = cloud_trail_event.get("userIdentity", {})

        # Priority 1: Extract ARN
        if "arn" in user_identity:
            return user_identity["arn"]

        # Priority 2: Fallback to accountId:userName
        account_id = user_identity.get("accountId")
        user_name = user_identity.get("userName")
        if account_id and user_name:
            return f"{account_id}:{user_name}"

        # Priority 3: None if no identifiable principal
        return None
    except (json.JSONDecodeError, AttributeError, KeyError):
        return None


def parse_event_time(event: CloudTrailEvent) -> datetime:
    """
    Parse EventTime from CloudTrail event to UTC datetime.

    Args:
        event: CloudTrail event dict with 'EventTime' key

    Returns:
        datetime in UTC (timezone-aware)

    Raises:
        ValueError: If EventTime is missing or unparseable

    Note:
        EventTime from boto3 is already a datetime object.
        For fixture JSON, it's an ISO 8601 string that needs parsing.
    """
    event_time = event.get("EventTime")
    if event_time is None:
        raise ValueError("EventTime is missing from event")

    # If it's already a datetime object (from boto3), ensure it's UTC
    if isinstance(event_time, datetime):
        if event_time.tzinfo is None:
            return event_time.replace(tzinfo=timezone.utc)
        return event_time.astimezone(timezone.utc)

    # If it's a string (from fixture JSON), parse it
    if isinstance(event_time, str):
        try:
            # Parse ISO 8601 format
            dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            return dt.astimezone(timezone.utc)
        except ValueError as e:
            raise ValueError(f"Unable to parse EventTime: {event_time}") from e

    raise ValueError(f"EventTime has unexpected type: {type(event_time)}")


def detect_mass_deletes(
    events: list[CloudTrailEvent],
    threshold: int = BURST_THRESHOLD,
    window_seconds: int = WINDOW_SECONDS,
) -> list[BurstWindow]:
    """
    Detect mass deletion bursts using sliding window algorithm.

    Args:
        events: List of CloudTrail event dicts
        threshold: Minimum events to trigger detection (exclusive: >threshold)
        window_seconds: Window size in seconds

    Returns:
        List of BurstWindow instances, sorted by:
            1. action_count descending
            2. window_start ascending (for stable ordering)

    Algorithm:
        1. Filter to events where eventName.startswith('Delete')
        2. Group by principal ARN
        3. For each principal, sort events by time
        4. Apply sliding window: for each event, count events within
           [event_time, event_time + window_seconds)
        5. When count > threshold, record burst with window_start = event_time
        6. Skip overlapping windows (only report first qualifying window per burst)
    """
    # Step 1: Filter to Delete* events
    delete_events = [
        event for event in events
        if event.get("EventName", "").startswith("Delete")
    ]

    # Step 2: Group by principal ARN
    events_by_principal: dict[str, list[tuple[datetime, str]]] = {}
    for event in delete_events:
        principal = extract_principal(event)
        if principal is None:
            continue

        try:
            event_time = parse_event_time(event)
            event_name = event.get("EventName", "")

            if principal not in events_by_principal:
                events_by_principal[principal] = []
            events_by_principal[principal].append((event_time, event_name))
        except ValueError:
            # Skip events with unparseable timestamps
            continue

    # Step 3-6: For each principal, detect bursts using sliding window
    bursts: list[BurstWindow] = []

    for principal, principal_events in events_by_principal.items():
        # Sort events by time
        principal_events.sort(key=lambda x: x[0])

        # Track the end time of the last reported burst to skip overlapping windows
        last_burst_end: datetime | None = None

        # Sliding window
        for i, (start_time, _) in enumerate(principal_events):
            # Skip if this window would overlap with a previously detected burst
            if last_burst_end is not None and start_time < last_burst_end:
                continue

            # Define window end time
            end_time = start_time + timedelta(seconds=window_seconds)

            # Count events in this window and collect action names
            window_events = [
                (t, name) for t, name in principal_events
                if start_time <= t < end_time
            ]
            event_count = len(window_events)

            # Check if this window exceeds threshold
            if event_count > threshold:
                # Collect unique action names, sorted, limited to MAX_SAMPLE_ACTIONS
                action_names = sorted(set(name for _, name in window_events))[:MAX_SAMPLE_ACTIONS]

                bursts.append(BurstWindow(
                    window_start=start_time,
                    principal=principal,
                    action_count=event_count,
                    sample_actions=tuple(action_names),
                ))

                # Mark this burst's end time to skip overlapping windows
                last_burst_end = end_time

    # Sort results: action_count descending, then window_start ascending
    bursts.sort(key=lambda b: (-b.action_count, b.window_start))

    return bursts


def format_output(windows: list[BurstWindow]) -> str:
    """
    Format detection results as markdown.

    Args:
        windows: List of BurstWindow instances (may be empty)

    Returns:
        Markdown string:
        - If windows empty: "## No Mass Delete Activity Detected"
        - Otherwise: Markdown table with columns:
            window_start | principal | action_count | sample_actions

    Output format:
        | window_start | principal | action_count | sample_actions |
        |--------------|-----------|--------------|----------------|
        | 2026-04-26T10:05:00Z | arn:aws:iam::123456789012:user/admin | 15 | DeleteBucket, DeleteObject, DeleteUser |
    """
    if not windows:
        return "## No Mass Delete Activity Detected"

    # Build markdown table
    lines = [
        "| window_start | principal | action_count | sample_actions |",
        "|--------------|-----------|--------------|----------------|",
    ]

    for window in windows:
        # Format timestamp as ISO 8601 with Z suffix
        timestamp = window.window_start.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Join sample actions with comma-space
        actions = ", ".join(window.sample_actions)

        lines.append(
            f"| {timestamp} | {window.principal} | {window.action_count} | {actions} |"
        )

    return "\n".join(lines)


def fetch_events(
    client: Any,  # boto3 CloudTrail client
    lookback_hours: int,
    principal_filter: str | None = None,
) -> list[CloudTrailEvent]:
    """
    Fetch CloudTrail events for the specified time range.

    Args:
        client: boto3 CloudTrail client
        lookback_hours: Hours of history to query
        principal_filter: Optional principal ARN to filter results

    Returns:
        List of CloudTrail event dicts

    Implementation:
        - Uses lookup_events with pagination (handles NextToken)
        - Captures 'now' once at start for consistent time range
        - StartTime = now - timedelta(hours=lookback_hours)
        - EndTime = now
        - Principal filtering applied client-side after fetch
          (CloudTrail API doesn't support principal filter directly)
    """
    # Capture current time for consistent time range
    now = datetime.now(timezone.utc)
    start_time = now - timedelta(hours=lookback_hours)

    events: list[CloudTrailEvent] = []
    next_token = None

    # Paginate through all results
    while True:
        kwargs = {
            "StartTime": start_time,
            "EndTime": now,
            "MaxResults": 50,
        }
        if next_token:
            kwargs["NextToken"] = next_token

        response = client.lookup_events(**kwargs)
        events.extend(response.get("Events", []))

        next_token = response.get("NextToken")
        if not next_token:
            break

    # Apply client-side principal filtering if requested
    if principal_filter:
        events = [
            event for event in events
            if extract_principal(event) == principal_filter
        ]

    return events


def load_fixture_events() -> list[CloudTrailEvent]:
    """
    Load events from fixtures/events.json for --dry-run mode.

    Returns:
        List of CloudTrail event dicts from fixture file

    Raises:
        FileNotFoundError: If fixtures/events.json doesn't exist
        json.JSONDecodeError: If fixture file is invalid JSON
    """
    # Determine fixture path relative to this script
    script_dir = Path(__file__).parent
    fixture_path = script_dir / "fixtures" / "events.json"

    if not fixture_path.exists():
        raise FileNotFoundError(f"Fixture file not found: {fixture_path}")

    with open(fixture_path) as f:
        data = json.load(f)

    return data.get("Events", [])


def main() -> None:
    """
    CLI entry point.

    Exit codes:
        0: Success (bursts detected or no bursts)
        1: Error (AWS API error, invalid arguments, etc.)

    Argument parsing:
        --lookback-hours HOURS  (required, int, >0)
        --principal ARN         (optional, str)
        --dry-run               (optional, flag)
    """
    parser = argparse.ArgumentParser(
        description="Detect mass deletion activity in CloudTrail logs."
    )
    parser.add_argument(
        "--lookback-hours",
        type=int,
        required=True,
        metavar="HOURS",
        help="Number of hours of CloudTrail history to analyze",
    )
    parser.add_argument(
        "--principal",
        type=str,
        metavar="ARN",
        help="Filter to specific IAM principal ARN",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Use fixture data instead of calling AWS APIs",
    )

    args = parser.parse_args()

    # Validate arguments
    if args.lookback_hours <= 0:
        print("Error: --lookback-hours must be a positive integer", file=sys.stderr)
        sys.exit(1)

    try:
        # Load events from fixture or AWS API
        if args.dry_run:
            events = load_fixture_events()
            # Apply client-side principal filtering for dry-run mode
            if args.principal:
                events = [
                    event for event in events
                    if extract_principal(event) == args.principal
                ]
        else:
            import boto3
            from botocore.exceptions import NoCredentialsError, ClientError

            try:
                client = boto3.client("cloudtrail")
                events = fetch_events(client, args.lookback_hours, args.principal)
            except NoCredentialsError:
                print("Error: AWS credentials not configured. Run 'aws configure' or set AWS_* env vars.", file=sys.stderr)
                sys.exit(1)
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "Unknown")
                error_msg = e.response.get("Error", {}).get("Message", str(e))
                if error_code == "AccessDeniedException":
                    print("Error: Access denied. Ensure IAM policy allows cloudtrail:LookupEvents.", file=sys.stderr)
                else:
                    print(f"Error: CloudTrail API error: {error_msg}", file=sys.stderr)
                sys.exit(1)

        # Detect bursts
        windows = detect_mass_deletes(events)

        # Format and print output
        output = format_output(windows)
        print(output)

        sys.exit(0)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in fixture file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

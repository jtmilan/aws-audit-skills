"""
Test suite for CloudTrail Mass Delete Detector

Tests use botocore.stub.Stubber to mock AWS API responses.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import ANY

import boto3
import pytest
from botocore.stub import Stubber

# Import functions under test
from detect import (
    BurstWindow,
    detect_mass_deletes,
    extract_principal,
    fetch_events,
    format_output,
    load_fixture_events,
    parse_event_time,
)


@pytest.fixture
def cloudtrail_client():
    """Create CloudTrail client for stubbing."""
    return boto3.client("cloudtrail", region_name="us-east-1")


@pytest.fixture
def base_time() -> datetime:
    """Fixed base time for deterministic tests."""
    return datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_name: str,
    event_time: datetime,
    principal_arn: str,
    event_id: str | None = None,
) -> dict:
    """
    Create a CloudTrail event dict matching AWS API response format.

    Args:
        event_name: e.g., "DeleteBucket"
        event_time: Event timestamp (UTC)
        principal_arn: IAM principal ARN
        event_id: Optional event ID (auto-generated if None)

    Returns:
        Dict matching CloudTrail LookupEvents response Event structure
    """
    return {
        "EventId": event_id or str(uuid.uuid4()),
        "EventName": event_name,
        "EventTime": event_time,
        "EventSource": "test.amazonaws.com",
        "Username": principal_arn.split("/")[-1] if "/" in principal_arn else "unknown",
        "Resources": [],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "type": "IAMUser",
                "arn": principal_arn,
            },
            "eventName": event_name,
            "eventTime": event_time.isoformat(),
        }),
    }


def test_burst_detected(cloudtrail_client, base_time):
    """
    Verify that >10 Delete* events in 5-minute window triggers detection.

    Setup:
        - 12 DeleteBucket events from same principal
        - All events within 4 minutes (well under 5-minute window)

    Expected:
        - One BurstWindow returned
        - action_count == 12
        - sample_actions contains "DeleteBucket"
    """
    principal = "arn:aws:iam::123456789012:user/admin"

    # Generate 12 events spread over 4 minutes (20 seconds apart)
    events = [
        make_event("DeleteBucket", base_time + timedelta(seconds=i * 20), principal)
        for i in range(12)
    ]

    # Stub the CloudTrail API response
    with Stubber(cloudtrail_client) as stubber:
        stubber.add_response(
            "lookup_events",
            {
                "Events": events,
            },
            expected_params={
                "StartTime": ANY,
                "EndTime": ANY,
                "MaxResults": 50,
            },
        )

        # Fetch events using stubbed client
        fetched = fetch_events(cloudtrail_client, lookback_hours=1)
        results = detect_mass_deletes(fetched)

        # Verify results
        assert len(results) == 1, f"Expected 1 burst, got {len(results)}"
        assert results[0].action_count == 12, f"Expected action_count=12, got {results[0].action_count}"
        assert "DeleteBucket" in results[0].sample_actions, f"Expected 'DeleteBucket' in sample_actions, got {results[0].sample_actions}"
        assert results[0].principal == principal, f"Expected principal={principal}, got {results[0].principal}"


def test_sub_threshold_ignored(cloudtrail_client, base_time):
    """
    Verify that ≤10 Delete* events in any window produces no burst output.

    Setup:
        - 10 DeleteBucket events from same principal within 5 minutes
        - Exactly at threshold (not above)

    Expected:
        - Empty list returned (no bursts)
        - Output is "## No Mass Delete Activity Detected"
    """
    principal = "arn:aws:iam::123456789012:user/admin"

    # Generate exactly 10 events spread over 4.5 minutes (30 seconds apart)
    events = [
        make_event("DeleteBucket", base_time + timedelta(seconds=i * 30), principal)
        for i in range(10)
    ]

    # Stub the CloudTrail API response
    with Stubber(cloudtrail_client) as stubber:
        stubber.add_response(
            "lookup_events",
            {
                "Events": events,
            },
            expected_params={
                "StartTime": ANY,
                "EndTime": ANY,
                "MaxResults": 50,
            },
        )

        # Fetch events using stubbed client
        fetched = fetch_events(cloudtrail_client, lookback_hours=1)
        results = detect_mass_deletes(fetched)

        # Verify no bursts detected
        assert len(results) == 0, f"Expected 0 bursts for exactly 10 events, got {len(results)}"

        # Verify output format
        output = format_output(results)
        assert output == "## No Mass Delete Activity Detected", f"Expected no activity message, got: {output}"


def test_multi_principal_ordering(cloudtrail_client, base_time):
    """
    Verify multiple principals are sorted by action_count descending.

    Setup:
        - Principal A: 15 delete events
        - Principal B: 20 delete events (largest count)
        - Principal C: 11 delete events (smallest burst)

    Expected:
        - 3 BurstWindow objects returned
        - Order: Principal B (20), Principal A (15), Principal C (11)
    """
    principal_a = "arn:aws:iam::123456789012:user/alice"
    principal_b = "arn:aws:iam::123456789012:user/bob"
    principal_c = "arn:aws:iam::123456789012:role/automation"

    # Generate events for each principal
    events = []

    # Principal A: 15 events (10 seconds apart, starting at base_time)
    for i in range(15):
        events.append(
            make_event("DeleteBucket", base_time + timedelta(seconds=i * 10), principal_a)
        )

    # Principal B: 20 events (10 seconds apart, starting at base_time + 10 minutes)
    for i in range(20):
        events.append(
            make_event("DeleteObject", base_time + timedelta(minutes=10, seconds=i * 10), principal_b)
        )

    # Principal C: 11 events (10 seconds apart, starting at base_time + 20 minutes)
    for i in range(11):
        events.append(
            make_event("DeleteUser", base_time + timedelta(minutes=20, seconds=i * 10), principal_c)
        )

    # Stub the CloudTrail API response
    with Stubber(cloudtrail_client) as stubber:
        stubber.add_response(
            "lookup_events",
            {
                "Events": events,
            },
            expected_params={
                "StartTime": ANY,
                "EndTime": ANY,
                "MaxResults": 50,
            },
        )

        # Fetch events using stubbed client
        fetched = fetch_events(cloudtrail_client, lookback_hours=1)
        results = detect_mass_deletes(fetched)

        # Verify 3 bursts detected
        assert len(results) == 3, f"Expected 3 bursts, got {len(results)}"

        # Verify ordering by action_count descending
        assert results[0].principal == principal_b, f"Expected first result to be {principal_b}, got {results[0].principal}"
        assert results[0].action_count == 20, f"Expected first result action_count=20, got {results[0].action_count}"

        assert results[1].principal == principal_a, f"Expected second result to be {principal_a}, got {results[1].principal}"
        assert results[1].action_count == 15, f"Expected second result action_count=15, got {results[1].action_count}"

        assert results[2].principal == principal_c, f"Expected third result to be {principal_c}, got {results[2].principal}"
        assert results[2].action_count == 11, f"Expected third result action_count=11, got {results[2].action_count}"


def test_extract_principal_fallback():
    """Test extract_principal with fallback to accountId:userName format."""
    # Test with ARN (primary path)
    event_with_arn = {
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/admin",
            }
        })
    }
    assert extract_principal(event_with_arn) == "arn:aws:iam::123456789012:user/admin"

    # Test fallback to accountId:userName
    event_without_arn = {
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "type": "IAMUser",
                "accountId": "123456789012",
                "userName": "admin",
            }
        })
    }
    assert extract_principal(event_without_arn) == "123456789012:admin"

    # Test with missing userIdentity
    event_no_identity = {
        "CloudTrailEvent": json.dumps({})
    }
    assert extract_principal(event_no_identity) is None


def test_parse_event_time_datetime():
    """Test parse_event_time with datetime object (from boto3)."""
    dt = datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc)
    event = {"EventTime": dt}
    result = parse_event_time(event)
    assert result == dt
    assert result.tzinfo == timezone.utc


def test_parse_event_time_string():
    """Test parse_event_time with ISO 8601 string (from fixture)."""
    event = {"EventTime": "2026-04-26T10:00:00Z"}
    result = parse_event_time(event)
    assert result == datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc)


def test_dry_run_mode_with_fixtures():
    """Test --dry-run mode by loading fixture data and detecting bursts."""
    # Load fixture events
    events = load_fixture_events()

    # Verify fixture loaded successfully
    assert len(events) > 0, "Fixture file should contain events"

    # Run detection on fixture data
    results = detect_mass_deletes(events)

    # The fixture should contain a burst scenario (15 Delete* events from admin user)
    # and a sub-threshold scenario (8 Delete* events from readonly user)
    assert len(results) >= 1, "Fixture should contain at least one burst scenario"

    # Verify the burst for admin user exists
    admin_bursts = [r for r in results if "admin" in r.principal.lower()]
    assert len(admin_bursts) >= 1, "Should detect burst from admin user in fixture"
    assert admin_bursts[0].action_count > 10, "Admin burst should have >10 events"


def test_format_output_table():
    """Test format_output generates correct markdown table."""
    windows = [
        BurstWindow(
            window_start=datetime(2026, 4, 26, 10, 5, 0, tzinfo=timezone.utc),
            principal="arn:aws:iam::123456789012:user/admin",
            action_count=15,
            sample_actions=("DeleteBucket", "DeleteObject", "DeleteUser"),
        ),
    ]

    output = format_output(windows)

    # Verify table structure
    assert "| window_start | principal | action_count | sample_actions |" in output
    assert "|--------------|-----------|--------------|----------------|" in output
    assert "2026-04-26T10:05:00Z" in output
    assert "arn:aws:iam::123456789012:user/admin" in output
    assert "15" in output
    assert "DeleteBucket, DeleteObject, DeleteUser" in output


def test_edge_case_exactly_11_events(base_time):
    """Test edge case: exactly 11 events should trigger a burst."""
    principal = "arn:aws:iam::123456789012:user/test"

    # Generate exactly 11 events within 5 minutes
    events = [
        make_event("DeleteBucket", base_time + timedelta(seconds=i * 20), principal)
        for i in range(11)
    ]

    results = detect_mass_deletes(events)

    # Should detect a burst (11 > 10)
    assert len(results) == 1, f"Expected 1 burst for 11 events, got {len(results)}"
    assert results[0].action_count == 11


def test_sample_actions_limited_to_three():
    """Test that sample_actions is limited to 3 and sorted alphabetically."""
    base_time = datetime(2026, 4, 26, 10, 0, 0, tzinfo=timezone.utc)
    principal = "arn:aws:iam::123456789012:user/test"

    # Create 12 events with 5 different action types
    events = [
        make_event("DeleteBucket", base_time + timedelta(seconds=0), principal),
        make_event("DeleteObject", base_time + timedelta(seconds=10), principal),
        make_event("DeleteUser", base_time + timedelta(seconds=20), principal),
        make_event("DeleteRole", base_time + timedelta(seconds=30), principal),
        make_event("DeleteFunction", base_time + timedelta(seconds=40), principal),
        make_event("DeleteBucket", base_time + timedelta(seconds=50), principal),
        make_event("DeleteObject", base_time + timedelta(seconds=60), principal),
        make_event("DeleteUser", base_time + timedelta(seconds=70), principal),
        make_event("DeleteRole", base_time + timedelta(seconds=80), principal),
        make_event("DeleteFunction", base_time + timedelta(seconds=90), principal),
        make_event("DeleteBucket", base_time + timedelta(seconds=100), principal),
        make_event("DeleteObject", base_time + timedelta(seconds=110), principal),
    ]

    results = detect_mass_deletes(events)

    assert len(results) == 1
    # Should have exactly 3 sample actions
    assert len(results[0].sample_actions) == 3, f"Expected 3 sample actions, got {len(results[0].sample_actions)}"
    # Should be sorted alphabetically (DeleteBucket, DeleteFunction, DeleteObject are first 3 alphabetically)
    assert results[0].sample_actions == ("DeleteBucket", "DeleteFunction", "DeleteObject")

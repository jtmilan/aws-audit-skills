"""Tests for cloudtrail-trail-tampering detection skill."""
import json
from datetime import datetime, timezone
from unittest.mock import ANY

import boto3
import pytest
from botocore.stub import Stubber

from detect import (
    DRY_RUN_FIXTURES,
    FIXTURE_ACCOUNT_ID,
    TARGET_EVENT_NAMES,
    extract_finding,
    fetch_events,
    is_tampering_event,
    resolve_account_id,
)


# ============================================================================
# Unit tests for is_tampering_event
# ============================================================================


def test_delete_trail_detected():
    """Verify DeleteTrail events are flagged as tampering."""
    event = {
        "EventId": "test-delete-001",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "test-user",
        "Resources": [{"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "test-trail"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "accountId": "123456789012"
            },
            "requestParameters": {"name": "test-trail"}
        })
    }

    assert is_tampering_event(event, "123456789012") is True

    finding = extract_finding(event)
    assert finding["action"] == "DeleteTrail"
    assert finding["severity"] == "high"
    assert finding["target_resource"] == "test-trail"


def test_stop_logging_detected():
    """Verify StopLogging events are flagged as tampering."""
    event = {
        "EventId": "test-stop-001",
        "EventName": "StopLogging",
        "EventTime": datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "test-user",
        "Resources": [{"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "main-trail"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "accountId": "123456789012"
            },
            "requestParameters": {"name": "main-trail"}
        })
    }

    assert is_tampering_event(event, "123456789012") is True

    finding = extract_finding(event)
    assert finding["action"] == "StopLogging"
    assert finding["severity"] == "high"


def test_harmless_update_trail_ignored():
    """Verify UpdateTrail without isLogging=False is NOT flagged."""
    # UpdateTrail that changes S3 bucket but doesn't disable logging
    event = {
        "EventId": "test-update-harmless-001",
        "EventName": "UpdateTrail",
        "EventTime": datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "admin-user",
        "Resources": [{"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "prod-trail"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/admin-user",
                "accountId": "123456789012"
            },
            "requestParameters": {
                "name": "prod-trail",
                "s3BucketName": "new-bucket-name"
                # Note: isLogging is NOT present, so this is harmless
            }
        })
    }

    assert is_tampering_event(event, "123456789012") is False


def test_update_trail_with_logging_disabled_detected():
    """Verify UpdateTrail with isLogging=False is flagged as tampering."""
    event = {
        "EventId": "test-update-disable-001",
        "EventName": "UpdateTrail",
        "EventTime": datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "attacker",
        "Resources": [{"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "prod-trail"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/attacker",
                "accountId": "123456789012"
            },
            "requestParameters": {"name": "prod-trail", "isLogging": False}
        })
    }

    assert is_tampering_event(event, "123456789012") is True

    finding = extract_finding(event)
    assert finding["action"] == "UpdateTrail"
    assert finding["severity"] == "high"
    assert finding["target_resource"] == "prod-trail"


def test_put_bucket_public_access_block_all_disabled_detected():
    """Verify PutBucketPublicAccessBlock with all protections disabled is flagged."""
    event = {
        "EventId": "test-pab-disabled-001",
        "EventName": "PutBucketPublicAccessBlock",
        "EventTime": datetime(2024, 1, 15, 13, 0, 0, tzinfo=timezone.utc),
        "EventSource": "s3.amazonaws.com",
        "Username": "bucket-modifier",
        "Resources": [{"ResourceType": "AWS::S3::Bucket", "ResourceName": "sensitive-logs-bucket"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/bucket-modifier",
                "accountId": "123456789012"
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

    assert is_tampering_event(event, "123456789012") is True

    finding = extract_finding(event)
    assert finding["action"] == "PutBucketPublicAccessBlock"
    assert finding["severity"] == "high"
    assert finding["target_resource"] == "sensitive-logs-bucket"


def test_put_bucket_public_access_block_partial_enabled_ignored():
    """Verify PutBucketPublicAccessBlock with some protections enabled is NOT flagged."""
    event = {
        "EventId": "test-pab-partial-001",
        "EventName": "PutBucketPublicAccessBlock",
        "EventTime": datetime(2024, 1, 15, 13, 0, 0, tzinfo=timezone.utc),
        "EventSource": "s3.amazonaws.com",
        "Username": "bucket-modifier",
        "Resources": [{"ResourceType": "AWS::S3::Bucket", "ResourceName": "some-bucket"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/bucket-modifier",
                "accountId": "123456789012"
            },
            "requestParameters": {
                "bucketName": "some-bucket",
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,  # This one is enabled
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            }
        })
    }

    assert is_tampering_event(event, "123456789012") is False


def test_unknown_event_ignored():
    """Verify unknown event types are NOT flagged."""
    event = {
        "EventId": "test-unknown-001",
        "EventName": "DescribeTrails",
        "EventTime": datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc),
        "EventSource": "cloudtrail.amazonaws.com",
        "Username": "some-user",
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/some-user",
                "accountId": "123456789012"
            },
            "requestParameters": {}
        })
    }

    assert is_tampering_event(event, "123456789012") is False


def test_invalid_json_in_cloud_trail_event():
    """Verify invalid JSON in CloudTrailEvent is handled gracefully."""
    event = {
        "EventId": "test-invalid-json-001",
        "EventName": "UpdateTrail",
        "EventTime": datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": "not valid json"
    }

    # Should return False (not classified as tampering) rather than raising
    assert is_tampering_event(event, "123456789012") is False


# ============================================================================
# Unit tests for extract_finding
# ============================================================================


def test_extract_finding_basic_fields():
    """Verify extract_finding extracts all required fields correctly."""
    event = {
        "EventId": "test-001",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test-user"},
            "requestParameters": {"name": "test-trail"}
        })
    }

    finding = extract_finding(event)

    assert finding["event_time"] == "2024-01-15T10:30:00+00:00"
    assert finding["principal"] == "arn:aws:iam::123456789012:user/test-user"
    assert finding["action"] == "DeleteTrail"
    assert finding["target_resource"] == "test-trail"
    assert finding["severity"] == "high"


def test_extract_finding_principal_fallback_username():
    """Verify extract_finding falls back to userName when arn is missing."""
    event = {
        "EventId": "test-002",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"userName": "fallback-user"},
            "requestParameters": {"name": "test-trail"}
        })
    }

    finding = extract_finding(event)
    assert finding["principal"] == "fallback-user"


def test_extract_finding_principal_fallback_principal_id():
    """Verify extract_finding falls back to principalId when arn and userName missing."""
    event = {
        "EventId": "test-003",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"principalId": "AIDAEXAMPLE"},
            "requestParameters": {"name": "test-trail"}
        })
    }

    finding = extract_finding(event)
    assert finding["principal"] == "AIDAEXAMPLE"


def test_extract_finding_principal_fallback_unknown():
    """Verify extract_finding returns 'unknown' when no principal info available."""
    event = {
        "EventId": "test-004",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {},
            "requestParameters": {"name": "test-trail"}
        })
    }

    finding = extract_finding(event)
    assert finding["principal"] == "unknown"


def test_extract_finding_target_resource_from_bucket_name():
    """Verify extract_finding extracts bucketName for S3 events."""
    event = {
        "EventId": "test-005",
        "EventName": "PutBucketPublicAccessBlock",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test-user"},
            "requestParameters": {"bucketName": "my-bucket"}
        })
    }

    finding = extract_finding(event)
    assert finding["target_resource"] == "my-bucket"


def test_extract_finding_target_resource_fallback_to_resources():
    """Verify extract_finding falls back to Resources array when name/bucketName missing."""
    event = {
        "EventId": "test-006",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "Resources": [{"ResourceType": "AWS::CloudTrail::Trail", "ResourceName": "resource-trail"}],
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test-user"},
            "requestParameters": {}
        })
    }

    finding = extract_finding(event)
    assert finding["target_resource"] == "resource-trail"


def test_extract_finding_target_resource_unknown():
    """Verify extract_finding returns 'unknown' when no resource info available."""
    event = {
        "EventId": "test-007",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/test-user"},
            "requestParameters": {}
        })
    }

    finding = extract_finding(event)
    assert finding["target_resource"] == "unknown"


def test_extract_finding_handles_invalid_json():
    """Verify extract_finding handles invalid CloudTrailEvent JSON gracefully."""
    event = {
        "EventId": "test-008",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": "not valid json"
    }

    finding = extract_finding(event)
    assert finding["principal"] == "unknown"
    assert finding["target_resource"] == "unknown"
    assert finding["action"] == "DeleteTrail"
    assert finding["severity"] == "high"


# ============================================================================
# Stubber integration tests for fetch_events
# ============================================================================


def test_fetch_events_with_stubber():
    """Integration test using botocore Stubber for CloudTrail API.

    IMPORTANT: fetch_events() queries for 4 event names, so we must
    add 4 stub responses - one for each event name query.
    """
    client = boto3.client("cloudtrail", region_name="us-east-1")
    stubber = Stubber(client)

    # Stub response for DeleteTrail lookup
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "stub-delete-001",
                    "EventName": "DeleteTrail",
                    "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "cloudtrail.amazonaws.com",
                    "Username": "stub-user",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/stub-user"},
                        "requestParameters": {"name": "stub-trail"}
                    })
                }
            ]
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteTrail"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Stub response for StopLogging lookup (empty - no events found)
    stubber.add_response(
        "lookup_events",
        {"Events": []},
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "StopLogging"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Stub response for UpdateTrail lookup (empty - no events found)
    stubber.add_response(
        "lookup_events",
        {"Events": []},
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "UpdateTrail"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Stub response for PutBucketPublicAccessBlock lookup (empty - no events found)
    stubber.add_response(
        "lookup_events",
        {"Events": []},
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "PutBucketPublicAccessBlock"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    stubber.activate()
    try:
        events = fetch_events(client, lookback_hours=24)
    finally:
        stubber.deactivate()

    assert len(events) == 1
    assert events[0]["EventName"] == "DeleteTrail"
    stubber.assert_no_pending_responses()


def test_fetch_events_pagination():
    """Verify NextToken pagination is handled correctly."""
    client = boto3.client("cloudtrail", region_name="us-east-1")
    stubber = Stubber(client)

    # First page of DeleteTrail results - has NextToken
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "stub-delete-001",
                    "EventName": "DeleteTrail",
                    "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "cloudtrail.amazonaws.com",
                    "Username": "user1",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/user1"},
                        "requestParameters": {"name": "trail1"}
                    })
                }
            ],
            "NextToken": "page2token"
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteTrail"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Second page of DeleteTrail results - no NextToken (end of results)
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "stub-delete-002",
                    "EventName": "DeleteTrail",
                    "EventTime": datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "cloudtrail.amazonaws.com",
                    "Username": "user2",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/user2"},
                        "requestParameters": {"name": "trail2"}
                    })
                }
            ]
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteTrail"}],
            "StartTime": ANY,
            "EndTime": ANY,
            "NextToken": "page2token"
        }
    )

    # Stub empty responses for remaining 3 event types
    for event_name in ["StopLogging", "UpdateTrail", "PutBucketPublicAccessBlock"]:
        stubber.add_response(
            "lookup_events",
            {"Events": []},
            expected_params={
                "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": event_name}],
                "StartTime": ANY,
                "EndTime": ANY
            }
        )

    stubber.activate()
    try:
        events = fetch_events(client, lookback_hours=24)
    finally:
        stubber.deactivate()

    # Should have both pages of DeleteTrail results
    assert len(events) == 2
    assert events[0]["EventId"] == "stub-delete-001"
    assert events[1]["EventId"] == "stub-delete-002"
    stubber.assert_no_pending_responses()


def test_fetch_events_multiple_event_types():
    """Verify fetch_events collects events from all 4 event types."""
    client = boto3.client("cloudtrail", region_name="us-east-1")
    stubber = Stubber(client)

    # Stub response for DeleteTrail
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "delete-001",
                    "EventName": "DeleteTrail",
                    "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "cloudtrail.amazonaws.com",
                    "Username": "user1",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/user1"},
                        "requestParameters": {"name": "trail1"}
                    })
                }
            ]
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "DeleteTrail"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Stub response for StopLogging
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "stop-001",
                    "EventName": "StopLogging",
                    "EventTime": datetime(2024, 1, 15, 11, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "cloudtrail.amazonaws.com",
                    "Username": "user2",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/user2"},
                        "requestParameters": {"name": "trail2"}
                    })
                }
            ]
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "StopLogging"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Stub response for UpdateTrail
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "update-001",
                    "EventName": "UpdateTrail",
                    "EventTime": datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "cloudtrail.amazonaws.com",
                    "Username": "user3",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/user3"},
                        "requestParameters": {"name": "trail3", "isLogging": False}
                    })
                }
            ]
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "UpdateTrail"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    # Stub response for PutBucketPublicAccessBlock
    stubber.add_response(
        "lookup_events",
        {
            "Events": [
                {
                    "EventId": "pab-001",
                    "EventName": "PutBucketPublicAccessBlock",
                    "EventTime": datetime(2024, 1, 15, 13, 0, 0, tzinfo=timezone.utc),
                    "EventSource": "s3.amazonaws.com",
                    "Username": "user4",
                    "CloudTrailEvent": json.dumps({
                        "userIdentity": {"arn": "arn:aws:iam::123:user/user4"},
                        "requestParameters": {
                            "bucketName": "bucket1",
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
        },
        expected_params={
            "LookupAttributes": [{"AttributeKey": "EventName", "AttributeValue": "PutBucketPublicAccessBlock"}],
            "StartTime": ANY,
            "EndTime": ANY
        }
    )

    stubber.activate()
    try:
        events = fetch_events(client, lookback_hours=24)
    finally:
        stubber.deactivate()

    # Should have all 4 events
    assert len(events) == 4
    event_names = [e["EventName"] for e in events]
    assert "DeleteTrail" in event_names
    assert "StopLogging" in event_names
    assert "UpdateTrail" in event_names
    assert "PutBucketPublicAccessBlock" in event_names
    stubber.assert_no_pending_responses()


# ============================================================================
# Account ID scoping tests
# ============================================================================


def test_account_id_cli_override():
    """Verify --account-id scopes event filtering correctly.

    Test Scenario:
    - Create DeleteTrail event from account '111111111111'
    - With account_id='111111111111': event SHOULD be flagged
    - With account_id='222222222222': event should NOT be flagged
    """
    # Event from account 111111111111
    event = {
        "EventId": "test-account-override-001",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::111111111111:user/test-user",
                "accountId": "111111111111"
            },
            "requestParameters": {"name": "test-trail"}
        })
    }

    # Matching account: should be flagged
    assert is_tampering_event(event, "111111111111") is True

    # Non-matching account: should NOT be flagged
    assert is_tampering_event(event, "222222222222") is False


def test_missing_account_id_returns_false():
    """Verify events without accountId in userIdentity return False.

    Per acceptance criteria: Function returns False if accountId field
    is missing from event.
    """
    # Event without accountId field
    event = {
        "EventId": "test-missing-account-001",
        "EventName": "DeleteTrail",
        "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        "CloudTrailEvent": json.dumps({
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/test-user"
                # Note: accountId is NOT present
            },
            "requestParameters": {"name": "test-trail"}
        })
    }

    # Should return False because accountId is missing
    assert is_tampering_event(event, "123456789012") is False


# ============================================================================
# Verification that DRY_RUN_FIXTURES work correctly
# ============================================================================


def test_dry_run_fixtures_missing_account_id():
    """Verify DRY_RUN_FIXTURES without accountId return False.

    Note: DRY_RUN_FIXTURES currently lack accountId in userIdentity.
    Per account-scoped filtering, events without accountId are not flagged.
    A separate issue will update fixtures to include accountId.
    """
    for fixture in DRY_RUN_FIXTURES:
        # Fixtures don't have accountId, so they should return False
        assert is_tampering_event(fixture, "123456789012") is False, (
            f"Fixture {fixture['EventId']} should NOT be tampering (missing accountId)"
        )


def test_target_event_names_constant():
    """Verify TARGET_EVENT_NAMES contains all expected event names."""
    assert "DeleteTrail" in TARGET_EVENT_NAMES
    assert "StopLogging" in TARGET_EVENT_NAMES
    assert "UpdateTrail" in TARGET_EVENT_NAMES
    assert "PutBucketPublicAccessBlock" in TARGET_EVENT_NAMES
    assert len(TARGET_EVENT_NAMES) == 4


# ============================================================================
# Tests for FIXTURE_ACCOUNT_ID constant
# ============================================================================


def test_fixture_account_id_constant():
    """Verify FIXTURE_ACCOUNT_ID is defined with expected placeholder value."""
    assert FIXTURE_ACCOUNT_ID == "<account-id>"


# ============================================================================
# Tests for resolve_account_id function
# ============================================================================


def test_account_id_sts_fallback():
    """Verify resolve_account_id uses STS fallback when explicit_id is None."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)

    stubber.add_response(
        "get_caller_identity",
        {
            "UserId": "AIDAEXAMPLE",
            "Account": "999999999999",
            "Arn": "arn:aws:iam::999999999999:user/test-user"
        },
        expected_params={}
    )

    stubber.activate()
    try:
        result = resolve_account_id(sts_client, None)
    finally:
        stubber.deactivate()

    assert result == "999999999999"
    stubber.assert_no_pending_responses()


def test_account_id_explicit_passthrough():
    """Verify resolve_account_id returns explicit_id unchanged without STS call."""
    sts_client = boto3.client("sts", region_name="us-east-1")
    stubber = Stubber(sts_client)

    # No stub responses added - STS should not be called
    stubber.activate()
    try:
        result = resolve_account_id(sts_client, "111111111111")
    finally:
        stubber.deactivate()

    assert result == "111111111111"
    # Verify no pending responses (none were added, none should be consumed)
    stubber.assert_no_pending_responses()

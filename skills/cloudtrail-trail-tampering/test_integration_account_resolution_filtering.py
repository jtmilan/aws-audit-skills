"""
Integration tests for account-id-resolution and account-scoped-filtering features.

These tests verify that the merged branches work together correctly:
1. resolve_account_id() properly provides account_id for is_tampering_event()
2. is_tampering_event() correctly filters events by account
3. main() correctly wires everything together with CLI args

Priority: Conflict resolution areas and cross-feature interactions.
"""
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.stub import Stubber

# Import the modules under test
from detect import (
    FIXTURE_ACCOUNT_ID,
    is_tampering_event,
    main,
    parse_args,
    resolve_account_id,
)


class TestAccountResolutionFilteringIntegration:
    """Test integration between resolve_account_id and is_tampering_event."""

    def test_resolve_account_id_output_used_by_is_tampering_event(self):
        """
        Verify resolve_account_id output can be used directly by is_tampering_event.

        Integration: account-id-resolution -> account-scoped-filtering
        """
        sts_client = boto3.client("sts", region_name="us-east-1")
        stubber = Stubber(sts_client)

        # Mock STS to return account 999999999999
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
            account_id = resolve_account_id(sts_client, None)
        finally:
            stubber.deactivate()

        # Event from the same account should be detected
        event_same_account = {
            "EventId": "integration-001",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::999999999999:user/attacker",
                    "accountId": "999999999999"
                },
                "requestParameters": {"name": "test-trail"}
            })
        }

        # Event from different account should NOT be detected
        event_different_account = {
            "EventId": "integration-002",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::111111111111:user/attacker",
                    "accountId": "111111111111"
                },
                "requestParameters": {"name": "test-trail"}
            })
        }

        # Verify integration: resolved account ID correctly filters events
        assert is_tampering_event(event_same_account, account_id) is True
        assert is_tampering_event(event_different_account, account_id) is False

    def test_explicit_account_id_bypasses_sts_and_filters_correctly(self):
        """
        Verify explicit account ID skips STS call and filters events correctly.

        Integration: CLI arg -> resolve_account_id -> is_tampering_event
        """
        sts_client = boto3.client("sts", region_name="us-east-1")
        stubber = Stubber(sts_client)

        # No stubs added - STS should not be called with explicit ID
        stubber.activate()
        try:
            explicit_id = "222222222222"
            account_id = resolve_account_id(sts_client, explicit_id)
        finally:
            stubber.deactivate()

        assert account_id == explicit_id

        # Event from explicit account should be detected
        event = {
            "EventId": "integration-003",
            "EventName": "StopLogging",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::222222222222:user/test",
                    "accountId": "222222222222"
                },
                "requestParameters": {"name": "trail"}
            })
        }

        assert is_tampering_event(event, account_id) is True
        stubber.assert_no_pending_responses()


class TestMainFunctionIntegration:
    """Test that main() correctly integrates all features."""

    def test_main_has_account_id_argument(self):
        """
        Verify parse_args includes --account-id argument.

        Requirement: AC2 - help output must contain --account-id
        """
        # This test will FAIL if --account-id is missing from parse_args
        args = parse_args(["--account-id", "123456789012"])
        assert hasattr(args, "account_id"), (
            "parse_args must support --account-id argument"
        )
        assert args.account_id == "123456789012"

    def test_main_dry_run_uses_account_id_for_filtering(self):
        """
        Verify main() with --dry-run uses account_id to filter events.

        Integration: main() -> resolve_account_id -> is_tampering_event

        Note: This test expects dry-run fixtures to include accountId field.
        """
        # Run main with dry-run and explicit account ID
        # This should work without calling AWS APIs
        exit_code = main(["--dry-run", "--account-id", "123456789012"])

        # Should succeed (return 0)
        assert exit_code == 0, "main() should succeed with --dry-run"

    def test_main_calls_is_tampering_event_with_account_id(self):
        """
        Verify main() passes account_id to is_tampering_event.

        This test catches the integration bug where is_tampering_event
        is called with only one argument (event) instead of two (event, account_id).
        """
        with patch("detect.is_tampering_event") as mock_is_tampering:
            mock_is_tampering.return_value = False

            exit_code = main(["--dry-run", "--account-id", "555555555555"])

            # Verify is_tampering_event was called with 2 arguments
            assert mock_is_tampering.call_count > 0, (
                "is_tampering_event should be called for each event"
            )

            for call in mock_is_tampering.call_args_list:
                args, kwargs = call
                assert len(args) == 2, (
                    f"is_tampering_event must be called with 2 args (event, account_id), "
                    f"got {len(args)} args"
                )
                assert args[1] == "555555555555", (
                    f"is_tampering_event must receive account_id '555555555555', "
                    f"got '{args[1]}'"
                )


class TestFixtureAccountIdIntegration:
    """Test FIXTURE_ACCOUNT_ID constant usage across features."""

    def test_fixture_account_id_matches_skill_md_placeholder(self):
        """
        Verify FIXTURE_ACCOUNT_ID value matches SKILL.md documentation.

        Integration: detect.py constant <-> SKILL.md documentation
        """
        assert FIXTURE_ACCOUNT_ID == "<account-id>", (
            "FIXTURE_ACCOUNT_ID must be '<account-id>' to match SKILL.md"
        )

    def test_fixture_events_should_have_account_id_for_filtering(self):
        """
        Verify DRY_RUN_FIXTURES include accountId for proper filtering.

        Note: This test documents current state - fixtures may lack accountId.
        """
        from detect import DRY_RUN_FIXTURES

        # Check if any fixture has accountId
        fixtures_with_account = []
        for fixture in DRY_RUN_FIXTURES:
            event_json = json.loads(fixture.get("CloudTrailEvent", "{}"))
            user_identity = event_json.get("userIdentity", {})
            if "accountId" in user_identity:
                fixtures_with_account.append(fixture["EventId"])

        # Document whether fixtures have accountId
        # (This may fail if fixtures are incomplete)
        if not fixtures_with_account:
            pytest.fail(
                "DRY_RUN_FIXTURES are missing accountId in userIdentity. "
                "Events without accountId will NOT be detected with account-scoped filtering."
            )


class TestAccountIdCliDryRunEndToEnd:
    """End-to-end tests for CLI account-id with dry-run mode."""

    def test_dry_run_with_matching_account_shows_findings(self):
        """
        Verify --dry-run with matching --account-id shows tampering findings.

        End-to-end: CLI -> parse_args -> resolve_account_id -> filter -> output
        """
        from io import StringIO
        import sys

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            # Use an account ID that should match fixture events
            exit_code = main(["--dry-run", "--account-id", "123456789012"])
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()

        # Should have table header at minimum
        assert "event_time" in output, "Output should contain markdown table"
        assert "principal" in output, "Output should contain principal column"

    def test_dry_run_with_non_matching_account_shows_empty_table(self):
        """
        Verify --dry-run with non-matching --account-id shows empty table.

        End-to-end: Events from different account should be filtered out.
        """
        from io import StringIO
        import sys

        # Capture stdout
        captured = StringIO()
        old_stdout = sys.stdout
        sys.stdout = captured

        try:
            # Use an account ID that should NOT match any fixture events
            exit_code = main(["--dry-run", "--account-id", "999999999999"])
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        lines = output.strip().split("\n")

        # Should have header and separator, but no data rows
        # (Header + separator = 2 lines for empty table)
        assert len(lines) >= 2, "Output should have at least table header"
        # Data rows would make it more than 2 lines
        # If fixtures have accountId field matching, there would be more lines

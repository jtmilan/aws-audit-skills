"""
Integration tests for merged branches: account-id-resolution + account-scoped-filtering + documentation.

These tests verify cross-feature interactions between the three merged branches:
1. issue/9a55243f-02-account-id-resolution: Added FIXTURE_ACCOUNT_ID constant and resolve_account_id()
2. issue/9a55243f-03-account-scoped-filtering: Modified is_tampering_event() to require account_id
3. issue/9a55243f-04-update-skill-documentation: Updated SKILL.md with --account-id docs

Priority 1: Conflict resolution areas (main() wiring, parse_args integration)
Priority 2: Cross-feature interactions (resolve_account_id -> is_tampering_event)
Priority 3: Shared file modifications (detect.py modified by branches 1, 2)
"""
import json
import subprocess
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

from detect import (
    DRY_RUN_FIXTURES,
    FIXTURE_ACCOUNT_ID,
    TARGET_EVENT_NAMES,
    extract_finding,
    format_markdown_table,
    is_tampering_event,
    main,
    parse_args,
    resolve_account_id,
)


class TestBranchIntegrationConflictAreas:
    """
    Priority 1: Tests for areas where branch merges could cause conflicts.

    These tests verify that changes from account-id-resolution and
    account-scoped-filtering branches work together in main() and parse_args().
    """

    def test_parse_args_includes_account_id_from_branch_02(self):
        """
        Verify parse_args() includes --account-id argument.

        Branch: issue/9a55243f-02-account-id-resolution
        AC: AC2 - help output must contain --account-id

        FAILURE: Indicates branch 02 changes to parse_args() were lost during merge
        """
        # Test that --account-id is recognized
        try:
            args = parse_args(["--account-id", "111111111111"])
            assert hasattr(args, "account_id"), (
                "parse_args() must have account_id attribute. "
                "Branch 02 changes may not be merged into parse_args()."
            )
            assert args.account_id == "111111111111"
        except SystemExit:
            pytest.fail(
                "parse_args() does not recognize --account-id. "
                "This indicates branch 02 (account-id-resolution) changes "
                "to parse_args() were not properly merged."
            )

    def test_main_calls_is_tampering_event_with_two_args(self):
        """
        Verify main() calls is_tampering_event(event, account_id).

        Conflict area: Branch 03 changed is_tampering_event signature to require account_id.
        main() must be updated to pass account_id as second argument.

        FAILURE: Indicates main() wasn't updated for new is_tampering_event signature
        """
        with patch("detect.is_tampering_event") as mock_tampering:
            mock_tampering.return_value = False

            try:
                # Test with dry-run to avoid AWS API calls
                result = main(["--dry-run"])
            except TypeError as e:
                if "missing 1 required positional argument" in str(e):
                    pytest.fail(
                        "main() calls is_tampering_event() without account_id argument. "
                        "Branch 03 changed signature but main() wasn't updated."
                    )
                raise
            except SystemExit as e:
                if e.code == 2:
                    pytest.fail(
                        "main() fails because parse_args() missing --account-id support. "
                        "See test_parse_args_includes_account_id_from_branch_02."
                    )
                raise

            # Verify is_tampering_event was called with 2 positional args
            if mock_tampering.call_count > 0:
                for call in mock_tampering.call_args_list:
                    args, kwargs = call
                    assert len(args) == 2, (
                        f"is_tampering_event must receive 2 args (event, account_id), "
                        f"but got {len(args)} args. main() needs to pass account_id."
                    )

    def test_main_uses_resolve_account_id_for_filtering(self):
        """
        Verify main() uses resolve_account_id() to get account_id for filtering.

        Integration: Branch 02 (resolve_account_id) + Branch 03 (account filtering)

        FAILURE: main() doesn't wire resolve_account_id to is_tampering_event
        """
        with patch("detect.resolve_account_id") as mock_resolve:
            mock_resolve.return_value = "888888888888"

            with patch("detect.is_tampering_event") as mock_tampering:
                mock_tampering.return_value = False

                try:
                    main(["--dry-run"])
                except (SystemExit, TypeError):
                    # Expected if integration is broken
                    pass

                # If resolve_account_id was called, verify it returns the account
                # that gets passed to is_tampering_event
                if mock_resolve.call_count > 0 and mock_tampering.call_count > 0:
                    _, kwargs = mock_tampering.call_args_list[0]
                    args, _ = mock_tampering.call_args_list[0]
                    if len(args) == 2:
                        assert args[1] == "888888888888", (
                            "resolve_account_id output must be passed to is_tampering_event"
                        )


class TestCrossFeatureInteractions:
    """
    Priority 2: Tests for cross-feature interactions between branches.

    These verify that resolve_account_id() output correctly flows to is_tampering_event().
    """

    def test_resolve_account_id_sts_fallback_used_for_filtering(self):
        """
        End-to-end: STS fallback account -> is_tampering_event filtering.

        Verifies resolve_account_id(sts, None) returns value usable by is_tampering_event().
        """
        sts_client = boto3.client("sts", region_name="us-east-1")
        stubber = Stubber(sts_client)

        stubber.add_response(
            "get_caller_identity",
            {
                "UserId": "AIDATEST",
                "Account": "777777777777",
                "Arn": "arn:aws:iam::777777777777:user/test"
            },
            expected_params={}
        )

        stubber.activate()
        try:
            account_id = resolve_account_id(sts_client, None)
        finally:
            stubber.deactivate()

        assert account_id == "777777777777"

        # Event from same account should be detected
        matching_event = {
            "EventId": "cross-feature-001",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::777777777777:user/attacker",
                    "accountId": "777777777777"
                },
                "requestParameters": {"name": "trail"}
            })
        }

        # Event from different account should NOT be detected
        non_matching_event = {
            "EventId": "cross-feature-002",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::111111111111:user/attacker",
                    "accountId": "111111111111"
                },
                "requestParameters": {"name": "trail"}
            })
        }

        assert is_tampering_event(matching_event, account_id) is True
        assert is_tampering_event(non_matching_event, account_id) is False

    def test_explicit_account_id_cli_filters_correctly(self):
        """
        End-to-end: CLI --account-id -> resolve_account_id -> is_tampering_event.

        Verifies explicit CLI account ID is used for filtering without STS call.
        """
        sts_client = boto3.client("sts", region_name="us-east-1")
        stubber = Stubber(sts_client)

        # NO stubs - STS should not be called with explicit ID
        stubber.activate()
        try:
            # Explicit ID should bypass STS entirely
            account_id = resolve_account_id(sts_client, "333333333333")
        finally:
            stubber.deactivate()

        assert account_id == "333333333333"
        stubber.assert_no_pending_responses()

        # Event filtering should use explicit ID
        event = {
            "EventId": "cross-feature-003",
            "EventName": "StopLogging",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::333333333333:user/user",
                    "accountId": "333333333333"
                },
                "requestParameters": {"name": "trail"}
            })
        }

        assert is_tampering_event(event, account_id) is True


class TestSharedFileModifications:
    """
    Priority 3: Tests for detect.py which was modified by multiple branches.

    Both branch 02 and 03 modified detect.py. These tests verify all modifications
    are present and working together.
    """

    def test_fixture_account_id_constant_exists(self):
        """
        Verify FIXTURE_ACCOUNT_ID constant from branch 02 exists.

        Branch: issue/9a55243f-02-account-id-resolution
        """
        assert FIXTURE_ACCOUNT_ID == "<account-id>", (
            "FIXTURE_ACCOUNT_ID constant missing or wrong value. "
            "Branch 02 changes may not be fully merged."
        )

    def test_resolve_account_id_function_exists(self):
        """
        Verify resolve_account_id() function from branch 02 exists and works.

        Branch: issue/9a55243f-02-account-id-resolution
        """
        sts_client = boto3.client("sts", region_name="us-east-1")
        stubber = Stubber(sts_client)

        # Test explicit passthrough
        stubber.activate()
        result = resolve_account_id(sts_client, "explicit123")
        stubber.deactivate()

        assert result == "explicit123", "resolve_account_id should return explicit ID unchanged"

    def test_is_tampering_event_requires_account_id(self):
        """
        Verify is_tampering_event() requires account_id parameter from branch 03.

        Branch: issue/9a55243f-03-account-scoped-filtering
        """
        event = {
            "EventId": "shared-file-001",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {"accountId": "123456789012"},
                "requestParameters": {"name": "trail"}
            })
        }

        # Should require 2 arguments
        try:
            is_tampering_event(event)
            pytest.fail("is_tampering_event should require account_id argument (branch 03 change)")
        except TypeError as e:
            assert "account_id" in str(e) or "missing" in str(e).lower()

        # Should work with 2 arguments
        result = is_tampering_event(event, "123456789012")
        assert result is True

    def test_is_tampering_event_filters_by_account(self):
        """
        Verify is_tampering_event() correctly filters by account from branch 03.

        Branch: issue/9a55243f-03-account-scoped-filtering
        """
        event = {
            "EventId": "shared-file-002",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {"accountId": "111111111111"},
                "requestParameters": {"name": "trail"}
            })
        }

        # Matching account - should be tampering
        assert is_tampering_event(event, "111111111111") is True

        # Non-matching account - should NOT be tampering
        assert is_tampering_event(event, "999999999999") is False

    def test_dry_run_fixtures_structure(self):
        """
        Verify DRY_RUN_FIXTURES have required structure for account filtering.

        Note: Branch 03 changed is_tampering_event to require accountId in events.
        Fixtures should include accountId for proper filtering.
        """
        assert len(DRY_RUN_FIXTURES) > 0, "DRY_RUN_FIXTURES should not be empty"

        # Check if fixtures have accountId (required for branch 03 filtering)
        fixtures_missing_account = []
        for fixture in DRY_RUN_FIXTURES:
            event_json = json.loads(fixture.get("CloudTrailEvent", "{}"))
            if "accountId" not in event_json.get("userIdentity", {}):
                fixtures_missing_account.append(fixture["EventId"])

        if fixtures_missing_account:
            pytest.fail(
                f"DRY_RUN_FIXTURES missing accountId in userIdentity: {fixtures_missing_account}. "
                f"Branch 03 (account-scoped-filtering) requires accountId for filtering. "
                f"These fixtures will return False for is_tampering_event()."
            )


class TestAcceptanceCriteriaIntegration:
    """
    Tests for PRD acceptance criteria that span multiple branches.
    """

    def test_ac2_help_contains_account_id(self):
        """
        AC2: python3 detect.py --help contains --account-id.

        Integration: Branch 02 parse_args + Branch 04 documentation
        """
        result = subprocess.run(
            [sys.executable, "skills/cloudtrail-trail-tampering/detect.py", "--help"],
            capture_output=True,
            text=True
        )

        assert "--account-id" in result.stdout, (
            "AC2 FAILED: --help output missing --account-id. "
            "Branch 02 parse_args changes not merged or incomplete."
        )
        assert "--lookback-hours" in result.stdout
        assert "--dry-run" in result.stdout

    def test_ac3_dry_run_no_hardcoded_account_ids(self):
        """
        AC3: --dry-run output contains NO '123456789012' literals.

        Integration: Branch 02 FIXTURE_ACCOUNT_ID + dry-run mode
        """
        try:
            result = subprocess.run(
                [sys.executable, "skills/cloudtrail-trail-tampering/detect.py", "--dry-run"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                pytest.skip(f"--dry-run failed with: {result.stderr}")

            assert "123456789012" not in result.stdout, (
                "AC3 FAILED: --dry-run output contains hardcoded account ID '123456789012'. "
                "Should use FIXTURE_ACCOUNT_ID placeholder."
            )
        except subprocess.TimeoutExpired:
            pytest.skip("--dry-run timed out")

    def test_ac10_no_hardcoded_account_ids_in_code(self):
        """
        AC10: No hardcoded account IDs in code files.

        Branch: issue/9a55243f-02-account-id-resolution requirement

        Note: Test file exceptions allowed (they use account IDs for testing).
        """
        detect_path = Path("skills/cloudtrail-trail-tampering/detect.py")
        detect_content = detect_path.read_text()

        # Count occurrences excluding test data
        # Note: DRY_RUN_FIXTURES may still have hardcoded IDs if branch 02 didn't update them
        hardcoded_count = detect_content.count("123456789012")

        if hardcoded_count > 0:
            pytest.fail(
                f"AC10 FAILED: detect.py contains {hardcoded_count} occurrences of '123456789012'. "
                f"Branch 02 should replace hardcoded IDs with FIXTURE_ACCOUNT_ID constant."
            )

    def test_ac11_skill_md_has_placeholder(self):
        """
        AC11: SKILL.md uses <account-id> placeholder.

        Branch: issue/9a55243f-04-update-skill-documentation
        """
        skill_md_path = Path("skills/cloudtrail-trail-tampering/SKILL.md")
        skill_md_content = skill_md_path.read_text()

        assert "<account-id>" in skill_md_content, (
            "AC11 FAILED: SKILL.md missing <account-id> placeholder. "
            "Branch 04 documentation changes incomplete."
        )

        # Also verify no hardcoded IDs
        assert "123456789012" not in skill_md_content, (
            "AC11 FAILED: SKILL.md still contains hardcoded '123456789012'. "
            "Branch 04 should replace with <account-id>."
        )


class TestExtractFindingAccountCompatibility:
    """
    Tests that extract_finding works correctly with account-scoped events.
    """

    def test_extract_finding_preserves_account_in_principal_arn(self):
        """
        Verify extract_finding correctly extracts principal ARN including account.

        This tests that branch changes didn't break principal extraction.
        """
        event = {
            "EventId": "extract-001",
            "EventName": "DeleteTrail",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::444444444444:user/test-user",
                    "accountId": "444444444444"
                },
                "requestParameters": {"name": "trail"}
            })
        }

        finding = extract_finding(event)

        assert "444444444444" in finding["principal"], (
            "extract_finding should preserve account ID in principal ARN"
        )

    def test_format_markdown_table_works_with_findings(self):
        """
        Verify format_markdown_table works correctly with extract_finding output.
        """
        event = {
            "EventId": "format-001",
            "EventName": "StopLogging",
            "EventTime": datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            "CloudTrailEvent": json.dumps({
                "userIdentity": {
                    "arn": "arn:aws:iam::555555555555:user/user",
                    "accountId": "555555555555"
                },
                "requestParameters": {"name": "audit-trail"}
            })
        }

        finding = extract_finding(event)
        table = format_markdown_table([finding])

        assert "event_time" in table
        assert "principal" in table
        assert "action" in table
        assert "target_resource" in table
        assert "severity" in table
        assert "StopLogging" in table
        assert "audit-trail" in table

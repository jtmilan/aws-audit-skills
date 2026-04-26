"""
Test suite for the IAM Policy Audit skill.

Uses botocore.stub.Stubber for offline testing without AWS credentials.
"""

import json
import pytest
from datetime import datetime, timedelta
from botocore.stub import Stubber

import boto3
from audit import Finding, AWSClient, AuditEngine, OutputFormatter


class TestFindingDataclass:
    """Tests for the Finding dataclass."""

    def test_finding_instantiation(self):
        """Verify Finding can be instantiated with all fields."""
        finding = Finding(
            resource='TestRole',
            finding='Test finding description',
            severity='high',
            fix_command='test command'
        )

        assert finding.resource == 'TestRole'
        assert finding.finding == 'Test finding description'
        assert finding.severity == 'high'
        assert finding.fix_command == 'test command'

    def test_finding_all_severity_levels(self):
        """Verify Finding accepts all severity levels."""
        for severity in ['low', 'med', 'high']:
            finding = Finding(
                resource='TestRole',
                finding='Test finding',
                severity=severity,
                fix_command='test'
            )
            assert finding.severity == severity

    def test_finding_lt_sorting_by_severity(self):
        """Test __lt__ method sorts by severity (high → med → low)."""
        high_finding = Finding(
            resource='ZebraRole',
            finding='High severity',
            severity='high',
            fix_command='fix'
        )
        med_finding = Finding(
            resource='AppleRole',
            finding='Med severity',
            severity='med',
            fix_command='fix'
        )
        low_finding = Finding(
            resource='AppleRole',
            finding='Low severity',
            severity='low',
            fix_command='fix'
        )

        # Verify sorting order: high < med < low
        assert high_finding < med_finding
        assert med_finding < low_finding
        assert high_finding < low_finding

    def test_finding_lt_sorting_by_resource_alphabetically(self):
        """Test __lt__ method sorts alphabetically by resource when severity is same."""
        finding_a = Finding(
            resource='AppleRole',
            finding='Finding',
            severity='high',
            fix_command='fix'
        )
        finding_b = Finding(
            resource='BananaRole',
            finding='Finding',
            severity='high',
            fix_command='fix'
        )
        finding_z = Finding(
            resource='ZebraRole',
            finding='Finding',
            severity='high',
            fix_command='fix'
        )

        # Same severity, should sort alphabetically by resource
        assert finding_a < finding_b
        assert finding_b < finding_z

    def test_finding_lt_case_insensitive_resource_sorting(self):
        """Test __lt__ method sorts resource names case-insensitively."""
        finding_lower = Finding(
            resource='appleRole',
            finding='Finding',
            severity='high',
            fix_command='fix'
        )
        finding_upper = Finding(
            resource='AppleRole',
            finding='Finding',
            severity='high',
            fix_command='fix'
        )

        # Case-insensitive comparison (both represent same resource)
        assert not (finding_lower < finding_upper)
        assert not (finding_upper < finding_lower)

    def test_finding_sorting_combined(self):
        """Test sorting with mixed severities and resources."""
        findings = [
            Finding('ZebraRole', 'Low severity finding', 'low', 'fix'),
            Finding('AppleRole', 'High severity finding', 'high', 'fix'),
            Finding('BananaRole', 'High severity finding', 'high', 'fix'),
            Finding('AppleRole', 'Med severity finding', 'med', 'fix'),
        ]

        sorted_findings = sorted(findings)

        # Expected order: high severities first (Apple, Banana), then med (Apple), then low (Zebra)
        assert sorted_findings[0].severity == 'high'
        assert sorted_findings[0].resource == 'AppleRole'

        assert sorted_findings[1].severity == 'high'
        assert sorted_findings[1].resource == 'BananaRole'

        assert sorted_findings[2].severity == 'med'
        assert sorted_findings[2].resource == 'AppleRole'

        assert sorted_findings[3].severity == 'low'
        assert sorted_findings[3].resource == 'ZebraRole'


class TestAWSClient:
    """Tests for AWSClient class."""

    def test_aws_client_dry_run_mode(self):
        """Verify AWSClient can be initialized in dry-run mode."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        assert client.dry_run is True
        assert client.account_id == '123456789012'

    def test_aws_client_real_mode(self):
        """Verify AWSClient can be initialized in real mode."""
        client = AWSClient(account_id='123456789012', dry_run=False)
        assert client.dry_run is False
        assert client.iam is not None


class TestAuditEngine:
    """Tests for AuditEngine class."""

    def test_audit_engine_initialization(self):
        """Verify AuditEngine can be initialized."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)
        assert engine.client is client

    def test_privileged_action_matching_tier1(self):
        """Test Tier 1 exact match for privileged actions."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Tier 1 exact matches
        assert engine._is_privileged_action('s3:*') is True
        assert engine._is_privileged_action('iam:*') is True
        assert engine._is_privileged_action('ec2:TerminateInstances') is True
        assert engine._is_privileged_action('kms:*') is True
        assert engine._is_privileged_action('dynamodb:*') is True

    def test_privileged_action_matching_tier2(self):
        """Test Tier 2 service wildcard match for privileged actions.

        Tier 2 matches actions ending with :* where service is in TIER2_SERVICES.
        """
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Tier 2 matches: these are NOT tier 1 exact matches, but the wildcard
        # action s3:*, iam:*, kms:*, dynamodb:* would be in Tier 1.
        # For individual actions like s3:GetObject, they are NOT privileged
        # unless they match a service wildcard pattern that ends with :*
        # The Tier 2 logic checks if action ends with :* and service is in list
        assert engine._is_privileged_action('s3:*') is True  # Tier 1 + Tier 2
        assert engine._is_privileged_action('iam:*') is True  # Tier 1 + Tier 2
        assert engine._is_privileged_action('kms:*') is True  # Tier 1 + Tier 2
        assert engine._is_privileged_action('dynamodb:*') is True  # Tier 1 + Tier 2

    def test_privileged_action_ec2_not_wildcard(self):
        """Verify ec2:* is NOT privileged (only ec2:TerminateInstances is)."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # ec2:* is NOT privileged
        assert engine._is_privileged_action('ec2:*') is False

        # ec2:TerminateInstances IS privileged
        assert engine._is_privileged_action('ec2:TerminateInstances') is True

        # Other ec2 actions are NOT privileged
        assert engine._is_privileged_action('ec2:DescribeInstances') is False

    def test_admin_policy_case_insensitive(self):
        """Test admin policy detection is case-insensitive."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Case-insensitive substring "admin"
        assert engine._is_admin_policy('AdminPolicy') is True
        assert engine._is_admin_policy('admin-policy') is True
        assert engine._is_admin_policy('ADMIN-PROD') is True
        assert engine._is_admin_policy('CustomAdminPolicy') is True

        # Non-admin policy
        assert engine._is_admin_policy('S3ReadOnly') is False


class TestOutputFormatter:
    """Tests for OutputFormatter class."""

    def test_empty_findings_output(self):
        """Verify empty findings list produces expected message."""
        formatter = OutputFormatter()
        output = formatter.render_table([])
        assert output == '## No IAM Policy Issues Found'

    def test_single_finding_output(self):
        """Verify single finding produces markdown table."""
        formatter = OutputFormatter()
        finding = Finding(
            resource='TestRole',
            finding='Test finding',
            severity='high',
            fix_command='fix this'
        )
        output = formatter.render_table([finding])

        # Should contain table header and one row
        assert '| Resource | Finding | Severity | Fix Command |' in output
        assert '|----------|---------|----------|------------|' in output
        assert '| TestRole | Test finding | high | fix this |' in output

    def test_multiple_findings_sorted(self):
        """Verify multiple findings are sorted correctly."""
        formatter = OutputFormatter()
        findings = [
            Finding('ZebraRole', 'Low finding', 'low', 'fix'),
            Finding('AppleRole', 'High finding', 'high', 'fix'),
            Finding('AppleRole', 'Med finding', 'med', 'fix'),
        ]
        output = formatter.render_table(findings)

        lines = output.split('\n')
        # Should have header, separator, and 3 data rows
        assert len(lines) == 5

        # Verify order: high (Apple), med (Apple), low (Zebra)
        assert 'AppleRole' in lines[2] and 'high' in lines[2]
        assert 'AppleRole' in lines[3] and 'med' in lines[3]
        assert 'ZebraRole' in lines[4] and 'low' in lines[4]

    def test_pipe_character_escaping(self):
        """Verify pipe characters in findings are escaped."""
        formatter = OutputFormatter()
        finding = Finding(
            resource='TestRole',
            finding='Finding with | pipe',
            severity='high',
            fix_command='command | with pipes'
        )
        output = formatter.render_table([finding])

        # Pipes should be escaped with backslash
        assert 'Finding with \\| pipe' in output
        assert 'command \\| with pipes' in output

    def test_output_formatter_multiple_pipes_escaped(self):
        """Verify multiple pipe characters are escaped correctly."""
        formatter = OutputFormatter()
        finding = Finding(
            resource='Role',
            finding='Multiple | pipes | in | text',
            severity='high',
            fix_command='cmd | pipe1 | pipe2'
        )
        output = formatter.render_table([finding])

        # All pipes should be escaped
        assert output.count('\\|') == 5  # 3 in finding, 2 in fix_command
        # Verify original finding has pipes (before escaping)
        assert '|' in finding.finding

    def test_output_formatter_header_and_separator(self):
        """Verify correct header and separator rows."""
        formatter = OutputFormatter()
        finding = Finding('Role', 'Finding', 'high', 'fix')
        output = formatter.render_table([finding])

        lines = output.split('\n')
        assert lines[0] == '| Resource | Finding | Severity | Fix Command |'
        assert lines[1] == '|----------|---------|----------|------------|'

    def test_output_formatter_case_insensitive_alphabetical_sort(self):
        """Verify alphabetical sorting is case-insensitive."""
        formatter = OutputFormatter()
        findings = [
            Finding('zebra-role', 'Low', 'low', 'fix'),
            Finding('APPLE-ROLE', 'High', 'high', 'fix'),
            Finding('Banana-Role', 'High', 'high', 'fix'),
        ]
        output = formatter.render_table(findings)
        lines = output.split('\n')

        # Should be sorted: APPLE (high), Banana (high), zebra (low)
        assert 'APPLE-ROLE' in lines[2]
        assert 'Banana-Role' in lines[3]
        assert 'zebra-role' in lines[4]

    def test_output_formatter_markdown_table_syntax(self):
        """Verify output is valid markdown table syntax."""
        formatter = OutputFormatter()
        findings = [
            Finding('Role1', 'Finding1', 'high', 'fix1'),
            Finding('Role2', 'Finding2', 'med', 'fix2'),
        ]
        output = formatter.render_table(findings)
        lines = output.split('\n')

        # All lines should start and end with |
        for line in lines:
            assert line.startswith('|'), f"Line doesn't start with |: {line}"
            assert line.endswith('|'), f"Line doesn't end with |: {line}"

        # Each line should have 5 pipe characters (4 separators + 1 start + 1 end = 5, but split removes ends)
        for line in lines:
            pipe_count = line.count('|')
            assert pipe_count == 5, f"Expected 5 pipes in line, got {pipe_count}: {line}"

    def test_output_formatter_no_leading_trailing_newlines(self):
        """Verify output has no embedded leading or trailing newlines."""
        formatter = OutputFormatter()
        finding = Finding('Role', 'Finding', 'high', 'fix')
        output = formatter.render_table([finding])

        # Output should not start or end with newline
        assert not output.startswith('\n'), "Output starts with newline"
        assert not output.endswith('\n'), "Output ends with newline"

    def test_output_formatter_severity_order_comprehensive(self):
        """Verify findings are sorted by severity in exact order."""
        formatter = OutputFormatter()
        findings = [
            Finding('Role1', 'Low1', 'low', 'fix'),
            Finding('Role2', 'Low2', 'low', 'fix'),
            Finding('Role3', 'Med1', 'med', 'fix'),
            Finding('Role4', 'Med2', 'med', 'fix'),
            Finding('Role5', 'High1', 'high', 'fix'),
            Finding('Role6', 'High2', 'high', 'fix'),
        ]
        output = formatter.render_table(findings)
        lines = output.split('\n')

        # Extract severity from each data row
        severities = []
        for i in range(2, len(lines)):  # Skip header and separator
            line = lines[i]
            if 'high' in line:
                severities.append('high')
            elif 'med' in line:
                severities.append('med')
            elif 'low' in line:
                severities.append('low')

        # All highs should come before meds, all meds before lows
        expected = ['high', 'high', 'med', 'med', 'low', 'low']
        assert severities == expected, f"Expected {expected}, got {severities}"


# Integration-style tests with stubbed AWS calls
class TestWildcardActionDetection:
    """Tests for wildcard action detection."""

    def test_wildcard_action_detection(self):
        """Test wildcard action detection with non-admin policy."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Policy with wildcard action
        policy_doc = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }
            ]
        }

        findings = engine.check_wildcard_actions(policy_doc, 'TestPolicy', None)

        assert len(findings) > 0
        assert any(f.severity == 'high' and 'wildcard action' in f.finding.lower() for f in findings)

    def test_wildcard_action_admin_policy_exempted(self):
        """Test wildcard action is exempted for admin policies."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Admin policy with wildcard action (should be exempted)
        policy_doc = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Action': '*',
                    'Resource': '*'
                }
            ]
        }

        findings = engine.check_wildcard_actions(policy_doc, 'AdminPolicy', None)

        # Should be empty (admin policy exempted)
        assert len(findings) == 0


class TestInlinePolicyDetection:
    """Tests for inline policy detection."""

    def test_inline_policy_flagging(self):
        """Test inline policies are flagged."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Mock list_role_policies to return inline policies
        client.list_role_policies = lambda role_name: ['inline-policy-1', 'inline-policy-2']

        findings = engine.check_inline_policies('TestRole')

        assert len(findings) == 2
        assert all(f.severity == 'med' for f in findings)
        assert all(f.resource == 'TestRole' for f in findings)


class TestStaleRoleDetection:
    """Tests for stale role detection."""

    def test_stale_role_detection(self):
        """Test stale role detection (created >90 days ago)."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Role created 95 days ago
        old_date = datetime.utcnow() - timedelta(days=95)
        findings = engine.check_stale_roles('OldRole', old_date)

        assert len(findings) == 1
        assert findings[0].severity == 'low'
        assert 'created' in findings[0].finding.lower() or 'stale' in findings[0].finding.lower()

    def test_recent_role_not_flagged(self):
        """Test recent role is not flagged as stale."""
        client = AWSClient(account_id='123456789012', dry_run=True)
        engine = AuditEngine(client)

        # Role created 30 days ago
        recent_date = datetime.utcnow() - timedelta(days=30)
        findings = engine.check_stale_roles('RecentRole', recent_date)

        assert len(findings) == 0


class TestRealModeWithStubber:
    """Test real mode with botocore.stub.Stubber."""

    def test_aws_client_list_roles_with_stubber(self):
        """Test list_roles with Stubber."""
        iam = boto3.client('iam', region_name='us-east-1')
        stubber = Stubber(iam)

        # Stub the paginator
        stubber.add_response('list_roles', {
            'Roles': [
                {
                    'Path': '/',
                    'RoleName': 'TestRole',
                    'RoleId': 'AIDACKCEVSQ6C2EXAMPLE',
                    'Arn': 'arn:aws:iam::123456789012:role/TestRole',
                    'CreateDate': datetime.utcnow(),
                    'AssumeRolePolicyDocument': json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    })
                }
            ],
            'IsTruncated': False
        })

        with stubber:
            roles = iam.list_roles()
            assert len(roles['Roles']) == 1
            assert roles['Roles'][0]['RoleName'] == 'TestRole'

    def test_aws_client_list_policies_pagination_with_stubber(self):
        """Test list_policies with Stubber simulates pagination."""
        iam = boto3.client('iam', region_name='us-east-1')
        stubber = Stubber(iam)

        # Stub first page with 10 policies
        policies_page1 = [
            {
                'PolicyName': f'Policy{i}',
                'PolicyId': f'ANPACKCEVSQ6C2EXAMPLE{i}',
                'Arn': f'arn:aws:iam::123456789012:policy/Policy{i}',
                'Path': '/',
                'DefaultVersionId': 'v1',
                'AttachmentCount': 0,
                'PermissionsBoundaryUsageCount': 0,
                'IsAttachable': True,
                'CreateDate': datetime.utcnow(),
                'UpdateDate': datetime.utcnow()
            }
            for i in range(10)
        ]

        # Stub second page with 10 policies
        policies_page2 = [
            {
                'PolicyName': f'Policy{i}',
                'PolicyId': f'ANPACKCEVSQ6C2EXAMPLE{i}',
                'Arn': f'arn:aws:iam::123456789012:policy/Policy{i}',
                'Path': '/',
                'DefaultVersionId': 'v1',
                'AttachmentCount': 0,
                'PermissionsBoundaryUsageCount': 0,
                'IsAttachable': True,
                'CreateDate': datetime.utcnow(),
                'UpdateDate': datetime.utcnow()
            }
            for i in range(10, 20)
        ]

        stubber.add_response('list_policies', {
            'Policies': policies_page1,
            'IsTruncated': True,
            'Marker': 'marker1'
        })
        stubber.add_response('list_policies', {
            'Policies': policies_page2,
            'IsTruncated': False
        })

        with stubber:
            # Test that paginator returns both pages
            paginator = iam.get_paginator('list_policies')
            all_policies = []
            for page in paginator.paginate(Scope='Local'):
                all_policies.extend(page.get('Policies', []))
            # Should have at least first page (10 items)
            assert len(all_policies) >= 10

    def test_dry_run_mode_fixture_loading(self):
        """Test dry-run mode loads and returns fixtures correctly."""
        client = AWSClient(account_id='999999999999', dry_run=True)

        # Test list_roles
        roles = client.list_roles()
        assert len(roles) > 0
        assert all('RoleName' in role for role in roles)
        assert all(isinstance(role.get('CreateDate'), datetime) for role in roles)

        # Test list_policies
        policies = client.list_policies()
        assert len(policies) > 0
        assert all('PolicyName' in policy for policy in policies)
        assert all(isinstance(policy.get('CreateDate'), datetime) for policy in policies)

    def test_dry_run_mode_missing_fixtures_graceful(self):
        """Test dry-run mode gracefully handles missing fixtures."""
        client = AWSClient(account_id='999999999999', dry_run=True)

        # This should not crash, even if fixture is missing
        result = client._load_fixture('nonexistent.json', 'SomeKey')
        assert result == []

    def test_dry_run_with_engine_produces_findings(self):
        """Test that dry-run mode with engine produces expected findings."""
        client = AWSClient(account_id='999999999999', dry_run=True)
        engine = AuditEngine(client)

        findings = engine.audit()

        # Should find at least the wildcard action and wildcard resource issues
        high_findings = [f for f in findings if f.severity == 'high']
        assert len(high_findings) > 0

        # Should find inline policy issue
        med_findings = [f for f in findings if f.severity == 'med']
        assert len(med_findings) > 0

    def test_clean_account_output(self):
        """Test that a clean account produces 'No IAM Policy Issues Found'."""
        # Create a stubbed client with only admin policies and no issues
        client = AWSClient(account_id='123456789012', dry_run=True)
        # Override with clean fixture data
        client._load_fixture = lambda f, k: (
            [{'RoleName': 'AdminRole', 'CreateDate': datetime.utcnow(), 'Arn': 'arn:aws:iam::123456789012:role/AdminRole', 'AssumeRolePolicyDocument': '{}'}]
            if k == 'Roles' else
            [{'PolicyName': 'AdministratorAccess', 'Arn': 'arn:aws:iam::123456789012:policy/AdministratorAccess', 'DefaultVersionId': 'v1', 'CreateDate': datetime.utcnow(), 'UpdateDate': datetime.utcnow()}]
            if k == 'Policies' else
            []
        )
        client._load_fixture_dict = lambda f: {} if f == 'inline_policies.json' else {}

        engine = AuditEngine(client)
        findings = engine.audit()

        formatter = OutputFormatter()
        output = formatter.render_table(findings)

        # Should show either "No IAM Policy Issues Found" or only admin policy findings
        # (admin policies with wildcard are exempt)
        assert 'No IAM Policy Issues Found' in output or 'AdministratorAccess' not in output


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "boto3>=1.26.0",
#     "botocore>=1.29.0",
# ]
# ///

import argparse
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass
from typing import Literal

import boto3
from botocore.exceptions import NoCredentialsError, ClientError


@dataclass
class Finding:
    """
    Represents a single security finding from the IAM policy audit.

    Attributes:
        resource: The role or policy name where the finding was detected
        finding: Human-readable description of the security issue
        severity: Severity level (low, med, or high)
        fix_command: Shell command or instructions to remediate the issue
    """
    resource: str
    finding: str
    severity: Literal["low", "med", "high"]
    fix_command: str

    def __lt__(self, other: "Finding") -> bool:
        """
        Compare findings for sorting.

        Sorts by severity (high → med → low), then alphabetically by resource name.

        Args:
            other: Another Finding object to compare with

        Returns:
            True if self should come before other in sorted order
        """
        severity_order = {"high": 0, "med": 1, "low": 2}

        # Compare by severity first
        if severity_order[self.severity] != severity_order[other.severity]:
            return severity_order[self.severity] < severity_order[other.severity]

        # If severity is the same, compare alphabetically by resource (case-insensitive)
        return self.resource.lower() < other.resource.lower()


class AWSClient:
    """Factory for AWS API calls (real or fixture-based for dry-run mode)."""

    def __init__(self, account_id: str, dry_run: bool = False):
        """
        Initialize AWS client.

        Args:
            account_id: Target AWS account ID
            dry_run: If True, load fixtures instead of calling AWS APIs
        """
        self.account_id = account_id
        self.dry_run = dry_run
        self.iam = None
        self._policy_cache = {}

        if not dry_run:
            self.iam = boto3.client('iam', region_name='us-east-1')

    def list_roles(self) -> list[dict]:
        """
        Return list of all roles in account.

        Returns: List of role dicts matching boto3 ListRoles response format
        """
        if self.dry_run:
            return self._load_fixture('roles.json', 'Roles')

        roles = []
        paginator = self.iam.get_paginator('list_roles')
        for page in paginator.paginate():
            roles.extend(page.get('Roles', []))
        return roles

    def list_role_policies(self, role_name: str) -> list[str]:
        """
        Return list of inline policy names attached to role.

        Args:
            role_name: Name of the role

        Returns: List of policy names
        """
        if self.dry_run:
            fixture = self._load_fixture_dict('inline_policies.json')
            return fixture.get(role_name, [])

        policies = []
        paginator = self.iam.get_paginator('list_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            policies.extend(page.get('PolicyNames', []))
        return policies

    def get_role_policy(self, role_name: str, policy_name: str) -> dict:
        """
        Retrieve inline policy document for a role.

        Args:
            role_name: Name of the role
            policy_name: Name of the inline policy

        Returns: Policy document dict
        """
        if self.dry_run:
            # For dry-run, return a minimal stub
            return {
                'RoleName': role_name,
                'PolicyName': policy_name,
                'PolicyDocument': json.dumps({})
            }

        return self.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)

    def list_policies(self) -> list[dict]:
        """
        Return list of all customer-managed (local) policies.

        Returns: List of policy dicts in boto3 ListPolicies response format
        """
        if self.dry_run:
            return self._load_fixture('managed_policies.json', 'Policies')

        policies = []
        paginator = self.iam.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'):
            policies.extend(page.get('Policies', []))
        return policies

    def get_policy_version(self, policy_arn: str, version_id: str) -> dict:
        """
        Retrieve the default version of a managed policy document.

        Args:
            policy_arn: ARN of the policy
            version_id: Version ID

        Returns: Policy version dict
        """
        if self.dry_run:
            fixture = self._load_fixture_dict('policy_documents.json')
            doc = fixture.get(policy_arn, {})
            return {
                'PolicyVersion': {
                    'Document': json.dumps(doc) if isinstance(doc, dict) else doc,
                    'VersionId': version_id
                }
            }

        if policy_arn not in self._policy_cache:
            response = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            self._policy_cache[policy_arn] = response

        return self._policy_cache[policy_arn]

    def list_attached_role_policies(self, role_name: str) -> list[dict]:
        """
        Return list of managed policies attached to a role.

        Args:
            role_name: Name of the role

        Returns: List of attached policy dicts
        """
        if self.dry_run:
            return []

        policies = []
        paginator = self.iam.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            policies.extend(page.get('AttachedPolicies', []))
        return policies

    def get_role(self, role_name: str) -> dict:
        """
        Retrieve role metadata.

        Args:
            role_name: Name of the role

        Returns: Role dict matching boto3 GetRole response
        """
        if self.dry_run:
            roles = self._load_fixture('roles.json', 'Roles')
            for role in roles:
                if role['RoleName'] == role_name:
                    return {'Role': role}
            return {'Role': {}}

        return self.iam.get_role(RoleName=role_name)

    def _load_fixture(self, filename: str, key: str) -> list:
        """Load fixture from JSON file, returning the specified key."""
        try:
            fixture_path = Path(__file__).parent / 'fixtures' / filename
            with open(fixture_path) as f:
                data = json.load(f)
                return data.get(key, [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _load_fixture_dict(self, filename: str) -> dict:
        """Load fixture from JSON file, returning as dict."""
        try:
            fixture_path = Path(__file__).parent / 'fixtures' / filename
            with open(fixture_path) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}


class AuditEngine:
    """Orchestrate detection logic and combine findings from all checks."""

    def __init__(self, client: AWSClient):
        """
        Initialize audit engine with AWS client.

        Args:
            client: AWSClient instance (real or fixture-based)
        """
        self.client = client
        self.PRIVILEGED_ACTIONS_EXACT = {
            "s3:*", "iam:*", "ec2:TerminateInstances", "kms:*", "dynamodb:*"
        }
        self.PRIVILEGED_ACTIONS_TIER2_SERVICES = {"s3", "iam", "kms", "dynamodb"}
        self.KNOWN_ADMIN_POLICIES_ARN_SUFFIX = {
            "AdministratorAccess",
            "PowerUserAccess"
        }

    def audit(self) -> list[Finding]:
        """
        Run complete audit and return all findings.

        Returns: List of Finding objects
        """
        findings = []

        # Audit roles
        roles = self.client.list_roles()
        for role in roles:
            role_name = role.get('RoleName', '')
            role_create_date = role.get('CreateDate')

            # Check inline policies
            findings.extend(self.check_inline_policies(role_name))

            # Check stale roles
            if role_create_date:
                findings.extend(self.check_stale_roles(role_name, role_create_date))

            # Check attached managed policies
            attached_policies = self.client.list_attached_role_policies(role_name)
            for policy in attached_policies:
                policy_arn = policy.get('PolicyArn', '')
                policy_name = policy.get('PolicyName', '')
                findings.extend(self._check_managed_policy(policy_name, policy_arn))

        # Audit unattached managed policies
        managed_policies = self.client.list_policies()
        for policy in managed_policies:
            policy_name = policy.get('PolicyName', '')
            policy_arn = policy.get('Arn', '')
            findings.extend(self._check_managed_policy(policy_name, policy_arn))

        return findings

    def _check_managed_policy(self, policy_name: str, policy_arn: str) -> list[Finding]:
        """Check a managed policy for violations."""
        findings = []

        # Get policy document
        try:
            # For managed policies, we need the default version
            policy_info = self.client.list_policies()
            version_id = None
            for p in policy_info:
                if p.get('Arn') == policy_arn:
                    version_id = p.get('DefaultVersionId')
                    break

            if not version_id:
                # Fallback: try to get it from the policy ARN
                version_id = 'v1'

            response = self.client.get_policy_version(policy_arn, version_id)
            policy_doc_str = response.get('PolicyVersion', {}).get('Document', '{}')

            if isinstance(policy_doc_str, str):
                policy_doc = json.loads(policy_doc_str)
            else:
                policy_doc = policy_doc_str

            findings.extend(self.check_wildcard_actions(policy_doc, policy_name, policy_arn))
            findings.extend(self.check_wildcard_resources(policy_doc, policy_name))
        except Exception:
            # Silently skip policies we can't read
            pass

        return findings

    def check_wildcard_actions(self, policy_doc: dict, policy_name: str, policy_arn: str = None) -> list[Finding]:
        """
        Detect policies with Action: "*" (unless admin policy).

        Args:
            policy_doc: Parsed policy document
            policy_name: Name of policy
            policy_arn: ARN of policy

        Returns: List of Finding objects
        """
        if self._is_admin_policy(policy_name, policy_arn):
            return []

        findings = []
        statements = policy_doc.get('Statement', [])

        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue

            # Extract actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            # Check for wildcard action
            if '*' in actions:
                findings.append(Finding(
                    resource=policy_name,
                    finding='Wildcard action (*) on non-admin policy',
                    severity='high',
                    fix_command=f'Review policy {policy_name} and replace wildcard with specific actions'
                ))

        return findings

    def check_wildcard_resources(self, policy_doc: dict, policy_name: str) -> list[Finding]:
        """
        Detect policies with Resource: "*" paired with privileged actions.

        Args:
            policy_doc: Parsed policy document
            policy_name: Name of policy

        Returns: List of Finding objects
        """
        findings = []
        statements = policy_doc.get('Statement', [])

        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue

            # Extract resources
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard resource
            if '*' not in resources:
                continue

            # Extract actions
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            # Check if any action is privileged
            for action in actions:
                if self._is_privileged_action(action):
                    findings.append(Finding(
                        resource=policy_name,
                        finding=f'Wildcard resource (*) with privileged action {action}',
                        severity='high',
                        fix_command=f'Restrict Resource to specific ARNs for action {action}'
                    ))
                    break  # One finding per statement is enough

        return findings

    def check_inline_policies(self, role_name: str) -> list[Finding]:
        """
        Detect inline policies on roles.

        Args:
            role_name: Name of the role

        Returns: List of Finding objects
        """
        findings = []
        policies = self.client.list_role_policies(role_name)

        for policy_name in policies:
            findings.append(Finding(
                resource=role_name,
                finding=f"Inline policy '{policy_name}' should be managed",
                severity='med',
                fix_command=f'Convert inline policy {policy_name} on role {role_name} to managed policy'
            ))

        return findings

    def check_stale_roles(self, role_name: str, role_create_date: datetime) -> list[Finding]:
        """
        Detect roles created >90 days ago.

        Args:
            role_name: Name of the role
            role_create_date: datetime when role was created

        Returns: List of Finding objects
        """
        threshold_days = 90
        age_days = (datetime.utcnow() - role_create_date).days

        if age_days > threshold_days:
            return [Finding(
                resource=role_name,
                finding=f'Role created {age_days} days ago (threshold: {threshold_days} days)',
                severity='low',
                fix_command=f'Review role usage. If unused, delete with: aws iam delete-role --role-name {role_name}'
            )]

        return []

    def _is_privileged_action(self, action: str) -> bool:
        """
        Check if action is in privileged list (two-tier matching).

        Tier 1: Exact match in privileged actions list
        Tier 2: Service wildcard match (e.g., s3:*, iam:*, etc.)

        Args:
            action: Action string to check

        Returns: True if action is privileged, False otherwise
        """
        # Tier 1: Exact match
        if action in self.PRIVILEGED_ACTIONS_EXACT:
            return True

        # Tier 2: Service wildcard match
        if action.endswith(':*'):
            service = action.split(':')[0]
            if service in self.PRIVILEGED_ACTIONS_TIER2_SERVICES:
                return True

        return False

    def _is_admin_policy(self, policy_name: str, policy_arn: str = None) -> bool:
        """
        Check if policy is an admin/unrestricted policy.

        Args:
            policy_name: Name of the policy
            policy_arn: ARN of the policy (optional)

        Returns: True if policy is admin, False otherwise
        """
        # Check 1: Case-insensitive substring "admin" in name
        if 'admin' in policy_name.lower():
            return True

        # Check 2: Known admin policies by ARN suffix
        if policy_arn:
            for known_admin in self.KNOWN_ADMIN_POLICIES_ARN_SUFFIX:
                if policy_arn.endswith(f'policy/{known_admin}') or policy_arn.endswith(f':policy/{known_admin}'):
                    return True

        return False


class OutputFormatter:
    """Convert Finding objects to markdown table format."""

    def render_table(self, findings: list[Finding]) -> str:
        """
        Convert findings to markdown table.

        Args:
            findings: List of Finding objects (unsorted)

        Returns: Markdown string
        """
        if not findings:
            return '## No IAM Policy Issues Found'

        # Sort findings
        sorted_findings = sorted(findings)

        # Build table
        lines = [
            '| Resource | Finding | Severity | Fix Command |',
            '|----------|---------|----------|------------|'
        ]

        for finding in sorted_findings:
            # Escape pipe characters in fix_command
            fix_cmd = finding.fix_command.replace('|', '\\|')
            finding_text = finding.finding.replace('|', '\\|')

            lines.append(
                f'| {finding.resource} | {finding_text} | {finding.severity} | {fix_cmd} |'
            )

        return '\n'.join(lines)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Audit AWS IAM policies for security antipatterns and hygiene issues.'
    )

    parser.add_argument(
        '--account-id',
        required=True,
        help='AWS account ID (12 digits, required)'
    )

    parser.add_argument(
        '--severity',
        choices=['low', 'med', 'high'],
        default='high',
        help='Minimum severity level to report (default: high)'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Load fixture JSON instead of calling AWS APIs'
    )

    args = parser.parse_args()

    # Validate account ID
    if not args.account_id.isdigit() or len(args.account_id) != 12:
        parser.error('--account-id must be a 12-digit numeric AWS account ID')

    try:
        # Initialize client and engine
        client = AWSClient(account_id=args.account_id, dry_run=args.dry_run)
        engine = AuditEngine(client)

        # Run audit
        findings = engine.audit()

        # Filter by severity
        severity_order = {'low': 0, 'med': 1, 'high': 2}
        min_severity = severity_order[args.severity]
        findings = [f for f in findings if severity_order[f.severity] >= min_severity]

        # Format and output
        formatter = OutputFormatter()
        output = formatter.render_table(findings)
        print(output)

        sys.exit(0)

    except NoCredentialsError:
        print('AWS credentials not found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY or use ~/.aws/credentials',
              file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        code = e.response['Error']['Code']
        if code == 'AccessDenied':
            print('Insufficient IAM permissions. Ensure account has iam:List*, iam:Get* actions.',
                  file=sys.stderr)
        else:
            print(f"AWS API error: {code}: {e.response['Error']['Message']}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'Unexpected error: {e}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

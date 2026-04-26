#!/usr/bin/env python3
# /// script
# dependencies = [
#   "boto3>=1.34.0",
# ]
# ///

"""
s3-public-bucket-scan: Scan S3 buckets for public exposure.

Detects public exposure via:
- Bucket ACL grants to AllUsers/AuthenticatedUsers
- Bucket policies with wildcard principals lacking IP restrictions
- Disabled BlockPublicAccess configurations
- Object-level ACLs on sample objects

Usage:
    python scan.py [--region REGION] [--include-empty] [--dry-run]
"""

import argparse
import json
import sys
from datetime import datetime


# ============================================================================
# DRY-RUN FIXTURES
# ============================================================================

DRY_RUN_FIXTURES = {
    'list_buckets': {
        'Buckets': [
            {'Name': 'public-bucket-demo', 'CreationDate': datetime(2024, 1, 1)},
            {'Name': 'intentional-public-bucket', 'CreationDate': datetime(2024, 1, 2)}
        ]
    },
    'get_bucket_location': {
        'public-bucket-demo': {'LocationConstraint': None},  # us-east-1
        'intentional-public-bucket': {'LocationConstraint': 'us-west-2'}
    },
    'get_bucket_acl': {
        'public-bucket-demo': {
            'Grants': [
                {
                    'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                    'Permission': 'FULL_CONTROL'
                }
            ]
        },
        'intentional-public-bucket': {
            'Grants': [
                {
                    'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'},
                    'Permission': 'READ'
                }
            ]
        }
    },
    'get_bucket_policy': {
        'public-bucket-demo': None,  # NoSuchBucketPolicy
    },
    'get_public_access_block': {
        'public-bucket-demo': {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        }
    },
    'list_objects_v2': {
        'public-bucket-demo': {
            'Contents': [
                {'Key': 'logs/2024-01-01.txt', 'Size': 1024},
                {'Key': 'logs/2024-01-02.txt', 'Size': 2048}
            ]
        },
        'intentional-public-bucket': {
            'Contents': [
                {'Key': 'website/index.html', 'Size': 512}
            ]
        }
    },
    'get_object_acl': {
        ('public-bucket-demo', 'logs/2024-01-01.txt'): {
            'Grants': [
                {
                    'Grantee': {'Type': 'Group', 'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'},
                    'Permission': 'READ'
                }
            ]
        },
        ('public-bucket-demo', 'logs/2024-01-02.txt'): {
            'Grants': [
                {
                    'Grantee': {'Type': 'CanonicalUser', 'ID': 'owner-id'},
                    'Permission': 'FULL_CONTROL'
                }
            ]
        },
        ('intentional-public-bucket', 'website/index.html'): {
            'Grants': [
                {
                    'Grantee': {'Type': 'CanonicalUser', 'ID': 'owner-id'},
                    'Permission': 'FULL_CONTROL'
                }
            ]
        }
    },
    'get_bucket_tagging': {
        'intentional-public-bucket': {
            'TagSet': [
                {'Key': 'public', 'Value': 'true'},
                {'Key': 'purpose', 'Value': 'website'}
            ]
        }
    }
}


# ============================================================================
# CLI PARSING
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse CLI arguments.

    Returns:
        argparse.Namespace with:
            - region (str|None): AWS region to scan, 'all', or None for default
            - include_empty (bool): Include buckets with 0 objects
            - dry_run (bool): Use hardcoded fixture data instead of AWS APIs
    """
    parser = argparse.ArgumentParser(
        description="Scan S3 buckets for public exposure via ACL, policy, and BlockPublicAccess"
    )
    parser.add_argument(
        '--region',
        type=str,
        default=None,
        help="AWS region to scan (e.g., 'us-east-1', 'us-west-2', or 'all' for all enabled regions). Default: user's default region from boto3 config."
    )
    parser.add_argument(
        '--include-empty',
        action='store_true',
        help="Include buckets with 0 objects in the scan results. Default: exclude empty buckets."
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help="Use hardcoded fixture data instead of calling AWS APIs (for testing without credentials)."
    )
    return parser.parse_args()


# ============================================================================
# DETECTION FUNCTIONS (STUB IMPLEMENTATIONS)
# ============================================================================

def check_bucket_acl(bucket_name: str, s3_client=None, dry_run: bool = False) -> list[str]:
    """
    Check bucket ACL for public grants.

    Returns: ["Grant {permission} to {AllUsers|AuthenticatedUsers}", ...]
    """
    if dry_run:
        fixture = DRY_RUN_FIXTURES['get_bucket_acl'].get(bucket_name, {'Grants': []})
    else:
        # Real implementation will be in issue-03
        return []

    exposure_vectors = []
    for grant in fixture.get('Grants', []):
        grantee = grant.get('Grantee', {})
        if grantee.get('Type') == 'Group':
            uri = grantee.get('URI', '')
            if 'AllUsers' in uri:
                exposure_vectors.append(f"Grant {grant['Permission']} to AllUsers")
            elif 'AuthenticatedUsers' in uri:
                exposure_vectors.append(f"Grant {grant['Permission']} to AuthenticatedUsers")

    return exposure_vectors


def check_bucket_policy(bucket_name: str, s3_client=None, dry_run: bool = False) -> list[str]:
    """
    Check bucket policy for public access without IP restrictions.

    Returns: ["Statement {idx}: Principal='*' without aws:SourceIp restriction", ...]
    """
    if dry_run:
        fixture = DRY_RUN_FIXTURES['get_bucket_policy'].get(bucket_name)
        if fixture is None:
            # NoSuchBucketPolicy
            return []
    else:
        # Real implementation will be in issue-03
        return []

    # Fixture contains policy dict
    exposure_vectors = []
    for idx, statement in enumerate(fixture.get('Statement', [])):
        if statement.get('Effect') != 'Allow':
            continue

        principal = statement.get('Principal')
        is_public_principal = False

        if principal == '*':
            is_public_principal = True
        elif isinstance(principal, dict) and principal.get('AWS') == '*':
            is_public_principal = True

        if not is_public_principal:
            continue

        condition = statement.get('Condition', {})
        has_ip_restriction = 'aws:SourceIp' in str(condition)

        if not has_ip_restriction:
            exposure_vectors.append(
                f"Statement {idx}: Principal='*' without aws:SourceIp restriction"
            )

    return exposure_vectors


def check_public_access_block(bucket_name: str, s3_client=None, dry_run: bool = False) -> list[str]:
    """
    Check BlockPublicAccess configuration.

    Returns: ["{SettingName}=false", ...] for disabled settings
    """
    if dry_run:
        fixture = DRY_RUN_FIXTURES['get_public_access_block'].get(bucket_name)
        if fixture is None:
            # NoSuchPublicAccessBlockConfiguration
            return []
        config = fixture.get('PublicAccessBlockConfiguration', {})
    else:
        # Real implementation will be in issue-03
        return []

    exposure_vectors = []
    settings = ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets']

    for setting in settings:
        if not config.get(setting, True):  # Default to True if missing
            exposure_vectors.append(f"{setting}=false")

    return exposure_vectors


def check_object_acls(bucket_name: str, s3_client=None, dry_run: bool = False, max_objects: int = 10) -> list[dict]:
    """
    Sample object ACLs.

    Returns: list of dicts with 'bucket', 'key', 'acl', 'public_grants' fields
    """
    if dry_run:
        list_fixture = DRY_RUN_FIXTURES['list_objects_v2'].get(bucket_name, {'Contents': []})
    else:
        # Real implementation will be in issue-03
        return []

    objects_data = []
    for obj in list_fixture.get('Contents', [])[:max_objects]:
        obj_key = obj['Key']  # boto3 uses capital K

        # Get object ACL from fixtures
        acl_response = DRY_RUN_FIXTURES['get_object_acl'].get((bucket_name, obj_key), {'Grants': []})

        # Detect public grants
        public_grants = []
        for grant in acl_response.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    public_grants.append(grant['Permission'])

        if public_grants:  # Only include objects with public grants
            objects_data.append({
                'bucket': bucket_name,
                'key': obj_key,
                'acl': acl_response,
                'public_grants': public_grants
            })

    return objects_data


def is_intentionally_public(bucket_name: str, s3_client=None, dry_run: bool = False) -> bool:
    """
    Check if bucket is tagged as intentionally public.

    Returns: True if tag Key='public' Value='true' exists (case-sensitive)
    """
    if dry_run:
        fixture = DRY_RUN_FIXTURES['get_bucket_tagging'].get(bucket_name)
        if fixture is None:
            # NoSuchTagSet
            return False
        tag_set = fixture.get('TagSet', [])
    else:
        # Real implementation will be in issue-03
        return False

    for tag in tag_set:
        if tag.get('Key') == 'public' and tag.get('Value') == 'true':
            return True

    return False


# ============================================================================
# REPORT FORMATTING
# ============================================================================

def generate_remediation_commands(bucket_name: str, exposure_vectors: list[str]) -> str:
    """
    Generate AWS CLI remediation commands based on exposure vectors.

    INTERFACE CONTRACT:
    - ACL findings MUST contain 'Grant' substring
    - BPA findings MUST contain 'BlockPublic', 'IgnorePublic', or 'RestrictPublic'
    - Policy findings MUST contain 'Statement' substring

    Returns: Markdown code block with bash commands
    """
    commands = []

    # Detect ACL exposure
    if any('Grant' in v for v in exposure_vectors):
        commands.append(
            f"# Remove public ACL\n"
            f"aws s3api put-bucket-acl --bucket {bucket_name} --acl private"
        )

    # Detect BPA exposure
    if any('BlockPublic' in v or 'IgnorePublic' in v or 'RestrictPublic' in v for v in exposure_vectors):
        commands.append(
            f"# Enable BlockPublicAccess\n"
            f"aws s3api put-public-access-block --bucket {bucket_name} \\\n"
            f"  --public-access-block-configuration \\\n"
            f"  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        )

    # Detect Policy exposure
    if any('Statement' in v for v in exposure_vectors):
        commands.append(
            f"# Review and update bucket policy\n"
            f"aws s3api get-bucket-policy --bucket {bucket_name}\n"
            f"# Then edit policy and apply with:\n"
            f"# aws s3api put-bucket-policy --bucket {bucket_name} --policy file://policy.json"
        )

    if not commands:
        return "```bash\n# No remediation needed\n```"

    return "```bash\n" + "\n\n".join(commands) + "\n```"


def format_report(scan_results: list[dict], args: argparse.Namespace) -> str:
    """
    Generate markdown report.

    Returns: Full markdown string with header, findings, remediation commands
    """
    # Generate header
    timestamp = datetime.now().isoformat()
    region = args.region if args.region else "default region"

    # Count buckets
    total_scanned = len(scan_results)
    public_buckets = [r for r in scan_results if (r['acl_vectors'] or r['policy_vectors'] or r['bpa_vectors'] or r['object_acls'])]
    public_count = len(public_buckets)

    report_lines = [
        "# S3 Public Bucket Scan Report",
        "",
        f"**Region:** {region}",
        f"**Timestamp:** {timestamp}",
        f"**Buckets Scanned:** {total_scanned}",
        f"**Public Buckets Found:** {public_count}",
        ""
    ]

    if public_count == 0:
        report_lines.append("No public buckets found.")
        return "\n".join(report_lines)

    report_lines.append("## Findings")
    report_lines.append("")

    # Generate findings for each public bucket
    for result in public_buckets:
        bucket_name = result['bucket_name']
        is_intentional = result.get('is_intentional', False)

        # Bucket header
        header = f"### {bucket_name}"
        if is_intentional:
            header += " [INTENTIONAL]"
        report_lines.append(header)
        report_lines.append("")

        # Exposure vectors
        all_vectors = result['acl_vectors'] + result['policy_vectors'] + result['bpa_vectors']
        if all_vectors:
            report_lines.append("**Exposure Vectors:**")
            for vector in all_vectors:
                if 'Grant' in vector:
                    report_lines.append(f"- ACL: {vector}")
                elif 'Statement' in vector:
                    report_lines.append(f"- Policy: {vector}")
                elif 'BlockPublic' in vector or 'IgnorePublic' in vector or 'RestrictPublic' in vector:
                    report_lines.append(f"- BlockPublicAccess: {vector}")
                else:
                    report_lines.append(f"- {vector}")
            report_lines.append("")

        # Sample affected objects
        if result['object_acls']:
            report_lines.append("**Sample Affected Objects:**")
            for obj in result['object_acls']:
                grants_str = ", ".join(obj['public_grants'])
                report_lines.append(f"- s3://{obj['bucket']}/{obj['key']} (ACL: {grants_str})")
            report_lines.append("")

        # Remediation commands
        report_lines.append("**Remediation:**")
        report_lines.append(generate_remediation_commands(bucket_name, all_vectors))
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("")

    return "\n".join(report_lines)


def main() -> int:
    """
    CLI entry point.

    Returns:
        0 on success, 1 on error
    """
    try:
        args = parse_args()

        if args.dry_run:
            # Dry-run mode: use fixture data
            scan_results = []

            # Get list of buckets from fixtures
            buckets_fixture = DRY_RUN_FIXTURES['list_buckets']
            for bucket in buckets_fixture['Buckets']:
                bucket_name = bucket['Name']

                # Scan each bucket using stub functions
                acl_vectors = check_bucket_acl(bucket_name, dry_run=True)
                policy_vectors = check_bucket_policy(bucket_name, dry_run=True)
                bpa_vectors = check_public_access_block(bucket_name, dry_run=True)
                object_acls = check_object_acls(bucket_name, dry_run=True)
                is_intentional = is_intentionally_public(bucket_name, dry_run=True)

                # Build scan result
                scan_results.append({
                    'bucket_name': bucket_name,
                    'acl_vectors': acl_vectors,
                    'policy_vectors': policy_vectors,
                    'bpa_vectors': bpa_vectors,
                    'object_acls': object_acls,
                    'is_intentional': is_intentional
                })

            # Generate and print report
            report = format_report(scan_results, args)
            print(report)
        else:
            # Real AWS mode: will be implemented in issue-03 and issue-04
            # For now, just inform the user
            sys.stderr.write("Error: AWS integration not yet implemented. Use --dry-run for testing.\n")
            return 1

        return 0

    except Exception as e:
        sys.stderr.write(f"Error: {str(e)}\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())

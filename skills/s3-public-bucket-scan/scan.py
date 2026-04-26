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

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    # boto3 not available - only dry-run mode will work
    boto3 = None
    ClientError = Exception
    NoCredentialsError = Exception


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
# AWS CLIENT MANAGEMENT
# ============================================================================

def get_clients(region: str | None, dry_run: bool):
    """
    Create boto3 clients for S3 and EC2.

    Args:
        region: Target region string, 'all', or None (default)
        dry_run: If True, return None clients (dry-run mode bypasses AWS)

    Returns: (s3_client, ec2_client) tuple

    CRITICAL DESIGN NOTES:
    - S3 client is ALWAYS created in us-east-1 because list_buckets() is a global operation
    - EC2 client is ALWAYS created in us-east-1 for describe_regions() (also global)
    - You CAN call get_bucket_acl(), get_bucket_policy(), etc. on buckets in ANY region
      from an S3 client created in ANY region (S3 control plane is region-aware)
    - We create one S3 client and reuse it for all operations (no per-region clients needed)
    - NO custom retry configuration per Blocker 5 Resolution
    """
    if dry_run:
        return (None, None)

    # Create S3 client in us-east-1 (list_buckets is global, other ops are region-aware)
    s3_client = boto3.client('s3', region_name='us-east-1')

    # Create EC2 client in us-east-1 (describe_regions is global)
    ec2_client = boto3.client('ec2', region_name='us-east-1')

    return (s3_client, ec2_client)


# ============================================================================
# BUCKET ENUMERATION
# ============================================================================

def enumerate_buckets(s3_client, ec2_client, target_region: str | None, dry_run: bool = False) -> list[dict]:
    """
    List all S3 buckets, optionally filtered by region.

    Args:
        s3_client: boto3 S3 client (created in us-east-1 for global list_buckets call)
        ec2_client: boto3 EC2 client (only used when target_region == 'all')
        target_region: None (default region), 'all', or specific region string
        dry_run: If True, use fixture data

    Returns: list[dict] where each dict has:
        - 'Name': str (bucket name, from boto3 response)
        - 'Region': str (bucket region, from get_bucket_location)
    """
    if dry_run:
        # Use fixture data
        buckets_fixture = DRY_RUN_FIXTURES['list_buckets']
        buckets = []
        for bucket in buckets_fixture['Buckets']:
            bucket_name = bucket['Name']
            location_response = DRY_RUN_FIXTURES['get_bucket_location'].get(bucket_name, {'LocationConstraint': None})
            bucket_region = location_response.get('LocationConstraint')

            # CRITICAL: AWS API returns None for us-east-1 buckets
            if bucket_region is None:
                bucket_region = 'us-east-1'

            buckets.append({
                'Name': bucket_name,
                'Region': bucket_region
            })
        return buckets

    # Step 1: Determine target region set
    if target_region == 'all':
        # Enumerate all enabled regions via EC2 API
        regions_response = ec2_client.describe_regions()
        target_regions = {r['RegionName'] for r in regions_response['Regions']}
    elif target_region is None:
        # Use default region (no filtering)
        target_regions = None  # Sentinel: include all buckets
    else:
        # Specific region
        target_regions = {target_region}

    # Step 2: List all buckets (global operation, no region filter in API)
    list_response = s3_client.list_buckets()
    buckets = []

    for bucket in list_response.get('Buckets', []):
        bucket_name = bucket['Name']

        # Step 3: Get bucket region
        try:
            location_response = s3_client.get_bucket_location(Bucket=bucket_name)
            bucket_region = location_response.get('LocationConstraint')

            # CRITICAL: AWS API returns None for us-east-1 buckets
            if bucket_region is None:
                bucket_region = 'us-east-1'

        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                # Skip bucket if no permission to get location
                continue
            raise

        # Step 4: Filter by target region(s)
        if target_regions is None or bucket_region in target_regions:
            buckets.append({
                'Name': bucket_name,
                'Region': bucket_region
            })

    return buckets


# ============================================================================
# SCANNING ORCHESTRATION
# ============================================================================

def scan_bucket(s3_client, bucket_name: str, bucket_region: str, include_empty: bool, dry_run: bool = False) -> dict | None:
    """
    Scan a single bucket for public exposure.

    Args:
        s3_client: boto3 S3 client
        bucket_name: Bucket name to scan
        bucket_region: Bucket region (for reporting)
        include_empty: If False, return None for buckets with 0 objects
        dry_run: If True, use fixture data

    Returns: dict with scan results, or None if bucket should be skipped
    """
    # Check object count FIRST (before expensive ACL/policy calls)
    try:
        if dry_run:
            objects_response = DRY_RUN_FIXTURES['list_objects_v2'].get(bucket_name, {'Contents': []})
        else:
            objects_response = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)

        object_count = len(objects_response.get('Contents', []))

        # CRITICAL: Apply empty bucket filter HERE per Issue 8 Resolution
        if not include_empty and object_count == 0:
            return None  # Skip this bucket entirely

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            return None
        raise

    # Bucket has objects (or include_empty=True), proceed with full scan
    acl_vectors = check_bucket_acl(bucket_name, s3_client, dry_run)
    policy_vectors = check_bucket_policy(bucket_name, s3_client, dry_run)
    bpa_vectors = check_public_access_block(bucket_name, s3_client, dry_run)
    object_acls = check_object_acls(bucket_name, s3_client, dry_run, max_objects=10)
    is_intentional = is_intentionally_public(bucket_name, s3_client, dry_run)

    return {
        'bucket_name': bucket_name,
        'bucket_region': bucket_region,
        'acl_vectors': acl_vectors,
        'policy_vectors': policy_vectors,
        'bpa_vectors': bpa_vectors,
        'object_acls': object_acls,
        'is_intentional': is_intentional
    }


# ============================================================================
# DETECTION FUNCTIONS (STUB IMPLEMENTATIONS)
# ============================================================================

def check_bucket_acl(bucket_name: str, s3_client=None, dry_run: bool = False) -> list[str]:
    """
    Check bucket ACL for public grants.

    Returns: ["Grant {permission} to {AllUsers|AuthenticatedUsers}", ...]
    """
    if dry_run:
        acl_response = DRY_RUN_FIXTURES['get_bucket_acl'].get(bucket_name, {'Grants': []})
    else:
        # Call real AWS API
        try:
            acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('AccessDenied', 'NoSuchBucket'):
                return []
            raise

    exposure_vectors = []
    for grant in acl_response.get('Grants', []):
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
        policy_fixture = DRY_RUN_FIXTURES['get_bucket_policy'].get(bucket_name)
        if policy_fixture is None:
            # NoSuchBucketPolicy
            return []
        policy_doc = policy_fixture
    else:
        # Call real AWS API
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_doc = json.loads(policy_response['Policy'])
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('NoSuchBucketPolicy', 'AccessDenied'):
                return []
            raise

    # Parse policy document
    exposure_vectors = []
    for idx, statement in enumerate(policy_doc.get('Statement', [])):
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

        # CRITICAL: Use 'aws:SourceIp' in str(condition) per Blocker 4 Resolution
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
        bpa_fixture = DRY_RUN_FIXTURES['get_public_access_block'].get(bucket_name)
        if bpa_fixture is None:
            # NoSuchPublicAccessBlockConfiguration
            return []
        config = bpa_fixture.get('PublicAccessBlockConfiguration', {})
    else:
        # Call real AWS API
        try:
            bpa_response = s3_client.get_public_access_block(Bucket=bucket_name)
            config = bpa_response.get('PublicAccessBlockConfiguration', {})
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('NoSuchPublicAccessBlockConfiguration', 'AccessDenied'):
                return []
            raise

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

    CRITICAL: Normalizes boto3's capital-K 'Key' to lowercase 'key' per Blocker 2 Resolution
    """
    if dry_run:
        list_response = DRY_RUN_FIXTURES['list_objects_v2'].get(bucket_name, {'Contents': []})
    else:
        # Call real AWS API
        try:
            list_response = s3_client.list_objects_v2(
                Bucket=bucket_name,
                MaxKeys=max_objects
            )
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('NoSuchBucket', 'AccessDenied'):
                return []
            raise

    objects_data = []
    for obj in list_response.get('Contents', [])[:max_objects]:
        obj_key = obj['Key']  # boto3 uses capital K

        # Get object ACL
        if dry_run:
            acl_response = DRY_RUN_FIXTURES['get_object_acl'].get((bucket_name, obj_key), {'Grants': []})
        else:
            try:
                acl_response = s3_client.get_object_acl(
                    Bucket=bucket_name,
                    Key=obj_key
                )
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AccessDenied', 'NoSuchKey'):
                    # Skip object if no permission to read ACL
                    continue
                raise

        # Detect public grants
        public_grants = []
        for grant in acl_response.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group':
                uri = grantee.get('URI', '')
                if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                    public_grants.append(grant['Permission'])

        if public_grants:  # Only include objects with public grants
            # CRITICAL: Normalize capital-K 'Key' to lowercase 'key' per Blocker 2 Resolution
            objects_data.append({
                'bucket': bucket_name,      # Explicitly add bucket name
                'key': obj_key,              # Normalized to lowercase 'key'
                'acl': acl_response,         # Full ACL response for reference
                'public_grants': public_grants  # Derived field
            })

    return objects_data


def is_intentionally_public(bucket_name: str, s3_client=None, dry_run: bool = False) -> bool:
    """
    Check if bucket is tagged as intentionally public.

    Returns: True if tag Key='public' Value='true' exists (case-sensitive)
    """
    if dry_run:
        tagging_fixture = DRY_RUN_FIXTURES['get_bucket_tagging'].get(bucket_name)
        if tagging_fixture is None:
            # NoSuchTagSet
            return False
        tag_set = tagging_fixture.get('TagSet', [])
    else:
        # Call real AWS API
        try:
            tagging_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
            tag_set = tagging_response.get('TagSet', [])
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ('NoSuchTagSet', 'AccessDenied'):
                return False
            raise

    # Check for exact case-sensitive match: Key='public' Value='true'
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

        # Step 1: Create AWS clients (or None for dry-run)
        s3_client, ec2_client = get_clients(args.region, args.dry_run)

        # Step 2: Enumerate buckets (with region filtering)
        buckets = enumerate_buckets(s3_client, ec2_client, args.region, args.dry_run)

        # Step 3: Scan each bucket
        scan_results = []
        for bucket in buckets:
            bucket_name = bucket['Name']
            bucket_region = bucket['Region']

            # Scan bucket (may return None if empty and include_empty=False)
            result = scan_bucket(s3_client, bucket_name, bucket_region, args.include_empty, args.dry_run)

            if result is not None:
                scan_results.append(result)

        # Step 4: Generate and print report
        report = format_report(scan_results, args)
        print(report)

        return 0

    except NoCredentialsError:
        sys.stderr.write("Error: AWS credentials not configured.\n")
        sys.stderr.write("Configure credentials via AWS CLI, environment variables, or IAM role.\n")
        return 1

    except Exception as e:
        sys.stderr.write(f"Error: {str(e)}\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())

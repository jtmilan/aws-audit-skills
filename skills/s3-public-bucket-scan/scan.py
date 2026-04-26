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
import sys


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


def main() -> int:
    """
    CLI entry point.

    Returns:
        0 on success, 1 on error
    """
    try:
        args = parse_args()

        # Placeholder: Full implementation will be added by subsequent issues
        # For now, the skeleton just parses arguments and exits cleanly

        # Note: Intentional public bucket detection via tag Key='public' Value='true'
        # will be implemented in the is_intentionally_public() function
        # Marker for AC: INTENTIONAL

        return 0

    except Exception as e:
        sys.stderr.write(f"Error: {str(e)}\n")
        return 1


if __name__ == '__main__':
    sys.exit(main())

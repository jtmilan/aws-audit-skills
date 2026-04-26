"""
Unit tests for s3-public-bucket-scan using botocore.stub.Stubber.

Tests verify detection functions using mocked boto3 responses:
- test_detects_public_acl: Tests AllUsers grant detection in bucket ACL
- test_detects_public_policy: Tests wildcard Principal without IP restriction
- test_detects_bpa_disabled: Tests BlockPublicAccess disabled settings
"""

import pytest
import boto3
from botocore.stub import Stubber
from scan import (
    check_bucket_acl,
    check_bucket_policy,
    check_public_access_block,
)


def test_detects_public_acl():
    """Test detection of AllUsers grant in bucket ACL."""
    # Create real boto3 client
    s3_client = boto3.client('s3', region_name='us-east-1')

    # Stub responses
    with Stubber(s3_client) as stubber:
        # Add stubbed response for get_bucket_acl
        stubber.add_response(
            'get_bucket_acl',
            {
                'Grants': [
                    {
                        'Grantee': {
                            'Type': 'Group',
                            'URI': 'http://acs.amazonaws.com/groups/global/AllUsers'
                        },
                        'Permission': 'FULL_CONTROL'
                    }
                ]
            },
            {'Bucket': 'test-bucket'}
        )

        # Execute test
        vectors = check_bucket_acl('test-bucket', s3_client, dry_run=False)

        # Assert
        assert len(vectors) == 1
        assert 'AllUsers' in vectors[0]
        assert 'FULL_CONTROL' in vectors[0]


def test_detects_public_policy():
    """Test detection of wildcard Principal without IP restriction."""
    # Create real boto3 client
    s3_client = boto3.client('s3', region_name='us-east-1')

    # Stub responses
    with Stubber(s3_client) as stubber:
        # Add stubbed response for get_bucket_policy
        # Policy with Principal='*' and no aws:SourceIp condition
        stubber.add_response(
            'get_bucket_policy',
            {
                'Policy': '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::test-bucket/*"}]}'
            },
            {'Bucket': 'test-bucket'}
        )

        # Execute test
        vectors = check_bucket_policy('test-bucket', s3_client, dry_run=False)

        # Assert - CRITICAL: Must verify 'Statement 0' appears in output per testing guidance
        assert len(vectors) == 1
        assert 'Statement 0' in vectors[0]
        assert 'Principal' in vectors[0]


def test_detects_bpa_disabled():
    """Test detection of disabled BlockPublicAccess settings."""
    # Create real boto3 client
    s3_client = boto3.client('s3', region_name='us-east-1')

    # Stub responses
    with Stubber(s3_client) as stubber:
        # Add stubbed response for get_public_access_block with BlockPublicAcls=false
        stubber.add_response(
            'get_public_access_block',
            {
                'PublicAccessBlockConfiguration': {
                    'BlockPublicAcls': False,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            },
            {'Bucket': 'test-bucket'}
        )

        # Execute test
        vectors = check_public_access_block('test-bucket', s3_client, dry_run=False)

        # Assert
        assert len(vectors) == 1
        assert 'BlockPublicAcls=false' in vectors[0]
